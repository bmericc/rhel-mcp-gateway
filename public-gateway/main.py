import os
import re
import html
import json
import base64
import hashlib
import shlex
import asyncio
from contextlib import asynccontextmanager
from typing import Dict, Any
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, Response
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth
import asyncssh
from cryptography.fernet import Fernet, InvalidToken

import cockpit_client
import fleet_tools

# MCP Kütüphaneleri
from mcp.server import Server
import mcp.types as types
from mcp.server.sse import SseServerTransport
from starlette.routing import Mount, Route

app = FastAPI()

SECRET_KEY = os.getenv("SECRET_KEY", "gizli-anahtar")
# Web paneline (sunucu ekleme/silme) girebilecek Google hesapları, virgülle ayrılmış
ALLOWED_EMAILS = {e.strip().lower() for e in os.getenv("ALLOWED_EMAILS", "").split(",") if e.strip()}

app.add_middleware(
    SessionMiddleware, 
    secret_key=SECRET_KEY
)

oauth = OAuth()
oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID", ""),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET", ""),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

SERVERS_FILE = "data/servers.json"

def load_servers() -> Dict[str, Dict[str, Any]]:
    os.makedirs(os.path.dirname(SERVERS_FILE), exist_ok=True)
    if os.path.exists(SERVERS_FILE):
        try:
            with open(SERVERS_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_servers(servers: Dict[str, Dict[str, Any]]):
    os.makedirs(os.path.dirname(SERVERS_FILE), exist_ok=True)
    with open(SERVERS_FILE, "w") as f:
        json.dump(servers, f, indent=4)

# --- Gizli bilgiler ---
# Cockpit şifreleri servers.json'da SECRET_KEY'den türetilen anahtarla şifreli tutulur
SECRET_FIELDS = ("cockpit_password",)

def _fernet() -> Fernet:
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(SECRET_KEY.encode()).digest()))

def encrypt_secret(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()

def decrypt_secret(value: str) -> str | None:
    try:
        return _fernet().decrypt(value.encode()).decode()
    except (InvalidToken, ValueError):
        return None

def public_server(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Şifreler olmadan, dışarıya gösterilebilir sunucu bilgisi."""
    out = {k: v for k, v in cfg.items() if k not in SECRET_FIELDS}
    out["cockpit"] = bool(cfg.get("cockpit_user"))
    if out["cockpit"]:
        out["cockpit_url"] = cockpit_url(cfg)
    return out

def cockpit_url(cfg: Dict[str, Any]) -> str:
    return cfg.get("cockpit_url") or f"https://{cfg['host']}:9090"

# --- SSH Giriş Ayarları ---
# Denenecek kullanıcılar ve key klasörleri, sırasıyla: "kullanici:/ssh/klasoru,..."
SSH_LOGINS = os.getenv("SSH_LOGINS", "root:/root/.ssh,bmericc:/home/bmericc/.ssh")
SSH_KEY_NAMES = ("id_ed25519", "id_ecdsa", "id_rsa")

def parse_ssh_logins(value: str) -> list[tuple[str, str]]:
    logins = []
    for item in value.split(","):
        user, _, ssh_dir = item.strip().partition(":")
        if user and ssh_dir:
            logins.append((user.strip(), ssh_dir.strip()))
    return logins

def find_ssh_keys(ssh_dir: str) -> list[str]:
    return [p for p in (os.path.join(ssh_dir, n) for n in SSH_KEY_NAMES) if os.path.isfile(p)]

def login_candidates(cfg: Dict[str, Any]) -> list[tuple[str, list[str]]]:
    """Önce sunucuya tanımlı kullanıcı, ardından SSH_LOGINS'teki diğer kullanıcılar denenir."""
    logins = parse_ssh_logins(SSH_LOGINS)
    candidates = []
    cfg_user = cfg.get("user")
    if cfg_user:
        if cfg.get("ssh_key_path"):
            keys = [cfg["ssh_key_path"]]
        else:
            keys = find_ssh_keys(dict(logins).get(cfg_user, ""))
        if keys:
            candidates.append((cfg_user, keys))
    for user, ssh_dir in logins:
        if user == cfg_user:
            continue
        keys = find_ssh_keys(ssh_dir)
        if keys:
            candidates.append((user, keys))
    return candidates

class SSHError(Exception):
    """Bağlantı kurulamadı veya hiçbir kullanıcı ile giriş yapılamadı."""

@asynccontextmanager
async def ssh_session(cfg: Dict[str, Any]):
    """Sunucuya bağlanır; (kullanıcı, bağlantı) döner.

    Kimlik doğrulama reddedilirse sıradaki kullanıcı denenir; ağ hatasında hemen vazgeçilir.
    """
    candidates = login_candidates(cfg)
    if not candidates:
        raise SSHError(f"Hata: '{cfg.get('name', cfg.get('host'))}' için kullanılabilir SSH key bulunamadı.")

    denied = []
    for user, keys in candidates:
        try:
            cm = asyncssh.connect(
                cfg["host"],
                port=cfg.get("port", 22),
                username=user,
                client_keys=keys,
                known_hosts=None
            )
            conn = await cm.__aenter__()
        except asyncssh.PermissionDenied as e:
            # Kimlik doğrulama reddedildi: sıradaki kullanıcıyı dene
            denied.append(f"{user}: {e.reason}")
            continue
        except Exception as e:
            # Ağ/bağlantı hatasında diğer kullanıcıları denemenin anlamı yok
            raise SSHError(f"SSH Bağlantı Hatası: {str(e)}") from e
        try:
            yield user, conn
        finally:
            await cm.__aexit__(None, None, None)
        return

    raise SSHError("SSH Kimlik Doğrulama Hatası, denenen kullanıcılar:\n" + "\n".join(denied))

def make_runner(user: str, conn) -> fleet_tools.Runner:
    async def run(argv, privileged: bool = False, timeout: int = fleet_tools.DEFAULT_TIMEOUT):
        if isinstance(argv, str):
            command = argv
            if privileged and user != "root":
                command = "sudo -n sh -c " + shlex.quote(argv)
        else:
            # Çıktıların ayrıştırılabilmesi için dil ayarını sabitle
            command = shlex.join(["env", "LC_ALL=C", *argv])
            if privileged and user != "root":
                command = "sudo -n " + command
        try:
            result = await asyncio.wait_for(conn.run(command, check=False), timeout)
        except asyncio.TimeoutError:
            return fleet_tools.CommandResult(user, None, "", f"Komut {timeout} saniyede zaman aşımına uğradı.", "ssh")
        return fleet_tools.CommandResult(user, result.exit_status, result.stdout or "", result.stderr or "", "ssh")
    return run

def make_cockpit_runner(session: cockpit_client.CockpitSession) -> fleet_tools.Runner:
    async def run(argv, privileged: bool = False, timeout: int = fleet_tools.DEFAULT_TIMEOUT):
        if isinstance(argv, str):
            argv = ["sh", "-c", argv]
        return await session.spawn(argv, superuser=privileged, timeout=timeout)
    return run

@asynccontextmanager
async def open_runner(cfg: Dict[str, Any]):
    """Önce Cockpit (tanımlıysa), bağlanılamazsa SSH. (runner, bağlantı bilgisi) döner."""
    cockpit_error = None
    if cfg.get("cockpit_user"):
        password = decrypt_secret(cfg.get("cockpit_password", ""))
        session = None
        if password is None:
            cockpit_error = "Cockpit şifresi çözülemedi (şifre girilmemiş ya da SECRET_KEY değişmiş olabilir)."
        else:
            candidate = cockpit_client.CockpitSession(
                cockpit_url(cfg), cfg["cockpit_user"], password,
                verify_tls=bool(cfg.get("cockpit_verify_tls")),
            )
            try:
                session = await candidate.connect()
            except cockpit_client.CockpitError as e:
                cockpit_error = str(e)
        if session is not None:
            try:
                yield make_cockpit_runner(session), {"via": "cockpit", "user": cfg["cockpit_user"]}
            finally:
                await session.close()
            return

    try:
        async with ssh_session(cfg) as (user, conn):
            info = {"via": "ssh", "user": user}
            if cockpit_error:
                info["cockpit_error"] = cockpit_error
            yield make_runner(user, conn), info
    except SSHError as e:
        if cockpit_error:
            raise SSHError(f"{cockpit_error}\nSSH yedeği de başarısız: {e}") from e
        raise

def text_result(value: Any) -> list[types.TextContent]:
    return [types.TextContent(type="text", text=fleet_tools.to_text(value))]

# --- MCP Sunucu Tanımları ---
mcp_server = Server("rhel-fleet-gateway")

SERVER_NAME_PROP = {"server_name": {"type": "string", "description": "Kayıtlı sunucu adı (örn: prod-db)"}}

@mcp_server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="list_servers",
            description="Kayıtlı tüm RHEL sunucularını (şifreler hariç) ve Cockpit girişi tanımlı olup olmadığını listeler.",
            inputSchema={"type": "object", "properties": {}},
            annotations=types.ToolAnnotations(readOnlyHint=True, openWorldHint=False),
        ),
        types.Tool(
            name="fleet_health",
            description="Tüm kayıtlı sunucuların yük, çökmüş servis ve kök disk doluluğu özetini paralel olarak toplar.",
            inputSchema={"type": "object", "properties": {}},
            annotations=types.ToolAnnotations(readOnlyHint=True, openWorldHint=False),
        ),
        *[spec.to_tool() for spec in fleet_tools.TOOLS],
        types.Tool(
            name="run_remote_command",
            description=(
                "Kayıtlı bir sunucuda serbest bir Linux komutu çalıştırır. Amaca özel bir araç varsa onu tercih edin. "
                "Sunucuya Cockpit girişi tanımlıysa Cockpit üzerinden, değilse veya Cockpit'e ulaşılamazsa SSH ile çalışır."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    **SERVER_NAME_PROP,
                    "command": {"type": "string", "description": "Çalıştırılacak Linux komutu (örn: systemctl status nginx)"},
                    "as_root": {"type": "boolean", "description": "Yönetici yetkisiyle çalıştır (Cockpit superuser / SSH'ta sudo -n)"},
                    "confirm": {"type": "boolean", "description": "Komutu gerçekten çalıştırmak için true. Verilmezse sadece ne çalıştırılacağı gösterilir."},
                },
                "required": ["server_name", "command"]
            },
            annotations=types.ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=False),
        ),
    ]

def confirmation_required(server_name: str, action: str) -> list[types.TextContent]:
    return text_result(
        f"Onay gerekli: '{server_name}' üzerinde şu işlem yapılacak:\n  {action}\n"
        "Uygulamak için aynı aracı confirm: true ile tekrar çağırın."
    )

async def fleet_health(servers: Dict[str, Dict[str, Any]]) -> dict:
    async def one(cfg):
        try:
            async with open_runner(cfg) as (run, info):
                return {**await fleet_tools.fleet_health_for(run), "connection": info}
        except Exception as e:
            return {"error": str(e)}

    names = list(servers)
    results = await asyncio.gather(*(one(servers[n]) for n in names))
    return dict(zip(names, results))

@mcp_server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    servers = load_servers()
    arguments = arguments or {}

    if name == "list_servers":
        return text_result({n: public_server(cfg) for n, cfg in servers.items()})

    if name == "fleet_health":
        return text_result(await fleet_health(servers))

    spec = fleet_tools.TOOLS_BY_NAME.get(name)
    if spec is None and name != "run_remote_command":
        raise ValueError(f"Bilinmeyen araç: {name}")

    server_name = arguments.get("server_name")
    if server_name not in servers:
        return text_result(f"Hata: '{server_name}' sunucusu hafızada bulunamadı.")
    cfg = servers[server_name]

    try:
        if name == "run_remote_command":
            command = arguments.get("command")
            if not arguments.get("confirm"):
                return confirmation_required(server_name, command)
            async with open_runner(cfg) as (run, info):
                result = await run(command, privileged=bool(arguments.get("as_root")))
            output = f"User: {result.user}\nVia: {result.via}\nExit Status: {result.exit_status}\nStdout:\n{result.stdout}\nStderr:\n{result.stderr}"
            if info.get("cockpit_error"):
                output = f"Not: Cockpit kullanılamadı, SSH ile çalıştırıldı ({info['cockpit_error']})\n" + output
            return text_result(output)

        if not spec.read_only and not arguments.get("confirm"):
            return confirmation_required(server_name, spec.preview(arguments))

        async with open_runner(cfg) as (run, info):
            value = await spec.handler(run, arguments)
        if isinstance(value, dict):
            value["connection"] = info
        return text_result(value)
    except (SSHError, cockpit_client.CockpitError) as e:
        return text_result(str(e))
    except fleet_tools.ToolInputError as e:
        raise ValueError(str(e)) from e

# FastAPI Web Uç Noktaları
SERVER_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
HOST_RE = re.compile(r"^[A-Za-z0-9.:_-]{1,253}$")

def current_admin(request: Request) -> str | None:
    """Oturumdaki kullanıcı ALLOWED_EMAILS içindeyse e-postasını döner."""
    user = request.session.get('user') or {}
    email = (user.get('email') or "").lower()
    return email if email and email in ALLOWED_EMAILS else None

PAGE_STYLE = """
<style>
  body { font-family: system-ui, sans-serif; max-width: 960px; margin: 24px auto; padding: 0 16px; }
  table { border-collapse: collapse; width: 100%; margin-bottom: 24px; }
  th, td { border: 1px solid #ddd; padding: 6px 8px; text-align: left; font-size: 14px; }
  form.add { display: grid; grid-template-columns: 200px 1fr; gap: 8px; max-width: 640px; }
  fieldset { border: 1px solid #ddd; margin: 12px 0; }
  .note { color: #555; font-size: 13px; }
  .err { color: #b00020; }
</style>
"""

def server_row(cfg: Dict[str, Any]) -> str:
    e = lambda v: html.escape(str(v)) if v not in (None, "") else "—"
    name = cfg["name"]
    cockpit = f"{e(cfg['cockpit_user'])} @ {e(cockpit_url(cfg))}" if cfg.get("cockpit_user") else "—"
    ssh = f"{e(cfg.get('user') or 'otomatik')} @ {e(cfg['host'])}:{e(cfg.get('port', 22))}"
    return (
        f"<tr><td><b>{e(name)}</b></td><td>{cockpit}</td><td>{ssh}</td>"
        f"<td><form method='post' action='/servers/{html.escape(name)}/delete' "
        f"onsubmit=\"return confirm('{html.escape(name)} silinsin mi?')\"><button>Sil</button></form></td></tr>"
    )

@app.get("/", response_class=HTMLResponse)
async def index(request: Request, error: str = ""):
    user = request.session.get('user')
    if not user:
        return """
        <h2>RHEL MCP Gateway - Giriş Yapın</h2>
        <a href="/login" style="padding: 10px 20px; background: #4285F4; color: white; text-decoration: none; border-radius: 5px;">Google ile Giriş Yap</a>
        """
    if not current_admin(request):
        return HTMLResponse(f"""
            <h2>Yetkiniz yok</h2>
            <p>{html.escape(user.get('email', ''))} hesabı bu paneli kullanamaz. Yönetici, e-postayı ALLOWED_EMAILS ayarına eklemeli.</p>
            <a href="/logout">Çıkış Yap</a>
        """, status_code=403)

    servers = load_servers()
    rows = "".join(server_row(cfg) for cfg in servers.values()) or "<tr><td colspan='4'>Henüz tanımlı sunucu yok.</td></tr>"
    error_html = f"<p class='err'>{html.escape(error)}</p>" if error else ""

    return f"""
        {PAGE_STYLE}
        <h2>Hoş geldiniz, {html.escape(user.get('email', ''))}!</h2>
        <p>MCP Gateway aktif. SSE Uç Noktası: <code>https://mcp.kalehost.net/sse</code></p>
        <h3>Kayıtlı Sunucular</h3>
        <table>
          <tr><th>Ad</th><th>Cockpit</th><th>SSH (yedek)</th><th></th></tr>
          {rows}
        </table>

        <h3>Sunucu Ekle / Güncelle</h3>
        <p class="note">Aynı adla kaydetmek mevcut sunucuyu günceller. Şifre alanı boş bırakılırsa mevcut şifre korunur.</p>
        {error_html}
        <form class="add" method="post" action="/servers">
          <label>Sunucu adı *</label><input name="name" required placeholder="prod-db">
          <label>Host (IP / alan adı) *</label><input name="host" required placeholder="192.168.0.98">
          <fieldset style="grid-column: 1 / -1">
            <legend>Cockpit</legend>
            <div class="add">
              <label>Cockpit kullanıcısı</label><input name="cockpit_user" placeholder="bmericc">
              <label>Cockpit şifresi</label><input name="cockpit_password" type="password" autocomplete="new-password">
              <label>Cockpit adresi</label><input name="cockpit_url" placeholder="https://HOST:9090 (boşsa)">
              <label>TLS sertifikasını doğrula</label><input name="cockpit_verify_tls" type="checkbox">
            </div>
          </fieldset>
          <fieldset style="grid-column: 1 / -1">
            <legend>SSH (yedek)</legend>
            <div class="add">
              <label>SSH kullanıcısı</label><input name="user" placeholder="boşsa SSH_LOGINS sırası">
              <label>SSH portu</label><input name="port" type="number" value="22">
              <label>SSH key yolu</label><input name="ssh_key_path" placeholder="boşsa kullanıcının .ssh klasörü">
            </div>
          </fieldset>
          <span></span><button type="submit">Kaydet</button>
        </form>
        <br><a href="/logout">Çıkış Yap</a>
    """

def _redirect_error(message: str) -> RedirectResponse:
    from urllib.parse import quote
    return RedirectResponse(url=f"/?error={quote(message)}", status_code=303)

@app.post("/servers")
async def save_server(request: Request):
    if not current_admin(request):
        return HTMLResponse("Yetkiniz yok", status_code=403)
    form = await request.form()
    field = lambda k: (form.get(k) or "").strip()

    name, host = field("name"), field("host")
    if not SERVER_NAME_RE.match(name):
        return _redirect_error("Sunucu adı yalnızca harf, rakam, nokta, alt çizgi ve tire içerebilir.")
    if not HOST_RE.match(host):
        return _redirect_error("Geçersiz host.")
    try:
        port = int(field("port") or 22)
        if not 1 <= port <= 65535:
            raise ValueError
    except ValueError:
        return _redirect_error("Geçersiz SSH portu.")
    cockpit_url_value = field("cockpit_url")
    if cockpit_url_value and not re.match(r"^https?://[^\s/]+(:\d+)?/?$", cockpit_url_value):
        return _redirect_error("Cockpit adresi https://host:9090 biçiminde olmalı.")

    servers = load_servers()
    existing = servers.get(name, {})
    cfg: Dict[str, Any] = {"name": name, "host": host, "port": port}
    for key in ("user", "ssh_key_path", "cockpit_user"):
        if field(key):
            cfg[key] = field(key)
    if cockpit_url_value:
        cfg["cockpit_url"] = cockpit_url_value.rstrip("/")
    if form.get("cockpit_verify_tls"):
        cfg["cockpit_verify_tls"] = True

    if cfg.get("cockpit_user"):
        password = form.get("cockpit_password") or ""
        if password:
            cfg["cockpit_password"] = encrypt_secret(password)
        elif existing.get("cockpit_password"):
            cfg["cockpit_password"] = existing["cockpit_password"]
        else:
            return _redirect_error("Cockpit kullanıcısı için şifre gerekli.")

    servers[name] = cfg
    save_servers(servers)
    return RedirectResponse(url="/", status_code=303)

@app.post("/servers/{name}/delete")
async def delete_server(name: str, request: Request):
    if not current_admin(request):
        return HTMLResponse("Yetkiniz yok", status_code=403)
    servers = load_servers()
    servers.pop(name, None)
    save_servers(servers)
    return RedirectResponse(url="/", status_code=303)

@app.get("/login")
async def login(request: Request):
    redirect_uri = request.url_for('auth')
    return await oauth.google.authorize_redirect(request, redirect_uri)

@app.get("/auth")
async def auth(request: Request):
    token = await oauth.google.authorize_access_token(request)
    user = token.get('userinfo')
    if not user:
        user = await oauth.google.parse_id_token(request, token)
    request.session['user'] = dict(user)
    return RedirectResponse(url='/', status_code=303)

@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url='/', status_code=303)

# --- MCP SSE Transport Entegrasyonu ---
# Sonda "/" olmalı: aksi halde her POST /messages isteği 307 ile /messages/'e yönlenir
sse = SseServerTransport("/messages/")

MCP_API_KEY = os.getenv("MCP_API_KEY", "")

async def handle_sse(request: Request):
    # /sse herkese açıksa, URL'yi bilen herkes kayıtlı sunucularda komut çalıştırabilir.
    # /messages/ istekleri tahmin edilemez session_id ile korunur.
    if MCP_API_KEY:
        auth_header = request.headers.get("authorization", "")
        token = auth_header[7:] if auth_header.lower().startswith("bearer ") else request.query_params.get("token", "")
        if token != MCP_API_KEY:
            return JSONResponse({"error": "unauthorized"}, status_code=401)

    async with sse.connect_sse(
        request.scope, request.receive, request._send
    ) as streams:
        await mcp_server.run(
            streams[0], streams[1], mcp_server.create_initialization_options()
        )
    # Bağlantı kapandığında Starlette bir Response bekler; None dönerse TypeError fırlar
    return Response()

# FastAPI route'larına MCP SSE ekleme
app.routes.append(Route("/sse", endpoint=handle_sse))
app.routes.append(Mount("/messages/", app=sse.handle_post_message))

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 7435))
    # Reverse proxy (https) arkasında url_for doğru şemayı üretsin diye X-Forwarded-* başlıklarına güven
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False, proxy_headers=True, forwarded_allow_ips="*")
