import os
import json
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

import fleet_tools

# MCP Kütüphaneleri
from mcp.server import Server
import mcp.types as types
from mcp.server.sse import SseServerTransport
from starlette.routing import Mount, Route

app = FastAPI()

app.add_middleware(
    SessionMiddleware, 
    secret_key=os.getenv("SECRET_KEY", "gizli-anahtar")
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
        else:
            # Çıktıların ayrıştırılabilmesi için dil ayarını sabitle
            command = shlex.join(["env", "LC_ALL=C", *argv])
            if privileged and user != "root":
                command = "sudo -n " + command
        try:
            result = await asyncio.wait_for(conn.run(command, check=False), timeout)
        except asyncio.TimeoutError:
            return fleet_tools.CommandResult(user, None, "", f"Komut {timeout} saniyede zaman aşımına uğradı.")
        return fleet_tools.CommandResult(user, result.exit_status, result.stdout or "", result.stderr or "")
    return run

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
            description="Hafızada kayıtlı olan tüm RHEL sunucularını listeler.",
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
                "Sunucuya tanımlı kullanıcı reddedilirse diğer kullanıcılar (örn. root, bmericc) sırayla denenir."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    **SERVER_NAME_PROP,
                    "command": {"type": "string", "description": "Çalıştırılacak Linux komutu (örn: systemctl status nginx)"},
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
            async with ssh_session(cfg) as (user, conn):
                return await fleet_tools.fleet_health_for(make_runner(user, conn))
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
        return [types.TextContent(type="text", text=json.dumps(servers, indent=4))]

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
            async with ssh_session(cfg) as (user, conn):
                result = await make_runner(user, conn)(command)
            output = f"User: {result.user}\nExit Status: {result.exit_status}\nStdout:\n{result.stdout}\nStderr:\n{result.stderr}"
            return text_result(output)

        if not spec.read_only and not arguments.get("confirm"):
            return confirmation_required(server_name, spec.preview(arguments))

        async with ssh_session(cfg) as (user, conn):
            return text_result(await spec.handler(make_runner(user, conn), arguments))
    except SSHError as e:
        return text_result(str(e))
    except fleet_tools.ToolInputError as e:
        raise ValueError(str(e)) from e

# FastAPI Web Uç Noktaları
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    user = request.session.get('user')
    if not user:
        return """
        <h2>RHEL MCP Gateway - Giriş Yapın</h2>
        <a href="/login" style="padding: 10px 20px; background: #4285F4; color: white; text-decoration: none; border-radius: 5px;">Google ile Giriş Yap</a>
        """
    
    servers = load_servers()
    servers_html = "".join([
        f"<li><b>{s['name']}</b> ({s.get('user', 'otomatik')}@{s['host']}:{s.get('port', 22)})</li>" 
        for s in servers.values()
    ]) if servers else "<li>Henüz tanımlı sunucu yok.</li>"
    
    return f"""
        <h2>Hoş geldiniz, {user.get('email')}!</h2>
        <p>MCP Gateway aktif. SSE Uç Noktası: <code>https://mcp.kalehost.net/sse</code></p>
        <h3>Kayıtlı Sunucular:</h3>
        <ul>{servers_html}</ul>
        <br><a href="/logout">Çıkış Yap</a>
    """

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
