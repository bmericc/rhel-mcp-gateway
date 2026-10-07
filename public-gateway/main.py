import os
import re
import html
import json
import base64
import hashlib
import secrets
import ipaddress
import shlex
from urllib.parse import urlencode
import asyncio
import time
from contextlib import asynccontextmanager
from typing import Dict, Any
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException, Query
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, Response
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware
import asyncssh
import httpx
from cryptography.fernet import Fernet, InvalidToken

import auth
import cockpit_client
import outbound_proxy
import fleet_tools

# MCP Kütüphaneleri
from mcp.server import Server
import mcp.types as types
from mcp.server.sse import SseServerTransport
from starlette.routing import Mount, Route
from pydantic import AnyHttpUrl
from mcp.server.auth.routes import create_auth_routes
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions

app = FastAPI()

SECRET_KEY = os.getenv("SECRET_KEY", "gizli-anahtar")
# Gateway'in dışarıdan erişilen adresi (OAuth yönlendirmeleri ve metadata için)
PUBLIC_URL = os.getenv("PUBLIC_URL", "http://localhost:7435").rstrip("/")
# Giriş doğrulaması yapılacak Cockpit (varsayılan: gateway'in çalıştığı host makine)
COCKPIT_AUTH_URL = os.getenv("COCKPIT_AUTH_URL", "https://host.docker.internal:9090").rstrip("/")
COCKPIT_AUTH_VERIFY_TLS = os.getenv("COCKPIT_AUTH_VERIFY_TLS", "").lower() in ("1", "true", "yes")
# Boşsa Cockpit'e giriş yapabilen herkes; doluysa sadece listedeki kullanıcılar (virgülle ayrılmış)
ALLOWED_USERS = {u.strip() for u in os.getenv("ALLOWED_USERS", "").split(",") if u.strip()}

app.add_middleware(
    SessionMiddleware, 
    secret_key=SECRET_KEY
)

SERVERS_FILE = "data/servers.json"
OAUTH_STORE_FILE = "data/oauth.json"

authenticator = auth.CockpitAuthenticator(COCKPIT_AUTH_URL, COCKPIT_AUTH_VERIFY_TLS, ALLOWED_USERS)
# Cockpit girişine ek olarak istenen erişim token'ı (ikinci faktör). Boşsa sadece Cockpit girişi yeter.
# MCP istemcisinin bağlandığı URL'de ?token=... olarak verilirse giriş sayfasında ayrıca sorulmaz.
MCP_API_KEY = os.getenv("MCP_API_KEY", "")

def login_token_ok(value: str | None) -> bool:
    if not MCP_API_KEY:
        return True
    return bool(value) and secrets.compare_digest(value, MCP_API_KEY)

def token_from_url(url: str | None) -> str | None:
    """URL'deki ?token= değerini döner (RFC 8707 resource veya istek URL'si)."""
    if not url:
        return None
    from urllib.parse import parse_qs, urlsplit
    values = parse_qs(urlsplit(url).query).get("token")
    return values[0] if values else None

oauth_provider = auth.CockpitOAuthProvider(OAUTH_STORE_FILE, f"{PUBLIC_URL}/oauth/login", token_policy=MCP_API_KEY)

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
SECRET_FIELDS = ("cockpit_password", "proxy")

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
    out["connection"] = proxy_label(cfg)
    return out

# --- Giden bağlantılar için proxy ---
# Sunuculara (Cockpit ve SSH) bu proxy üzerinden bağlanılır; sunucular gateway yerine proxy'nin
# IP adresini görür. Sunucu bazında farklı bir proxy ya da "direct" (proxysiz) seçilebilir.
OUTBOUND_PROXY = os.getenv("OUTBOUND_PROXY", "").strip()

PROXY_UNREADABLE = "Sunucunun proxy ayarı çözülemedi (SECRET_KEY değişmiş olabilir); panelden yeniden girin."

def server_proxy(cfg: Dict[str, Any]) -> str | None:
    """Sunucuya bağlanırken kullanılacak proxy adresi (None = doğrudan).

    Sunucuya özel ayar var ama çözülemiyorsa bağlantı kurulmaz (ProxyError): sessizce varsayılan
    proxy'ye ya da doğrudan bağlantıya düşmek, beklenmeyen bir IP adresinden bağlanmak demek olur.
    """
    if cfg.get("proxy"):
        stored = decrypt_secret(cfg["proxy"])
        if stored is None:
            raise outbound_proxy.ProxyError(PROXY_UNREADABLE)
        return None if stored == "direct" else stored
    return OUTBOUND_PROXY or None

def proxy_label(cfg: Dict[str, Any]) -> str:
    stored = decrypt_secret(cfg["proxy"]) if cfg.get("proxy") else None
    if cfg.get("proxy") and stored is None:
        return "proxy ayarı çözülemedi"
    if stored == "direct":
        return "doğrudan"
    if stored:
        return f"proxy {outbound_proxy.redact(stored)}"
    if OUTBOUND_PROXY:
        return f"proxy {outbound_proxy.redact(OUTBOUND_PROXY)} (varsayılan)"
    return "doğrudan"

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

# --- Ortak SSH anahtarları (web panelinden eklenir, tüm sunucularda denenir) ---
SSH_KEYS_FILE = "data/ssh_keys.json"
MAX_KEY_SIZE = 16 * 1024

def load_shared_keys() -> Dict[str, Dict[str, Any]]:
    if not os.path.exists(SSH_KEYS_FILE):
        return {}
    try:
        with open(SSH_KEYS_FILE) as f:
            return json.load(f)
    except Exception:
        return {}

def save_shared_keys(keys: Dict[str, Dict[str, Any]]):
    os.makedirs(os.path.dirname(SSH_KEYS_FILE), exist_ok=True)
    tmp = SSH_KEYS_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(keys, f, indent=4)
    os.chmod(tmp, 0o600)
    os.replace(tmp, SSH_KEYS_FILE)

def shared_key_entry(name: str, key: "asyncssh.SSHKey") -> Dict[str, Any]:
    """Özel anahtar şifrelenmiş (ve parolasız hâliyle) saklanır; açık anahtar gösterim içindir."""
    return {
        "name": name,
        "type": key.get_algorithm(),
        "fingerprint": key.get_fingerprint(),
        "public": key.export_public_key().decode().strip(),
        "private": encrypt_secret(key.export_private_key().decode()),
        "created": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

def import_shared_key(name: str, private_text: str, passphrase: str = "") -> Dict[str, Any]:
    if len(private_text) > MAX_KEY_SIZE:
        raise ValueError("Anahtar çok büyük.")
    try:
        key = asyncssh.import_private_key(private_text.strip() + "\n", passphrase or None)
    except asyncssh.KeyEncryptionError:
        raise ValueError("Anahtarın parolası hatalı.")
    except asyncssh.KeyImportError as e:
        if "Passphrase" in str(e):
            raise ValueError("Bu anahtar parolalı; anahtar parolasını da girin.")
        raise ValueError("Geçerli bir SSH özel anahtarı değil (açık anahtar değil, özel anahtar yapıştırın).")
    return shared_key_entry(name, key)

def shared_client_keys() -> list:
    """Çözülebilen tüm ortak anahtarlar (asyncssh SSHKey nesneleri)."""
    keys = []
    for entry in load_shared_keys().values():
        private = decrypt_secret(entry.get("private", ""))
        if private is None:
            continue
        try:
            keys.append(asyncssh.import_private_key(private))
        except Exception:
            continue
    return keys

def login_candidates(cfg: Dict[str, Any]) -> list[tuple[str, list]]:
    """Önce sunucuya tanımlı kullanıcı, ardından SSH_LOGINS'teki diğer kullanıcılar denenir.

    Her kullanıcı için kendi .ssh klasöründeki anahtarlara ek olarak ortak anahtarlar da denenir.
    """
    logins = parse_ssh_logins(SSH_LOGINS)
    shared = shared_client_keys()
    candidates = []
    cfg_user = cfg.get("user")
    if cfg_user:
        if cfg.get("ssh_key_path"):
            keys = [cfg["ssh_key_path"]]
        else:
            keys = find_ssh_keys(dict(logins).get(cfg_user, ""))
        keys = [*keys, *shared]
        if keys:
            candidates.append((cfg_user, keys))
    for user, ssh_dir in logins:
        if user == cfg_user:
            continue
        keys = [*find_ssh_keys(ssh_dir), *shared]
        if keys:
            candidates.append((user, keys))
    return candidates

class SSHError(Exception):
    """Bağlantı kurulamadı veya hiçbir kullanıcı ile giriş yapılamadı."""

SSH_CONNECT_TIMEOUT = 15

@asynccontextmanager
async def ssh_session(cfg: Dict[str, Any], connect_timeout: float = SSH_CONNECT_TIMEOUT):
    """Sunucuya bağlanır; (kullanıcı, bağlantı) döner.

    Kimlik doğrulama reddedilirse sıradaki kullanıcı denenir; ağ hatasında hemen vazgeçilir.
    """
    candidates = login_candidates(cfg)
    if not candidates:
        raise SSHError(f"Hata: '{cfg.get('name', cfg.get('host'))}' için kullanılabilir SSH key bulunamadı.")

    try:
        proxy = server_proxy(cfg)
    except outbound_proxy.ProxyError as e:
        raise SSHError(f"SSH Bağlantı Hatası: {e}") from e
    denied = []
    for user, keys in candidates:
        try:
            extra = {}
            if proxy:
                # Proxy tüneli üzerinden açılmış soket asyncssh'e verilir
                extra["sock"] = await outbound_proxy.open_tunnel(proxy, cfg["host"], cfg.get("port", 22), connect_timeout)
            cm = asyncssh.connect(
                cfg["host"],
                port=cfg.get("port", 22),
                username=user,
                client_keys=keys,
                known_hosts=None,
                # asyncssh'de varsayılan olarak bağlantı için zaman aşımı yok; takılan sunucu beklenmesin
                connect_timeout=connect_timeout,
                **extra,
            )
            conn = await cm.__aenter__()
        except asyncssh.PermissionDenied as e:
            # Kimlik doğrulama reddedildi: sıradaki kullanıcıyı dene
            denied.append(f"{user}: {e.reason}")
            continue
        except Exception as e:
            # Ağ/bağlantı hatasında diğer kullanıcıları denemenin anlamı yok
            reason = "bağlantı zaman aşımına uğradı" if isinstance(e, (asyncio.TimeoutError, TimeoutError)) else (str(e) or type(e).__name__)
            raise SSHError(f"SSH Bağlantı Hatası: {reason}") from e
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
            try:
                candidate = cockpit_client.CockpitSession(
                    cockpit_url(cfg), cfg["cockpit_user"], password,
                    verify_tls=bool(cfg.get("cockpit_verify_tls")), proxy=server_proxy(cfg),
                )
                session = await candidate.connect()
            except (cockpit_client.CockpitError, outbound_proxy.ProxyError) as e:
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

def current_user(request: Request) -> str | None:
    """Cockpit ile giriş yapmış ve hâlâ yetkili olan kullanıcının adı."""
    username = (request.session.get('user') or {}).get('username')
    return username if username and authenticator.is_allowed(username) else None

PAGE_STYLE = """
<style>
  body { font-family: system-ui, sans-serif; max-width: 960px; margin: 24px auto; padding: 0 16px; }
  table { border-collapse: collapse; width: 100%; margin-bottom: 24px; }
  th, td { border: 1px solid #ddd; padding: 6px 8px; text-align: left; font-size: 14px; }
  form.add { display: grid; grid-template-columns: 200px 1fr; gap: 8px; max-width: 640px; }
  fieldset { border: 1px solid #ddd; margin: 12px 0; }
  .note { color: #555; font-size: 13px; }
  .err { color: #b00020; }
  .ok { color: #1b7f3b; }
  .warn { color: #a15c00; }
  td form { display: inline; }
  form.login { display: grid; grid-template-columns: 140px 220px; gap: 8px; }
  textarea.key { width: 100%; font-family: monospace; font-size: 12px; }
</style>
"""

def render_page(title: str, body: str, status_code: int = 200) -> HTMLResponse:
    """Tüm panel sayfaları için ortak HTML iskeleti (başlık, karakter seti, stil)."""
    return HTMLResponse(f"""<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)} · RHEL MCP Gateway</title>
  {PAGE_STYLE}
</head>
<body>
{body}
</body>
</html>""", status_code=status_code)

def forbidden() -> HTMLResponse:
    return render_page("Yetkiniz yok", "<h2>Yetkiniz yok</h2><p><a href='/login'>Giriş yap</a></p>", 403)

def invalid_login_request() -> HTMLResponse:
    return render_page(
        "Giriş isteği geçersiz",
        "<h2>Giriş isteği geçersiz</h2><p>Giriş isteği geçersiz veya süresi dolmuş. MCP istemcisinden tekrar bağlanın.</p>",
        400,
    )

CHECK_TIMEOUT = 10

# --- Gateway'in dış (public) IP adresi ---
# Uzaktaki sunucuların güvenlik duvarında izin verilmesi gereken adres; panelde gösterilir.
PUBLIC_IP_SERVICES = {
    "ipv4": ["https://api.ipify.org", "https://ipv4.icanhazip.com"],
    "ipv6": ["https://api6.ipify.org", "https://ipv6.icanhazip.com"],
}
PUBLIC_IP_CACHE_TTL = 600
# Anahtar: proxy adresi ("" = doğrudan); değer: {"at": zaman, "value": {...}}
_public_ip_cache: Dict[str, Dict[str, Any]] = {}

async def _fetch_ip(url: str, proxy: str | None = None) -> str | None:
    try:
        if proxy:
            status, _, body = await outbound_proxy.http_get(proxy, url, timeout=5)
            if status != 200:
                return None
            value = body.decode(errors="replace").strip()
        else:
            async with httpx.AsyncClient(timeout=3) as client:
                resp = await client.get(url)
            value = resp.text.strip()
        ipaddress.ip_address(value)
        return value
    except Exception:
        return None

async def public_ips(force: bool = False, proxy: str | None = None) -> Dict[str, str | None]:
    """{"ipv4": ..., "ipv6": ...}; belirlenemeyenler None. Sonuç 10 dakika önbelleklenir.

    proxy verilirse adres o proxy üzerinden sorgulanır (sunucuların göreceği adres).
    """
    cached = _public_ip_cache.get(proxy or "")
    if not force and cached and time.time() - cached["at"] < PUBLIC_IP_CACHE_TTL:
        return cached["value"]

    async def first(urls):
        for url in urls:
            ip = await _fetch_ip(url, proxy)
            if ip:
                return ip
        return None

    v4, v6 = await asyncio.gather(first(PUBLIC_IP_SERVICES["ipv4"]), first(PUBLIC_IP_SERVICES["ipv6"]))
    value = {"ipv4": v4, "ipv6": v6}
    # Hiçbiri bulunamadıysa önbelleğe alma; sonraki sayfa açılışında tekrar denensin
    if v4 or v6:
        _public_ip_cache[proxy or ""] = {"at": time.time(), "value": value}
    return value

def public_ip_html(ips: Dict[str, str | None], proxy_ips: Dict[str, str | None] | None = None) -> str:
    """proxy_ips: varsayılan proxy (OUTBOUND_PROXY) tanımlıysa onun üzerinden görünen adres."""
    proxy_html = ""
    if OUTBOUND_PROXY:
        via = [ip for ip in ((proxy_ips or {}).get("ipv4"), (proxy_ips or {}).get("ipv6")) if ip]
        shown = " ".join(f"<code>{html.escape(ip)}</code>" for ip in via) or "<span class='err'>belirlenemedi</span>"
        proxy_html = (f"<p>Varsayılan proxy ({html.escape(outbound_proxy.redact(OUTBOUND_PROXY))}) çıkış IP adresi: "
                      f"{shown}<br><span class='note'>Proxy kullanan sunucular bu adresi görür; "
                      f"onlarda bu adrese izin verin.</span></p>")
    found = [ip for ip in (ips.get("ipv4"), ips.get("ipv6")) if ip]
    if not found:
        return proxy_html + ("<p class='note'>Gateway'in dış IP adresi belirlenemedi "
                             "(dışarıya erişim kapalı olabilir).</p>")
    codes = " ".join(f"<code>{html.escape(ip)}</code>" for ip in found)
    v4 = ips.get("ipv4")
    example = ""
    if v4:
        rule = (f"firewall-cmd --permanent --add-rich-rule='rule family=\"ipv4\" source address=\"{v4}\" "
                f"port port=\"9090\" protocol=\"tcp\" accept' && firewall-cmd --reload")
        example = f"<br>Örnek (RHEL, firewalld): <code>{html.escape(rule)}</code>"
    return proxy_html + (
        f"<p>Gateway dış IP adresi: {codes} "
        f"<form method='post' action='/public-ip/refresh' style='display:inline'><button>Yenile</button></form><br>"
        f"<span class='note'>Uzaktaki sunucularda bu adrese Cockpit (9090/tcp) ve SSH yedeği için 22/tcp izni verin. "
        f"Aynı yerel ağdaki sunucular ise gateway'i çalıştıran makinenin yerel IP adresini görür.{example}</span></p>"
    )

async def check_server(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Sunucuya gerçekten bağlanıp basit bir komut çalıştırarak bilgileri doğrular.

    MCP araçlarıyla aynı sıra izlenir: Cockpit tanımlıysa önce Cockpit, çalışmazsa SSH yedeği.
    Yalnızca SSH ile bağlanılabiliyorsa sonuç başarılı ama "warning" işaretlidir.
    """
    checked_at = time.strftime("%Y-%m-%d %H:%M:%S")

    async def try_ssh() -> str | None:
        try:
            async with ssh_session(cfg, connect_timeout=CHECK_TIMEOUT) as (user, conn):
                result = await make_runner(user, conn)("true", timeout=CHECK_TIMEOUT)
            if result.exit_status != 0:
                return f"SSH komutu başarısız: {result.stderr.strip() or result.exit_status}"
            return None
        except Exception as e:
            return str(e)

    if cfg.get("cockpit_user"):
        password = decrypt_secret(cfg.get("cockpit_password", ""))
        error = None
        if password is None:
            error = "Cockpit şifresi çözülemedi; şifreyi yeniden girin."
        else:
            try:
                proxy = server_proxy(cfg)
            except outbound_proxy.ProxyError as e:
                proxy, error = None, str(e)
            session = cockpit_client.CockpitSession(
                cockpit_url(cfg), cfg["cockpit_user"], password,
                verify_tls=bool(cfg.get("cockpit_verify_tls")), connect_timeout=CHECK_TIMEOUT,
                proxy=proxy,
            )
            try:
                if error:
                    raise cockpit_client.CockpitError(error)
                await session.connect()
                result = await session.spawn(["true"], timeout=CHECK_TIMEOUT)
                if result.exit_status != 0:
                    error = f"Cockpit üzerinden komut çalıştırılamadı: {result.stderr.strip() or result.exit_status}"
            except cockpit_client.CockpitError as e:
                error = str(e)
            finally:
                await session.close()
        if error is None:
            return {"ok": True, "via": "cockpit", "message": "Cockpit bağlantısı başarılı.", "at": checked_at}
        ssh_error = await try_ssh()
        if ssh_error is None:
            # MCP araçları da bu durumda SSH yedeğiyle çalışır: sunucu kullanılabilir, ama uyarı gösterilir
            return {"ok": True, "warning": True, "via": "ssh",
                    "message": f"SSH yedeği ile bağlanıldı; Cockpit çalışmıyor: {error}", "at": checked_at}
        return {"ok": False, "via": None, "message": f"{error} (SSH yedeği de çalışmıyor: {ssh_error})",
                "at": checked_at}

    ssh_error = await try_ssh()
    if ssh_error is None:
        return {"ok": True, "via": "ssh", "message": "SSH bağlantısı başarılı.", "at": checked_at}
    return {"ok": False, "via": None, "message": ssh_error, "at": checked_at}

def server_row(cfg: Dict[str, Any]) -> str:
    e = lambda v: html.escape(str(v)) if v not in (None, "") else "—"
    name = cfg["name"]
    cockpit = f"{e(cfg['cockpit_user'])} @ {e(cockpit_url(cfg))}" if cfg.get("cockpit_user") else "—"
    ssh = f"{e(cfg.get('user') or 'otomatik')} @ {e(cfg['host'])}:{e(cfg.get('port', 22))}"
    check = cfg.get("last_check")
    if check:
        if not check.get("ok"):
            mark, css = "✗", "err"
        elif check.get("warning"):
            mark, css = "⚠", "warn"
        else:
            mark, css = "✓", "ok"
        status = (f"<span class='{css}' title='{e(check.get('message'))}'>{mark} {e(check.get('message'))}</span>"
                  f"<br><span class='note'>{e(check.get('at'))}</span>")
    else:
        status = "<span class='note'>Test edilmedi</span>"
    quoted = html.escape(name)
    return (
        f"<tr><td><b>{e(name)}</b><br><span class='note'>{e(proxy_label(cfg))}</span></td><td>{cockpit}</td><td>{ssh}</td><td>{status}</td>"
        f"<td><form method='post' action='/servers/{quoted}/test'><button>Test et</button></form> "
        f"<form method='post' action='/servers/{quoted}/delete' "
        f"onsubmit=\"return confirm('{quoted} silinsin mi?')\"><button>Sil</button></form></td></tr>"
    )

@app.get("/", response_class=HTMLResponse)
async def index(request: Request, error: str = "", info: str = ""):
    username = current_user(request)
    if not username:
        return RedirectResponse(url="/login", status_code=303)

    servers = load_servers()
    rows = "".join(server_row(cfg) for cfg in servers.values()) or "<tr><td colspan='5'>Henüz tanımlı sunucu yok.</td></tr>"
    error_html = f"<p class='err'>{html.escape(error)}</p>" if error else ""
    info_html = f"<p class='ok'>{html.escape(info)}</p>" if info else ""
    key_rows = "".join(shared_key_row(k) for k in load_shared_keys().values()) or \
        "<tr><td colspan='4'>Henüz ortak anahtar yok.</td></tr>"

    return render_page("Sunucular", f"""
        <h2>Hoş geldiniz, {html.escape(username)}!</h2>
        <p>MCP Gateway aktif. SSE Uç Noktası: <code>{html.escape(PUBLIC_URL)}/sse</code></p>
        {public_ip_html(await public_ips(), await public_ips(proxy=OUTBOUND_PROXY) if OUTBOUND_PROXY else None)}
        <h3>Kayıtlı Sunucular</h3>
        {info_html}
        <table>
          <tr><th>Ad</th><th>Cockpit</th><th>SSH (yedek)</th><th>Bağlantı durumu</th><th></th></tr>
          {rows}
        </table>

        <h3>Sunucu Ekle / Güncelle</h3>
        <p class="note">Aynı adla kaydetmek mevcut sunucuyu günceller. Şifre alanı boş bırakılırsa mevcut şifre korunur.
        Kaydetmeden önce sunucuya bağlanılıp bilgiler doğrulanır; bağlantı kurulamazsa kayıt yapılmaz.</p>
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
          <fieldset style="grid-column: 1 / -1">
            <legend>Bağlantı proxy'si</legend>
            <div class="add">
              <label>Proxy</label><input name="proxy" autocomplete="off"
                placeholder="socks5://host:1080 · http://host:3128 · direct · default">
            </div>
            <p class="note">Cockpit ve SSH bağlantıları bu proxy üzerinden yapılır; sunucu proxy'nin IP adresini görür.
            Boş bırakılırsa mevcut ayar korunur (yeni sunucuda varsayılan kullanılır).
            <code>default</code>: varsayılan (.env'deki OUTBOUND_PROXY{'' if not OUTBOUND_PROXY else ' = ' + html.escape(outbound_proxy.redact(OUTBOUND_PROXY))}),
            <code>direct</code>: proxysiz. Kullanıcı adı/parola adreste verilebilir (socks5://kullanici:parola@host:1080) ve şifreli saklanır.</p>
          </fieldset>
          <label>Bağlantıyı test etmeden kaydet</label><input name="skip_check" type="checkbox">
          <span></span><button type="submit">Kaydet</button>
        </form>

        <h3 id="ssh-keys">Ortak SSH Anahtarları</h3>
        <p class="note">Buradaki anahtarlar SSH yedeğinde tüm sunucularda, her kullanıcı için denenir.
        Kullanmak için anahtarın açık kısmını sunuculardaki <code>~/.ssh/authorized_keys</code> dosyasına ekleyin.
        Özel anahtarlar <code>data/ssh_keys.json</code> içinde şifreli saklanır ve panelde gösterilmez.</p>
        <table>
          <tr><th>Ad</th><th>Tür / parmak izi</th><th>Açık anahtar (authorized_keys satırı)</th><th></th></tr>
          {key_rows}
        </table>
        <form class="add" method="post" action="/ssh-keys">
          <label>Anahtar adı *</label><input name="name" required placeholder="ortak-anahtar">
          <label>Özel anahtar *</label><textarea class="key" name="private_key" rows="6" required
            placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea>
          <label>Anahtar parolası</label><input name="passphrase" type="password" autocomplete="off" placeholder="parolasızsa boş">
          <span></span><button type="submit">Anahtarı ekle</button>
        </form>
        <form class="add" method="post" action="/ssh-keys/generate" style="margin-top:12px">
          <label>Yeni anahtar üret</label><input name="name" required placeholder="anahtar adı">
          <span></span><button type="submit">Ed25519 anahtarı üret</button>
        </form>
        <br><a href="/logout">Çıkış Yap</a>
    """)

def _redirect_error(message: str) -> RedirectResponse:
    return RedirectResponse(url="/?" + urlencode({"error": message}), status_code=303)

def _redirect_info(message: str) -> RedirectResponse:
    return RedirectResponse(url="/?" + urlencode({"info": message}), status_code=303)

@app.post("/servers")
async def save_server(request: Request):
    if not current_user(request):
        return forbidden()
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

    proxy_value = field("proxy")
    if proxy_value == "":
        if existing.get("proxy"):
            cfg["proxy"] = existing["proxy"]
    elif proxy_value == "direct":
        cfg["proxy"] = encrypt_secret("direct")
    elif proxy_value != "default":
        try:
            outbound_proxy.parse_proxy(proxy_value)
        except ValueError as e:
            return _redirect_error(f"Geçersiz proxy: {e}")
        cfg["proxy"] = encrypt_secret(proxy_value)

    if cfg.get("cockpit_user"):
        password = form.get("cockpit_password") or ""
        if password:
            cfg["cockpit_password"] = encrypt_secret(password)
        elif existing.get("cockpit_password"):
            cfg["cockpit_password"] = existing["cockpit_password"]
        else:
            return _redirect_error("Cockpit kullanıcısı için şifre gerekli.")

    if form.get("skip_check"):
        # Bilgiler test edilmedi: eski (başka ayarlara ait olabilecek) durum gösterilmesin
        servers[name] = cfg
        save_servers(servers)
        return _redirect_info(f"'{name}' bağlantı testi yapılmadan kaydedildi.")

    check = await check_server(cfg)
    if not check["ok"]:
        return _redirect_error(f"'{name}' kaydedilmedi, bağlantı kurulamadı: {check['message']}")
    cfg["last_check"] = check
    # Kontrol sürerken dosya değişmiş olabilir; en güncel hâli üzerine yaz
    servers = load_servers()
    servers[name] = cfg
    save_servers(servers)
    if check.get("warning"):
        return _redirect_error(f"'{name}' kaydedildi. {check['message']}")
    return _redirect_info(f"'{name}' kaydedildi. {check['message']}")

@app.post("/public-ip/refresh")
async def refresh_public_ip(request: Request):
    if not current_user(request):
        return forbidden()
    ips = await public_ips(force=True)
    if OUTBOUND_PROXY:
        await public_ips(force=True, proxy=OUTBOUND_PROXY)
    found = ", ".join(ip for ip in ips.values() if ip)
    if found:
        return _redirect_info(f"Dış IP adresi: {found}")
    return _redirect_error("Dış IP adresi belirlenemedi.")

@app.post("/servers/{name}/test")
async def test_server(name: str, request: Request):
    if not current_user(request):
        return forbidden()
    cfg = load_servers().get(name)
    if cfg is None:
        return _redirect_error(f"'{name}' bulunamadı.")
    check = await check_server(cfg)
    servers = load_servers()
    if name in servers:
        servers[name]["last_check"] = check
        save_servers(servers)
    if check["ok"] and not check.get("warning"):
        return _redirect_info(f"'{name}': {check['message']}")
    return _redirect_error(f"'{name}': {check['message']}")

@app.post("/servers/{name}/delete")
async def delete_server(name: str, request: Request):
    if not current_user(request):
        return forbidden()
    servers = load_servers()
    servers.pop(name, None)
    save_servers(servers)
    return RedirectResponse(url="/", status_code=303)

def shared_key_row(entry: Dict[str, Any]) -> str:
    name = html.escape(entry["name"])
    return (
        f"<tr><td><b>{name}</b><br><span class='note'>{html.escape(entry.get('created', ''))}</span></td>"
        f"<td>{html.escape(entry.get('type', ''))}<br><span class='note'>{html.escape(entry.get('fingerprint', ''))}</span></td>"
        f"<td><textarea class='key' rows='3' readonly onclick='this.select()'>{html.escape(entry.get('public', ''))}</textarea></td>"
        f"<td><form method='post' action='/ssh-keys/{name}/delete' "
        f"onsubmit=\"return confirm('{name} anahtarı silinsin mi?')\"><button>Sil</button></form></td></tr>"
    )

def _key_name(form) -> str | None:
    name = (form.get("name") or "").strip()
    return name if SERVER_NAME_RE.match(name) else None

@app.post("/ssh-keys")
async def add_shared_key(request: Request):
    if not current_user(request):
        return forbidden()
    form = await request.form()
    name = _key_name(form)
    if not name:
        return _redirect_error("Anahtar adı yalnızca harf, rakam, nokta, alt çizgi ve tire içerebilir.")
    keys = load_shared_keys()
    if name in keys:
        # Eski açık anahtar sunuculara dağıtılmış olabilir; yanlışlıkla üzerine yazılmasın
        return _redirect_error(f"'{name}' adında bir anahtar zaten var. Değiştirmek için önce silin.")
    try:
        entry = import_shared_key(name, form.get("private_key") or "", form.get("passphrase") or "")
    except ValueError as e:
        return _redirect_error(f"Anahtar eklenmedi: {e}")
    keys[name] = entry
    save_shared_keys(keys)
    return _redirect_info(f"'{name}' anahtarı eklendi ({entry['fingerprint']}).")

@app.post("/ssh-keys/generate")
async def generate_shared_key(request: Request):
    if not current_user(request):
        return forbidden()
    form = await request.form()
    name = _key_name(form)
    if not name:
        return _redirect_error("Anahtar adı yalnızca harf, rakam, nokta, alt çizgi ve tire içerebilir.")
    keys = load_shared_keys()
    if name in keys:
        return _redirect_error(f"'{name}' adında bir anahtar zaten var.")
    key = asyncssh.generate_private_key("ssh-ed25519", comment=f"rhel-mcp-gateway:{name}")
    keys[name] = shared_key_entry(name, key)
    save_shared_keys(keys)
    return _redirect_info(f"'{name}' anahtarı üretildi. Açık anahtarı sunuculardaki authorized_keys dosyasına ekleyin.")

@app.post("/ssh-keys/{name}/delete")
async def delete_shared_key(name: str, request: Request):
    if not current_user(request):
        return forbidden()
    keys = load_shared_keys()
    keys.pop(name, None)
    save_shared_keys(keys)
    return _redirect_info(f"'{name}' anahtarı silindi.")

def login_page(action: str, title: str, error: str = "", note: str = "", hidden: Dict[str, str] | None = None,
               status_code: int = 200, ask_token: bool = False) -> HTMLResponse:
    hidden_inputs = "".join(
        f"<input type='hidden' name='{html.escape(k)}' value='{html.escape(v)}'>" for k, v in (hidden or {}).items()
    )
    return render_page(title, f"""
        <h2>{html.escape(title)}</h2>
        <p class="note">{note}Cockpit kullanıcı adınız ve parolanızla giriş yapın ({html.escape(COCKPIT_AUTH_URL)}).</p>
        {f"<p class='err'>{html.escape(error)}</p>" if error else ""}
        <form class="login" method="post" action="{html.escape(action)}">
          {hidden_inputs}
          <label>Kullanıcı adı</label><input name="username" autocomplete="username" required autofocus>
          <label>Cockpit parolası</label><input name="password" type="password" autocomplete="current-password" required>
          {'<label>Gateway parolası</label><input name="token" type="password" autocomplete="off" required>' if ask_token else ''}
          <span></span><button type="submit">Giriş Yap</button>
        </form>
    """, status_code)

TOKEN_ERROR = "Gateway parolası hatalı."

def _token_fields(url_token: str | None) -> tuple[bool, Dict[str, str]]:
    """URL'de geçerli token varsa formda sorma, gizli alanla taşı."""
    if login_token_ok(url_token):
        return False, ({"token": url_token} if url_token else {})
    return True, {}

@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request, token: str | None = None):
    ask_token, hidden = _token_fields(token)
    return login_page("/login", "RHEL MCP Gateway - Giriş", hidden=hidden, ask_token=ask_token)

@app.post("/login")
async def login_submit(request: Request):
    form = await request.form()
    username = (form.get("username") or "").strip()
    # Token Cockpit'ten önce kontrol edilir: token'sız denemeler şifreyi hiç sınayamaz
    error = TOKEN_ERROR if not login_token_ok(form.get("token")) else await authenticator.login(username, form.get("password") or "")
    if error:
        return login_page("/login", "RHEL MCP Gateway - Giriş", error=error, status_code=401, ask_token=bool(MCP_API_KEY))
    request.session['user'] = {"username": username}
    return RedirectResponse(url='/', status_code=303)

# --- MCP istemcileri için OAuth girişi (/authorize buraya yönlendirir) ---
@app.get("/oauth/login", response_class=HTMLResponse)
async def oauth_login_form(request_id: str = Query(alias="request")):
    client_name = oauth_provider.pending_client_name(request_id)
    if client_name is None:
        return invalid_login_request()
    return login_page(
        "/oauth/login", "MCP İstemcisine Erişim İzni",
        note=f"<b>{html.escape(client_name)}</b> bu gateway'deki araçlara erişmek istiyor. ",
        hidden={"request": request_id},
        ask_token=not login_token_ok(token_from_url(oauth_provider.pending_resource(request_id))),
    )

@app.post("/oauth/login")
async def oauth_login_submit(request: Request):
    form = await request.form()
    request_id = form.get("request") or ""
    client_name = oauth_provider.pending_client_name(request_id)
    if client_name is None:
        return invalid_login_request()
    username = (form.get("username") or "").strip()
    # Token: istemcinin bağlandığı URL'den (?token=) ya da formdan
    url_token = token_from_url(oauth_provider.pending_resource(request_id))
    token_ok = login_token_ok(url_token) or login_token_ok(form.get("token"))
    error = TOKEN_ERROR if not token_ok else await authenticator.login(username, form.get("password") or "")
    if error:
        return login_page(
            "/oauth/login", "MCP İstemcisine Erişim İzni", error=error,
            note=f"<b>{html.escape(client_name)}</b> bu gateway'deki araçlara erişmek istiyor. ",
            hidden={"request": request_id}, status_code=401, ask_token=not login_token_ok(url_token),
        )
    redirect = oauth_provider.complete_authorization(request_id, username)
    return RedirectResponse(url=redirect, status_code=302)

@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url='/', status_code=303)

# --- MCP SSE Transport Entegrasyonu ---
# Sonda "/" olmalı: aksi halde her POST /messages isteği 307 ile /messages/'e yönlenir
sse = SseServerTransport("/messages/")

MCP_RESOURCE_URL = f"{PUBLIC_URL}/sse"
RESOURCE_METADATA_URL = f"{PUBLIC_URL}/.well-known/oauth-protected-resource/sse"

async def authenticate_mcp(request: Request) -> str | None:
    """MCP isteğini doğrular; başarılıysa kullanıcı adını döner.

    Kabul edilenler:
    - OAuth erişim token'ı (Bearer): giriş sırasında Cockpit + erişim token'ı zaten doğrulandı.
    - Cockpit kullanıcı adı/şifresi (Basic): MCP_API_KEY tanımlıysa ayrıca X-MCP-Token başlığı
      veya ?token= ile erişim token'ı da gerekir.
    Erişim token'ı tek başına giriş sağlamaz.
    """
    header = request.headers.get("authorization", "")
    if header[:7].lower() == "bearer ":
        access = await oauth_provider.load_access_token(header[7:].strip())
        if access and access.subject and authenticator.is_allowed(access.subject):
            return access.subject
        return None
    if header[:6].lower() == "basic ":
        token = request.headers.get("x-mcp-token") or request.query_params.get("token")
        if not login_token_ok(token):
            return None
        return await authenticator.check_basic(header)
    return None

async def handle_sse(request: Request):
    # /messages/ istekleri tahmin edilemez session_id ile korunur; kimlik doğrulama /sse'de yapılır.
    if await authenticate_mcp(request) is None:
        # URL'deki geçerli token metadata adresine taşınır; istemci bunu OAuth isteğindeki
        # "resource" alanında geri gönderir ve giriş sayfası token'ı ayrıca sormaz.
        metadata_url = RESOURCE_METADATA_URL
        url_token = request.query_params.get("token")
        if MCP_API_KEY and login_token_ok(url_token):
            metadata_url += "?" + urlencode({"token": url_token})
        return JSONResponse(
            {"error": "invalid_token", "error_description": "Cockpit hesabıyla giriş gerekli"},
            status_code=401,
            headers={"WWW-Authenticate": f'Bearer error="invalid_token", resource_metadata="{metadata_url}"'},
        )

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

# OAuth 2.1 yetkilendirme sunucusu (/authorize, /token, /register, /revoke) ve metadata
app.routes.extend(create_auth_routes(
    oauth_provider,
    issuer_url=AnyHttpUrl(PUBLIC_URL),
    client_registration_options=ClientRegistrationOptions(enabled=True, valid_scopes=[auth.SCOPE], default_scopes=[auth.SCOPE]),
    revocation_options=RevocationOptions(enabled=True),
))

async def protected_resource_metadata(request: Request):
    """RFC 9728 metadata. Geçerli ?token= varsa resource adresine eklenir (bkz. handle_sse)."""
    cors = {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, OPTIONS"}
    if request.method == "OPTIONS":
        return Response(status_code=204, headers=cors)
    resource = MCP_RESOURCE_URL
    url_token = request.query_params.get("token")
    if MCP_API_KEY and login_token_ok(url_token):
        resource += "?" + urlencode({"token": url_token})
    return JSONResponse({
        "resource": resource,
        "authorization_servers": [PUBLIC_URL + "/"],
        "scopes_supported": [auth.SCOPE],
        "bearer_methods_supported": ["header"],
        "resource_name": "RHEL MCP Gateway",
    }, headers=cors)

app.routes.append(Route("/.well-known/oauth-protected-resource/sse", endpoint=protected_resource_metadata,
                        methods=["GET", "OPTIONS"]))

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 7435))
    # Reverse proxy (https) arkasında url_for doğru şemayı üretsin diye X-Forwarded-* başlıklarına güven
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False, proxy_headers=True, forwarded_allow_ips="*")
