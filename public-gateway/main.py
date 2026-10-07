import os
import re
import html
import json
import base64
import hashlib
import secrets
import ipaddress
import shlex
from urllib.parse import urlencode, urlsplit
import asyncio
import time
from contextvars import ContextVar
from contextlib import AsyncExitStack, asynccontextmanager
from typing import Dict, Any
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException, Query
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, Response
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware
import asyncssh
import httpx
from cryptography.fernet import Fernet, InvalidToken

import auth
import audit_log
import cockpit_client
import outbound_proxy
import fleet_tools
import i18n
from i18n import N, t

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
# Interface language from the browser's Accept-Language header (English by default)
app.add_middleware(i18n.LanguageMiddleware)

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

PROXY_UNREADABLE = N("The server's proxy setting could not be decrypted (SECRET_KEY may have changed); re-enter it in the panel.")

def server_proxy(cfg: Dict[str, Any]) -> str | None:
    """Sunucuya bağlanırken kullanılacak proxy adresi (None = doğrudan).

    Sunucuya özel ayar var ama çözülemiyorsa bağlantı kurulmaz (ProxyError): sessizce varsayılan
    proxy'ye ya da doğrudan bağlantıya düşmek, beklenmeyen bir IP adresinden bağlanmak demek olur.
    """
    if cfg.get("proxy"):
        stored = decrypt_secret(cfg["proxy"])
        if stored is None:
            raise outbound_proxy.ProxyError(t(PROXY_UNREADABLE))
        return None if stored == "direct" else stored
    return OUTBOUND_PROXY or None

def proxy_label(cfg: Dict[str, Any]) -> str:
    stored = decrypt_secret(cfg["proxy"]) if cfg.get("proxy") else None
    if cfg.get("proxy") and stored is None:
        return t("proxy setting unreadable")
    if stored == "direct":
        return t("direct")
    if stored:
        return f"proxy {outbound_proxy.redact(stored)}"
    if OUTBOUND_PROXY:
        return t("proxy {proxy} (default)", proxy=outbound_proxy.redact(OUTBOUND_PROXY))
    return t("direct")

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
        raise ValueError(t("The key is too large."))
    try:
        key = asyncssh.import_private_key(private_text.strip() + "\n", passphrase or None)
    except asyncssh.KeyEncryptionError:
        raise ValueError(t("Wrong key passphrase."))
    except asyncssh.KeyImportError as e:
        if "Passphrase" in str(e):
            raise ValueError(t("This key is passphrase-protected; enter the key passphrase too."))
        raise ValueError(t("Not a valid SSH private key (paste the private key, not the public key)."))
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
        raise SSHError(t("Error: no usable SSH key found for '{name}'.", name=cfg.get("name", cfg.get("host"))))

    try:
        proxy = server_proxy(cfg)
    except outbound_proxy.ProxyError as e:
        raise SSHError(t("SSH connection error: {reason}", reason=e)) from e
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
            reason = t("connection timed out") if isinstance(e, (asyncio.TimeoutError, TimeoutError)) else (str(e) or type(e).__name__)
            raise SSHError(t("SSH connection error: {reason}", reason=reason)) from e
        try:
            yield user, conn
        finally:
            await cm.__aexit__(None, None, None)
        return

    raise SSHError(t("SSH authentication failed, users tried:") + "\n" + "\n".join(denied))

# --- İşlem kaydı (audit log) bağlamı ---
# MCP bağlantısını açan kullanıcı; /sse isteğinde atanır, araç çağrıları aynı bağlamı devralır.
_mcp_actor: ContextVar[Dict[str, Any]] = ContextVar("mcp_actor", default={})
# Bir araç çağrısı sırasında sunucularda çalıştırılan komutlar (araç çağrısı dışında None)
_command_log: ContextVar[list | None] = ContextVar("command_log", default=None)

def _recorded(run: fleet_tools.Runner) -> fleet_tools.Runner:
    """Runner'ı, çalıştırdığı komutları geçerli araç çağrısının kaydına ekleyecek şekilde sarar."""
    async def wrapper(argv, privileged: bool = False, timeout: int = fleet_tools.DEFAULT_TIMEOUT):
        result = await run(argv, privileged=privileged, timeout=timeout)
        commands = _command_log.get()
        if commands is not None:
            commands.append({
                "command": argv if isinstance(argv, str) else shlex.join(argv),
                "as_root": privileged, "user": result.user, "via": result.via,
                "exit_status": result.exit_status,
            })
        return result
    return wrapper

def request_actor(request: Request) -> Dict[str, Any]:
    return {"ip": request.client.host if request.client else None}

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
            return fleet_tools.CommandResult(user, None, "", t("Command timed out after {timeout} seconds.", timeout=timeout), "ssh")
        return fleet_tools.CommandResult(user, result.exit_status, result.stdout or "", result.stderr or "", "ssh")
    return _recorded(run)

def make_cockpit_runner(session: cockpit_client.CockpitSession) -> fleet_tools.Runner:
    async def run(argv, privileged: bool = False, timeout: int = fleet_tools.DEFAULT_TIMEOUT):
        if isinstance(argv, str):
            argv = ["sh", "-c", argv]
        return await session.spawn(argv, superuser=privileged, timeout=timeout)
    return _recorded(run)

# Doğrudan Cockpit'e ulaşılamayan sunucularda her çağrıda zaman aşımı beklenmesin:
# başarısızlık bir süre hatırlanır ve bu sürede doğrudan SSH tüneli kullanılır.
COCKPIT_DOWN_TTL = 600
_cockpit_direct_down: Dict[str, tuple[float, str]] = {}

def _cockpit_down_key(cfg: Dict[str, Any]) -> str:
    return f"{cockpit_url(cfg)}|{cfg.get('proxy', '')}"

def cockpit_password(cfg: Dict[str, Any]) -> str | None:
    return decrypt_secret(cfg.get("cockpit_password", ""))

COCKPIT_PASSWORD_UNREADABLE = N("The Cockpit password could not be decrypted (no password was entered, or SECRET_KEY may have changed).")

async def connect_cockpit_direct(cfg: Dict[str, Any], password: str,
                                 connect_timeout: float = 10) -> cockpit_client.CockpitSession:
    """Cockpit'e doğrudan (gerekirse proxy ile) bağlanır. Sonuç tünel kararı için hatırlanır."""
    key = _cockpit_down_key(cfg)
    try:
        session = cockpit_client.CockpitSession(
            cockpit_url(cfg), cfg["cockpit_user"], password,
            verify_tls=bool(cfg.get("cockpit_verify_tls")), connect_timeout=connect_timeout,
            proxy=server_proxy(cfg),
        )
        await session.connect()
    except cockpit_client.CockpitAuthError:
        raise
    except outbound_proxy.ProxyError as e:
        raise cockpit_client.CockpitError(str(e)) from e
    except cockpit_client.CockpitError as e:
        _cockpit_direct_down[key] = (time.time() + COCKPIT_DOWN_TTL, str(e))
        raise
    _cockpit_direct_down.pop(key, None)
    return session

def cockpit_recently_down(cfg: Dict[str, Any]) -> str | None:
    entry = _cockpit_direct_down.get(_cockpit_down_key(cfg))
    if entry and entry[0] > time.time():
        return entry[1]
    return None

@asynccontextmanager
async def cockpit_over_ssh(cfg: Dict[str, Any], conn, password: str, connect_timeout: float = 10):
    """SSH bağlantısının içinden sunucunun kendi Cockpit'ine (localhost) bağlanır.

    Böylece Cockpit portunu (9090) dışarıya açmak gerekmez. Bağlantı SSH ile korunduğu için
    tünel ucunda sertifika doğrulanmaz.
    """
    parts = urlsplit(cockpit_url(cfg))
    port = parts.port or 9090
    listener = await conn.forward_local_port("127.0.0.1", 0, "localhost", port)
    try:
        session = cockpit_client.CockpitSession(
            f"{parts.scheme}://127.0.0.1:{listener.get_port()}", cfg["cockpit_user"], password,
            verify_tls=False, connect_timeout=connect_timeout,
        )
        await session.connect()
        try:
            yield session
        finally:
            await session.close()
    finally:
        listener.close()

@asynccontextmanager
async def open_runner(cfg: Dict[str, Any]):
    """Sıra: Cockpit (doğrudan) -> SSH tüneli içinden Cockpit -> düz SSH. (runner, bağlantı bilgisi) döner."""
    cockpit_error = None
    password = None
    if cfg.get("cockpit_user"):
        password = cockpit_password(cfg)
        if password is None:
            cockpit_error = t(COCKPIT_PASSWORD_UNREADABLE)
        elif (down := cockpit_recently_down(cfg)) is not None:
            cockpit_error = down
        else:
            session = None
            try:
                session = await connect_cockpit_direct(cfg, password)
            except cockpit_client.CockpitAuthError as e:
                # Şifre yanlış: tünelden de aynı sonuç alınır
                cockpit_error, password = str(e), None
            except cockpit_client.CockpitError as e:
                cockpit_error = str(e)
            if session is not None:
                try:
                    yield make_cockpit_runner(session), {"via": "cockpit", "user": cfg["cockpit_user"]}
                finally:
                    await session.close()
                return

    try:
        async with ssh_session(cfg) as (user, conn), AsyncExitStack() as stack:
            session = None
            if password is not None:
                try:
                    session = await stack.enter_async_context(cockpit_over_ssh(cfg, conn, password))
                except Exception as e:
                    cockpit_error = t("{error}; also failed over the SSH tunnel: {reason}",
                                      error=cockpit_error, reason=str(e) or type(e).__name__)
            if session is not None:
                yield make_cockpit_runner(session), {"via": "cockpit-ssh", "user": cfg["cockpit_user"], "ssh_user": user}
                return
            info = {"via": "ssh", "user": user}
            if cockpit_error:
                info["cockpit_error"] = cockpit_error
            yield make_runner(user, conn), info
    except SSHError as e:
        if cockpit_error:
            raise SSHError(t("{error}\nSSH fallback also failed: {reason}", error=cockpit_error, reason=e)) from e
        raise

def text_result(value: Any) -> list[types.TextContent]:
    return [types.TextContent(type="text", text=fleet_tools.to_text(value))]

# --- MCP Sunucu Tanımları ---
mcp_server = Server("rhel-fleet-gateway")

def server_name_prop() -> dict:
    return {"server_name": {"type": "string", "description": t("Registered server name (e.g. prod-db)")}}

@mcp_server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="list_servers",
            description=t("Lists all registered RHEL servers (without passwords) and whether a Cockpit login is configured."),
            inputSchema={"type": "object", "properties": {}},
            annotations=types.ToolAnnotations(readOnlyHint=True, openWorldHint=False),
        ),
        types.Tool(
            name="fleet_health",
            description=t("Collects a load, failed-service and root-disk-usage summary from all registered servers in parallel."),
            inputSchema={"type": "object", "properties": {}},
            annotations=types.ToolAnnotations(readOnlyHint=True, openWorldHint=False),
        ),
        *[spec.to_tool() for spec in fleet_tools.TOOLS],
        types.Tool(
            name="run_remote_command",
            description=t(
                "Runs an arbitrary Linux command on a registered server. Prefer a purpose-built tool when one exists. "
                "Runs through Cockpit if the server has a Cockpit login configured; otherwise, or if Cockpit is unreachable, over SSH."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    **server_name_prop(),
                    "command": {"type": "string", "description": t("Linux command to run (e.g. systemctl status nginx)")},
                    "as_root": {"type": "boolean", "description": t("Run with administrator privileges (Cockpit superuser / sudo -n over SSH)")},
                    "confirm": {"type": "boolean", "description": t("Set to true to actually run the command. Otherwise only what would be run is shown.")},
                },
                "required": ["server_name", "command"]
            },
            annotations=types.ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=False),
        ),
    ]

def confirmation_required(server_name: str, action: str) -> list[types.TextContent]:
    return text_result(t(
        "Confirmation required: the following will be done on '{server}':\n  {action}\n"
        "Call the same tool again with confirm: true to apply.",
        server=server_name, action=action,
    ))

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
    """Aracı çalıştırır ve çağrıyı (kim, hangi sunucu, hangi komutlar, sonuç) işlem kaydına yazar."""
    arguments = arguments or {}
    commands: list = []
    token = _command_log.set(commands)
    started = time.monotonic()
    status, content, error = "error", None, None
    try:
        content, status = await _call_tool(name, arguments)
        return content
    except Exception as e:
        error = str(e) or type(e).__name__
        raise
    finally:
        _command_log.reset(token)
        server_name = arguments.get("server_name")
        audit_log.record(
            "mcp", name, status, **_mcp_actor.get(),
            server=server_name if isinstance(server_name, str) else None,
            args={k: v for k, v in arguments.items() if k != "server_name"},
            commands=commands,
            result=error or (content[0].text if content else None),
            duration_ms=round((time.monotonic() - started) * 1000),
        )

async def _call_tool(name: str, arguments: dict) -> tuple[list[types.TextContent], str]:
    """(çıktı, durum) döner; durum: "ok" | "error" | "preview" (onay bekliyor)."""
    servers = load_servers()

    if name == "list_servers":
        return text_result({n: public_server(cfg) for n, cfg in servers.items()}), "ok"

    if name == "fleet_health":
        return text_result(await fleet_health(servers)), "ok"

    spec = fleet_tools.TOOLS_BY_NAME.get(name)
    if spec is None and name != "run_remote_command":
        raise ValueError(t("Unknown tool: {name}", name=name))

    server_name = arguments.get("server_name")
    if server_name not in servers:
        return text_result(t("Error: server '{name}' not found.", name=server_name)), "error"
    cfg = servers[server_name]

    try:
        if name == "run_remote_command":
            command = arguments.get("command")
            if not arguments.get("confirm"):
                return confirmation_required(server_name, command), "preview"
            async with open_runner(cfg) as (run, info):
                result = await run(command, privileged=bool(arguments.get("as_root")))
            output = f"User: {result.user}\nVia: {result.via}\nExit Status: {result.exit_status}\nStdout:\n{result.stdout}\nStderr:\n{result.stderr}"
            if info.get("cockpit_error"):
                output = t("Note: Cockpit was unavailable, ran over SSH ({error})", error=info["cockpit_error"]) + "\n" + output
            return text_result(output), "ok"

        if not spec.read_only and not arguments.get("confirm"):
            return confirmation_required(server_name, spec.preview(arguments)), "preview"

        async with open_runner(cfg) as (run, info):
            value = await spec.handler(run, arguments)
        if isinstance(value, dict):
            value["connection"] = info
        return text_result(value), "ok"
    except (SSHError, cockpit_client.CockpitError) as e:
        return text_result(str(e)), "error"
    except fleet_tools.ToolInputError as e:
        raise ValueError(str(e)) from e

# FastAPI Web Uç Noktaları
SERVER_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
HOST_RE = re.compile(r"^[A-Za-z0-9.:_-]{1,253}$")

def audit_web(request: Request, action: str, status: str = "ok", **fields: Any) -> None:
    """Panelde yapılan bir işlemi kaydeder (kullanıcı oturumdan alınır; fields ile ezilebilir)."""
    fields.setdefault("user", (request.session.get("user") or {}).get("username"))
    audit_log.record("web", action, status, **request_actor(request), **fields)

def current_user(request: Request) -> str | None:
    """Cockpit ile giriş yapmış ve hâlâ yetkili olan kullanıcının adı."""
    username = (request.session.get('user') or {}).get('username')
    return username if username and authenticator.is_allowed(username) else None

BOOTSTRAP_CDN = "https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist"

PAGE_STYLE = f"""
<link rel="stylesheet" href="{BOOTSTRAP_CDN}/css/bootstrap.min.css">
<style>
  form.add, div.add {{ display: grid; grid-template-columns: 220px 1fr; gap: 8px; align-items: center; max-width: 720px; }}
  form.add .form-check-input, form.add .btn {{ justify-self: start; margin: 0; }}
  @media (max-width: 575.98px) {{ form.add, div.add {{ grid-template-columns: 1fr; }} }}
  .note {{ color: var(--bs-secondary-color); font-size: .8125rem; }}
  .err {{ color: var(--bs-danger); }}
  .ok {{ color: var(--bs-success); }}
  .warn {{ color: #a15c00; }}
  td form {{ display: inline; }}
  textarea.key {{ font-family: var(--bs-font-monospace); font-size: 12px; }}
  table.logs td {{ vertical-align: top; }}
  table.logs pre {{ white-space: pre-wrap; word-break: break-word; margin: 4px 0; font-size: 12px; max-height: 320px; overflow: auto; }}
  code {{ word-break: break-word; }}
</style>
"""

# Üst menü: (anahtar, adres, etiket)
NAV_ITEMS = [
    ("servers", "/", N("Servers")),
    ("ssh-keys", "/#ssh-keys", N("SSH Keys")),
    ("logs", "/logs", N("Audit Log")),
]

def navbar(user: str | None, active: str = "") -> str:
    """Üst menü; giriş yapılmamışsa yalnızca başlık gösterilir."""
    menu = ""
    if user:
        links = "".join(
            f'<li class="nav-item"><a class="nav-link{" active" if key == active else ""}" href="{href}">{t(label)}</a></li>'
            for key, href, label in NAV_ITEMS
        )
        menu = f"""
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#topnav"
            aria-controls="topnav" aria-expanded="false" aria-label="{t('Menu')}">
      <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="topnav">
      <ul class="navbar-nav me-auto">{links}</ul>
      <span class="navbar-text me-3">{html.escape(user)}</span>
      <a class="btn btn-sm btn-outline-light" href="/logout">{t('Log out')}</a>
    </div>"""
    return f"""<nav class="navbar navbar-expand-md navbar-dark bg-dark mb-4">
  <div class="container">
    <a class="navbar-brand" href="/">RHEL MCP Gateway</a>{menu}
  </div>
</nav>"""

def render_page(title: str, body: str, status_code: int = 200, user: str | None = None,
                active: str = "") -> HTMLResponse:
    """Tüm panel sayfaları için ortak HTML iskeleti (başlık, karakter seti, stil, üst menü)."""
    return HTMLResponse(f"""<!doctype html>
<html lang="{i18n.get_language()}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)} · RHEL MCP Gateway</title>
  {PAGE_STYLE}
</head>
<body class="bg-body-tertiary">
{navbar(user, active)}
<main class="container pb-5">
{body}
</main>
<script src="{BOOTSTRAP_CDN}/js/bootstrap.bundle.min.js"></script>
</body>
</html>""", status_code=status_code)

def forbidden() -> HTMLResponse:
    title = t("Access denied")
    return render_page(title, f"<h2 class='h4'>{title}</h2><p><a class='btn btn-primary' href='/login'>{t('Log in')}</a></p>", 403)

def invalid_login_request() -> HTMLResponse:
    title = t("Invalid login request")
    detail = t("The login request is invalid or has expired. Connect again from the MCP client.")
    return render_page(title, f"<h2 class='h4'>{title}</h2><p>{detail}</p>", 400)

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
        shown = " ".join(f"<code>{html.escape(ip)}</code>" for ip in via) or f"<span class='err'>{t('could not be determined')}</span>"
        label = t("Default proxy ({proxy}) egress IP address:", proxy=html.escape(outbound_proxy.redact(OUTBOUND_PROXY)))
        proxy_html = (f"<p>{label} {shown}<br><span class='note'>"
                      f"{t('Servers that use the proxy see this address; allow this address on them.')}</span></p>")
    found = [ip for ip in (ips.get("ipv4"), ips.get("ipv6")) if ip]
    if not found:
        return proxy_html + "<p class='note'>" + t(
            "The gateway's public IP address could not be determined (outbound access may be blocked).") + "</p>"
    codes = " ".join(f"<code>{html.escape(ip)}</code>" for ip in found)
    v4 = ips.get("ipv4")
    example = ""
    if v4:
        rule = (f"firewall-cmd --permanent --add-rich-rule='rule family=\"ipv4\" source address=\"{v4}\" "
                f"port port=\"9090\" protocol=\"tcp\" accept' && firewall-cmd --reload")
        example = f"<br>{t('Example (RHEL, firewalld):')} <code>{html.escape(rule)}</code>"
    note = t("On remote servers, allow this address for Cockpit (9090/tcp) and 22/tcp for the SSH fallback. "
             "Servers on the same local network see the local IP address of the machine running the gateway instead.")
    return proxy_html + (
        f"<p>{t('Gateway public IP address:')} {codes} "
        f"<form method='post' action='/public-ip/refresh' style='display:inline'><button class='btn btn-sm btn-outline-secondary'>{t('Refresh')}</button></form><br>"
        f"<span class='note'>{note}{example}</span></p>"
    )

async def check_server(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Sunucuya gerçekten bağlanıp basit bir komut çalıştırarak bilgileri doğrular.

    MCP araçlarıyla aynı sıra izlenir: Cockpit (doğrudan), SSH tüneli içinden Cockpit, düz SSH.
    Yalnızca düz SSH ile bağlanılabiliyorsa sonuç başarılı ama "warning" işaretlidir.
    """
    checked_at = time.strftime("%Y-%m-%d %H:%M:%S")

    async def spawn_true(session) -> str | None:
        result = await session.spawn(["true"], timeout=CHECK_TIMEOUT)
        if result.exit_status != 0:
            return t("Could not run a command through Cockpit: {reason}", reason=result.stderr.strip() or result.exit_status)
        return None

    async def try_ssh(password: str | None) -> tuple[str | None, str | None]:
        """(SSH hatası, tünel hatası). password verilirse SSH içinden Cockpit de denenir."""
        tunnel_error = None
        try:
            async with ssh_session(cfg, connect_timeout=CHECK_TIMEOUT) as (user, conn):
                if password is not None:
                    try:
                        async with cockpit_over_ssh(cfg, conn, password, CHECK_TIMEOUT) as session:
                            tunnel_error = await spawn_true(session)
                    except Exception as e:
                        tunnel_error = str(e) or type(e).__name__
                result = await make_runner(user, conn)("true", timeout=CHECK_TIMEOUT)
            if result.exit_status != 0:
                return t("SSH command failed: {reason}", reason=result.stderr.strip() or result.exit_status), tunnel_error
            return None, tunnel_error
        except Exception as e:
            return str(e), tunnel_error

    if cfg.get("cockpit_user"):
        password = cockpit_password(cfg)
        error = None
        if password is None:
            error = t("The Cockpit password could not be decrypted; re-enter the password.")
        else:
            session = None
            try:
                session = await connect_cockpit_direct(cfg, password, CHECK_TIMEOUT)
                error = await spawn_true(session)
            except cockpit_client.CockpitAuthError as e:
                # Şifre yanlış: tünel denemenin anlamı yok
                error, password = str(e), None
            except cockpit_client.CockpitError as e:
                error = str(e)
            finally:
                if session is not None:
                    await session.close()
        if error is None:
            return {"ok": True, "via": "cockpit", "message": t("Cockpit connection successful."), "at": checked_at}
        ssh_error, tunnel_error = await try_ssh(password)
        if ssh_error is None and password is not None and tunnel_error is None:
            return {"ok": True, "via": "cockpit-ssh", "at": checked_at,
                    "message": t("Connected to Cockpit over the SSH tunnel (the Cockpit port is not reachable from outside).")}
        if ssh_error is None:
            # MCP araçları da bu durumda SSH yedeğiyle çalışır: sunucu kullanılabilir, ama uyarı gösterilir
            detail = " " + t("Cockpit over the SSH tunnel: {error}", error=tunnel_error) if tunnel_error else ""
            return {"ok": True, "warning": True, "via": "ssh",
                    "message": t("Connected with the SSH fallback; Cockpit is not working: {error}.", error=error) + detail,
                    "at": checked_at}
        return {"ok": False, "via": None, "message": t("{error} (the SSH fallback is not working either: {ssh_error})", error=error, ssh_error=ssh_error),
                "at": checked_at}

    ssh_error, _ = await try_ssh(None)
    if ssh_error is None:
        return {"ok": True, "via": "ssh", "message": t("SSH connection successful."), "at": checked_at}
    return {"ok": False, "via": None, "message": ssh_error, "at": checked_at}

def server_row(cfg: Dict[str, Any]) -> str:
    e = lambda v: html.escape(str(v)) if v not in (None, "") else "—"
    name = cfg["name"]
    cockpit = f"{e(cfg['cockpit_user'])} @ {e(cockpit_url(cfg))}" if cfg.get("cockpit_user") else "—"
    ssh = f"{e(cfg.get('user') or t('automatic'))} @ {e(cfg['host'])}:{e(cfg.get('port', 22))}"
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
        status = f"<span class='note'>{t('Not tested')}</span>"
    quoted = html.escape(name)
    return (
        f"<tr><td><b>{e(name)}</b><br><span class='note'>{e(proxy_label(cfg))}</span></td><td>{cockpit}</td><td>{ssh}</td><td>{status}</td>"
        f"<td><form method='post' action='/servers/{quoted}/test'><button class='btn btn-sm btn-outline-primary'>{t('Test')}</button></form> "
        f"<form method='post' action='/servers/{quoted}/delete' "
        f"onsubmit=\"return confirm('{t('Delete {name}?', name=quoted)}')\"><button class='btn btn-sm btn-outline-danger'>{t('Delete')}</button></form></td></tr>"
    )

@app.get("/", response_class=HTMLResponse)
async def index(request: Request, error: str = "", info: str = ""):
    username = current_user(request)
    if not username:
        return RedirectResponse(url="/login", status_code=303)

    servers = load_servers()
    rows = "".join(server_row(cfg) for cfg in servers.values()) or f"<tr><td colspan='5'>{t('No servers defined yet.')}</td></tr>"
    error_html = f"<div class='alert alert-danger'>{html.escape(error)}</div>" if error else ""
    info_html = f"<div class='alert alert-success'>{html.escape(info)}</div>" if info else ""
    key_rows = "".join(shared_key_row(k) for k in load_shared_keys().values()) or \
        f"<tr><td colspan='4'>{t('No shared keys yet.')}</td></tr>"
    add_note = t(
        "Saving with an existing name updates that server. If the password field is left empty, the current password is kept. "
        "Before saving, the gateway connects to the server to verify the details; if no connection can be made, nothing is saved.")
    default_proxy = "" if not OUTBOUND_PROXY else " = " + html.escape(outbound_proxy.redact(OUTBOUND_PROXY))
    proxy_note = (
        t("Cockpit and SSH connections go through this proxy; the server sees the proxy's IP address. "
          "If left empty, the current setting is kept (a new server uses the default).")
        + " <code>default</code>: " + t("the default (OUTBOUND_PROXY in .env{value})", value=default_proxy)
        + ", <code>direct</code>: " + t("no proxy.") + " "
        + t("A username/password can be given in the address (socks5://user:password@host:1080) and is stored encrypted.")
    )
    keys_note = t(
        "The keys here are tried on all servers, for every user, in the SSH fallback. "
        "To use one, add the public part of the key to <code>~/.ssh/authorized_keys</code> on the servers. "
        "Private keys are stored encrypted in <code>data/ssh_keys.json</code> and are not shown in the panel.")

    return render_page(t("Servers"), f"""
        {info_html}{error_html}
        <div class="card mb-4"><div class="card-body">
          <h2 class="h5">{t("Welcome, {user}!", user=html.escape(username))}</h2>
          <p>{t("MCP Gateway is active. SSE endpoint:")} <code>{html.escape(PUBLIC_URL)}/sse</code></p>
          {public_ip_html(await public_ips(), await public_ips(proxy=OUTBOUND_PROXY) if OUTBOUND_PROXY else None)}
        </div></div>

        <div class="card mb-4"><div class="card-header">{t("Registered Servers")}</div><div class="card-body">
        <div class="table-responsive"><table class="table table-sm table-bordered table-hover align-middle bg-body mb-0">
          <tr><th>{t("Name")}</th><th>Cockpit</th><th>{t("SSH (fallback)")}</th><th>{t("Connection status")}</th><th></th></tr>
          {rows}
        </table></div>
        </div></div>

        <div class="card mb-4"><div class="card-header">{t("Add / Update Server")}</div><div class="card-body">
        <p class="note">{add_note}</p>
        <form class="add" method="post" action="/servers">
          <label>{t("Server name *")}</label><input class="form-control form-control-sm" name="name" required placeholder="prod-db">
          <label>{t("Host (IP / domain name) *")}</label><input class="form-control form-control-sm" name="host" required placeholder="192.168.0.98">
          <fieldset class="border rounded p-3" style="grid-column: 1 / -1">
            <legend class="float-none w-auto px-2 fs-6 mb-0">Cockpit</legend>
            <div class="add">
              <label>{t("Cockpit user")}</label><input class="form-control form-control-sm" name="cockpit_user" placeholder="bmericc">
              <label>{t("Cockpit password")}</label><input class="form-control form-control-sm" name="cockpit_password" type="password" autocomplete="new-password">
              <label>{t("Cockpit address")}</label><input class="form-control form-control-sm" name="cockpit_url" placeholder="{t("https://HOST:9090 (if empty)")}">
              <label>{t("Verify TLS certificate")}</label><input name="cockpit_verify_tls" type="checkbox" class="form-check-input">
            </div>
          </fieldset>
          <fieldset class="border rounded p-3" style="grid-column: 1 / -1">
            <legend class="float-none w-auto px-2 fs-6 mb-0">{t("SSH (fallback)")}</legend>
            <div class="add">
              <label>{t("SSH user")}</label><input class="form-control form-control-sm" name="user" placeholder="{t("SSH_LOGINS order if empty")}">
              <label>{t("SSH port")}</label><input class="form-control form-control-sm" name="port" type="number" value="22">
              <label>{t("SSH key path")}</label><input class="form-control form-control-sm" name="ssh_key_path" placeholder="{t("the user's .ssh folder if empty")}">
            </div>
          </fieldset>
          <fieldset class="border rounded p-3" style="grid-column: 1 / -1">
            <legend class="float-none w-auto px-2 fs-6 mb-0">{t("Connection proxy")}</legend>
            <div class="add">
              <label>Proxy</label><input class="form-control form-control-sm" name="proxy" autocomplete="off"
                placeholder="socks5://host:1080 · http://host:3128 · direct · default">
            </div>
            <p class="note mt-2 mb-0">{proxy_note}</p>
          </fieldset>
          <label>{t("Save without testing the connection")}</label><input name="skip_check" type="checkbox" class="form-check-input">
          <span></span><button type="submit" class="btn btn-primary">{t("Save")}</button>
        </form>
        </div></div>

        <div class="card mb-4" id="ssh-keys"><div class="card-header">{t("Shared SSH Keys")}</div><div class="card-body">
        <p class="note">{keys_note}</p>
        <div class="table-responsive"><table class="table table-sm table-bordered table-hover align-middle bg-body">
          <tr><th>{t("Name")}</th><th>{t("Type / fingerprint")}</th><th>{t("Public key (authorized_keys line)")}</th><th></th></tr>
          {key_rows}
        </table></div>
        <form class="add" method="post" action="/ssh-keys">
          <label>{t("Key name *")}</label><input class="form-control form-control-sm" name="name" required placeholder="{t("shared-key")}">
          <label>{t("Private key *")}</label><textarea class="key form-control form-control-sm" name="private_key" rows="6" required
            placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea>
          <label>{t("Key passphrase")}</label><input class="form-control form-control-sm" name="passphrase" type="password" autocomplete="off" placeholder="{t("empty if none")}">
          <span></span><button type="submit" class="btn btn-primary">{t("Add key")}</button>
        </form>
        <form class="add" method="post" action="/ssh-keys/generate" style="margin-top:12px">
          <label>{t("Generate a new key")}</label><input class="form-control form-control-sm" name="name" required placeholder="{t("key name")}">
          <span></span><button type="submit" class="btn btn-outline-primary">{t("Generate Ed25519 key")}</button>
        </form>
        </div></div>
    """, user=username, active="servers")

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
        return _redirect_error(t("The server name may only contain letters, digits, dots, underscores and hyphens."))
    if not HOST_RE.match(host):
        return _redirect_error(t("Invalid host."))
    try:
        port = int(field("port") or 22)
        if not 1 <= port <= 65535:
            raise ValueError
    except ValueError:
        return _redirect_error(t("Invalid SSH port."))
    cockpit_url_value = field("cockpit_url")
    if cockpit_url_value and not re.match(r"^https?://[^\s/]+(:\d+)?/?$", cockpit_url_value):
        return _redirect_error(t("The Cockpit address must look like https://host:9090."))

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
            return _redirect_error(t("Invalid proxy: {error}", error=e))
        cfg["proxy"] = encrypt_secret(proxy_value)

    if cfg.get("cockpit_user"):
        password = form.get("cockpit_password") or ""
        if password:
            cfg["cockpit_password"] = encrypt_secret(password)
        elif existing.get("cockpit_password"):
            cfg["cockpit_password"] = existing["cockpit_password"]
        else:
            return _redirect_error(t("A password is required for the Cockpit user."))

    if form.get("skip_check"):
        # Bilgiler test edilmedi: eski (başka ayarlara ait olabilecek) durum gösterilmesin
        servers[name] = cfg
        save_servers(servers)
        audit_web(request, "server_save", server=name, args=public_server(cfg), result=t("Saved without a connection test."))
        return _redirect_info(t("'{name}' saved without a connection test.", name=name))

    check = await check_server(cfg)
    audit_web(request, "server_save", "ok" if check["ok"] else "error", server=name, args=public_server(cfg),
              via=check.get("via"), result=check["message"])
    if not check["ok"]:
        return _redirect_error(t("'{name}' was not saved, could not connect: {message}", name=name, message=check["message"]))
    cfg["last_check"] = check
    # Kontrol sürerken dosya değişmiş olabilir; en güncel hâli üzerine yaz
    servers = load_servers()
    servers[name] = cfg
    save_servers(servers)
    if check.get("warning"):
        return _redirect_error(t("'{name}' saved.", name=name) + " " + check["message"])
    return _redirect_info(t("'{name}' saved.", name=name) + " " + check["message"])

@app.post("/public-ip/refresh")
async def refresh_public_ip(request: Request):
    if not current_user(request):
        return forbidden()
    ips = await public_ips(force=True)
    if OUTBOUND_PROXY:
        await public_ips(force=True, proxy=OUTBOUND_PROXY)
    found = ", ".join(ip for ip in ips.values() if ip)
    audit_web(request, "public_ip_refresh", "ok" if found else "error", result=found)
    if found:
        return _redirect_info(t("Public IP address: {ips}", ips=found))
    return _redirect_error(t("The public IP address could not be determined."))

@app.post("/servers/{name}/test")
async def test_server(name: str, request: Request):
    if not current_user(request):
        return forbidden()
    cfg = load_servers().get(name)
    if cfg is None:
        return _redirect_error(t("'{name}' not found.", name=name))
    check = await check_server(cfg)
    audit_web(request, "server_test", "ok" if check["ok"] else "error", server=name,
              via=check.get("via"), result=check["message"])
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
    removed = servers.pop(name, None)
    save_servers(servers)
    audit_web(request, "server_delete", "ok" if removed else "error", server=name,
              result=None if removed else t("Server not found."))
    return RedirectResponse(url="/", status_code=303)

def shared_key_row(entry: Dict[str, Any]) -> str:
    name = html.escape(entry["name"])
    return (
        f"<tr><td><b>{name}</b><br><span class='note'>{html.escape(entry.get('created', ''))}</span></td>"
        f"<td>{html.escape(entry.get('type', ''))}<br><span class='note'>{html.escape(entry.get('fingerprint', ''))}</span></td>"
        f"<td><textarea class='key form-control' rows='3' readonly onclick='this.select()'>{html.escape(entry.get('public', ''))}</textarea></td>"
        f"<td><form method='post' action='/ssh-keys/{name}/delete' "
        f"onsubmit=\"return confirm('{t('Delete key {name}?', name=name)}')\"><button class='btn btn-sm btn-outline-danger'>{t('Delete')}</button></form></td></tr>"
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
        return _redirect_error(t("The key name may only contain letters, digits, dots, underscores and hyphens."))
    keys = load_shared_keys()
    if name in keys:
        # Eski açık anahtar sunuculara dağıtılmış olabilir; yanlışlıkla üzerine yazılmasın
        return _redirect_error(t("A key named '{name}' already exists. Delete it first to replace it.", name=name))
    try:
        entry = import_shared_key(name, form.get("private_key") or "", form.get("passphrase") or "")
    except ValueError as e:
        audit_web(request, "ssh_key_add", "error", args={"name": name}, result=str(e))
        return _redirect_error(t("Key not added: {error}", error=e))
    keys[name] = entry
    save_shared_keys(keys)
    audit_web(request, "ssh_key_add", args={"name": name, "fingerprint": entry["fingerprint"]})
    return _redirect_info(t("Key '{name}' added ({fingerprint}).", name=name, fingerprint=entry["fingerprint"]))

@app.post("/ssh-keys/generate")
async def generate_shared_key(request: Request):
    if not current_user(request):
        return forbidden()
    form = await request.form()
    name = _key_name(form)
    if not name:
        return _redirect_error(t("The key name may only contain letters, digits, dots, underscores and hyphens."))
    keys = load_shared_keys()
    if name in keys:
        return _redirect_error(t("A key named '{name}' already exists.", name=name))
    key = asyncssh.generate_private_key("ssh-ed25519", comment=f"rhel-mcp-gateway:{name}")
    keys[name] = shared_key_entry(name, key)
    save_shared_keys(keys)
    audit_web(request, "ssh_key_generate", args={"name": name, "fingerprint": keys[name]["fingerprint"]})
    return _redirect_info(t("Key '{name}' generated. Add the public key to the authorized_keys file on the servers.", name=name))

@app.post("/ssh-keys/{name}/delete")
async def delete_shared_key(name: str, request: Request):
    if not current_user(request):
        return forbidden()
    keys = load_shared_keys()
    removed = keys.pop(name, None)
    save_shared_keys(keys)
    audit_web(request, "ssh_key_delete", "ok" if removed else "error",
              args={"name": name, "fingerprint": (removed or {}).get("fingerprint")})
    return _redirect_info(t("Key '{name}' deleted.", name=name))

# --- İşlem kayıtları ---
LOGS_PER_PAGE = 100
LOG_STATUS = {"ok": ("✓", "ok"), "error": (N("✗ error"), "err"), "preview": (N("awaiting confirmation"), "warn")}

def log_row(entry: Dict[str, Any]) -> str:
    e = lambda v: html.escape(str(v)) if v not in (None, "") else "—"
    mark, css = LOG_STATUS.get(entry.get("status"), (entry.get("status"), "note"))
    details = []
    if entry.get("args"):
        details.append(f"<b>{t('Parameters')}</b><pre>" + html.escape(json.dumps(entry["args"], ensure_ascii=False, indent=2)) + "</pre>")
    if entry.get("commands"):
        lines = "\n".join(
            f"[{c.get('via')} · {c.get('user')}{' · root' if c.get('as_root') else ''} · {t('exit')} {c.get('exit_status')}] {c.get('command')}"
            for c in entry["commands"]
        )
        details.append(f"<b>{t('Commands run')}</b><pre>" + html.escape(lines) + "</pre>")
    if entry.get("result"):
        details.append(f"<b>{t('Result')}</b><pre>" + html.escape(str(entry["result"])) + "</pre>")
    if entry.get("commands"):
        summary = t("{count} command(s)", count=len(entry["commands"]))
    else:
        summary = e(entry["via"]) if entry.get("via") else t("Details")
    if entry.get("duration_ms") is not None:
        summary += f" · {entry['duration_ms']} ms"
    detail_html = f"<details><summary>{summary}</summary>{''.join(details)}</details>" if details else "—"
    return (
        f"<tr><td>{e(entry.get('at'))}</td>"
        f"<td>{e(entry.get('user'))}<br><span class='note'>{e(entry.get('ip'))}</span></td>"
        f"<td>{e(entry.get('source'))}</td><td><b>{e(entry.get('action'))}</b></td>"
        f"<td>{e(entry.get('server'))}</td><td><span class='{css}'>{e(mark and t(mark))}</span></td><td>{detail_html}</td></tr>"
    )

@app.get("/logs", response_class=HTMLResponse)
async def logs_page(request: Request, q: str = "", source: str = "", status: str = "", user: str = "",
                    server: str = "", page: int = 1):
    username = current_user(request)
    if not username:
        return forbidden()
    page = max(page, 1)
    entries, has_more = audit_log.read(LOGS_PER_PAGE, (page - 1) * LOGS_PER_PAGE, q=q, source=source,
                                       status=status, user=user.strip(), server=server.strip())
    rows = "".join(log_row(entry) for entry in entries) or f"<tr><td colspan='7'>{t('No entries.')}</td></tr>"
    filters = {"q": q, "source": source, "status": status, "user": user, "server": server}

    def options(selected: str, choices: Dict[str, str]) -> str:
        return "".join(f"<option value='{v}'{' selected' if v == selected else ''}>{html.escape(label)}</option>"
                       for v, label in choices.items())

    def page_link(number: int, label: str) -> str:
        query = urlencode({**{k: v for k, v in filters.items() if v}, "page": number})
        return f"<a class='btn btn-sm btn-outline-secondary' href='/logs?{query}'>{label}</a>"

    nav = " ".join(filter(None, [
        page_link(page - 1, t("← Newer")) if page > 1 else "",
        f"<span class='mx-2'>{t('Page {page}', page=page)}</span>",
        page_link(page + 1, t("Older →")) if has_more else "",
    ]))
    logs_note = t(
        "MCP tool calls, panel actions and logins. The newest entry is on top. "
        "Entries are kept in <code>{file}</code>; passwords and keys are not recorded.",
        file=html.escape(audit_log.LOG_FILE))
    return render_page(t("Audit log"), f"""
        <h2 class="h4">{t("Audit log")}</h2>
        <p class="note">{logs_note}</p>
        <form class="row g-2 align-items-center mb-3" method="get" action="/logs">
          <div class="col-md"><input class="form-control form-control-sm" name="q" value="{html.escape(q)}" placeholder="{t("Search (command, tool, output…)")}"></div>
          <div class="col-6 col-md-2"><input class="form-control form-control-sm" name="user" value="{html.escape(user)}" placeholder="{t("User")}"></div>
          <div class="col-6 col-md-2"><input class="form-control form-control-sm" name="server" value="{html.escape(server)}" placeholder="{t("Server")}"></div>
          <div class="col-6 col-md-auto"><select class="form-select form-select-sm" name="source">{options(source, {"": t("All sources"), "mcp": "MCP", "web": "Panel"})}</select></div>
          <div class="col-6 col-md-auto"><select class="form-select form-select-sm" name="status">{options(status, {"": t("All statuses"), "ok": t("Success"), "error": t("Error"), "preview": t("Awaiting confirmation")})}</select></div>
          <div class="col-auto"><button type="submit" class="btn btn-sm btn-primary">{t("Filter")}</button>
            <a class="btn btn-sm btn-link" href="/logs">{t("Clear")}</a></div>
        </form>
        <div class="table-responsive"><table class="logs table table-sm table-bordered table-hover align-middle bg-body">
          <tr><th>{t("Time")}</th><th>{t("User")}</th><th>{t("Source")}</th><th>{t("Action")}</th><th>{t("Server")}</th><th>{t("Status")}</th><th>{t("Details")}</th></tr>
          {rows}
        </table></div>
        <p>{nav}</p>
    """, user=username, active="logs")

def login_page(action: str, title: str, error: str = "", note: str = "", hidden: Dict[str, str] | None = None,
               status_code: int = 200, ask_token: bool = False) -> HTMLResponse:
    hidden_inputs = "".join(
        f"<input type='hidden' name='{html.escape(k)}' value='{html.escape(v)}'>" for k, v in (hidden or {}).items()
    )
    token_field = (
        f'<div class="mb-3"><label class="form-label">{t("Gateway password")}</label>'
        '<input class="form-control" name="token" type="password" autocomplete="off" required></div>'
    ) if ask_token else ""
    return render_page(title, f"""
        <div class="card mx-auto shadow-sm" style="max-width: 420px"><div class="card-body">
        <h2 class="h5 mb-3">{html.escape(title)}</h2>
        <p class="note">{note}{t("Log in with your Cockpit username and password ({url}).", url=html.escape(COCKPIT_AUTH_URL))}</p>
        {f"<div class='alert alert-danger py-2'>{html.escape(error)}</div>" if error else ""}
        <form method="post" action="{html.escape(action)}">
          {hidden_inputs}
          <div class="mb-3"><label class="form-label">{t("Username")}</label>
            <input class="form-control" name="username" autocomplete="username" required autofocus></div>
          <div class="mb-3"><label class="form-label">{t("Cockpit password")}</label>
            <input class="form-control" name="password" type="password" autocomplete="current-password" required></div>
          {token_field}
          <button type="submit" class="btn btn-primary w-100">{t("Log in")}</button>
        </form>
        </div></div>
    """, status_code)

TOKEN_ERROR = N("Wrong gateway password.")

def _token_fields(url_token: str | None) -> tuple[bool, Dict[str, str]]:
    """URL'de geçerli token varsa formda sorma, gizli alanla taşı."""
    if login_token_ok(url_token):
        return False, ({"token": url_token} if url_token else {})
    return True, {}

@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request, token: str | None = None):
    ask_token, hidden = _token_fields(token)
    return login_page("/login", t("RHEL MCP Gateway - Login"), hidden=hidden, ask_token=ask_token)

@app.post("/login")
async def login_submit(request: Request):
    form = await request.form()
    username = (form.get("username") or "").strip()
    # Token Cockpit'ten önce kontrol edilir: token'sız denemeler şifreyi hiç sınayamaz
    error = t(TOKEN_ERROR) if not login_token_ok(form.get("token")) else await authenticator.login(username, form.get("password") or "")
    if error:
        audit_web(request, "login", "error", user=username, result=error)
        return login_page("/login", t("RHEL MCP Gateway - Login"), error=error, status_code=401, ask_token=bool(MCP_API_KEY))
    request.session['user'] = {"username": username}
    audit_web(request, "login")
    return RedirectResponse(url='/', status_code=303)

# --- MCP istemcileri için OAuth girişi (/authorize buraya yönlendirir) ---
@app.get("/oauth/login", response_class=HTMLResponse)
async def oauth_login_form(request_id: str = Query(alias="request")):
    client_name = oauth_provider.pending_client_name(request_id)
    if client_name is None:
        return invalid_login_request()
    return login_page(
        "/oauth/login", t("Grant Access to MCP Client"),
        note=t("<b>{client}</b> wants to access the tools on this gateway.", client=html.escape(client_name)) + " ",
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
    error = t(TOKEN_ERROR) if not token_ok else await authenticator.login(username, form.get("password") or "")
    if error:
        audit_web(request, "oauth_login", "error", user=username, args={"client": client_name}, result=error)
        return login_page(
            "/oauth/login", t("Grant Access to MCP Client"), error=error,
            note=t("<b>{client}</b> wants to access the tools on this gateway.", client=html.escape(client_name)) + " ",
            hidden={"request": request_id}, status_code=401, ask_token=not login_token_ok(url_token),
        )
    redirect = oauth_provider.complete_authorization(request_id, username)
    audit_web(request, "oauth_login", user=username, args={"client": client_name})
    return RedirectResponse(url=redirect, status_code=302)

@app.get("/logout")
async def logout(request: Request):
    if request.session.get("user"):
        audit_web(request, "logout")
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
    username = await authenticate_mcp(request)
    if username is None:
        if request.headers.get("authorization"):
            # Kimlik bilgisi gönderilmiş ama reddedilmiş (başlıksız ilk keşif isteği kaydedilmez)
            audit_log.record("mcp", "connect", "error", **request_actor(request), result=t("Authentication rejected."))
        # URL'deki geçerli token metadata adresine taşınır; istemci bunu OAuth isteğindeki
        # "resource" alanında geri gönderir ve giriş sayfası token'ı ayrıca sormaz.
        metadata_url = RESOURCE_METADATA_URL
        url_token = request.query_params.get("token")
        if MCP_API_KEY and login_token_ok(url_token):
            metadata_url += "?" + urlencode({"token": url_token})
        return JSONResponse(
            {"error": "invalid_token", "error_description": t("Login with a Cockpit account is required")},
            status_code=401,
            headers={"WWW-Authenticate": f'Bearer error="invalid_token", resource_metadata="{metadata_url}"'},
        )

    actor = {"user": username, **request_actor(request)}
    audit_log.record("mcp", "connect", **actor, args={"user_agent": request.headers.get("user-agent")})
    # Araç çağrıları bu görevin bağlamını devralır; kayıtlarda kullanıcı ve IP görünür
    _mcp_actor.set(actor)
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
