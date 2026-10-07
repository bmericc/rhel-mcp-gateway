"""Gateway'den sunuculara giden bağlantılar için proxy (HTTP CONNECT ve SOCKS5).

Amaç: sunuculara sabit bir çıkış IP'si üzerinden bağlanmak (güvenlik duvarında tek adrese
izin verebilmek). Ek kütüphane kullanılmaz; proxy ile el sıkışma burada yapılır ve
hedefe açılmış bir TCP soketi döner. Bu soket asyncssh'e (`sock=`), websockets'e (`sock=`)
ve aşağıdaki küçük HTTP istemcisine verilir.

Desteklenen adresler:
  http://[kullanıcı:parola@]host:port     HTTP CONNECT
  socks5://[kullanıcı:parola@]host:port   SOCKS5, hedef adı gateway'de çözülür
  socks5h://[kullanıcı:parola@]host:port  SOCKS5, hedef adı proxy'de çözülür
"""
import asyncio
import base64
import ipaddress
import socket
import ssl
import struct
from urllib.parse import unquote, urlsplit

from i18n import N, t

SCHEMES = ("http", "socks5", "socks5h")
MAX_RESPONSE = 64 * 1024


class ProxyError(Exception):
    """Proxy'ye bağlanılamadı veya proxy hedefe bağlantı kuramadı."""


def parse_proxy(url: str) -> dict:
    parts = urlsplit(url.strip())
    if parts.scheme not in SCHEMES:
        raise ValueError(t("The proxy address must start with http://, socks5:// or socks5h://."))
    if not parts.hostname or not parts.port:
        raise ValueError(t("The proxy address needs a host and a port (e.g. socks5://10.0.0.1:1080)."))
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ValueError(t("The proxy address may only consist of a scheme, host and port."))
    return {
        "scheme": parts.scheme,
        "host": parts.hostname,
        "port": parts.port,
        "username": unquote(parts.username) if parts.username else None,
        "password": unquote(parts.password) if parts.password else None,
    }


def redact(url: str) -> str:
    """Parolayı gizleyerek gösterilebilir proxy adresi."""
    try:
        p = parse_proxy(url)
    except ValueError:
        return t("invalid proxy")
    user = f"{p['username']}:***@" if p["username"] else ""
    return f"{p['scheme']}://{user}{p['host']}:{p['port']}"


async def _recv_exact(loop, sock, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = await loop.sock_recv(sock, n - len(data))
        if not chunk:
            raise ProxyError(t("The proxy closed the connection."))
        data += chunk
    return data


async def _http_connect(loop, sock, p: dict, host: str, port: int):
    target = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    lines = [f"CONNECT {target} HTTP/1.1", f"Host: {target}"]
    if p["username"]:
        token = base64.b64encode(f"{p['username']}:{p['password'] or ''}".encode()).decode()
        lines.append(f"Proxy-Authorization: Basic {token}")
    await loop.sock_sendall(sock, ("\r\n".join(lines) + "\r\n\r\n").encode())
    # Yanıt başlığı bayt bayt okunur: hedefin ilk verisi (örn. SSH banner'ı) aynı pakette
    # gelebilir ve başlığın sonundan sonrasını tüketmemek gerekir.
    response = b""
    while not response.endswith(b"\r\n\r\n"):
        chunk = await loop.sock_recv(sock, 1)
        if not chunk:
            raise ProxyError(t("The HTTP proxy closed the connection."))
        response += chunk
        if len(response) > MAX_RESPONSE:
            raise ProxyError(t("The HTTP proxy response is too long."))
    status_line = response.split(b"\r\n", 1)[0].decode(errors="replace")
    parts = status_line.split(" ", 2)
    if len(parts) < 2 or parts[1] != "200":
        raise ProxyError(t("The HTTP proxy refused the connection: {status}", status=status_line))


SOCKS5_ERRORS = {
    1: N("general failure"), 2: N("not allowed by the ruleset"), 3: N("network unreachable"), 4: N("host unreachable"),
    5: N("connection refused"), 6: N("TTL expired"), 7: N("command not supported"), 8: N("address type not supported"),
}


async def _socks5_connect(loop, sock, p: dict, host: str, port: int):
    methods = b"\x00\x02" if p["username"] else b"\x00"
    await loop.sock_sendall(sock, b"\x05" + bytes([len(methods)]) + methods)
    version, method = await _recv_exact(loop, sock, 2)
    if version != 5 or method == 0xFF:
        raise ProxyError(t("The SOCKS5 proxy did not accept the authentication method."))
    if method == 2:
        user = (p["username"] or "").encode()
        password = (p["password"] or "").encode()
        await loop.sock_sendall(sock, b"\x01" + bytes([len(user)]) + user + bytes([len(password)]) + password)
        _, status = await _recv_exact(loop, sock, 2)
        if status != 0:
            raise ProxyError(t("The SOCKS5 proxy rejected the username/password."))

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is None and p["scheme"] == "socks5":
        # Ad gateway'de çözülür
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        ip = ipaddress.ip_address(infos[0][4][0])
    if ip is None:
        encoded = host.encode("idna")
        address = b"\x03" + bytes([len(encoded)]) + encoded
    elif ip.version == 4:
        address = b"\x01" + ip.packed
    else:
        address = b"\x04" + ip.packed
    await loop.sock_sendall(sock, b"\x05\x01\x00" + address + struct.pack(">H", port))

    version, reply, _, atype = await _recv_exact(loop, sock, 4)
    if version != 5 or reply != 0:
        reason = t(SOCKS5_ERRORS[reply]) if reply in SOCKS5_ERRORS else reply
        raise ProxyError(t("The SOCKS5 proxy could not connect to the target: {reason}", reason=reason))
    # Bağlanılan adresi oku ve at
    if atype == 1:
        await _recv_exact(loop, sock, 4 + 2)
    elif atype == 4:
        await _recv_exact(loop, sock, 16 + 2)
    elif atype == 3:
        (length,) = await _recv_exact(loop, sock, 1)
        await _recv_exact(loop, sock, length + 2)
    else:
        raise ProxyError(t("The SOCKS5 proxy returned an unexpected address type."))


async def open_tunnel(proxy_url: str, host: str, port: int, timeout: float = 15) -> socket.socket:
    """Proxy üzerinden host:port'a açılmış, bloklamayan bir TCP soketi döner."""
    try:
        p = parse_proxy(proxy_url)
    except ValueError as e:
        raise ProxyError(t("Invalid proxy setting: {error}", error=e)) from e
    loop = asyncio.get_running_loop()

    async def connect():
        infos = await loop.getaddrinfo(p["host"], p["port"], type=socket.SOCK_STREAM)
        family, type_, proto, _, address = infos[0]
        sock = socket.socket(family, type_, proto)
        sock.setblocking(False)
        try:
            await loop.sock_connect(sock, address)
            if p["scheme"] == "http":
                await _http_connect(loop, sock, p, host, port)
            else:
                await _socks5_connect(loop, sock, p, host, port)
        except BaseException:
            sock.close()
            raise
        return sock

    try:
        return await asyncio.wait_for(connect(), timeout)
    except ProxyError:
        raise
    except asyncio.TimeoutError as e:
        raise ProxyError(t("The proxy connection timed out ({proxy})", proxy=redact(proxy_url))) from e
    except OSError as e:
        raise ProxyError(t("Could not connect to the proxy ({proxy}): {reason}", proxy=redact(proxy_url), reason=e)) from e


def _dechunk(data: bytes) -> bytes:
    out = b""
    while data:
        size_line, _, rest = data.partition(b"\r\n")
        size = int(size_line.split(b";")[0] or b"0", 16)
        if size == 0:
            break
        out += rest[:size]
        data = rest[size + 2:]
    return out


async def http_get(proxy_url: str, url: str, headers: dict | None = None, ssl_context: ssl.SSLContext | None = None,
                   timeout: float = 15) -> tuple[int, list[tuple[str, str]], bytes]:
    """Proxy tüneli üzerinden basit bir HTTP/1.1 GET isteği. (durum, başlıklar, gövde) döner."""
    parts = urlsplit(url)
    secure = parts.scheme == "https"
    port = parts.port or (443 if secure else 80)
    sock = await open_tunnel(proxy_url, parts.hostname, port, timeout)
    if secure and ssl_context is None:
        ssl_context = ssl.create_default_context()

    async def request():
        reader, writer = await asyncio.open_connection(
            sock=sock, ssl=ssl_context if secure else None, server_hostname=parts.hostname if secure else None,
        )
        try:
            path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
            lines = [f"GET {path} HTTP/1.1", f"Host: {parts.netloc.rsplit('@', 1)[-1]}", "Connection: close"]
            lines += [f"{k}: {v}" for k, v in (headers or {}).items()]
            writer.write(("\r\n".join(lines) + "\r\n\r\n").encode())
            await writer.drain()
            raw = await reader.read(MAX_RESPONSE)
            while len(raw) < MAX_RESPONSE:
                chunk = await reader.read(MAX_RESPONSE - len(raw))
                if not chunk:
                    break
                raw += chunk
        finally:
            writer.close()
        head, _, body = raw.partition(b"\r\n\r\n")
        lines = head.decode(errors="replace").split("\r\n")
        status = int(lines[0].split(" ")[1])
        hdrs = [tuple(x.strip() for x in line.split(":", 1)) for line in lines[1:] if ":" in line]
        if any(k.lower() == "transfer-encoding" and "chunked" in v.lower() for k, v in hdrs):
            body = _dechunk(body)
        return status, hdrs, body

    try:
        return await asyncio.wait_for(request(), timeout)
    except (asyncio.TimeoutError, OSError, ValueError, IndexError) as e:
        sock.close()
        raise ProxyError(t("Request through the proxy failed ({proxy}): {reason}",
                           proxy=redact(proxy_url), reason=e or type(e).__name__)) from e
