"""Sunuculara giden bağlantılar için proxy (HTTP CONNECT ve SOCKS5)."""
import asyncio
import base64
import json
import socket

import itsdangerous
import pytest
from fastapi.testclient import TestClient

import cockpit_client
import main
import outbound_proxy
from creds import PASSWORD, WRONG_PASSWORD

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


def proxy(kind, **kw):
    from fake_proxy import FakeProxy
    return FakeProxy(kind, **kw).start()


@pytest.fixture
def http_proxy():
    p = proxy("http")
    yield p
    p.stop()


@pytest.fixture
def socks_proxy():
    p = proxy("socks5")
    yield p
    p.stop()


@pytest.fixture
def cockpit():
    from fake_cockpit import LiveFakeCockpit
    live = LiveFakeCockpit().start()
    yield live
    live.stop()


async def echo_server():
    async def handle(reader, writer):
        data = await reader.read(100)
        writer.write(b"echo:" + data)
        await writer.drain()
        writer.close()
    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def roundtrip(sock):
    reader, writer = await asyncio.open_connection(sock=sock)
    writer.write(b"merhaba")
    await writer.drain()
    data = await reader.read(100)
    writer.close()
    return data


# --- Adres ayrıştırma ---

@pytest.mark.parametrize("url,expected", [
    ("socks5://10.0.0.1:1080", {"scheme": "socks5", "host": "10.0.0.1", "port": 1080, "username": None, "password": None}),
    ("http://u:x%40x@proxy.local:3128", {"scheme": "http", "host": "proxy.local", "port": 3128, "username": "u", "password": "x@x"}),
])
def test_parse_proxy(url, expected):
    assert outbound_proxy.parse_proxy(url) == expected


@pytest.mark.parametrize("url", ["ftp://h:1", "socks5://h", "http://h:1/yol", "javascript:alert(1)", "h:1080"])
def test_parse_proxy_rejects(url):
    with pytest.raises(ValueError):
        outbound_proxy.parse_proxy(url)


def test_redact_hides_password():
    assert outbound_proxy.redact(f"socks5://ali:{PASSWORD}@h:1080") == "socks5://ali:***@h:1080"
    assert outbound_proxy.redact("http://h:3128") == "http://h:3128"


# --- Tünel ---

@pytest.mark.parametrize("kind,scheme", [("http", "http"), ("socks5", "socks5"), ("socks5", "socks5h")])
async def test_tunnel_relays_data(kind, scheme):
    server, port = await echo_server()
    p = proxy(kind)
    try:
        sock = await outbound_proxy.open_tunnel(p.url(scheme), "127.0.0.1", port, timeout=5)
        assert await roundtrip(sock) == b"echo:merhaba"
        assert p.targets == [("127.0.0.1", port)]
    finally:
        p.stop()
        server.close()


async def test_socks5h_sends_hostname_to_proxy():
    server, port = await echo_server()
    p = proxy("socks5")
    try:
        sock = await outbound_proxy.open_tunnel(p.url("socks5h"), "localhost", port, timeout=5)
        sock.close()
        assert p.targets == [("localhost", port)]
    finally:
        p.stop()
        server.close()


@pytest.mark.parametrize("kind", ["http", "socks5"])
async def test_proxy_authentication(kind):
    server, port = await echo_server()
    user = "ali"
    good, bad = (user, PASSWORD), (user, WRONG_PASSWORD)
    p = proxy(kind, username=good[0], password=good[1])
    try:
        sock = await outbound_proxy.open_tunnel(p.url(auth=good), "127.0.0.1", port, timeout=5)
        assert await roundtrip(sock) == b"echo:merhaba"
        with pytest.raises(outbound_proxy.ProxyError):
            await outbound_proxy.open_tunnel(p.url(auth=bad), "127.0.0.1", port, timeout=5)
        with pytest.raises(outbound_proxy.ProxyError):
            await outbound_proxy.open_tunnel(p.url(), "127.0.0.1", port, timeout=5)
    finally:
        p.stop()
        server.close()


@pytest.mark.parametrize("kind", ["http", "socks5"])
async def test_target_unreachable_through_proxy(kind):
    p = proxy(kind)
    try:
        with pytest.raises(outbound_proxy.ProxyError):
            await outbound_proxy.open_tunnel(p.url(), "127.0.0.1", 1, timeout=5)
    finally:
        p.stop()


async def test_proxy_unreachable():
    with pytest.raises(outbound_proxy.ProxyError, match="Proxy'ye bağlanılamadı"):
        await outbound_proxy.open_tunnel("socks5://127.0.0.1:1", "127.0.0.1", 22, timeout=3)


async def test_proxy_timeout():
    # Bağlantıyı kabul eden ama hiç cevap vermeyen "proxy"
    silent = socket.socket()
    silent.bind(("127.0.0.1", 0))
    silent.listen()
    try:
        with pytest.raises(outbound_proxy.ProxyError, match="zaman aşımı"):
            await outbound_proxy.open_tunnel(f"socks5://127.0.0.1:{silent.getsockname()[1]}", "127.0.0.1", 22, timeout=0.5)
    finally:
        silent.close()


async def test_invalid_proxy_setting():
    with pytest.raises(outbound_proxy.ProxyError, match="Geçersiz proxy"):
        await outbound_proxy.open_tunnel("ftp://h:1", "127.0.0.1", 22)


def test_dechunk():
    assert outbound_proxy._dechunk(b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n") == b"Wikipedia"


# --- Cockpit proxy üzerinden ---

@pytest.mark.parametrize("kind", ["http", "socks5"])
async def test_cockpit_session_through_proxy(cockpit, kind):
    p = proxy(kind)
    try:
        async with cockpit_client.CockpitSession(cockpit.url, "admin", PASSWORD, proxy=p.url()) as s:
            r = await s.spawn(["echo", "proxy"])
        assert r.stdout == "echo proxy\n"
        # Giriş (HTTP) ve WebSocket, ikisi de proxy'den geçti
        assert len(p.targets) == 2
        assert all(t == ("127.0.0.1", cockpit.port) for t in p.targets)
    finally:
        p.stop()


async def test_cockpit_wrong_password_through_proxy(cockpit, socks_proxy):
    with pytest.raises(cockpit_client.CockpitAuthError):
        await cockpit_client.check_login(cockpit.url, "admin", WRONG_PASSWORD, proxy=socks_proxy.url())


async def test_cockpit_proxy_down(cockpit):
    with pytest.raises(cockpit_client.CockpitError, match="proxy"):
        await cockpit_client.CockpitSession(cockpit.url, "admin", PASSWORD, proxy="socks5://127.0.0.1:1",
                                            connect_timeout=3).connect()


# --- SSH proxy üzerinden ---

class SSHConn:
    async def run(self, command, check=False):
        class R:
            exit_status, stdout, stderr = 0, "", ""
        return R()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


async def test_ssh_uses_tunnel_socket(socks_proxy, monkeypatch, ssh_dirs):
    server, port = await echo_server()
    ssh_dirs("root")
    seen = []

    def connect(host, **kw):
        seen.append(kw)
        return SSHConn()

    monkeypatch.setattr(main.asyncssh, "connect", connect)
    cfg = {"name": "s", "host": "127.0.0.1", "port": port, "proxy": main.encrypt_secret(socks_proxy.url())}
    async with main.ssh_session(cfg):
        pass
    assert isinstance(seen[0]["sock"], socket.socket)
    assert socks_proxy.targets == [("127.0.0.1", port)]
    seen[0]["sock"].close()
    server.close()


async def test_ssh_proxy_error_is_reported(monkeypatch, ssh_dirs):
    ssh_dirs("root")
    monkeypatch.setattr(main.asyncssh, "connect", lambda host, **kw: SSHConn())
    cfg = {"name": "s", "host": "127.0.0.1", "proxy": main.encrypt_secret("socks5://127.0.0.1:1")}
    with pytest.raises(main.SSHError, match="Proxy'ye bağlanılamadı"):
        async with main.ssh_session(cfg):
            pass


# --- Hangi proxy kullanılır ---

def test_server_proxy_precedence(monkeypatch):
    enc = main.encrypt_secret
    assert main.server_proxy({}) is None
    monkeypatch.setattr(main, "OUTBOUND_PROXY", "socks5://varsayilan:1080")
    assert main.server_proxy({}) == "socks5://varsayilan:1080"
    assert main.server_proxy({"proxy": enc("http://ozel:3128")}) == "http://ozel:3128"
    assert main.server_proxy({"proxy": enc("direct")}) is None
    assert main.proxy_label({}) == "proxy socks5://varsayilan:1080 (varsayılan)"
    assert main.proxy_label({"proxy": enc("direct")}) == "doğrudan"


# --- Panel ---

@pytest.fixture
def client(monkeypatch, servers_file):
    monkeypatch.setattr(main.authenticator, "allowed_users", {"admin"})

    async def always_ok(cfg):
        return {"ok": True, "via": "cockpit", "message": "ok", "at": "x"}

    monkeypatch.setattr(main, "check_server", always_ok)
    c = TestClient(main.app)
    data = base64.b64encode(json.dumps({"user": {"username": "admin"}}).encode())
    c.cookies.set("session", itsdangerous.TimestampSigner(main.SECRET_KEY).sign(data).decode())
    return c


def save(client, **extra):
    data = {"name": "srv", "host": "10.0.0.1", "port": "22"}
    data.update(extra)
    return client.post("/servers", data=data, follow_redirects=False)


def test_panel_proxy_lifecycle(client):
    save(client, proxy=f"socks5://ali:{PASSWORD}@10.9.9.9:1080")
    cfg = main.load_servers()["srv"]
    assert PASSWORD not in json.dumps(cfg)
    assert main.server_proxy(cfg) == f"socks5://ali:{PASSWORD}@10.9.9.9:1080"
    page = client.get("/").text
    assert "proxy socks5://ali:***@10.9.9.9:1080" in page
    assert PASSWORD not in page

    save(client)  # boş: korunur
    assert main.server_proxy(main.load_servers()["srv"]) == f"socks5://ali:{PASSWORD}@10.9.9.9:1080"

    save(client, proxy="direct")
    assert main.server_proxy(main.load_servers()["srv"]) is None

    save(client, proxy="default")
    assert "proxy" not in main.load_servers()["srv"]


def test_panel_rejects_invalid_proxy(client):
    resp = save(client, proxy="ftp://h:21")
    assert "Geçersiz proxy" in client.get(resp.headers["location"]).text
    assert main.load_servers() == {}


def test_list_servers_hides_proxy_password(servers_file):
    servers_file({"srv": {"name": "srv", "host": "h", "proxy": main.encrypt_secret(f"http://u:{PASSWORD}@p:3128")}})
    data = main.public_server(main.load_servers()["srv"])
    assert "proxy" not in data
    assert data["connection"] == "proxy http://u:***@p:3128"


async def test_public_ip_through_default_proxy(monkeypatch):
    monkeypatch.setattr(main, "OUTBOUND_PROXY", "socks5://p:1080")
    monkeypatch.setattr(main, "_public_ip_cache", {})

    async def fetch(url, proxy=None):
        if "ipify.org" in url and "api6" not in url:
            return "198.51.100.9" if proxy else "203.0.113.7"
        return None

    monkeypatch.setattr(main, "_fetch_ip", fetch)
    direct = await main.public_ips()
    via = await main.public_ips(proxy=main.OUTBOUND_PROXY)
    html = main.public_ip_html(direct, via)
    assert "Varsayılan proxy (socks5://p:1080) çıkış IP adresi: <code>198.51.100.9</code>" in html
    assert "Gateway dış IP adresi: <code>203.0.113.7</code>" in html


# --- Codex incelemesinden gelen durumlar ---

async def test_http_connect_keeps_bytes_after_header():
    """Proxy 200 yanıtıyla hedefin ilk verisini (SSH banner'ı) aynı pakette gönderirse veri kaybolmamalı."""
    async def handle(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"HTTP/1.1 200 Connection established\r\n\r\nSSH-2.0-OpenSSH_9.6\r\n")
        await writer.drain()
        await asyncio.sleep(0.5)
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        sock = await outbound_proxy.open_tunnel(f"http://127.0.0.1:{port}", "10.0.0.1", 22, timeout=5)
        reader, writer = await asyncio.open_connection(sock=sock)
        assert await asyncio.wait_for(reader.readline(), 2) == b"SSH-2.0-OpenSSH_9.6\r\n"
        writer.close()
    finally:
        server.close()


def test_unreadable_proxy_setting_fails_closed(monkeypatch):
    monkeypatch.setattr(main, "OUTBOUND_PROXY", "socks5://varsayilan:1080")
    cfg = {"name": "s", "host": "h", "proxy": "bozuk-sifreli-deger"}
    with pytest.raises(outbound_proxy.ProxyError, match="çözülemedi"):
        main.server_proxy(cfg)
    assert main.proxy_label(cfg) == "proxy ayarı çözülemedi"


async def test_unreadable_proxy_blocks_ssh(monkeypatch, ssh_dirs):
    ssh_dirs("root")
    calls = []
    monkeypatch.setattr(main.asyncssh, "connect", lambda host, **kw: calls.append(kw) or SSHConn())
    with pytest.raises(main.SSHError, match="çözülemedi"):
        async with main.ssh_session({"name": "s", "host": "127.0.0.1", "proxy": "bozuk"}):
            pass
    assert calls == []


async def test_unreadable_proxy_blocks_cockpit_and_check(cockpit, monkeypatch, ssh_dirs):
    ssh_dirs("root")
    calls = []
    monkeypatch.setattr(main.asyncssh, "connect", lambda host, **kw: calls.append(kw) or SSHConn())
    cfg = {"name": "s", "host": "127.0.0.1", "cockpit_url": cockpit.url, "cockpit_user": "admin",
           "cockpit_password": main.encrypt_secret(PASSWORD), "proxy": "bozuk"}
    result = await main.check_server(cfg)
    assert result["ok"] is False
    assert "çözülemedi" in result["message"]
    # Ne Cockpit'e ne SSH'a doğrudan bağlanıldı
    assert cockpit.fake.logins == []
    assert calls == []
