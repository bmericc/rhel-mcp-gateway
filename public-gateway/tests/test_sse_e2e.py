"""Gerçek uvicorn sunucusu + resmi MCP SSE client ile uçtan uca test."""
import logging
import socket
import threading
import time

import pytest
import uvicorn
from mcp import ClientSession
from mcp.client.sse import sse_client

import main

pytestmark = pytest.mark.anyio


class _Collector(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record)


class LiveServer:
    def __init__(self, url, server, thread, errors, access):
        self.url = url
        self._server = server
        self._thread = thread
        self.errors = errors
        self.access = access

    def stop(self):
        self._server.should_exit = True
        self._thread.join(timeout=10)

    def error_messages(self):
        return [r.getMessage() for r in self.errors.records if r.levelno >= logging.ERROR]

    def status_codes(self):
        # uvicorn.access args: (client_addr, method, path, http_version, status_code)
        return [r.args[4] for r in self.access.records]


@pytest.fixture
def access_token(monkeypatch, tmp_path):
    """Cockpit girişi + erişim token'ı ile alınmış gibi bir OAuth erişim token'ı üretir."""
    monkeypatch.setattr(main.oauth_provider, "store_path", str(tmp_path / "oauth.json"))
    monkeypatch.setattr(main.authenticator, "allowed_users", set())
    return main.oauth_provider._issue("test-client", ["mcp"], "admin", None).access_token


@pytest.fixture
def live_server(monkeypatch, servers_file):
    monkeypatch.setattr(main, "MCP_API_KEY", "xxx")

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    # Config oluşturulurken uvicorn logging'i yeniden yapılandırır; handler'lar ondan sonra eklenmeli
    config = uvicorn.Config(main.app, host="127.0.0.1", port=port, log_level="info")
    errors, access = _Collector(), _Collector()
    logging.getLogger("uvicorn.error").addHandler(errors)
    logging.getLogger("uvicorn.access").addHandler(access)

    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started:
        if time.time() > deadline:
            raise RuntimeError("uvicorn başlamadı")
        time.sleep(0.05)

    live = LiveServer(f"http://127.0.0.1:{port}", server, thread, errors, access)
    yield live

    live.stop()
    logging.getLogger("uvicorn.error").removeHandler(errors)
    logging.getLogger("uvicorn.access").removeHandler(access)


async def test_sse_roundtrip(live_server, access_token):
    async with sse_client(f"{live_server.url}/sse", headers={"Authorization": f"Bearer {access_token}"}) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            assert {"list_servers", "run_remote_command", "server_info"} <= {t.name for t in tools.tools}
            result = await session.call_tool("list_servers", {})
            assert result.content[0].text == "{}"

    # Sunucu durdurulunca kapanan SSE bağlantısı hata (örn. NoneType response) üretmemeli
    live_server.stop()
    assert live_server.error_messages() == []
    # /messages POST'ları yönlendirilmeden doğrudan 202 almalı
    assert 307 not in live_server.status_codes()
    assert 202 in live_server.status_codes()


async def test_access_token_alone_is_not_enough(live_server):
    # Erişim token'ı (MCP_API_KEY) tek başına giriş sağlamaz; Cockpit girişi de gerekir
    import httpx

    async with httpx.AsyncClient(trust_env=False) as client:
        for kwargs in ({"params": {"token": "xxx"}}, {"headers": {"Authorization": "Bearer xxx"}}):
            resp = await client.get(f"{live_server.url}/sse", **kwargs)
            assert resp.status_code == 401
