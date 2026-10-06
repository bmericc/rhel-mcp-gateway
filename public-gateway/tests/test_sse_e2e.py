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
def live_server(monkeypatch, servers_file):
    monkeypatch.setattr(main, "MCP_API_KEY", "s3cret")

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


async def test_sse_roundtrip(live_server):
    async with sse_client(f"{live_server.url}/sse?token=s3cret") as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            assert {t.name for t in tools.tools} == {"list_servers", "run_remote_command"}
            result = await session.call_tool("list_servers", {})
            assert result.content[0].text == "{}"

    # Sunucu durdurulunca kapanan SSE bağlantısı hata (örn. NoneType response) üretmemeli
    live_server.stop()
    assert live_server.error_messages() == []
    # /messages POST'ları yönlendirilmeden doğrudan 202 almalı
    assert 307 not in live_server.status_codes()
    assert 202 in live_server.status_codes()


async def test_sse_bearer_header(live_server):
    async with sse_client(f"{live_server.url}/sse", headers={"Authorization": "Bearer s3cret"}) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
