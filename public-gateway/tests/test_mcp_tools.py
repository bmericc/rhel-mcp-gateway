import json

import pytest
from mcp.shared.memory import create_connected_server_and_client_session

import main

pytestmark = pytest.mark.anyio


class FakeResult:
    def __init__(self, exit_status=0, stdout="", stderr=""):
        self.exit_status = exit_status
        self.stdout = stdout
        self.stderr = stderr


class FakeConn:
    def __init__(self, result, calls):
        self.result = result
        self.calls = calls

    async def run(self, command, check=False):
        self.calls.append(("run", command, check))
        return self.result

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


@pytest.fixture
def fake_ssh(monkeypatch):
    calls = []
    state = {"result": FakeResult(0, "active (running)\n", ""), "error": None}

    def connect(host, **kwargs):
        calls.append(("connect", host, kwargs))
        if state["error"]:
            raise state["error"]
        return FakeConn(state["result"], calls)

    monkeypatch.setattr(main.asyncssh, "connect", connect)
    return calls, state


async def call(name, arguments):
    async with create_connected_server_and_client_session(main.mcp_server) as client:
        return await client.call_tool(name, arguments)


async def test_list_tools():
    async with create_connected_server_and_client_session(main.mcp_server) as client:
        result = await client.list_tools()
    tools = {t.name: t for t in result.tools}
    assert set(tools) == {"list_servers", "run_remote_command"}
    assert tools["run_remote_command"].inputSchema["required"] == ["server_name", "command"]


async def test_list_servers_empty(servers_file):
    result = await call("list_servers", {})
    assert not result.isError
    assert json.loads(result.content[0].text) == {}


async def test_list_servers_returns_saved(servers_file, sample_server):
    servers_file(sample_server)
    result = await call("list_servers", {})
    assert json.loads(result.content[0].text) == sample_server


async def test_run_remote_command_unknown_server(servers_file, fake_ssh):
    calls, _ = fake_ssh
    result = await call("run_remote_command", {"server_name": "yok", "command": "uptime"})
    assert "'yok' sunucusu hafızada bulunamadı" in result.content[0].text
    assert calls == []


async def test_run_remote_command_success(servers_file, sample_server, fake_ssh):
    servers_file(sample_server)
    calls, _ = fake_ssh
    result = await call(
        "run_remote_command", {"server_name": "prod-db", "command": "systemctl status nginx"}
    )
    text = result.content[0].text
    assert "Exit Status: 0" in text
    assert "active (running)" in text

    _, host, kwargs = calls[0]
    assert host == "10.0.0.5"
    assert kwargs["port"] == 2222
    assert kwargs["username"] == "admin"
    assert kwargs["client_keys"] == ["/root/.ssh/id_rsa"]
    assert calls[1] == ("run", "systemctl status nginx", False)


async def test_run_remote_command_default_port(servers_file, sample_server, fake_ssh):
    del sample_server["prod-db"]["port"]
    servers_file(sample_server)
    calls, _ = fake_ssh
    await call("run_remote_command", {"server_name": "prod-db", "command": "uptime"})
    assert calls[0][2]["port"] == 22


async def test_run_remote_command_nonzero_exit(servers_file, sample_server, fake_ssh):
    servers_file(sample_server)
    _, state = fake_ssh
    state["result"] = FakeResult(3, "", "Unit nginx.service could not be found.\n")
    result = await call("run_remote_command", {"server_name": "prod-db", "command": "x"})
    text = result.content[0].text
    assert "Exit Status: 3" in text
    assert "could not be found" in text


async def test_run_remote_command_ssh_error(servers_file, sample_server, fake_ssh):
    servers_file(sample_server)
    _, state = fake_ssh
    state["error"] = OSError("Connection refused")
    result = await call("run_remote_command", {"server_name": "prod-db", "command": "uptime"})
    assert "SSH Bağlantı Hatası: Connection refused" in result.content[0].text


async def test_unknown_tool_returns_error():
    result = await call("olmayan_arac", {})
    assert result.isError
    assert "Bilinmeyen araç: olmayan_arac" in result.content[0].text
