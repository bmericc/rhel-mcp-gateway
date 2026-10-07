import json

import asyncssh
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
    state = {"result": FakeResult(0, "active (running)\n", ""), "error": None, "deny": set()}

    def connect(host, **kwargs):
        calls.append(("connect", host, kwargs))
        if state["error"]:
            raise state["error"]
        if kwargs["username"] in state["deny"]:
            raise asyncssh.PermissionDenied("Permission denied")
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
    assert {"list_servers", "fleet_health", "run_remote_command", "service_status", "service_action"} <= set(tools)
    assert tools["run_remote_command"].inputSchema["required"] == ["server_name", "command"]
    assert tools["run_remote_command"].annotations.destructiveHint is True
    assert tools["service_status"].annotations.readOnlyHint is True
    assert "confirm" in tools["service_action"].inputSchema["properties"]
    assert "confirm" not in tools["service_status"].inputSchema["properties"]


async def test_run_remote_command_requires_confirm(servers_file, sample_server, fake_ssh):
    servers_file(sample_server)
    calls, _ = fake_ssh
    result = await call("run_remote_command", {"server_name": "prod-db", "command": "rm -rf /tmp/x"})
    text = result.content[0].text
    assert "Confirmation required" in text
    assert "rm -rf /tmp/x" in text
    assert calls == []


async def test_list_servers_empty(servers_file):
    result = await call("list_servers", {})
    assert not result.isError
    assert json.loads(result.content[0].text) == {}


async def test_list_servers_returns_saved(servers_file, sample_server):
    servers_file(sample_server)
    result = await call("list_servers", {})
    assert json.loads(result.content[0].text) == {"prod-db": {**sample_server["prod-db"], "cockpit": False, "connection": "direct"}}


async def test_run_remote_command_unknown_server(servers_file, fake_ssh):
    calls, _ = fake_ssh
    result = await call("run_remote_command", {"confirm": True, "server_name": "yok", "command": "uptime"})
    assert "server 'yok' not found" in result.content[0].text
    assert calls == []


async def test_run_remote_command_success(servers_file, sample_server, fake_ssh):
    servers_file(sample_server)
    calls, _ = fake_ssh
    result = await call("run_remote_command", {"confirm": True, "server_name": "prod-db", "command": "systemctl status nginx"}
    )
    text = result.content[0].text
    assert "User: admin" in text
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
    await call("run_remote_command", {"confirm": True, "server_name": "prod-db", "command": "uptime"})
    assert calls[0][2]["port"] == 22


async def test_run_remote_command_nonzero_exit(servers_file, sample_server, fake_ssh):
    servers_file(sample_server)
    _, state = fake_ssh
    state["result"] = FakeResult(3, "", "Unit nginx.service could not be found.\n")
    result = await call("run_remote_command", {"confirm": True, "server_name": "prod-db", "command": "x"})
    text = result.content[0].text
    assert "Exit Status: 3" in text
    assert "could not be found" in text


async def test_run_remote_command_ssh_error(servers_file, sample_server, fake_ssh):
    servers_file(sample_server)
    _, state = fake_ssh
    state["error"] = OSError("Connection refused")
    result = await call("run_remote_command", {"confirm": True, "server_name": "prod-db", "command": "uptime"})
    assert "SSH connection error: Connection refused" in result.content[0].text


async def test_unknown_tool_returns_error():
    result = await call("olmayan_arac", {})
    assert result.isError
    assert "Unknown tool: olmayan_arac" in result.content[0].text


def connected_users(calls):
    return [c[2]["username"] for c in calls if c[0] == "connect"]


async def test_falls_back_to_bmericc_when_root_denied(servers_file, sample_server, fake_ssh, ssh_dirs):
    sample_server["prod-db"]["user"] = "root"
    servers_file(sample_server)
    bmericc_key = ssh_dirs("bmericc", "id_ed25519")
    calls, state = fake_ssh
    state["deny"] = {"root"}

    result = await call("run_remote_command", {"confirm": True, "server_name": "prod-db", "command": "uptime"})

    assert connected_users(calls) == ["root", "bmericc"]
    assert calls[1][2]["client_keys"] == [bmericc_key]
    assert "User: bmericc" in result.content[0].text


async def test_server_without_user_tries_logins_in_order(servers_file, fake_ssh, ssh_dirs):
    servers_file({"web": {"name": "web", "host": "10.0.0.9"}})
    root_key = ssh_dirs("root")
    ssh_dirs("bmericc")
    calls, _ = fake_ssh

    result = await call("run_remote_command", {"confirm": True, "server_name": "web", "command": "uptime"})

    assert connected_users(calls) == ["root"]
    assert calls[0][2]["client_keys"] == [root_key]
    assert "User: root" in result.content[0].text


async def test_configured_user_without_key_path_uses_its_ssh_dir(servers_file, fake_ssh, ssh_dirs):
    servers_file({"web": {"name": "web", "host": "10.0.0.9", "user": "bmericc"}})
    ssh_dirs("root")
    bmericc_key = ssh_dirs("bmericc")
    calls, _ = fake_ssh

    await call("run_remote_command", {"confirm": True, "server_name": "web", "command": "uptime"})

    assert connected_users(calls) == ["bmericc"]
    assert calls[0][2]["client_keys"] == [bmericc_key]


async def test_all_users_denied(servers_file, sample_server, fake_ssh, ssh_dirs):
    servers_file(sample_server)
    ssh_dirs("root")
    ssh_dirs("bmericc")
    calls, state = fake_ssh
    state["deny"] = {"admin", "root", "bmericc"}

    result = await call("run_remote_command", {"confirm": True, "server_name": "prod-db", "command": "uptime"})

    assert connected_users(calls) == ["admin", "root", "bmericc"]
    text = result.content[0].text
    assert "SSH authentication failed" in text
    assert "root: Permission denied" in text
    assert "bmericc: Permission denied" in text


async def test_network_error_does_not_try_other_users(servers_file, sample_server, fake_ssh, ssh_dirs):
    servers_file(sample_server)
    ssh_dirs("bmericc")
    calls, state = fake_ssh
    state["error"] = OSError("Connection refused")

    await call("run_remote_command", {"confirm": True, "server_name": "prod-db", "command": "uptime"})

    assert connected_users(calls) == ["admin"]


async def test_no_keys_available(servers_file, fake_ssh):
    servers_file({"web": {"name": "web", "host": "10.0.0.9"}})
    calls, _ = fake_ssh

    result = await call("run_remote_command", {"confirm": True, "server_name": "web", "command": "uptime"})

    assert "no usable SSH key found" in result.content[0].text
    assert calls == []
