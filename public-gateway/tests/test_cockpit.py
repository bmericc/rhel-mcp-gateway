"""Cockpit istemcisi ve Cockpit -> SSH yedek akışı (sahte cockpit-ws ile)."""
import asyncio
import json

import pytest
from mcp.shared.memory import create_connected_server_and_client_session

import cockpit_client
import main
from creds import PASSWORD, WRONG_PASSWORD

pytestmark = pytest.mark.anyio


@pytest.fixture
def cockpit():
    from fake_cockpit import LiveFakeCockpit

    live = LiveFakeCockpit().start()
    yield live
    live.stop()


def session(cockpit, user="admin", password=PASSWORD):
    return cockpit_client.CockpitSession(cockpit.url, user, password)


# --- İstemci ---

async def test_spawn_collects_output_and_exit_status(cockpit):
    async with session(cockpit) as s:
        r = await s.spawn(["echo", "merhaba", "dünya"])
    assert r == ("admin", 0, "echo merhaba dünya\n", "", "cockpit")
    opened = cockpit.fake.opened[0]
    assert opened["payload"] == "stream"
    assert opened["environ"] == ["LC_ALL=C"]
    assert opened["err"] == "message"
    assert "superuser" not in opened


async def test_login_requests_superuser_reuse(cockpit):
    async with session(cockpit):
        pass
    assert cockpit.fake.logins == [{"user": "admin", "superuser": "any"}]


async def test_nonzero_exit_and_stderr(cockpit):
    async with session(cockpit) as s:
        r = await s.spawn(["fail"])
    assert (r.exit_status, r.stdout, r.stderr) == (3, "partial\n", "err\n")


async def test_command_not_found(cockpit):
    async with session(cockpit) as s:
        r = await s.spawn(["missing"])
    assert r.exit_status is None
    assert r.stderr == "Cockpit hatası: not-found (komut bulunamadı)"


async def test_superuser(cockpit):
    async with session(cockpit) as s:
        r = await s.spawn(["id", "-u"], superuser=True)
    assert r.stdout == "0\n"
    assert cockpit.fake.opened[0]["superuser"] == "require"


async def test_superuser_denied_without_sudo(cockpit):
    async with session(cockpit, user="plain") as s:
        r = await s.spawn(["id", "-u"], superuser=True)
    assert r.exit_status is None
    assert "yönetici yetkisi alınamadı" in r.stderr


async def test_parallel_spawns_on_one_session(cockpit):
    async with session(cockpit) as s:
        results = await asyncio.gather(*(s.spawn(["echo", str(i)]) for i in range(5)))
    assert [r.stdout for r in results] == [f"echo {i}\n" for i in range(5)]


async def test_timeout(cockpit):
    async with session(cockpit) as s:
        r = await s.spawn(["sleep", "100"], timeout=0.2)
    assert r.exit_status is None
    assert "zaman aşımına uğradı" in r.stderr


async def test_wrong_password(cockpit):
    with pytest.raises(cockpit_client.CockpitError, match="girişi reddedildi"):
        await session(cockpit, password=WRONG_PASSWORD).connect()


async def test_unreachable():
    s = cockpit_client.CockpitSession("http://127.0.0.1:1", "admin", PASSWORD, connect_timeout=2)
    with pytest.raises(cockpit_client.CockpitError, match="bağlanılamadı"):
        await s.connect()


# --- MCP: Cockpit öncelikli, SSH yedek ---

class SSHResult:
    def __init__(self, stdout=""):
        self.exit_status, self.stdout, self.stderr = 0, stdout, ""


class SSHConn:
    def __init__(self, commands):
        self.commands = commands

    async def run(self, command, check=False):
        self.commands.append(command)
        return SSHResult("ssh-output\n")

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


@pytest.fixture
def ssh(monkeypatch):
    commands = []
    monkeypatch.setattr(main.asyncssh, "connect", lambda host, **kw: SSHConn(commands))
    return commands


def cockpit_server(url, password=PASSWORD, **extra):
    cfg = {
        "name": "box", "host": "127.0.0.1", "user": "root", "ssh_key_path": "/k",
        "cockpit_url": url, "cockpit_user": "admin", "cockpit_password": main.encrypt_secret(password),
    }
    cfg.update(extra)
    return {"box": cfg}


async def call(name, arguments):
    async with create_connected_server_and_client_session(main.mcp_server) as client:
        return await client.call_tool(name, arguments)


async def test_tool_runs_over_cockpit(cockpit, servers_file, ssh):
    servers_file(cockpit_server(cockpit.url))
    data = json.loads((await call("service_status", {"server_name": "box", "service": "nginx"})).content[0].text)
    assert data["connection"] == {"via": "cockpit", "user": "admin"}
    spawned = {tuple(o["spawn"]): o.get("superuser") for o in cockpit.fake.opened}
    assert spawned[("systemctl", "is-active", "nginx")] is None
    assert spawned[("systemctl", "status", "nginx", "--no-pager", "-l", "-n", "20")] == "require"
    assert ssh == []


async def test_run_remote_command_over_cockpit(cockpit, servers_file, ssh):
    servers_file(cockpit_server(cockpit.url))
    text = (await call("run_remote_command", {
        "server_name": "box", "command": "uptime", "as_root": True, "confirm": True,
    })).content[0].text
    assert "Via: cockpit" in text
    assert "sh:uptime" in text
    assert cockpit.fake.opened[0]["spawn"] == ["sh", "-c", "uptime"]
    assert cockpit.fake.opened[0]["superuser"] == "require"


async def test_falls_back_to_ssh_when_cockpit_unreachable(servers_file, ssh):
    servers_file(cockpit_server("http://127.0.0.1:1"))
    text = (await call("run_remote_command", {"server_name": "box", "command": "uptime", "confirm": True})).content[0].text
    assert "Via: ssh" in text
    assert "Cockpit kullanılamadı" in text
    assert ssh == ["uptime"]


async def test_falls_back_to_ssh_on_wrong_password(cockpit, servers_file, ssh):
    servers_file(cockpit_server(cockpit.url, password=WRONG_PASSWORD))
    data = json.loads((await call("failed_services", {"server_name": "box"})).content[0].text)
    assert data["connection"]["via"] == "ssh"
    assert "girişi reddedildi" in data["connection"]["cockpit_error"]


async def test_cockpit_and_ssh_both_fail(servers_file, monkeypatch, ssh_dirs):
    def refuse(host, **kw):
        raise OSError("Connection refused")

    monkeypatch.setattr(main.asyncssh, "connect", refuse)
    servers_file(cockpit_server("http://127.0.0.1:1"))
    text = (await call("server_info", {"server_name": "box"})).content[0].text
    assert "Cockpit'e bağlanılamadı" in text
    assert "SSH yedeği de başarısız" in text


async def test_undecryptable_password_falls_back(cockpit, servers_file, ssh):
    cfg = cockpit_server(cockpit.url)
    cfg["box"]["cockpit_password"] = "sifreli-olmayan-deger"
    servers_file(cfg)
    data = json.loads((await call("failed_services", {"server_name": "box"})).content[0].text)
    assert data["connection"]["via"] == "ssh"
    assert "şifresi çözülemedi" in data["connection"]["cockpit_error"]
    assert cockpit.fake.logins == []


async def test_list_servers_hides_password(servers_file):
    servers_file(cockpit_server("https://10.0.0.1:9090"))
    data = json.loads((await call("list_servers", {})).content[0].text)
    assert "cockpit_password" not in data["box"]
    assert data["box"]["cockpit"] is True
    assert data["box"]["cockpit_url"] == "https://10.0.0.1:9090"


def test_default_cockpit_url():
    assert main.cockpit_url({"host": "192.168.0.98"}) == "https://192.168.0.98:9090"


def test_encrypt_roundtrip():
    token = main.encrypt_secret(PASSWORD)
    assert token != PASSWORD
    assert main.decrypt_secret(token) == PASSWORD
    assert main.decrypt_secret("bozuk") is None
