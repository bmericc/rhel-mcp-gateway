"""Sunucu eklenirken / 'Test et' ile bağlantının gerçekten doğrulanması."""
import base64
import json

import itsdangerous
import pytest
from fastapi.testclient import TestClient

import main
from creds import PASSWORD, WRONG_PASSWORD


@pytest.fixture
def cockpit():
    from fake_cockpit import LiveFakeCockpit

    live = LiveFakeCockpit().start()
    yield live
    live.stop()


@pytest.fixture
def client(monkeypatch, servers_file):
    monkeypatch.setattr(main.authenticator, "allowed_users", {"admin"})
    c = TestClient(main.app)
    data = base64.b64encode(json.dumps({"user": {"username": "admin"}}).encode())
    c.cookies.set("session", itsdangerous.TimestampSigner(main.SECRET_KEY).sign(data).decode())
    return c


def form(cockpit_url, password=PASSWORD, **extra):
    data = {"name": "srv", "host": "127.0.0.1", "port": "22", "cockpit_url": cockpit_url,
            "cockpit_user": "admin", "cockpit_password": password}
    data.update(extra)
    return data


class SSHConn:
    async def run(self, command, check=False):
        class R:
            exit_status, stdout, stderr = 0, "", ""
        return R()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


def test_save_with_correct_cockpit_credentials(cockpit, client):
    resp = client.post("/servers", data=form(cockpit.url), follow_redirects=False)
    assert "info=" in resp.headers["location"]
    cfg = main.load_servers()["srv"]
    assert cfg["last_check"]["ok"] is True
    assert cfg["last_check"]["via"] == "cockpit"
    # Gerçekten komut çalıştırıldı
    assert cockpit.fake.opened[-1]["spawn"] == ["true"]
    assert "✓" in client.get("/").text


def test_wrong_cockpit_password_is_not_saved(cockpit, client, ssh_dirs):
    resp = client.post("/servers", data=form(cockpit.url, password=WRONG_PASSWORD), follow_redirects=False)
    location = resp.headers["location"]
    assert "error=" in location
    page = client.get(location).text
    assert "was not saved" in page
    assert "login rejected" in page
    assert main.load_servers() == {}


def test_unreachable_cockpit_is_not_saved(client, ssh_dirs):
    resp = client.post("/servers", data=form("http://127.0.0.1:1"), follow_redirects=False)
    assert "error=" in resp.headers["location"]
    assert "Could not connect" in client.get(resp.headers["location"]).text
    assert main.load_servers() == {}


def test_skip_check_clears_previous_status(cockpit, client, servers_file):
    servers_file({"srv": {"name": "srv", "host": "127.0.0.1", "last_check": {"ok": True, "message": "eski", "at": "x"}}})
    client.post("/servers", data=form(cockpit.url, password=WRONG_PASSWORD, skip_check="on"))
    assert "last_check" not in main.load_servers()["srv"]


def test_skip_check_saves_without_connecting(cockpit, client):
    resp = client.post("/servers", data=form(cockpit.url, password=WRONG_PASSWORD, skip_check="on"),
                       follow_redirects=False)
    assert "info=" in resp.headers["location"]
    assert "srv" in main.load_servers()
    assert cockpit.fake.logins == []
    assert "Not tested" in client.get("/").text


def test_ssh_only_server_checked_over_ssh(client, monkeypatch, ssh_dirs):
    ssh_dirs("root")
    seen = []

    def connect(host, **kw):
        seen.append(kw)
        return SSHConn()

    monkeypatch.setattr(main.asyncssh, "connect", connect)
    resp = client.post("/servers", data={"name": "srv", "host": "10.0.0.1", "port": "22"}, follow_redirects=False)
    assert "info=" in resp.headers["location"]
    assert main.load_servers()["srv"]["last_check"]["via"] == "ssh"
    # Bağlantı kurulumu da zaman aşımıyla sınırlı
    assert seen[0]["connect_timeout"] == main.CHECK_TIMEOUT


def test_ssh_only_server_unreachable(client, monkeypatch, ssh_dirs):
    ssh_dirs("root")

    def refuse(host, **kw):
        raise OSError("Connection refused")

    monkeypatch.setattr(main.asyncssh, "connect", refuse)
    resp = client.post("/servers", data={"name": "srv", "host": "10.0.0.1", "port": "22"}, follow_redirects=False)
    assert "Connection refused" in client.get(resp.headers["location"]).text
    assert main.load_servers() == {}


def test_test_button_updates_status(cockpit, client, servers_file, ssh_dirs):
    servers_file({"srv": {"name": "srv", "host": "127.0.0.1", "cockpit_url": cockpit.url,
                          "cockpit_user": "admin", "cockpit_password": main.encrypt_secret(WRONG_PASSWORD)}})
    resp = client.post("/servers/srv/test", follow_redirects=False)
    assert "error=" in resp.headers["location"]
    assert main.load_servers()["srv"]["last_check"]["ok"] is False
    assert "✗" in client.get("/").text

    cfg = main.load_servers()
    cfg["srv"]["cockpit_password"] = main.encrypt_secret(PASSWORD)
    servers_file(cfg)
    resp = client.post("/servers/srv/test", follow_redirects=False)
    assert "info=" in resp.headers["location"]
    assert main.load_servers()["srv"]["last_check"]["ok"] is True


def test_test_button_requires_login(servers_file):
    assert TestClient(main.app).post("/servers/srv/test").status_code == 403


def test_cockpit_down_but_ssh_works_is_warning(client, monkeypatch, servers_file, ssh_dirs):
    # Cockpit portu kapalı, SSH yedeği çalışıyor: MCP araçları gibi test de bağlanabilmeli
    ssh_dirs("root")
    monkeypatch.setattr(main.asyncssh, "connect", lambda host, **kw: SSHConn())
    servers_file({"srv": {"name": "srv", "host": "127.0.0.1", "cockpit_url": "https://127.0.0.1:1",
                          "cockpit_user": "admin", "cockpit_password": main.encrypt_secret(PASSWORD)}})
    client.post("/servers/srv/test", follow_redirects=False)
    check = main.load_servers()["srv"]["last_check"]
    assert check["ok"] is True and check["warning"] is True and check["via"] == "ssh"
    assert "Connected with the SSH fallback" in check["message"]
    # Boş hata mesajı yerine sebep yazılır
    assert not check["message"].rstrip().endswith("):")
    assert "⚠" in client.get("/").text
