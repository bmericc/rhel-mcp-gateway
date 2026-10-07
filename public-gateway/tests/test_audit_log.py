import json

import pytest
from fastapi.testclient import TestClient

import audit_log
import main
from creds import PASSWORD, WRONG_PASSWORD
from test_auth import cockpit  # noqa: F401
from test_mcp_tools import call, fake_ssh  # noqa: F401
from test_web import add_form, admin_client, login_as  # noqa: F401


# --- Kayıt dosyası ---

def test_record_and_read_newest_first(audit_file):
    audit_log.record("web", "login", user="admin", ip="10.0.0.1")
    audit_log.record("mcp", "server_info", "error", user="admin", server="prod-db", result="olmadı")
    entries = audit_file()
    assert [e["action"] for e in entries] == ["server_info", "login"]
    assert entries[0]["status"] == "error" and entries[0]["server"] == "prod-db"
    # Boş alanlar yazılmaz
    assert "server" not in entries[1] and "result" not in entries[1]


def test_read_filters_and_paging(audit_file):
    for i in range(5):
        audit_log.record("mcp", "run_remote_command", user="admin", server=f"srv-{i % 2}", args={"command": f"echo {i}"})
    audit_log.record("web", "login", "error", user="baskasi")

    assert len(audit_file(source="mcp")) == 5
    assert len(audit_file(server="srv-1")) == 2
    assert [e["user"] for e in audit_file(status="error")] == ["baskasi"]
    assert [e["args"]["command"] for e in audit_file(q="ECHO 3")] == ["echo 3"]

    page, has_more = audit_log.read(2, 0, source="mcp")
    assert [e["args"]["command"] for e in page] == ["echo 4", "echo 3"] and has_more
    page, has_more = audit_log.read(2, 4, source="mcp")
    assert [e["args"]["command"] for e in page] == ["echo 0"] and not has_more


def test_long_values_are_clipped(audit_file):
    audit_log.record("mcp", "read_logs", result="x" * 10000, args={"command": "y" * 10000})
    entry = audit_file()[0]
    assert len(entry["result"]) < 4100 and "kırpıldı" in entry["result"]
    assert len(entry["args"]["command"]) < 4100


def test_rotation_keeps_previous_file(audit_file, monkeypatch):
    monkeypatch.setattr(audit_log, "MAX_BYTES", 200)
    for i in range(10):
        audit_log.record("web", f"islem-{i}", result="x" * 100)
    import os
    assert os.path.exists(audit_log.LOG_FILE + ".1")
    # Yedeklenen dosyadaki kayıtlar da okunur
    assert audit_file()[0]["action"] == "islem-9"
    assert len(audit_file()) >= 2


def test_log_file_is_private(audit_file):
    import os
    audit_log.record("web", "login")
    assert os.stat(audit_log.LOG_FILE).st_mode & 0o777 == 0o600


# --- MCP araç çağrıları ---

@pytest.mark.anyio
async def test_tool_call_is_logged_with_commands(servers_file, sample_server, fake_ssh, audit_file):  # noqa: F811
    servers_file(sample_server)
    token = main._mcp_actor.set({"user": "admin", "ip": "203.0.113.7"})
    try:
        await call("run_remote_command", {"confirm": True, "server_name": "prod-db", "command": "systemctl status nginx", "as_root": True})
    finally:
        main._mcp_actor.reset(token)

    entry = audit_file()[0]
    assert (entry["source"], entry["action"], entry["status"]) == ("mcp", "run_remote_command", "ok")
    assert (entry["user"], entry["ip"], entry["server"]) == ("admin", "203.0.113.7", "prod-db")
    assert entry["args"] == {"confirm": True, "command": "systemctl status nginx", "as_root": True}
    assert entry["commands"] == [{"command": "systemctl status nginx", "as_root": True, "user": "admin",
                                  "via": "ssh", "exit_status": 0}]
    assert "active (running)" in entry["result"]
    assert isinstance(entry["duration_ms"], int)


@pytest.mark.anyio
async def test_unconfirmed_call_is_logged_as_preview(servers_file, sample_server, fake_ssh, audit_file):  # noqa: F811
    servers_file(sample_server)
    await call("run_remote_command", {"server_name": "prod-db", "command": "reboot"})
    entry = audit_file()[0]
    assert entry["status"] == "preview"
    assert "commands" not in entry


@pytest.mark.anyio
async def test_failed_calls_are_logged_as_error(servers_file, sample_server, fake_ssh, audit_file):  # noqa: F811
    servers_file(sample_server)
    _, state = fake_ssh
    await call("service_status", {"server_name": "prod-db", "service": "; rm -rf /"})
    await call("server_info", {"server_name": "yok"})
    state["error"] = OSError("Connection refused")
    await call("server_info", {"server_name": "prod-db"})
    await call("olmayan_arac", {})

    by_action = audit_file()
    assert [e["status"] for e in by_action] == ["error"] * 4
    assert "Bilinmeyen araç" in by_action[0]["result"]
    assert "Connection refused" in by_action[1]["result"]
    assert "bulunamadı" in by_action[2]["result"]
    assert "Geçersiz servis adı" in by_action[3]["result"]


@pytest.mark.anyio
async def test_command_log_does_not_leak_between_calls(servers_file, sample_server, fake_ssh, audit_file):  # noqa: F811
    servers_file(sample_server)
    await call("run_remote_command", {"confirm": True, "server_name": "prod-db", "command": "uptime"})
    await call("list_servers", {})
    assert main._command_log.get() is None
    assert "commands" not in audit_file()[0]


# --- Panel ---

def test_web_login_and_logout_are_logged(cockpit, servers_file, audit_file):  # noqa: F811
    client = TestClient(main.app)
    client.post("/login", data={"username": "admin", "password": WRONG_PASSWORD})
    client.post("/login", data={"username": "admin", "password": PASSWORD})
    client.get("/logout")

    entries = audit_file(source="web")
    assert [(e["action"], e["status"], e["user"]) for e in entries] == [
        ("logout", "ok", "admin"), ("login", "ok", "admin"), ("login", "error", "admin")]
    assert entries[0]["ip"] == "testclient"


def test_server_changes_are_logged_without_secrets(admin_client, audit_file):  # noqa: F811
    admin_client.post("/servers", data=add_form(proxy="socks5://kullanici:cokgizli@proxy:1080", skip_check="on"))
    admin_client.post("/servers/prod/test")
    admin_client.post("/servers/prod/delete")

    entries = audit_file(source="web")
    assert [e["action"] for e in entries] == ["server_delete", "server_test", "server_save"]
    assert all(e["user"] == "admin" and e["server"] == "prod" for e in entries)
    assert entries[2]["args"]["host"] == add_form()["host"]
    raw = open(audit_log.LOG_FILE, encoding="utf-8").read()
    assert add_form()["cockpit_password"] not in raw
    assert "cokgizli" not in raw


def test_shared_key_changes_are_logged_without_private_key(admin_client, audit_file):  # noqa: F811
    admin_client.post("/ssh-keys/generate", data={"name": "ortak"})
    admin_client.post("/ssh-keys/ortak/delete")
    entries = audit_file(source="web")
    assert [e["action"] for e in entries] == ["ssh_key_delete", "ssh_key_generate"]
    assert entries[1]["args"]["fingerprint"].startswith("SHA256:")
    assert "PRIVATE KEY" not in open(audit_log.LOG_FILE, encoding="utf-8").read()


def test_logs_page_requires_login(servers_file):
    assert TestClient(main.app).get("/logs").status_code == 403


def test_logs_page_shows_and_filters_entries(admin_client):  # noqa: F811
    audit_log.record("mcp", "run_remote_command", user="admin", server="prod-db",
                     args={"command": "echo <b>merhaba</b>"},
                     commands=[{"command": "echo <b>merhaba</b>", "as_root": True, "user": "root", "via": "cockpit", "exit_status": 0}],
                     result="merhaba", duration_ms=12)
    audit_log.record("web", "login", "error", user="baskasi", result="Kullanıcı adı veya şifre hatalı.")

    page = admin_client.get("/logs").text
    assert "run_remote_command" in page and "baskasi" in page
    # Kayıt içeriği HTML olarak yorumlanmaz
    assert "<b>merhaba</b>" not in page and "&lt;b&gt;merhaba&lt;/b&gt;" in page
    assert "[cockpit · root · root · çıkış 0]" in page

    filtered = admin_client.get("/logs", params={"status": "error"}).text
    assert "baskasi" in filtered and "run_remote_command" not in filtered
    assert "run_remote_command" in admin_client.get("/logs", params={"q": "merhaba", "server": "prod-db"}).text


def test_logs_page_paging(admin_client, monkeypatch):  # noqa: F811
    monkeypatch.setattr(main, "LOGS_PER_PAGE", 2)
    for i in range(3):
        audit_log.record("mcp", f"arac-{i}")
    first = admin_client.get("/logs", params={"source": "mcp"}).text
    assert "arac-2" in first and "arac-0" not in first and "page=2" in first and "source=mcp" in first
    second = admin_client.get("/logs", params={"source": "mcp", "page": 2}).text
    assert "arac-0" in second and "Daha eski" not in second


def test_index_links_to_logs(admin_client):  # noqa: F811
    assert 'href="/logs"' in admin_client.get("/").text
