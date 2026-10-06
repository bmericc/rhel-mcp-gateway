from fastapi.testclient import TestClient

import main


def test_index_requires_login():
    client = TestClient(main.app)
    resp = client.get("/")
    assert resp.status_code == 200
    assert "/login" in resp.text
    assert "Hoş geldiniz" not in resp.text


def test_logout_redirects():
    client = TestClient(main.app)
    resp = client.get("/logout", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/"


def test_sse_rejects_missing_token(monkeypatch):
    monkeypatch.setattr(main, "MCP_API_KEY", "s3cret")
    client = TestClient(main.app)
    assert client.get("/sse").status_code == 401


def test_sse_rejects_wrong_token(monkeypatch):
    monkeypatch.setattr(main, "MCP_API_KEY", "s3cret")
    client = TestClient(main.app)
    assert client.get("/sse?token=yanlis").status_code == 401
    assert client.get("/sse", headers={"Authorization": "Bearer yanlis"}).status_code == 401


def test_messages_endpoint_does_not_redirect():
    # /messages/ (sonda slash) doğrudan handler'a ulaşmalı, 307 yönlendirmesi olmamalı
    client = TestClient(main.app)
    resp = client.post("/messages/?session_id=gecersiz", json={}, follow_redirects=False)
    assert resp.status_code == 400


# --- Sunucu yönetim paneli ---

import base64  # noqa: E402
import json  # noqa: E402

import itsdangerous  # noqa: E402
import pytest  # noqa: E402


def login_as(client, email):
    """Starlette SessionMiddleware'in imzaladığı oturum çerezini üretir."""
    data = base64.b64encode(json.dumps({"user": {"email": email}}).encode())
    client.cookies.set("session", itsdangerous.TimestampSigner(main.SECRET_KEY).sign(data).decode())


@pytest.fixture
def admin_client(monkeypatch, servers_file):
    monkeypatch.setattr(main, "ALLOWED_EMAILS", {"admin@example.com"})
    client = TestClient(main.app)
    login_as(client, "Admin@Example.com")
    return client


def add_form(**overrides):
    form = {"name": "prod", "host": "192.168.0.98", "port": "22",
            "cockpit_user": "bmericc", "cockpit_password": "s3cret"}
    form.update(overrides)
    return form


def test_panel_rejects_unlisted_email(monkeypatch, servers_file):
    monkeypatch.setattr(main, "ALLOWED_EMAILS", {"admin@example.com"})
    client = TestClient(main.app)
    login_as(client, "someone@gmail.com")
    assert client.get("/").status_code == 403
    assert client.post("/servers", data=add_form(), follow_redirects=False).status_code == 403
    assert main.load_servers() == {}


def test_panel_rejects_everyone_when_allowed_emails_empty(monkeypatch, servers_file):
    monkeypatch.setattr(main, "ALLOWED_EMAILS", set())
    client = TestClient(main.app)
    login_as(client, "admin@example.com")
    assert client.get("/").status_code == 403


def test_add_server_encrypts_password(admin_client):
    resp = admin_client.post("/servers", data=add_form(), follow_redirects=False)
    assert resp.status_code == 303
    cfg = main.load_servers()["prod"]
    assert cfg["cockpit_user"] == "bmericc"
    assert cfg["cockpit_password"] != "s3cret"
    assert main.decrypt_secret(cfg["cockpit_password"]) == "s3cret"
    page = admin_client.get("/").text
    assert "prod" in page and "bmericc" in page
    assert "s3cret" not in page


def test_update_keeps_password_when_blank(admin_client):
    admin_client.post("/servers", data=add_form())
    admin_client.post("/servers", data=add_form(cockpit_password="", host="10.0.0.1"))
    cfg = main.load_servers()["prod"]
    assert cfg["host"] == "10.0.0.1"
    assert main.decrypt_secret(cfg["cockpit_password"]) == "s3cret"


def test_cockpit_user_requires_password(admin_client):
    resp = admin_client.post("/servers", data=add_form(cockpit_password=""), follow_redirects=False)
    assert "error=" in resp.headers["location"]
    assert main.load_servers() == {}


def test_ssh_only_server(admin_client):
    admin_client.post("/servers", data=add_form(cockpit_user="", cockpit_password="", user="root"))
    cfg = main.load_servers()["prod"]
    assert "cockpit_user" not in cfg and "cockpit_password" not in cfg
    assert cfg["user"] == "root"


@pytest.mark.parametrize("field,value", [
    ("name", "kötü ad"), ("host", "a b"), ("port", "70000"), ("cockpit_url", "javascript:alert(1)"),
])
def test_add_server_validation(admin_client, field, value):
    resp = admin_client.post("/servers", data=add_form(**{field: value}), follow_redirects=False)
    assert "error=" in resp.headers["location"]
    assert main.load_servers() == {}


def test_page_escapes_html(admin_client, servers_file):
    servers_file({"x": {"name": "x", "host": "h", "cockpit_user": "<script>alert(1)</script>", "cockpit_password": "e"}})
    page = admin_client.get("/").text
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page


def test_delete_server(admin_client):
    admin_client.post("/servers", data=add_form())
    resp = admin_client.post("/servers/prod/delete", follow_redirects=False)
    assert resp.status_code == 303
    assert main.load_servers() == {}
