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
