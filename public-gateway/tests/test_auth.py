"""Cockpit hesabıyla giriş: web paneli, HTTP Basic ve MCP OAuth akışı."""
import base64
import hashlib
import secrets
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

import auth
import main
from creds import PASSWORD, WRONG_PASSWORD


@pytest.fixture
def cockpit(monkeypatch):
    from fake_cockpit import LiveFakeCockpit

    live = LiveFakeCockpit().start()
    monkeypatch.setattr(main.authenticator, "url", live.url)
    monkeypatch.setattr(main.authenticator, "allowed_users", set())
    monkeypatch.setattr(main.authenticator, "_basic_cache", {})
    yield live
    live.stop()


@pytest.fixture
def provider(tmp_path, monkeypatch):
    """SDK route'ları main.oauth_provider nesnesini tutar; nesneyi değiştirmek yerine durumunu sıfırla."""
    p = main.oauth_provider
    monkeypatch.setattr(p, "store_path", str(tmp_path / "oauth.json"))
    for attr in ("clients", "access_tokens", "refresh_tokens", "codes", "pending"):
        monkeypatch.setattr(p, attr, {})
    return p


def basic(user, password):
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


# --- Web paneli ---

def test_web_login_success(cockpit, servers_file):
    client = TestClient(main.app)
    resp = client.post("/login", data={"username": "admin", "password": PASSWORD}, follow_redirects=False)
    assert resp.status_code == 303
    page = client.get("/")
    assert page.status_code == 200
    assert "Hoş geldiniz, admin" in page.text
    # Sadece doğrulama için giriş: superuser köprüsü istenmez
    assert cockpit.fake.logins[-1] == {"user": "admin", "superuser": "none"}


def test_web_login_wrong_password(cockpit, servers_file):
    client = TestClient(main.app)
    resp = client.post("/login", data={"username": "admin", "password": WRONG_PASSWORD})
    assert resp.status_code == 401
    assert "Kullanıcı adı veya şifre hatalı" in resp.text
    assert client.get("/", follow_redirects=False).status_code == 303


def test_web_login_cockpit_unreachable(monkeypatch, servers_file):
    monkeypatch.setattr(main.authenticator, "url", "http://127.0.0.1:1")
    resp = TestClient(main.app).post("/login", data={"username": "admin", "password": PASSWORD})
    assert resp.status_code == 401
    assert "Cockpit&#x27;e ulaşılamadı" in resp.text


def test_web_login_respects_allowed_users(cockpit, monkeypatch, servers_file):
    monkeypatch.setattr(main.authenticator, "allowed_users", {"plain"})
    resp = TestClient(main.app).post("/login", data={"username": "admin", "password": PASSWORD})
    assert resp.status_code == 401
    assert "erişim yetkisi yok" in resp.text


# --- /sse kimlik doğrulama ---

def test_sse_401_points_to_oauth_metadata():
    resp = TestClient(main.app).get("/sse")
    assert resp.status_code == 401
    assert f'resource_metadata="{main.RESOURCE_METADATA_URL}"' in resp.headers["www-authenticate"]


@pytest.mark.anyio
async def test_authenticate_basic(cockpit):
    from starlette.requests import Request

    def request(header):
        return Request({"type": "http", "headers": [(b"authorization", header.encode())], "query_string": b""})

    assert await main.authenticate_mcp(request(basic("admin", PASSWORD))) == "admin"
    assert await main.authenticate_mcp(request(basic("admin", WRONG_PASSWORD))) is None
    logins = len(cockpit.fake.logins)
    # Başarılı giriş kısa süre önbelleklenir
    assert await main.authenticate_mcp(request(basic("admin", PASSWORD))) == "admin"
    assert len(cockpit.fake.logins) == logins


def test_protected_resource_metadata():
    data = TestClient(main.app).get("/.well-known/oauth-protected-resource/sse").json()
    assert data["resource"] == main.MCP_RESOURCE_URL
    assert data["authorization_servers"] == [main.PUBLIC_URL + "/"]


def test_authorization_server_metadata():
    data = TestClient(main.app).get("/.well-known/oauth-authorization-server").json()
    assert data["authorization_endpoint"] == main.PUBLIC_URL + "/authorize"
    assert data["registration_endpoint"] == main.PUBLIC_URL + "/register"
    assert data["code_challenge_methods_supported"] == ["S256"]


# --- Uçtan uca OAuth akışı (MCP istemcisinin yaptığı gibi) ---

def oauth_flow(client, username="admin", password=PASSWORD, resource=None, token=None):
    reg = client.post("/register", json={
        "client_name": "Test MCP Client",
        "redirect_uris": ["http://localhost:9999/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    })
    assert reg.status_code == 201, reg.text
    client_id = reg.json()["client_id"]

    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    resp = client.get("/authorize", params={
        "response_type": "code", "client_id": client_id, "redirect_uri": "http://localhost:9999/callback",
        "code_challenge": challenge, "code_challenge_method": "S256", "state": "xyz",
        **({"resource": resource} if resource else {}),
    }, follow_redirects=False)
    assert resp.status_code == 302, resp.text
    login_url = urlparse(resp.headers["location"])
    assert login_url.path == "/oauth/login"
    request_id = parse_qs(login_url.query)["request"][0]

    page = client.get("/oauth/login", params={"request": request_id})
    assert "Test MCP Client" in page.text
    client.last_login_page = page.text

    data = {"request": request_id, "username": username, "password": password}
    if token is not None:
        data["token"] = token
    resp = client.post("/oauth/login", data=data, follow_redirects=False)
    return client_id, verifier, request_id, resp


def full_oauth_flow():
    client = TestClient(main.app)
    client_id, verifier, _, resp = oauth_flow(client)
    assert resp.status_code == 302
    callback = urlparse(resp.headers["location"])
    params = parse_qs(callback.query)
    assert callback.netloc == "localhost:9999" and params["state"] == ["xyz"]

    token = client.post("/token", data={
        "grant_type": "authorization_code", "code": params["code"][0], "client_id": client_id,
        "redirect_uri": "http://localhost:9999/callback", "code_verifier": verifier,
    })
    assert token.status_code == 200, token.text
    tokens = token.json()
    assert tokens["token_type"] == "Bearer"

    # Kod tek kullanımlık
    again = client.post("/token", data={
        "grant_type": "authorization_code", "code": params["code"][0], "client_id": client_id,
        "redirect_uri": "http://localhost:9999/callback", "code_verifier": verifier,
    })
    assert again.status_code == 400

    # Token'lar diske hash'lenmiş yazılır
    stored = open(main.oauth_provider.store_path).read()
    assert tokens["access_token"] not in stored
    assert tokens["refresh_token"] not in stored

    # Refresh: yeni token gelir, eski refresh token geçersiz olur
    refreshed = client.post("/token", data={
        "grant_type": "refresh_token", "refresh_token": tokens["refresh_token"], "client_id": client_id,
    })
    assert refreshed.status_code == 200, refreshed.text
    reuse = client.post("/token", data={
        "grant_type": "refresh_token", "refresh_token": tokens["refresh_token"], "client_id": client_id,
    })
    assert reuse.status_code == 400
    return tokens, refreshed.json()


def test_oauth_full_flow(cockpit, provider):
    full_oauth_flow()


def test_oauth_wrong_password_stays_on_login(cockpit, provider):
    client = TestClient(main.app)
    _, _, request_id, resp = oauth_flow(client, password=WRONG_PASSWORD)
    assert resp.status_code == 401
    assert "Kullanıcı adı veya şifre hatalı" in resp.text
    # Aynı istekle doğru şifre denenebilir
    ok = client.post("/oauth/login", data={"request": request_id, "username": "admin", "password": PASSWORD},
                     follow_redirects=False)
    assert ok.status_code == 302
    assert "code=" in ok.headers["location"]


def test_oauth_invalid_request_id(provider):
    client = TestClient(main.app)
    assert client.get("/oauth/login", params={"request": "yok"}).status_code == 400
    resp = client.post("/oauth/login", data={"request": "yok", "username": "a", "password": "b"})
    assert resp.status_code == 400


@pytest.mark.anyio
async def test_access_token_authenticates_mcp(cockpit, provider):
    from starlette.requests import Request

    tokens, refreshed = full_oauth_flow()

    def request(token):
        return Request({"type": "http", "headers": [(b"authorization", f"Bearer {token}".encode())], "query_string": b""})

    assert await main.authenticate_mcp(request(refreshed["access_token"])) == "admin"
    assert await main.authenticate_mcp(request("uydurma")) is None


@pytest.mark.anyio
async def test_tokens_survive_restart_and_expire(cockpit, provider):
    tokens, _ = full_oauth_flow()
    reloaded = auth.CockpitOAuthProvider(provider.store_path, provider.login_url)
    access = await reloaded.load_access_token(tokens["access_token"])
    # İlk access token refresh sonrası da süresi dolana kadar geçerli kalır
    assert access is not None and access.subject == "admin"
    access.expires_at = 1
    assert await reloaded.load_access_token(tokens["access_token"]) is None


@pytest.mark.anyio
async def test_token_rejected_if_user_removed_from_allowed(cockpit, provider, monkeypatch):
    from starlette.requests import Request

    tokens, _ = full_oauth_flow()
    monkeypatch.setattr(main.authenticator, "allowed_users", {"baska"})
    req = Request({"type": "http", "headers": [(b"authorization", f"Bearer {tokens['access_token']}".encode())],
                   "query_string": b""})
    assert await main.authenticate_mcp(req) is None


# --- Erişim token'ı (MCP_API_KEY) ikinci faktör olarak ---

LOGIN_TOKEN = "xxx-giris-token"


@pytest.fixture
def login_token(monkeypatch):
    monkeypatch.setattr(main, "MCP_API_KEY", LOGIN_TOKEN)
    return LOGIN_TOKEN


def test_web_login_asks_for_token(cockpit, login_token, servers_file):
    client = TestClient(main.app)
    assert 'name="token"' in client.get("/login").text

    logins = len(cockpit.fake.logins)
    resp = client.post("/login", data={"username": "admin", "password": PASSWORD})
    assert resp.status_code == 401
    assert "Gateway parolası hatalı" in resp.text
    # Token yanlışsa şifre Cockpit'e hiç gönderilmez
    assert len(cockpit.fake.logins) == logins

    resp = client.post("/login", data={"username": "admin", "password": PASSWORD, "token": "yanlis-xxx"})
    assert resp.status_code == 401

    resp = client.post("/login", data={"username": "admin", "password": PASSWORD, "token": LOGIN_TOKEN},
                       follow_redirects=False)
    assert resp.status_code == 303


def test_web_login_token_from_url(cockpit, login_token, servers_file):
    client = TestClient(main.app)
    page = client.get("/login", params={"token": LOGIN_TOKEN}).text
    assert "Gateway parolası" not in page
    assert f"name='token' value='{LOGIN_TOKEN}'" in page
    # URL'deki token yanlışsa form yine sorar
    assert 'name="token"' in client.get("/login", params={"token": "yanlis-xxx"}).text


def test_oauth_asks_token_when_not_in_url(cockpit, provider, login_token):
    client = TestClient(main.app)
    _, _, request_id, resp = oauth_flow(client)
    assert 'name="token"' in client.last_login_page
    assert resp.status_code == 401
    ok = client.post("/oauth/login", data={"request": request_id, "username": "admin", "password": PASSWORD,
                                           "token": LOGIN_TOKEN}, follow_redirects=False)
    assert ok.status_code == 302
    assert "code=" in ok.headers["location"]


def test_oauth_uses_token_from_connection_url(cockpit, provider, login_token):
    client = TestClient(main.app)
    resource = f"{main.MCP_RESOURCE_URL}?token={LOGIN_TOKEN}"
    _, _, _, resp = oauth_flow(client, resource=resource)
    assert "Gateway parolası" not in client.last_login_page
    assert resp.status_code == 302
    assert "code=" in resp.headers["location"]


def test_oauth_wrong_token_in_url_asks_again(cockpit, provider, login_token):
    client = TestClient(main.app)
    _, _, _, resp = oauth_flow(client, resource=f"{main.MCP_RESOURCE_URL}?token=yanlis-xxx")
    assert 'name="token"' in client.last_login_page
    assert resp.status_code == 401


def test_sse_401_carries_valid_url_token_to_metadata(login_token):
    client = TestClient(main.app)
    header = client.get("/sse", params={"token": LOGIN_TOKEN}).headers["www-authenticate"]
    assert f'oauth-protected-resource/sse?token={LOGIN_TOKEN}"' in header
    header = client.get("/sse", params={"token": "yanlis-xxx"}).headers["www-authenticate"]
    assert "?token=" not in header

    data = client.get("/.well-known/oauth-protected-resource/sse", params={"token": LOGIN_TOKEN}).json()
    assert data["resource"] == f"{main.MCP_RESOURCE_URL}?token={LOGIN_TOKEN}"
    data = client.get("/.well-known/oauth-protected-resource/sse", params={"token": "yanlis-xxx"}).json()
    assert data["resource"] == main.MCP_RESOURCE_URL


@pytest.mark.anyio
async def test_basic_requires_token(cockpit, login_token):
    from starlette.requests import Request

    def request(headers, query=b""):
        return Request({"type": "http", "query_string": query,
                        "headers": [(k.encode(), v.encode()) for k, v in headers.items()]})

    creds = {"authorization": basic("admin", PASSWORD)}
    assert await main.authenticate_mcp(request(creds)) is None
    assert await main.authenticate_mcp(request({**creds, "x-mcp-token": "yanlis-xxx"})) is None
    assert await main.authenticate_mcp(request({**creds, "x-mcp-token": LOGIN_TOKEN})) == "admin"
    assert await main.authenticate_mcp(request(creds, f"token={LOGIN_TOKEN}".encode())) == "admin"


@pytest.mark.anyio
async def test_changing_token_logs_everyone_out(tmp_path):
    store = str(tmp_path / "oauth.json")
    first = auth.CockpitOAuthProvider(store, "x", token_policy="eski-xxx")
    tokens = first._issue("c", ["mcp"], "admin", None)

    same = auth.CockpitOAuthProvider(store, "x", token_policy="eski-xxx")
    assert await same.load_access_token(tokens.access_token) is not None

    changed = auth.CockpitOAuthProvider(store, "x", token_policy="yeni-xxx")
    assert await changed.load_access_token(tokens.access_token) is None
    assert changed.refresh_tokens == {}
    # Kalıcı olarak da silinmiş olmalı
    reloaded = auth.CockpitOAuthProvider(store, "x", token_policy="yeni-xxx")
    assert await reloaded.load_access_token(tokens.access_token) is None
