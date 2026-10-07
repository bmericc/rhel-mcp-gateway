"""Web panelinden eklenen ortak SSH anahtarları ve sayfa başlıkları."""
import base64
import json

import asyncssh
import itsdangerous
import pytest
from fastapi.testclient import TestClient

import main
from creds import PASSWORD


@pytest.fixture
def client(monkeypatch, servers_file):
    monkeypatch.setattr(main.authenticator, "allowed_users", {"admin"})
    c = TestClient(main.app)
    data = base64.b64encode(json.dumps({"user": {"username": "admin"}}).encode())
    c.cookies.set("session", itsdangerous.TimestampSigner(main.SECRET_KEY).sign(data).decode())
    return c


def new_key():
    return asyncssh.generate_private_key("ssh-ed25519")


# --- Ortak SSH anahtarları ---

def test_generate_key(client, shared_keys_file):
    resp = client.post("/ssh-keys/generate", data={"name": "ortak"}, follow_redirects=False)
    assert "info=" in resp.headers["location"]
    entry = main.load_shared_keys()["ortak"]
    assert entry["type"] == "ssh-ed25519"
    assert entry["public"].startswith("ssh-ed25519 ")
    page = client.get("/").text
    assert entry["public"] in page
    assert entry["fingerprint"] in page
    # Özel anahtar ne sayfada ne dosyada açık hâliyle durur
    private_body = main.decrypt_secret(entry["private"]).splitlines()[1]
    assert private_body not in page
    assert private_body not in shared_keys_file.read_text()
    assert "PRIVATE KEY" not in shared_keys_file.read_text()
    assert oct(shared_keys_file.stat().st_mode & 0o777) == "0o600"


def test_paste_duplicate_name_rejected(client):
    client.post("/ssh-keys/generate", data={"name": "ortak"})
    before = main.load_shared_keys()["ortak"]["fingerprint"]
    resp = client.post("/ssh-keys", data={"name": "ortak", "private_key": new_key().export_private_key().decode()},
                       follow_redirects=False)
    assert "zaten var" in client.get(resp.headers["location"]).text
    assert main.load_shared_keys()["ortak"]["fingerprint"] == before


def test_generate_duplicate_name_rejected(client):
    client.post("/ssh-keys/generate", data={"name": "ortak"})
    resp = client.post("/ssh-keys/generate", data={"name": "ortak"}, follow_redirects=False)
    assert "zaten var" in client.get(resp.headers["location"]).text


def test_add_pasted_key(client):
    key = new_key()
    resp = client.post("/ssh-keys", data={"name": "yapistirilan", "private_key": key.export_private_key().decode()},
                       follow_redirects=False)
    assert "info=" in resp.headers["location"]
    assert main.load_shared_keys()["yapistirilan"]["fingerprint"] == key.get_fingerprint()


def test_add_passphrase_key(client):
    key = new_key()
    encrypted = key.export_private_key(passphrase=PASSWORD).decode()

    resp = client.post("/ssh-keys", data={"name": "parolali", "private_key": encrypted}, follow_redirects=False)
    assert "parolalı" in client.get(resp.headers["location"]).text

    resp = client.post("/ssh-keys", data={"name": "parolali", "private_key": encrypted, "passphrase": "yanlis-xxx"},
                       follow_redirects=False)
    assert "parolası hatalı" in client.get(resp.headers["location"]).text

    client.post("/ssh-keys", data={"name": "parolali", "private_key": encrypted, "passphrase": PASSWORD})
    # Kullanımda parola tekrar sorulmasın diye parolasız hâli (gateway anahtarıyla şifreli) saklanır
    assert [k.get_fingerprint() for k in main.shared_client_keys()] == [key.get_fingerprint()]


@pytest.mark.parametrize("private_key", ["çöp", None])
def test_add_invalid_key(client, private_key):
    text = new_key().export_public_key().decode() if private_key is None else private_key
    resp = client.post("/ssh-keys", data={"name": "kotu", "private_key": text}, follow_redirects=False)
    assert "Geçerli bir SSH özel anahtarı değil" in client.get(resp.headers["location"]).text
    assert main.load_shared_keys() == {}


def test_invalid_key_name(client):
    resp = client.post("/ssh-keys/generate", data={"name": "kötü ad"}, follow_redirects=False)
    assert "error=" in resp.headers["location"]
    assert main.load_shared_keys() == {}


def test_delete_key(client):
    client.post("/ssh-keys/generate", data={"name": "ortak"})
    client.post("/ssh-keys/ortak/delete")
    assert main.load_shared_keys() == {}


def test_key_routes_require_login(servers_file):
    c = TestClient(main.app)
    assert c.post("/ssh-keys/generate", data={"name": "x"}).status_code == 403
    assert c.post("/ssh-keys", data={"name": "x", "private_key": "x"}).status_code == 403
    assert c.post("/ssh-keys/x/delete").status_code == 403
    assert main.load_shared_keys() == {}


def test_shared_keys_used_for_ssh_login(client, monkeypatch, ssh_dirs):
    client.post("/ssh-keys/generate", data={"name": "ortak"})
    fingerprint = main.load_shared_keys()["ortak"]["fingerprint"]
    # .ssh klasörlerinde hiç anahtar yok; yalnızca ortak anahtar var
    candidates = main.login_candidates({"name": "s", "host": "h", "user": "deploy"})
    assert [u for u, _ in candidates] == ["deploy", "root", "bmericc"]
    for _, keys in candidates:
        assert [k.get_fingerprint() for k in keys] == [fingerprint]


def test_shared_keys_appended_after_user_keys(client, ssh_dirs):
    client.post("/ssh-keys/generate", data={"name": "ortak"})
    root_key = ssh_dirs("root")
    _, keys = main.login_candidates({"name": "s", "host": "h", "user": "root"})[0]
    assert keys[0] == root_key
    assert isinstance(keys[1], asyncssh.SSHKey)


def test_undecryptable_shared_key_is_skipped(client, shared_keys_file):
    client.post("/ssh-keys/generate", data={"name": "ortak"})
    data = json.loads(shared_keys_file.read_text())
    data["ortak"]["private"] = "bozuk"
    shared_keys_file.write_text(json.dumps(data))
    assert main.shared_client_keys() == []


# --- Sayfa başlıkları ---

def page_title(text):
    assert text.lstrip().startswith("<!doctype html>")
    start = text.index("<title>") + len("<title>")
    return text[start:text.index("</title>")]


def test_titles(client):
    assert page_title(client.get("/").text) == "Sunucular · RHEL MCP Gateway"
    anon = TestClient(main.app)
    assert page_title(anon.get("/login").text) == "RHEL MCP Gateway - Giriş · RHEL MCP Gateway"
    assert page_title(anon.post("/servers", data={}).text) == "Yetkiniz yok · RHEL MCP Gateway"
    assert page_title(anon.get("/oauth/login", params={"request": "yok"}).text) == "Giriş isteği geçersiz · RHEL MCP Gateway"
