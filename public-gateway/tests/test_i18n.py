import ast
import pathlib
import string

import pytest
from fastapi.testclient import TestClient

import fleet_tools
import i18n
import main

SOURCE_DIR = pathlib.Path(__file__).resolve().parent.parent


@pytest.fixture
def turkish():
    token = i18n.set_language("tr")
    yield
    i18n.reset_language(token)


@pytest.mark.parametrize("header,expected", [
    (None, "en"),
    ("", "en"),
    ("tr", "tr"),
    ("tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7", "tr"),
    ("en-US,en;q=0.9,tr;q=0.8", "en"),
    ("de-DE,de;q=0.9", "en"),
    ("de,tr;q=0.5", "tr"),
    ("en;q=0.2,tr;q=0.7", "tr"),
    ("tr;q=0,en;q=0.1", "en"),
    ("tr;q=abc", "en"),
    ("*", "en"),
])
def test_pick_language(header, expected):
    assert i18n.pick_language(header) == expected


def test_default_language_is_english():
    assert i18n.get_language() == "en"
    assert i18n.t("Invalid host.") == "Invalid host."
    assert i18n.t("Unknown tool: {name}", name="x") == "Unknown tool: x"


def test_turkish_translation(turkish):
    assert i18n.t("Invalid host.") == "Geçersiz host."
    assert i18n.t("Unknown tool: {name}", name="x") == "Bilinmeyen araç: x"
    # Untranslated strings fall back to the English source
    assert i18n.t("not in the dictionary") == "not in the dictionary"


def test_unsupported_language_falls_back_to_default():
    token = i18n.set_language("de")
    try:
        assert i18n.get_language() == "en"
    finally:
        i18n.reset_language(token)


def source_strings():
    """String literals passed to t() / N() in the application code."""
    found = set()
    for path in SOURCE_DIR.glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
            first = node.args[0]
            if name in ("t", "N") and isinstance(first, ast.Constant) and isinstance(first.value, str):
                found.add(first.value)
    return found


def tool_strings():
    found = set()
    for spec in fleet_tools.TOOLS:
        found.add(spec.description)
        found.update(prop["description"] for prop in spec.properties.values() if "description" in prop)
    return found


def test_every_string_has_a_turkish_translation():
    strings = source_strings()
    assert len(strings) > 200
    assert sorted((strings | tool_strings()) - set(i18n.TR)) == []


def test_translations_keep_placeholders():
    fields = lambda text: sorted(name for _, name, _, _ in string.Formatter().parse(text) if name)
    assert [key for key, value in i18n.TR.items() if fields(key) != fields(value)] == []


def test_no_unused_translations():
    assert sorted(set(i18n.TR) - source_strings() - tool_strings()) == []


def test_login_page_follows_browser_language():
    client = TestClient(main.app)
    english = client.get("/login").text
    assert '<html lang="en">' in english and "Username" in english and "Log in" in english

    turkish = client.get("/login", headers={"Accept-Language": "tr-TR,tr;q=0.9,en;q=0.8"}).text
    assert '<html lang="tr">' in turkish and "Kullanıcı adı" in turkish and "Giriş yap" in turkish
    assert "Username" not in turkish

    # The language is per request: the next request without the header is English again
    assert '<html lang="en">' in client.get("/login", headers={"Accept-Language": "de"}).text


def test_login_error_follows_browser_language():
    client = TestClient(main.app)
    resp = client.post("/login", data={"username": "", "password": ""}, headers={"Accept-Language": "tr"})
    assert "Kullanıcı adı ve şifre gerekli." in resp.text
    resp = client.post("/login", data={"username": "", "password": ""})
    assert "Username and password are required." in resp.text


def test_tool_descriptions_are_translated(turkish):
    tool = fleet_tools.TOOLS_BY_NAME["service_action"].to_tool()
    assert tool.description.startswith("Bir systemd servisini başlatır")
    assert tool.inputSchema["properties"]["service"]["description"] == "Servis adı"
    assert tool.inputSchema["properties"]["server_name"]["description"] == "Kayıtlı sunucu adı"
    assert tool.inputSchema["properties"]["confirm"]["description"].startswith("İşlemi gerçekten uygulamak")


def test_tool_descriptions_default_to_english():
    tool = fleet_tools.TOOLS_BY_NAME["service_action"].to_tool()
    assert tool.description == "Starts, stops, restarts, reloads, enables or disables a systemd service."
    assert tool.inputSchema["properties"]["service"]["description"] == "Service name"
    # The spec itself is not mutated by translation
    assert fleet_tools.TOOLS_BY_NAME["service_action"].properties["service"]["description"] == "Service name"


def test_tool_errors_are_translated(turkish):
    with pytest.raises(fleet_tools.ToolInputError, match="Geçersiz servis adı: '-x'"):
        fleet_tools.validate_service("-x")


def test_panel_pages_follow_browser_language(monkeypatch, servers_file, sample_server):
    from test_web import login_as

    monkeypatch.setattr(main.authenticator, "allowed_users", {"admin"})
    servers_file(sample_server)
    client = TestClient(main.app)
    login_as(client, "admin")
    turkish = {"Accept-Language": "tr"}

    page = client.get("/").text
    for text in ("Registered Servers", "Add / Update Server", "Shared SSH Keys", "Not tested", "Log out",
                 "confirm('Delete prod-db?')"):
        assert text in page
    page = client.get("/", headers=turkish).text
    for text in ("Kayıtlı Sunucular", "Sunucu Ekle / Güncelle", "Ortak SSH Anahtarları", "Test edilmedi", "Çıkış Yap",
                 "confirm('prod-db silinsin mi?')"):
        assert text in page
    assert "Registered Servers" not in page

    assert "All statuses" in client.get("/logs").text
    page = client.get("/logs", headers=turkish).text
    assert "Tüm durumlar" in page and "İşlem kayıtları" in page

    resp = client.post("/servers", data={"name": "bad name", "host": "h"}, headers=turkish, follow_redirects=False)
    assert "Sunucu adı yalnızca harf" in client.get(resp.headers["location"], headers=turkish).text
