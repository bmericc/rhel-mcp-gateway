"""Gerçek bir cockpit-ws'e karşı test. Ortam değişkenleri verilmezse atlanır:

COCKPIT_TEST_URL=http://127.0.0.1:9091 COCKPIT_TEST_USER=... COCKPIT_TEST_PASSWORD=... python -m pytest
"""
import os

import pytest

import cockpit_client

URL = os.getenv("COCKPIT_TEST_URL")
pytestmark = [
    pytest.mark.anyio,
    pytest.mark.skipif(not URL, reason="COCKPIT_TEST_URL tanımlı değil"),
]


def session(password=None):
    return cockpit_client.CockpitSession(URL, os.environ["COCKPIT_TEST_USER"], password or os.environ["COCKPIT_TEST_PASSWORD"])


async def test_spawn_and_exit_status():
    async with session() as s:
        ok = await s.spawn(["sh", "-c", "echo out; echo err >&2; exit 3"])
        missing = await s.spawn(["bu-komut-yok"])
    assert (ok.exit_status, ok.stdout, ok.stderr) == (3, "out\n", "err\n")
    assert "not-found" in missing.stderr


async def test_locale_is_c():
    async with session() as s:
        r = await s.spawn(["sh", "-c", "echo $LC_ALL"])
    assert r.stdout == "C\n"


async def test_superuser():
    async with session() as s:
        r = await s.spawn(["id", "-u"], superuser=True)
    # sudo yetkisi olan kullanıcıda root, olmayanda açıklayıcı hata
    assert r.stdout == "0\n" or "yönetici yetkisi alınamadı" in r.stderr


async def test_wrong_password():
    with pytest.raises(cockpit_client.CockpitError):
        await session(password="kesinlikle-yanlis").connect()
