import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import main  # noqa: E402


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def servers_file(tmp_path, monkeypatch):
    """main.SERVERS_FILE'ı geçici bir dosyaya yönlendirir, yazıcı fonksiyon döner."""
    path = tmp_path / "data" / "servers.json"
    monkeypatch.setattr(main, "SERVERS_FILE", str(path))

    def write(servers):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(servers))

    return write


@pytest.fixture
def sample_server():
    return {
        "prod-db": {
            "name": "prod-db",
            "host": "10.0.0.5",
            "port": 2222,
            "user": "admin",
            "ssh_key_path": "/root/.ssh/id_rsa",
        }
    }


@pytest.fixture(autouse=True)
def ssh_dirs(tmp_path, monkeypatch):
    """SSH_LOGINS'i boş geçici klasörlere yönlendirir; gerçek ~/.ssh'a dokunulmaz.

    Dönen fonksiyon ilgili kullanıcının klasörüne sahte key dosyası ekler.
    """
    dirs = {"root": tmp_path / "root-ssh", "bmericc": tmp_path / "bmericc-ssh"}
    for d in dirs.values():
        d.mkdir()
    monkeypatch.setattr(main, "SSH_LOGINS", ",".join(f"{u}:{d}" for u, d in dirs.items()))

    def add_key(user, name="id_rsa"):
        path = dirs[user] / name
        path.write_text("fake key")
        return str(path)

    return add_key
