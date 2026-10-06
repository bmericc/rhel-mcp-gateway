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
