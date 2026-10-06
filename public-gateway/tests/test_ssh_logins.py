import main


def test_parse_ssh_logins():
    assert main.parse_ssh_logins(" root:/root/.ssh , bmericc:/home/bmericc/.ssh,bozuk,:x") == [
        ("root", "/root/.ssh"),
        ("bmericc", "/home/bmericc/.ssh"),
    ]


def test_find_ssh_keys_only_existing_in_priority_order(tmp_path):
    (tmp_path / "id_rsa").write_text("k")
    (tmp_path / "id_ed25519").write_text("k")
    (tmp_path / "id_rsa.pub").write_text("pub")
    assert main.find_ssh_keys(str(tmp_path)) == [
        str(tmp_path / "id_ed25519"),
        str(tmp_path / "id_rsa"),
    ]


def test_find_ssh_keys_missing_dir():
    assert main.find_ssh_keys("/olmayan/klasor") == []

