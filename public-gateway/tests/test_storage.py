import main


def test_load_servers_missing_file_returns_empty(servers_file):
    assert main.load_servers() == {}


def test_save_and_load_roundtrip(servers_file, sample_server):
    main.save_servers(sample_server)
    assert main.load_servers() == sample_server


def test_load_servers_corrupt_json_returns_empty(servers_file):
    servers_file({})
    with open(main.SERVERS_FILE, "w") as f:
        f.write("{bozuk json")
    assert main.load_servers() == {}
