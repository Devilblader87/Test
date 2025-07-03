from app import app, save_servers


def test_get_server_returns_data(tmp_path):
    server_file = tmp_path / "servers.json"
    # patch server file location
    app.SERVER_FILE = str(server_file)

    servers = {"myserver": {"host": "127.0.0.1", "port": "27015", "password": "pw"}}
    save_servers(servers)

    with app.test_client() as client:
        resp = client.get("/get_server/myserver")
        assert resp.status_code == 200
        assert resp.get_json() == servers["myserver"]

