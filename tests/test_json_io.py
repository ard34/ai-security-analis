from storage.json_io import read_json, write_json


def test_json_io_redacts_sensitive_keys(tmp_path):
    path = tmp_path / "x.json"
    write_json(path, {"token": "abc", "ok": "yes"})
    data = read_json(path)
    assert data["token"] == "[REDACTED]"
    assert data["ok"] == "yes"

