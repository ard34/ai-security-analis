from cli import main


def test_cli_scan_source(tmp_path, capsys):
    (tmp_path / "app.py").write_text("@app.get('/x')\n", encoding="utf-8")
    assert main(["scan-source", "--path", str(tmp_path)]) == 0
    assert "scan_" in capsys.readouterr().out

