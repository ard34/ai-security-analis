from modules.source_mapper import map_source_folder


def test_source_mapper_routes_and_smells(tmp_path):
    app = tmp_path / "app.py"
    app.write_text("@app.get('/health')\nDEBUG = True\n", encoding="utf-8")
    result = map_source_folder(tmp_path)
    assert result.routes[0]["path"] == "/health"
    assert result.security_smells


def test_source_mapper_skips_large_file(tmp_path):
    big = tmp_path / "big.py"
    big.write_text("x" * 20, encoding="utf-8")
    result = map_source_folder(tmp_path, max_file_bytes=10)
    assert result.skipped_large_files == 1

