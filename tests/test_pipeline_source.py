from core.pipeline_source import run_source_assessment


def test_source_pipeline_returns_potential_findings(tmp_path):
    (tmp_path / "app.py").write_text("@app.get('/x')\nSECRET_KEY = \"\"\n", encoding="utf-8")
    result = run_source_assessment(tmp_path)
    assert result.workflow == "type1_source"
    assert result.endpoints
    assert all(f.is_potential for f in result.findings)

