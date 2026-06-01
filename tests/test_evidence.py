from core.evidence import collect_local_evidence, read_text_limited


def test_collect_evidence_redacts_secret_like_values():
    evidence = collect_local_evidence("x", "token=abc123")
    assert "[REDACTED]" in evidence.content


def test_read_text_limited(tmp_path):
    path = tmp_path / "x.txt"
    path.write_text("abcdef", encoding="utf-8")
    assert read_text_limited(path, max_bytes=3) == "abc"

