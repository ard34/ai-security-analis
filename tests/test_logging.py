from core.logging import AuditLogger, read_audit_log


def test_audit_log_jsonl_redacts_sensitive_fields(tmp_path):
    path = tmp_path / "audit.jsonl"
    AuditLogger(path).event("test", Authorization="Bearer secret", target="example.com")
    events = read_audit_log(path)
    assert events[0]["Authorization"] == "[REDACTED]"
    assert events[0]["target"] == "example.com"

