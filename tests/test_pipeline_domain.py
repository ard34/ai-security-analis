from core.assessment import Assessment
from core.pipeline_domain import run_domain_assessment
from core.policies import DomainRunPolicy


def test_domain_pipeline_uses_gated_modules(monkeypatch, tmp_path):
    class FakeEngine:
        def __init__(self, policy, assessment_approved, audit):
            self.policy = policy
            self.assessment_approved = assessment_approved
            self.audit = audit

    monkeypatch.setattr("core.pipeline_domain.ExecutionEngine", FakeEngine)
    monkeypatch.setattr("core.pipeline_domain.resolve_a_aaaa", lambda host, engine: {"A": ["93.184.216.34"], "AAAA": []})
    monkeypatch.setattr("core.pipeline_domain.fetch_security_headers", lambda url, engine: {"headers": {"server": "x"}, "status": 200})
    monkeypatch.setattr("core.pipeline_domain.fingerprint_http", lambda url, engine: {"status": 200})
    monkeypatch.setattr("core.pipeline_domain.fetch_robots_and_sitemap", lambda url, engine: {})
    assessment = Assessment("a", ["example.com"]).approve()
    policy = DomainRunPolicy(True, True, True, audit_log_path=str(tmp_path / "audit.jsonl"))
    result = run_domain_assessment("example.com", assessment, policy)
    assert result.workflow == "type2_domain"
    assert all(f.is_potential for f in result.findings)

