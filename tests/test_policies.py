import pytest

from core.policies import (
    DomainRunPolicy,
    PolicyViolation,
    require_domain_run_policy,
    require_safe_http_method,
    sanitize_headers,
)


def test_safe_methods_only():
    assert require_safe_http_method("head") == "HEAD"
    with pytest.raises(PolicyViolation):
        require_safe_http_method("POST")


def test_domain_policy_requires_gates():
    with pytest.raises(PolicyViolation):
        require_domain_run_policy(DomainRunPolicy(), assessment_approved=True)


def test_sensitive_headers_removed():
    assert sanitize_headers({"Authorization": "Bearer x", "Server": "test"}) == {"Server": "test"}

