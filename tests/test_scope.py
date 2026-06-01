import pytest

from core.scope import Scope, ScopeError, validate_public_host


def test_scope_allows_domain_and_subdomain():
    scope = Scope(["example.com"])
    assert scope.contains("https://www.example.com/path")


def test_scope_rejects_private_and_lookalike():
    with pytest.raises(ScopeError):
        validate_public_host("127.0.0.1")
    with pytest.raises(ScopeError):
        validate_public_host("xn--example-9d0b.com")


def test_scope_rejects_out_of_scope():
    with pytest.raises(ScopeError):
        Scope(["example.com"]).require_in_scope("example.org")

