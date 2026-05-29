from __future__ import annotations

import pytest

from core.scope import validate_scope


ALLOWED = ["example.com"]


def test_exact_domain_allowed() -> None:
    result = validate_scope("example.com", allowed_domains=ALLOWED)
    assert result.allowed
    assert result.normalized_target == "example.com"


def test_valid_subdomain_allowed() -> None:
    assert validate_scope("api.example.com", allowed_domains=ALLOWED).allowed


def test_deep_subdomain_allowed() -> None:
    assert validate_scope("v1.api.example.com", allowed_domains=ALLOWED).allowed


@pytest.mark.parametrize("target", ["evil.com", "example.com.evil.com", "fakeexample.com"])
def test_unrelated_and_lookalike_domains_blocked(target: str) -> None:
    result = validate_scope(target, allowed_domains=ALLOWED)
    assert not result.allowed


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("https://api.example.com/login?next=/", "api.example.com"),
        ("http://example.com/path?q=1", "example.com"),
        ("EXAMPLE.COM.", "example.com"),
    ],
)
def test_url_input_normalized_before_validation(target: str, expected: str) -> None:
    result = validate_scope(target, allowed_domains=ALLOWED)
    assert result.allowed
    assert result.normalized_target == expected


@pytest.mark.parametrize("target", ["localhost", "http://localhost:8000"])
def test_localhost_blocked(target: str) -> None:
    assert not validate_scope(target, allowed_domains=ALLOWED).allowed


@pytest.mark.parametrize("target", ["127.0.0.1", "10.0.0.1", "192.168.1.10", "172.16.0.5"])
def test_private_and_loopback_ip_blocked_by_default(target: str) -> None:
    assert not validate_scope(target, allowed_domains=ALLOWED).allowed


def test_public_ip_blocked_if_not_explicitly_allowed() -> None:
    result = validate_scope("8.8.8.8", allowed_domains=ALLOWED)
    assert not result.allowed


def test_explicitly_allowed_public_ip_accepted() -> None:
    result = validate_scope("8.8.8.8", allowed_domains=ALLOWED, allowed_ips=["8.8.8.8"])
    assert result.allowed


def test_explicitly_allowed_private_ip_accepted() -> None:
    result = validate_scope("10.0.0.10", allowed_domains=ALLOWED, allowed_ips=["10.0.0.10"])
    assert result.allowed


@pytest.mark.parametrize("target", ["", "http://", "bad host.com", "http://exa mple.com"])
def test_malformed_or_empty_input_rejected_safely(target: str) -> None:
    result = validate_scope(target, allowed_domains=ALLOWED)
    assert not result.allowed
    assert result.normalized_target is None


def test_denied_pattern_blocks_target() -> None:
    result = validate_scope("admin.example.com", allowed_domains=ALLOWED, denied_patterns=[r"^admin\."])
    assert not result.allowed
    assert "denied pattern" in result.reason
