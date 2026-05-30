from __future__ import annotations

import inspect
import os
import socket
import subprocess

import pytest

import core.dns_resolver as dns_resolver_module
from core.dns_resolver import (
    SafeDNSQuery,
    normalize_dns_name,
    perform_safe_dns_query,
    resolve_a_aaaa_with_socket,
    validate_dns_record_type,
)


def fake_getaddrinfo(name, port, family=0, type=0, proto=0, flags=0):
    value = "2001:db8::1" if family == socket.AF_INET6 else "93.184.216.34"
    return [
        (family, type, proto, "", (value, 0)),
        (family, type, proto, "", (value, 0)),
    ]


class CountingResolver:
    def __init__(self):
        self.calls = []

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return fake_getaddrinfo(*args, **kwargs)


def make_query(**overrides) -> SafeDNSQuery:
    payload = {"name": "example.com", "record_type": "A", "allowed_domains": ["example.com"]}
    payload.update(overrides)
    return SafeDNSQuery(**payload)


def test_normalize_dns_name_lowercase() -> None:
    assert normalize_dns_name("Example.COM") == "example.com"


def test_normalize_dns_name_remove_trailing_dot() -> None:
    assert normalize_dns_name("example.com.") == "example.com"


def test_normalize_dns_name_reject_empty() -> None:
    with pytest.raises(ValueError):
        normalize_dns_name("")


def test_normalize_dns_name_reject_path_traversal() -> None:
    with pytest.raises(ValueError):
        normalize_dns_name("../evil.com")


def test_validate_dns_record_type_accepts_a() -> None:
    assert validate_dns_record_type("a") == "A"


def test_validate_dns_record_type_accepts_aaaa() -> None:
    assert validate_dns_record_type("aaaa") == "AAAA"


def test_validate_dns_record_type_accepts_mx() -> None:
    assert validate_dns_record_type("mx") == "MX"


def test_validate_dns_record_type_rejects_invalid() -> None:
    with pytest.raises(ValueError):
        validate_dns_record_type("AXFR")


def test_perform_safe_dns_query_blocks_network_by_default(monkeypatch) -> None:
    def fail_getaddrinfo(*args, **kwargs):
        raise AssertionError("Real DNS resolution is not allowed by default")

    monkeypatch.setattr(socket, "getaddrinfo", fail_getaddrinfo)

    result = perform_safe_dns_query(make_query())

    assert result.error


def test_blocked_dns_result_has_empty_commands() -> None:
    result = perform_safe_dns_query(make_query())

    assert result.commands_executed == []


def test_out_of_scope_domain_blocked_before_resolver_called() -> None:
    resolver = CountingResolver()
    result = perform_safe_dns_query(make_query(name="evil.com"), allow_network=True, resolver=resolver)

    assert result.error
    assert resolver.calls == []


def test_lookalike_domain_blocked() -> None:
    resolver = CountingResolver()
    result = perform_safe_dns_query(make_query(name="example.com.evil.com"), allow_network=True, resolver=resolver)

    assert result.error
    assert resolver.calls == []


def test_localhost_blocked_by_default() -> None:
    resolver = CountingResolver()
    result = perform_safe_dns_query(make_query(name="localhost", allowed_domains=["localhost"]), allow_network=True, resolver=resolver)

    assert result.error
    assert resolver.calls == []


def test_authorized_a_query_allow_network_uses_mocked_resolver() -> None:
    resolver = CountingResolver()
    result = perform_safe_dns_query(make_query(record_type="A"), allow_network=True, resolver=resolver)

    assert result.error is None
    assert result.records[0]["type"] == "A"
    assert resolver.calls


def test_authorized_aaaa_query_allow_network_uses_mocked_resolver() -> None:
    resolver = CountingResolver()
    result = perform_safe_dns_query(make_query(record_type="AAAA"), allow_network=True, resolver=resolver)

    assert result.error is None
    assert result.records[0]["type"] == "AAAA"
    assert resolver.calls


def test_unsupported_mx_returns_safe_error() -> None:
    resolver = CountingResolver()
    result = perform_safe_dns_query(make_query(record_type="MX"), allow_network=True, resolver=resolver)

    assert result.error == "Record type is not supported by the standard-library resolver in this stage."
    assert resolver.calls == []


def test_resolver_deduplicates_records() -> None:
    records = resolve_a_aaaa_with_socket("example.com", "A", resolver=fake_getaddrinfo)

    assert len(records) == 1


def test_result_includes_audit_events() -> None:
    result = perform_safe_dns_query(make_query())

    assert result.audit_events


def test_dns_resolver_does_not_bruteforce_subdomains() -> None:
    resolver = CountingResolver()
    perform_safe_dns_query(make_query(), allow_network=True, resolver=resolver)

    assert len(resolver.calls) == 1
    assert resolver.calls[0][0][0] == "example.com"


def test_dns_resolver_does_not_use_subprocess(monkeypatch) -> None:
    def fail_run(*args, **kwargs):
        raise AssertionError("subprocess is not allowed in Safe DNS Resolver")

    monkeypatch.setattr(subprocess, "run", fail_run)

    result = perform_safe_dns_query(make_query())

    assert result.commands_executed == []


def test_dns_resolver_does_not_use_os_system(monkeypatch) -> None:
    def fail_system(*args, **kwargs):
        raise AssertionError("os.system is not allowed in Safe DNS Resolver")

    monkeypatch.setattr(os, "system", fail_system)

    result = perform_safe_dns_query(make_query())

    assert result.commands_executed == []


def test_dns_resolver_source_does_not_use_eval() -> None:
    assert "eval(" not in inspect.getsource(dns_resolver_module)


def test_dns_resolver_source_does_not_use_exec() -> None:
    assert "exec(" not in inspect.getsource(dns_resolver_module)


def test_dns_resolver_source_does_not_use_pickle() -> None:
    assert "pickle" not in inspect.getsource(dns_resolver_module)


def test_unit_tests_do_not_perform_real_dns_query(monkeypatch) -> None:
    def fail_getaddrinfo(*args, **kwargs):
        raise AssertionError("Real DNS query is not allowed")

    monkeypatch.setattr(socket, "getaddrinfo", fail_getaddrinfo)

    result = perform_safe_dns_query(make_query(), allow_network=False)

    assert result.error
