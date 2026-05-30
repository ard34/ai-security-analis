from __future__ import annotations

import inspect
import os
import socket
import subprocess

from core.modules import ModuleContext, validate_module_result
from modules.live_dns import LiveDNSModule


def fake_getaddrinfo(name, port, family=0, type=0, proto=0, flags=0):
    value = "2001:db8::1" if family == socket.AF_INET6 else "93.184.216.34"
    return [(family, type, proto, "", (value, 0))]


class CountingResolver:
    def __init__(self):
        self.calls = []

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return fake_getaddrinfo(*args, **kwargs)


def make_context(**overrides) -> ModuleContext:
    payload = {
        "scan_id": "scan-001",
        "target": "example.com",
        "normalized_target": "example.com",
        "allowed_domains": ["example.com"],
        "allowed_ips": [],
        "scan_mode": "safe",
        "policy": {"allow_network": True, "allow_exploit": False, "allow_bruteforce": False, "allow_zap_active": False},
        "metadata": {"dns_resolver": CountingResolver(), "dns_record_types": ["A"]},
    }
    payload.update(overrides)
    return ModuleContext(**payload)


def test_live_dns_module_name() -> None:
    assert LiveDNSModule.name == "live_dns"


def test_live_dns_required_policy_flag() -> None:
    assert LiveDNSModule.required_policy_flags == ("allow_network",)


def test_network_disabled_returns_skipped() -> None:
    result = LiveDNSModule().run(make_context(policy={"allow_network": False}))

    assert result.status == "skipped"


def test_authorized_a_query_with_fake_resolver_success() -> None:
    result = LiveDNSModule().run(make_context())

    assert result.status == "success"
    assert result.evidence[0]["records"][0]["type"] == "A"


def test_authorized_aaaa_query_with_fake_resolver_success() -> None:
    result = LiveDNSModule().run(make_context(metadata={"dns_resolver": CountingResolver(), "dns_record_types": ["AAAA"]}))

    assert result.status == "success"
    assert result.evidence[0]["records"][0]["type"] == "AAAA"


def test_out_of_scope_target_blocked() -> None:
    result = LiveDNSModule().run(make_context(normalized_target="evil.com"))

    assert result.errors


def test_unsupported_record_type_handled_safely() -> None:
    result = LiveDNSModule().run(make_context(metadata={"dns_resolver": CountingResolver(), "dns_record_types": ["AXFR"]}))

    assert result.status == "success"
    assert "Unsupported DNS record type" in result.findings[0]["title"]


def test_no_bruteforce_subdomains() -> None:
    resolver = CountingResolver()
    LiveDNSModule().run(make_context(metadata={"dns_resolver": resolver, "dns_record_types": ["A", "AAAA"]}))

    assert len(resolver.calls) == 2
    assert all(call[0][0] == "example.com" for call in resolver.calls)


def test_commands_executed_empty() -> None:
    assert LiveDNSModule().run(make_context()).commands_executed == []


def test_evidence_contains_dns_records() -> None:
    assert LiveDNSModule().run(make_context()).evidence[0]["records"]


def test_findings_are_potential() -> None:
    assert all(item["is_potential"] is True for item in LiveDNSModule().run(make_context()).findings)


def test_module_result_validates() -> None:
    validate_module_result(LiveDNSModule().run(make_context()))


def test_no_subprocess(monkeypatch) -> None:
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("no subprocess")))

    assert LiveDNSModule().run(make_context()).commands_executed == []


def test_no_os_system(monkeypatch) -> None:
    monkeypatch.setattr(os, "system", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("no os.system")))

    assert LiveDNSModule().run(make_context()).commands_executed == []


def test_no_eval_exec_pickle() -> None:
    source = inspect.getsource(__import__("modules.live_dns").live_dns)

    assert "eval(" not in source
    assert "exec(" not in source
    assert "pickle" not in source


def test_no_real_network(monkeypatch) -> None:
    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("no network")))
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("no DNS")))

    assert LiveDNSModule().run(make_context()).status == "success"
