from __future__ import annotations

import inspect
import os
import socket
import subprocess

from core.modules import ModuleContext, validate_module_result
from modules.live_headers import LiveSecurityHeadersModule


class FakeHTTPResponse:
    def __init__(self, status=200, headers=None, body=b"", url="https://example.com"):
        self.status = status
        self.headers = headers or {"Content-Type": "text/html", "Cookie": "secret", "Set-Cookie": "session=abc"}
        self._body = body
        self.url = url

    def read(self, n=-1):
        return self._body if n == -1 else self._body[:n]

    def geturl(self):
        return self.url


class FakeOpener:
    def __init__(self, response=None):
        self.response = response or FakeHTTPResponse()
        self.requests = []

    def open(self, request, timeout=None):
        self.requests.append((request, timeout))
        return self.response


def make_context(**overrides) -> ModuleContext:
    payload = {
        "scan_id": "scan-001",
        "target": "example.com",
        "normalized_target": "example.com",
        "allowed_domains": ["example.com"],
        "allowed_ips": [],
        "scan_mode": "safe",
        "policy": {"allow_network": True, "allow_exploit": False, "allow_bruteforce": False, "allow_zap_active": False},
        "metadata": {"http_opener": FakeOpener()},
    }
    payload.update(overrides)
    return ModuleContext(**payload)


def test_module_name() -> None:
    assert LiveSecurityHeadersModule.name == "live_security_headers"


def test_required_policy_flag() -> None:
    assert LiveSecurityHeadersModule.required_policy_flags == ("allow_network",)


def test_network_disabled_returns_skipped() -> None:
    assert LiveSecurityHeadersModule().run(make_context(policy={"allow_network": False})).status == "skipped"


def test_authorized_fake_http_response_returns_success() -> None:
    assert LiveSecurityHeadersModule().run(make_context()).status == "success"


def test_headers_analyzer_generates_findings() -> None:
    assert LiveSecurityHeadersModule().run(make_context()).findings


def test_missing_csp_finding_appears() -> None:
    titles = {finding["title"] for finding in LiveSecurityHeadersModule().run(make_context()).findings}

    assert "Missing Content-Security-Policy Header" in titles


def test_sensitive_headers_not_stored_in_evidence() -> None:
    evidence = str(LiveSecurityHeadersModule().run(make_context()).evidence)

    assert "Cookie" not in evidence
    assert "Set-Cookie" not in evidence
    assert "session=abc" not in evidence


def test_out_of_scope_url_blocked() -> None:
    result = LiveSecurityHeadersModule().run(make_context(metadata={"url": "https://evil.com", "http_opener": FakeOpener()}))

    assert result.status == "failed"


def test_commands_executed_empty() -> None:
    assert LiveSecurityHeadersModule().run(make_context()).commands_executed == []


def test_audit_events_present() -> None:
    assert LiveSecurityHeadersModule().run(make_context()).metadata["audit_events"]


def test_module_result_validates() -> None:
    validate_module_result(LiveSecurityHeadersModule().run(make_context()))


def test_no_subprocess(monkeypatch) -> None:
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("no subprocess")))

    assert LiveSecurityHeadersModule().run(make_context()).commands_executed == []


def test_no_os_system(monkeypatch) -> None:
    monkeypatch.setattr(os, "system", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("no os.system")))

    assert LiveSecurityHeadersModule().run(make_context()).commands_executed == []


def test_no_eval_exec_pickle() -> None:
    source = inspect.getsource(__import__("modules.live_headers").live_headers)

    assert "eval(" not in source
    assert "exec(" not in source
    assert "pickle" not in source


def test_no_real_network(monkeypatch) -> None:
    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("no network")))

    assert LiveSecurityHeadersModule().run(make_context()).status == "success"
