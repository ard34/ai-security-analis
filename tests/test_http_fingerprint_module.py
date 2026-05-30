from __future__ import annotations

import inspect
import os
import socket
import subprocess

from core.modules import ModuleContext, validate_module_result
from modules.http_fingerprint import HTTPFingerprintModule, sanitize_fingerprint_headers


class FakeHTTPResponse:
    def __init__(self, status=200, headers=None, body=b"", url="https://example.com"):
        self.status = status
        self.headers = headers or {}
        self._body = body
        self.url = url

    def read(self, n=-1):
        return self._body if n == -1 else self._body[:n]

    def geturl(self):
        return self.url


class FakeOpener:
    def __init__(self, response):
        self.response = response
        self.requests = []

    def open(self, request, timeout=None):
        self.requests.append((request, timeout))
        return self.response


def make_context(**overrides) -> ModuleContext:
    headers = {"Server": "nginx", "X-Powered-By": "PHP", "Content-Type": "text/html"}
    payload = {
        "scan_id": "scan-001",
        "target": "example.com",
        "normalized_target": "example.com",
        "allowed_domains": ["example.com"],
        "allowed_ips": [],
        "scan_mode": "safe",
        "policy": {"allow_network": True, "allow_exploit": False, "allow_bruteforce": False, "allow_zap_active": False},
        "metadata": {"http_opener": FakeOpener(FakeHTTPResponse(headers=headers))},
    }
    payload.update(overrides)
    return ModuleContext(**payload)


def test_module_name() -> None:
    assert HTTPFingerprintModule.name == "http_fingerprint"


def test_sanitize_captures_server() -> None:
    assert sanitize_fingerprint_headers({"Server": "nginx"})["server"] == "nginx"


def test_sanitize_captures_x_powered_by() -> None:
    assert sanitize_fingerprint_headers({"X-Powered-By": "PHP"})["x_powered_by"] == "PHP"


def test_sanitize_captures_content_type() -> None:
    assert sanitize_fingerprint_headers({"Content-Type": "text/html"})["content_type"] == "text/html"


def test_sanitize_captures_hsts_presence() -> None:
    assert sanitize_fingerprint_headers({"Strict-Transport-Security": "max-age=1"})["strict_transport_security_present"] is True


def test_sanitize_captures_csp_presence() -> None:
    assert sanitize_fingerprint_headers({"Content-Security-Policy": "default-src 'self'"})["content_security_policy_present"] is True


def test_sanitize_redacts_cookie() -> None:
    assert "cookie" not in sanitize_fingerprint_headers({"Cookie": "session=abc"})


def test_sanitize_set_cookie_presence_no_value() -> None:
    result = sanitize_fingerprint_headers({"Set-Cookie": "session=abc"})

    assert result["set_cookie_present"] is True
    assert "session=abc" not in str(result)


def test_sanitize_does_not_mutate_input() -> None:
    headers = {"Cookie": "session=abc"}

    sanitize_fingerprint_headers(headers)

    assert headers == {"Cookie": "session=abc"}


def test_network_disabled_returns_skipped() -> None:
    assert HTTPFingerprintModule().run(make_context(policy={"allow_network": False})).status == "skipped"


def test_fake_http_response_returns_fingerprint_evidence() -> None:
    result = HTTPFingerprintModule().run(make_context())

    assert result.evidence[0]["fingerprint"]["server"] == "nginx"


def test_server_banner_finding_generated() -> None:
    titles = {finding["title"] for finding in HTTPFingerprintModule().run(make_context()).findings}

    assert "Server banner exposed" in titles


def test_x_powered_by_finding_generated() -> None:
    titles = {finding["title"] for finding in HTTPFingerprintModule().run(make_context()).findings}

    assert "X-Powered-By header exposed" in titles


def test_findings_are_potential() -> None:
    assert all(item["is_potential"] is True for item in HTTPFingerprintModule().run(make_context()).findings)


def test_commands_executed_empty() -> None:
    assert HTTPFingerprintModule().run(make_context()).commands_executed == []


def test_module_result_validates() -> None:
    validate_module_result(HTTPFingerprintModule().run(make_context()))


def test_no_subprocess(monkeypatch) -> None:
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("no subprocess")))

    assert HTTPFingerprintModule().run(make_context()).commands_executed == []


def test_no_os_system(monkeypatch) -> None:
    monkeypatch.setattr(os, "system", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("no os.system")))

    assert HTTPFingerprintModule().run(make_context()).commands_executed == []


def test_no_eval_exec_pickle() -> None:
    source = inspect.getsource(__import__("modules.http_fingerprint").http_fingerprint)

    assert "eval(" not in source
    assert "exec(" not in source
    assert "pickle" not in source


def test_no_real_network(monkeypatch) -> None:
    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("no network")))

    assert HTTPFingerprintModule().run(make_context()).status == "success"
