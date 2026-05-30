from __future__ import annotations

import inspect
import os
import socket
import subprocess

import pytest

import core.http_client as http_client_module
from core.http_client import (
    SafeHTTPRequest,
    extract_hostname,
    filter_sensitive_headers,
    is_redirect_in_scope,
    normalize_url,
    perform_safe_http_request,
    validate_http_method,
)


class FakeHTTPResponse:
    def __init__(self, status=200, headers=None, body=b"OK", url="https://example.com"):
        self.status = status
        self.headers = headers or {"Content-Type": "text/plain"}
        self._body = body
        self.url = url

    def read(self, n=-1):
        return self._body if n == -1 else self._body[:n]

    def geturl(self):
        return self.url


class FakeOpener:
    def __init__(self, responses):
        self.responses = list(responses if isinstance(responses, list) else [responses])
        self.requests = []

    def open(self, request, timeout=None):
        self.requests.append((request, timeout))
        if len(self.responses) > 1:
            return self.responses.pop(0)
        return self.responses[0]


def make_request(**overrides) -> SafeHTTPRequest:
    payload = {"method": "GET", "url": "https://example.com", "allowed_domains": ["example.com"]}
    payload.update(overrides)
    return SafeHTTPRequest(**payload)


def test_normalize_url_accepts_http_url() -> None:
    assert normalize_url("HTTP://Example.COM/path#frag") == "http://example.com/path"


def test_normalize_url_accepts_https_url() -> None:
    assert normalize_url(" https://Example.COM ") == "https://example.com/"


def test_normalize_url_rejects_invalid_scheme() -> None:
    with pytest.raises(ValueError):
        normalize_url("ftp://example.com")


def test_normalize_url_rejects_empty() -> None:
    with pytest.raises(ValueError):
        normalize_url("")


def test_extract_hostname_returns_lowercase() -> None:
    assert extract_hostname("https://Example.COM/path") == "example.com"


def test_validate_http_method_accepts_get() -> None:
    assert validate_http_method("get") == "GET"


def test_validate_http_method_accepts_head() -> None:
    assert validate_http_method("head") == "HEAD"


def test_validate_http_method_rejects_post() -> None:
    with pytest.raises(ValueError):
        validate_http_method("POST")


def test_validate_http_method_rejects_delete() -> None:
    with pytest.raises(ValueError):
        validate_http_method("DELETE")


def test_filter_sensitive_headers_removes_authorization() -> None:
    assert "Authorization" not in filter_sensitive_headers({"Authorization": "Bearer abc"})


def test_filter_sensitive_headers_removes_cookie() -> None:
    assert "Cookie" not in filter_sensitive_headers({"Cookie": "session=abc"})


def test_filter_sensitive_headers_removes_x_api_key() -> None:
    assert "X-API-Key" not in filter_sensitive_headers({"X-API-Key": "abc"})


def test_filter_sensitive_headers_does_not_mutate_input() -> None:
    headers = {"Authorization": "Bearer abc"}

    filter_sensitive_headers(headers)

    assert headers == {"Authorization": "Bearer abc"}


def test_filter_sensitive_headers_adds_user_agent() -> None:
    assert "User-Agent" in filter_sensitive_headers({})


def test_redirect_in_scope_accepts_in_scope_redirect() -> None:
    assert is_redirect_in_scope("https://app.example.com", ["example.com"]) is True


def test_redirect_in_scope_rejects_out_of_scope_redirect() -> None:
    assert is_redirect_in_scope("https://evil.com", ["example.com"]) is False


def test_perform_safe_http_request_blocks_network_by_default(monkeypatch) -> None:
    def fail_socket(*args, **kwargs):
        raise AssertionError("Real network access is not allowed in HTTP client tests")

    monkeypatch.setattr(socket, "socket", fail_socket)

    response = perform_safe_http_request(make_request())

    assert response.error


def test_blocked_response_has_empty_commands() -> None:
    response = perform_safe_http_request(make_request())

    assert response.commands_executed == []


def test_out_of_scope_url_blocked_before_opener_called() -> None:
    opener = FakeOpener(FakeHTTPResponse())
    response = perform_safe_http_request(make_request(url="https://evil.com"), allow_network=True, opener=opener)

    assert response.error
    assert opener.requests == []


def test_lookalike_domain_blocked() -> None:
    opener = FakeOpener(FakeHTTPResponse())
    response = perform_safe_http_request(make_request(url="https://example.com.evil.com"), allow_network=True, opener=opener)

    assert response.error
    assert opener.requests == []


def test_localhost_blocked_by_default() -> None:
    opener = FakeOpener(FakeHTTPResponse())
    response = perform_safe_http_request(make_request(url="http://localhost", allowed_domains=["localhost"]), allow_network=True, opener=opener)

    assert response.error
    assert opener.requests == []


def test_in_scope_get_allow_network_uses_mocked_opener() -> None:
    opener = FakeOpener(FakeHTTPResponse(body=b"OK"))
    response = perform_safe_http_request(make_request(method="GET"), allow_network=True, opener=opener)

    assert response.error is None
    assert response.body_sample == "OK"
    assert len(opener.requests) == 1


def test_in_scope_head_allow_network_uses_mocked_opener() -> None:
    opener = FakeOpener(FakeHTTPResponse(body=b"IGNORED"))
    response = perform_safe_http_request(make_request(method="HEAD"), allow_network=True, opener=opener)

    assert response.error is None
    assert response.body_sample == ""
    assert opener.requests[0][0].get_method() == "HEAD"


def test_sensitive_headers_are_not_sent_to_opener() -> None:
    opener = FakeOpener(FakeHTTPResponse())
    perform_safe_http_request(
        make_request(headers={"Authorization": "Bearer abc", "Cookie": "session=abc", "X-Test": "ok"}),
        allow_network=True,
        opener=opener,
    )
    sent_headers = {key.lower(): value for key, value in opener.requests[0][0].header_items()}

    assert "authorization" not in sent_headers
    assert "cookie" not in sent_headers
    assert sent_headers["x-test"] == "ok"


def test_body_sample_limited_to_max_body_bytes() -> None:
    opener = FakeOpener(FakeHTTPResponse(body=b"abcdef"))
    response = perform_safe_http_request(make_request(max_body_bytes=3), allow_network=True, opener=opener)

    assert response.body_sample == "abc"


def test_redirect_out_of_scope_blocked() -> None:
    opener = FakeOpener(FakeHTTPResponse(status=302, headers={"Location": "https://evil.com"}, body=b""))
    response = perform_safe_http_request(make_request(), allow_network=True, opener=opener)

    assert response.error == "Redirect target is outside authorized scope."


def test_redirect_max_count_enforced() -> None:
    opener = FakeOpener(
        [
            FakeHTTPResponse(status=302, headers={"Location": "https://example.com/1"}, body=b""),
            FakeHTTPResponse(status=302, headers={"Location": "https://example.com/2"}, body=b""),
        ]
    )
    response = perform_safe_http_request(make_request(max_redirects=0), allow_network=True, opener=opener)

    assert response.error == "Maximum redirects exceeded."


def test_response_includes_audit_events() -> None:
    response = perform_safe_http_request(make_request())

    assert response.audit_events


def test_response_includes_elapsed_ms() -> None:
    response = perform_safe_http_request(make_request())

    assert isinstance(response.elapsed_ms, int)


def test_http_client_does_not_use_subprocess(monkeypatch) -> None:
    def fail_run(*args, **kwargs):
        raise AssertionError("subprocess is not allowed in Safe HTTP Client")

    monkeypatch.setattr(subprocess, "run", fail_run)

    response = perform_safe_http_request(make_request())

    assert response.commands_executed == []


def test_http_client_does_not_use_os_system(monkeypatch) -> None:
    def fail_system(*args, **kwargs):
        raise AssertionError("os.system is not allowed in Safe HTTP Client")

    monkeypatch.setattr(os, "system", fail_system)

    response = perform_safe_http_request(make_request())

    assert response.commands_executed == []


def test_http_client_source_does_not_use_eval() -> None:
    assert "eval(" not in inspect.getsource(http_client_module)


def test_http_client_source_does_not_use_exec() -> None:
    assert "exec(" not in inspect.getsource(http_client_module)


def test_http_client_source_does_not_use_pickle() -> None:
    assert "pickle" not in inspect.getsource(http_client_module)


def test_unit_tests_do_not_perform_real_internet_request(monkeypatch) -> None:
    def fail_socket(*args, **kwargs):
        raise AssertionError("Real internet access is not allowed")

    monkeypatch.setattr(socket, "socket", fail_socket)

    response = perform_safe_http_request(make_request(), allow_network=False)

    assert response.error
