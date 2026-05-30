from __future__ import annotations

import inspect
import os
import socket
import subprocess

from core.modules import ModuleContext, validate_module_result
from modules.robots_sitemap import RobotsSitemapModule, is_sensitive_path_hint, parse_robots_txt, parse_sitemap_xml


class FakeHTTPResponse:
    def __init__(self, status=200, headers=None, body=b"", url="https://example.com"):
        self.status = status
        self.headers = headers or {"Content-Type": "text/plain"}
        self._body = body
        self.url = url

    def read(self, n=-1):
        return self._body if n == -1 else self._body[:n]

    def geturl(self):
        return self.url


class MultiResponseFakeOpener:
    def __init__(self, responses_by_url):
        self.responses_by_url = responses_by_url
        self.requests = []

    def open(self, request, timeout=None):
        self.requests.append((request, timeout))
        return self.responses_by_url[request.full_url]


def make_opener():
    return MultiResponseFakeOpener(
        {
            "https://example.com/robots.txt": FakeHTTPResponse(body=b"User-agent: *\nDisallow: /admin\nAllow: /public\n"),
            "https://example.com/sitemap.xml": FakeHTTPResponse(body=b"<urlset><url><loc>https://example.com/docs</loc></url></urlset>"),
        }
    )


def make_context(**overrides) -> ModuleContext:
    payload = {
        "scan_id": "scan-001",
        "target": "example.com",
        "normalized_target": "example.com",
        "allowed_domains": ["example.com"],
        "allowed_ips": [],
        "scan_mode": "safe",
        "policy": {"allow_network": True, "allow_exploit": False, "allow_bruteforce": False, "allow_zap_active": False},
        "metadata": {"http_opener": make_opener()},
    }
    payload.update(overrides)
    return ModuleContext(**payload)


def test_module_name() -> None:
    assert RobotsSitemapModule.name == "robots_sitemap"


def test_parse_robots_extracts_disallow() -> None:
    assert "/admin" in parse_robots_txt("Disallow: /admin")


def test_parse_robots_extracts_allow() -> None:
    assert "/public" in parse_robots_txt("Allow: /public")


def test_parse_robots_ignores_comments() -> None:
    assert parse_robots_txt("# comment\nDisallow: /admin # note") == ["/admin"]


def test_parse_sitemap_extracts_in_scope_paths() -> None:
    assert parse_sitemap_xml("<loc>https://example.com/docs</loc>", ["example.com"]) == ["/docs"]


def test_parse_sitemap_rejects_out_of_scope_urls() -> None:
    assert parse_sitemap_xml("<loc>https://evil.com/docs</loc>", ["example.com"]) == []


def test_parse_sitemap_invalid_xml_safely() -> None:
    assert parse_sitemap_xml("<broken>", ["example.com"]) == []


def test_sensitive_path_detects_admin() -> None:
    assert is_sensitive_path_hint("/admin")


def test_sensitive_path_detects_backup() -> None:
    assert is_sensitive_path_hint("/backup")


def test_sensitive_path_detects_debug() -> None:
    assert is_sensitive_path_hint("/debug")


def test_sensitive_path_does_not_flag_normal() -> None:
    assert not is_sensitive_path_hint("/about")


def test_network_disabled_returns_skipped() -> None:
    assert RobotsSitemapModule().run(make_context(policy={"allow_network": False})).status == "skipped"


def test_fake_robots_response_returns_endpoints() -> None:
    result = RobotsSitemapModule().run(make_context())

    assert "/admin" in result.endpoints
    assert "/public" in result.endpoints


def test_fake_sitemap_response_returns_endpoints() -> None:
    assert "/docs" in RobotsSitemapModule().run(make_context()).endpoints


def test_fetches_max_two_urls() -> None:
    opener = make_opener()
    RobotsSitemapModule().run(make_context(metadata={"http_opener": opener}))

    assert len(opener.requests) == 2


def test_does_not_fetch_discovered_endpoints() -> None:
    opener = make_opener()
    RobotsSitemapModule().run(make_context(metadata={"http_opener": opener}))

    assert {request.full_url for request, _ in opener.requests} == {"https://example.com/robots.txt", "https://example.com/sitemap.xml"}


def test_sensitive_path_finding_generated_potential() -> None:
    findings = RobotsSitemapModule().run(make_context()).findings

    assert findings
    assert findings[0]["is_potential"] is True


def test_commands_executed_empty() -> None:
    assert RobotsSitemapModule().run(make_context()).commands_executed == []


def test_module_result_validates() -> None:
    validate_module_result(RobotsSitemapModule().run(make_context()))


def test_no_subprocess(monkeypatch) -> None:
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("no subprocess")))

    assert RobotsSitemapModule().run(make_context()).commands_executed == []


def test_no_os_system(monkeypatch) -> None:
    monkeypatch.setattr(os, "system", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("no os.system")))

    assert RobotsSitemapModule().run(make_context()).commands_executed == []


def test_no_eval_exec_pickle() -> None:
    source = inspect.getsource(__import__("modules.robots_sitemap").robots_sitemap)

    assert "eval(" not in source
    assert "exec(" not in source
    assert "pickle" not in source


def test_no_real_network(monkeypatch) -> None:
    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("no network")))

    assert RobotsSitemapModule().run(make_context()).status == "success"
