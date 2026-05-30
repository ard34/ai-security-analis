from __future__ import annotations

from typing import Any
from urllib.parse import urljoin, urlparse
import re
import xml.etree.ElementTree as ET

from core.http_client import SafeHTTPRequest, is_redirect_in_scope, normalize_url, perform_safe_http_request
from core.modules import BaseReconModule, ModuleContext, ModuleResult


SENSITIVE_PATH_HINTS = ("admin", "backup", "debug", "staging", "internal")


class RobotsSitemapModule(BaseReconModule):
    name = "robots_sitemap"
    description = "Fetches robots.txt and sitemap.xml through SafeHTTPClient and extracts potential endpoints."
    required_policy_flags = ("allow_network",)

    def run(self, context: ModuleContext) -> ModuleResult:
        allow_network = bool(context.policy.get("allow_network", False))
        if not allow_network:
            return ModuleResult(module_name=self.name, status="skipped", errors=["Network access is disabled by policy."])

        base_url = normalize_url(str(context.metadata.get("base_url") or f"https://{context.normalized_target}"))
        opener = context.metadata.get("http_opener")
        endpoints: list[str] = []
        evidence: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        errors: list[str] = []
        requests = [urljoin(base_url, "/robots.txt"), urljoin(base_url, "/sitemap.xml")]

        for url in requests[:2]:
            response = perform_safe_http_request(
                SafeHTTPRequest(
                    method="GET",
                    url=url,
                    allowed_domains=context.allowed_domains,
                    allowed_ips=context.allowed_ips,
                    scan_id=context.scan_id,
                    scan_mode=context.scan_mode,
                    max_body_bytes=262144,
                ),
                allow_network=allow_network,
                opener=opener,
            )
            if response.error:
                errors.append(response.error)
                continue
            if url.endswith("/robots.txt"):
                endpoints.extend(parse_robots_txt(response.body_sample))
            elif url.endswith("/sitemap.xml"):
                endpoints.extend(parse_sitemap_xml(response.body_sample, context.allowed_domains, context.allowed_ips))

        endpoints = sorted(set(endpoints))
        for path in endpoints:
            if is_sensitive_path_hint(path):
                findings.append(_finding(context, path))
        evidence.append(
            {
                "type": "robots_sitemap",
                "robots_found": any(path == "/robots.txt" for path in [urlparse(item).path for item in requests]),
                "sitemap_found": any(path == "/sitemap.xml" for path in [urlparse(item).path for item in requests]),
                "endpoint_count": len(endpoints),
            }
        )
        return ModuleResult(
            module_name=self.name,
            status="success" if endpoints or not errors else "failed",
            endpoints=endpoints,
            findings=findings,
            evidence=evidence,
            errors=errors,
            metadata={"requests_attempted": len(requests[:2])},
        )


def parse_robots_txt(text: str) -> list[str]:
    paths: set[str] = set()
    for raw_line in str(text or "").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key.strip().lower() not in {"allow", "disallow"}:
            continue
        path = value.strip()
        if path and path.startswith("/"):
            paths.add(path)
    return sorted(paths)


def parse_sitemap_xml(text: str, allowed_domains: list[str], allowed_ips: list[str] | None = None) -> list[str]:
    paths: set[str] = set()
    try:
        root = ET.fromstring(str(text or ""))
        loc_values = [element.text or "" for element in root.iter() if element.tag.rsplit("}", 1)[-1].lower() == "loc"]
    except ET.ParseError:
        loc_values = re.findall(r"<loc>\s*([^<]+)\s*</loc>", str(text or ""), flags=re.IGNORECASE)
    for loc in loc_values:
        raw = loc.strip()
        if not raw:
            continue
        try:
            if raw.startswith("http://") or raw.startswith("https://"):
                if not is_redirect_in_scope(raw, allowed_domains, allowed_ips):
                    continue
                parsed = urlparse(raw)
                path = parsed.path or "/"
            else:
                path = raw
            if path.startswith("/"):
                paths.add(path)
        except ValueError:
            continue
    return sorted(paths)


def is_sensitive_path_hint(path: str) -> bool:
    value = str(path or "").lower()
    return any(hint in value for hint in SENSITIVE_PATH_HINTS)


def _finding(context: ModuleContext, path: str) -> dict[str, Any]:
    return {
        "target": context.normalized_target,
        "asset": f"https://{context.normalized_target}",
        "endpoint": path,
        "module": RobotsSitemapModule.name,
        "finding_type": "sensitive_path_hint",
        "title": "Sensitive-looking path listed in robots.txt or sitemap.xml",
        "severity": "info",
        "confidence": "low",
        "evidence": f"Path listed for manual review: {path}",
        "recommendation": "Review whether the listed path exposes sensitive functionality or metadata within authorized scope.",
        "source": "robots_sitemap",
        "is_potential": True,
    }
