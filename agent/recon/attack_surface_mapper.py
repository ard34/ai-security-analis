from __future__ import annotations

from agent.report.json_writer import read_json, write_json


def _endpoints_for(items: list[dict[str, object]], labels: set[str], terms: tuple[str, ...] = ()) -> list[dict[str, object]]:
    return [item for item in items if str(item.get("category", "")) in labels or any(term in str(item.get("url", "")).lower() for term in terms)]


def _card(category: str, assets: list[object], endpoints: list[object], technology: list[object], risk_hints: list[str], checks: list[str]) -> dict[str, object]:
    return {
        "category": category,
        "assets": assets,
        "endpoints": endpoints,
        "technology": technology,
        "risk_hints": risk_hints,
        "recommended_manual_checks": checks,
    }


def build_attack_surface(output_path: str = "outputs/recon/attack_surface.json") -> list[dict[str, object]]:
    live_hosts = read_json("outputs/recon/live_hosts.json", default=[]) or []
    ports = read_json("outputs/recon/open_ports.json", default=[]) or []
    services = read_json("outputs/recon/services.json", default=[]) or []
    technologies = read_json("outputs/recon/technologies.json", default=[]) or []
    endpoints = read_json("outputs/recon/important_endpoints.json", default=[]) or []
    headers = read_json("outputs/recon/security_headers.json", default=[]) or []
    external = read_json("outputs/external_dependencies.json", default=[]) or []

    surface = [
        _card("Public Web Assets", live_hosts, endpoints, technologies, ["Internet-facing web services identified."], ["Review exposed host purpose, ownership, and expected access paths."]),
        _card("API Assets", live_hosts, _endpoints_for(endpoints, {"api"}, ("/api/",)), technologies, ["API endpoints may expose object and authorization boundaries."], ["Validate authentication, object authorization, rate limits, and schema validation manually."]),
        _card("Authentication Surfaces", live_hosts, _endpoints_for(endpoints, {"auth", "register"}, ("login", "signin", "register", "reset")), [], ["Authentication and account recovery flows require manual review."], ["Validate session, CSRF, reset, registration, lockout, and MFA behavior safely."]),
        _card("Admin-like Surfaces", live_hosts, _endpoints_for(endpoints, {"admin-like"}, ("admin", "manage", "role")), [], ["Admin-like paths may indicate authorization boundaries."], ["Verify role restrictions with approved low-privilege test accounts."]),
        _card("File Upload/Download Surfaces", live_hosts, _endpoints_for(endpoints, {"file-upload", "file-download"}, ("upload", "download", "export")), [], ["File handling can create access-control or content validation risk."], ["Use only benign test files and authorized records."]),
        _card("Search/Input Surfaces", live_hosts, _endpoints_for(endpoints, {"search"}, ("search", "query", "filter", "q=")), [], ["Input surfaces may need validation and output encoding review."], ["Use benign strings only; avoid aggressive payloads."]),
        _card("Payment/Order/Business Surfaces", live_hosts, _endpoints_for(endpoints, {"order", "invoice", "payment"}, ("order", "invoice", "payment", "checkout")), [], ["Business workflow endpoints may require logic validation."], ["Validate server-side authorization and state transitions in staging or approved lab flows."]),
        _card("Exposed Services", [item.get("host") for item in ports], services, [], ["Open services expand the perimeter."], ["Confirm each service is expected, patched, and access-controlled."]),
        _card("Misconfiguration Indicators", live_hosts, headers, [], ["Security header or cookie gaps are potential hardening items."], ["Validate headers in browser context and confirm intended policy."]),
        _card("Third-party / External Dependencies Observed", external, [], [], ["External resources were observed but not scanned deeply."], ["Review supplier inventory and CSP/allowlist policy; do not scan third parties without authorization."]),
    ]
    write_json(output_path, surface)
    return surface
