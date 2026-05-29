from __future__ import annotations

from agent.report.json_writer import read_json, write_json
from agent.standards.owasp_catalog import get_owasp_api_catalog, get_owasp_web_catalog


def _match(text: str, catalog: list[dict[str, object]]) -> dict[str, object] | None:
    lower = text.lower()
    for item in catalog:
        if any(str(sig).lower() in lower for sig in item.get("detection_signals", [])):
            return item
    return None


def map_findings(output_path: str = "outputs/owasp_mapping.json") -> list[dict[str, object]]:
    findings = []
    for path in ["outputs/potential_findings.json", "outputs/alerts.json", "outputs/zap/zap_passive_alerts.json", "outputs/zap/zap_active_alerts.json"]:
        data = read_json(path, default=[]) or []
        findings.extend(data if isinstance(data, list) else [])
    web = get_owasp_web_catalog()
    api = get_owasp_api_catalog()
    mapped = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        text = " ".join(str(finding.get(key, "")) for key in ["title", "type", "evidence", "reason", "url", "endpoint", "description"])
        web_item = _match(text, web) or {}
        api_item = _match(text, api) or {}
        mapped.append({
            "finding_id": finding.get("finding_id", ""),
            "title": finding.get("title") or finding.get("alert", ""),
            "owasp_web_id": web_item.get("id", ""),
            "owasp_web_name": web_item.get("name", ""),
            "owasp_api_id": api_item.get("id", ""),
            "owasp_api_name": api_item.get("name", ""),
            "reason_for_mapping": f"Mapping berdasarkan sinyal teks: {text[:160]}",
            "confidence": "Medium" if web_item or api_item else "Low",
            "manual_validation_required": True,
        })
    write_json(output_path, mapped)
    return mapped
