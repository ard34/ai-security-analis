from __future__ import annotations

from agent.report.json_writer import read_json, write_json
from agent.standards.owasp_catalog import get_owasp_api_catalog, get_owasp_web_catalog


def build_detection_coverage_matrix(output_path: str = "outputs/detection_coverage_matrix.json") -> list[dict[str, object]]:
    mappings = read_json("outputs/owasp_mapping.json", default=[]) or []
    findings_count = {}
    for item in mappings:
        for key in ["owasp_web_id", "owasp_api_id"]:
            cid = item.get(key) if isinstance(item, dict) else ""
            if cid:
                findings_count[cid] = findings_count.get(cid, 0) + 1
    rows = []
    module_map = {
        "A01": ["idor_bola_analyzer", "bfla_analyzer", "zap alerts"],
        "A06": ["technology_fingerprint", "cve_correlator", "nuclei_safe_scan"],
        "API1": ["api_top10_analyzer", "idor_bola_analyzer"],
        "API5": ["api_top10_analyzer", "bfla_analyzer"],
    }
    for item in get_owasp_web_catalog() + get_owasp_api_catalog():
        cid = str(item["id"])
        count = findings_count.get(cid, 0)
        rows.append({"owasp_category": f"{cid} {item['name']}", "detection_modules_used": module_map.get(cid, ["passive analyzers", "manual validation"]), "evidence_files": ["outputs/potential_findings.json", "outputs/recon/security_headers.json", "outputs/cve_correlations.json"], "status": "Covered" if count else "Partially Covered", "findings_count": count, "requires_manual_validation": True, "notes": "Coverage berbasis black box; validasi manual tetap diperlukan."})
    write_json(output_path, rows)
    return rows
