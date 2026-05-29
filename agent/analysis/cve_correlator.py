from __future__ import annotations

from agent.integrations.cve_sources import query_nvd, query_osv
from agent.report.json_writer import read_json, write_json


def _severity(score: float) -> str:
    if score >= 9:
        return "Critical"
    if score >= 7:
        return "High"
    if score >= 4:
        return "Medium"
    if score > 0:
        return "Low"
    return "Unknown"


def _from_nvd(vuln: dict[str, object], product: dict[str, object]) -> dict[str, object]:
    cve = vuln.get("cve", {}) if isinstance(vuln.get("cve"), dict) else {}
    metrics = cve.get("metrics", {}) if isinstance(cve.get("metrics"), dict) else {}
    cvss = 0.0
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        values = metrics.get(key, []) if isinstance(metrics.get(key), list) else []
        if values:
            cvss = float(values[0].get("cvssData", {}).get("baseScore", 0) or 0)
            break
    descriptions = cve.get("descriptions", []) if isinstance(cve.get("descriptions"), list) else []
    description = descriptions[0].get("value", "") if descriptions else ""
    cve_id = str(cve.get("id", ""))
    refs = [ref.get("url", "") for ref in cve.get("references", {}).get("referenceData", [])] if isinstance(cve.get("references"), dict) else []
    return _item(cve_id, product, "NVD", cvss, description, refs, cve.get("published", ""), cve.get("lastModified", ""))


def _item(cve_id: str, product: dict[str, object], source: str, cvss: float, description: str, refs: list[str], published: str = "", modified: str = "") -> dict[str, object]:
    version = product.get("version")
    confidence = "High" if version else "Low"
    return {"cve_id": cve_id, "affected_asset": product.get("host") or product.get("url"), "affected_host": product.get("host", ""), "affected_url": product.get("url", ""), "detected_product": product.get("product"), "detected_version": version, "detected_vendor": product.get("vendor", ""), "source_of_detection": product.get("source", ""), "cve_source": source, "cvss_score": cvss, "severity": _severity(float(cvss or 0)), "published_date": published, "last_modified_date": modified, "description": description, "references": refs, "cwe": [], "cpe_match": "", "confidence": confidence, "status": "Potential CVE Correlation", "manual_validation_required": True, "validation_guidance": "Konfirmasi produk dan versi secara manual sebelum menyimpulkan rentan.", "remediation_guidance": "Upgrade atau patch sesuai advisory vendor jika korelasi tervalidasi.", "black_box_limitations": "Korelasi berdasarkan fingerprint black box; bukan bukti eksploitasi."}


def correlate_cves(config: dict[str, object] | None = None, output_path: str = "outputs/cve_correlations.json") -> list[dict[str, object]]:
    config = config or {}
    cve_cfg = config.get("cve", {}) if isinstance(config.get("cve"), dict) else {}
    if cve_cfg.get("enabled", True) is False:
        write_json(output_path, [])
        return []
    products = read_json("outputs/detected_products.json", default=[]) or []
    results = []
    for product in products:
        if not isinstance(product, dict) or not product.get("product"):
            continue
        nvd = query_nvd(str(product["product"]), product.get("version"), config)
        for vuln in nvd[: int((config.get("cve", {}) if isinstance(config.get("cve"), dict) else {}).get("max_results_per_product", 20))]:
            if isinstance(vuln, dict):
                results.append(_from_nvd(vuln, product))
        for vuln in query_osv(str(product["product"]), product.get("version"), config):
            if isinstance(vuln, dict):
                results.append(_item(str(vuln.get("id", "")), product, "OSV", float((vuln.get("database_specific", {}) or {}).get("cvss", 0) or 0), str(vuln.get("summary", "")), [ref.get("url", "") for ref in vuln.get("references", []) if isinstance(ref, dict)]))
    nuclei = read_json("outputs/nuclei/nuclei_results.json", default=[]) or []
    for item in nuclei if isinstance(nuclei, list) else []:
        info = item.get("info", {}) if isinstance(item, dict) else {}
        for tag in info.get("tags", []) if isinstance(info.get("tags"), list) else []:
            if str(tag).upper().startswith("CVE-"):
                results.append(_item(str(tag).upper(), {"product": item.get("template-id", ""), "host": item.get("host", ""), "url": item.get("matched-at", ""), "source": "nuclei"}, "Nuclei metadata", 0, str(info.get("description", "")), []))
    if not cve_cfg.get("show_low_confidence", False):
        results = [item for item in results if item.get("confidence") != "Low"]
    write_json(output_path, results)
    return results
