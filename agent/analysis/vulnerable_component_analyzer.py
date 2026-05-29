from __future__ import annotations

from agent.report.json_writer import read_json, write_json


def analyze_vulnerable_components(output_path: str = "outputs/potential_vulnerable_components.json") -> list[dict[str, object]]:
    products = read_json("outputs/detected_products.json", default=[]) or []
    cves = read_json("outputs/cve_correlations.json", default=[]) or []
    by_key: dict[tuple[str, str, str], list[dict[str, object]]] = {}
    for cve in cves:
        if isinstance(cve, dict):
            key = (str(cve.get("detected_product")), str(cve.get("detected_version")), str(cve.get("affected_host")))
            by_key.setdefault(key, []).append(cve)
    results = []
    for product in products:
        if not isinstance(product, dict):
            continue
        key = (str(product.get("product")), str(product.get("version")), str(product.get("host")))
        related = by_key.get(key, [])
        if not related and not product.get("version"):
            related = []
        highest = max([float(item.get("cvss_score") or 0) for item in related], default=0)
        if related or product.get("version_confidence") == "Low":
            results.append({"product": product.get("product"), "version": product.get("version"), "host": product.get("host"), "url": product.get("url"), "evidence": product.get("evidence"), "related_cves": [item.get("cve_id") for item in related], "highest_cvss": highest, "highest_severity": max([str(item.get("severity", "Unknown")) for item in related], default="Unknown"), "confidence": "High" if related and product.get("version") else "Low", "reason": "Komponen terdeteksi dan dikorelasikan dengan CVE atau versi belum pasti.", "manual_validation_steps": ["Konfirmasi produk dan versi.", "Cek advisory vendor resmi.", "Validasi exposure dalam scope berizin."], "remediation": "Upgrade atau patch komponen jika korelasi tervalidasi.", "status": "Potential", "owasp_web": "A06 Vulnerable and Outdated Components", "owasp_api": "API9 Improper Inventory Management"})
    write_json(output_path, results)
    return results
