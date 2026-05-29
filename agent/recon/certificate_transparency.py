from __future__ import annotations

from agent.core.scope_validator import get_registered_domain, is_same_registered_domain
from agent.report.json_writer import write_json


def collect_ct_subdomains(domain: str, output_path: str = "outputs/recon/ct_subdomains.json") -> list[dict[str, object]]:
    root = get_registered_domain(domain)
    results: dict[str, dict[str, object]] = {}
    try:
        import requests

        response = requests.get(f"https://crt.sh/?q=%25.{root}&output=json", timeout=15)
        if response.status_code != 200:
            raise RuntimeError(f"crt.sh returned {response.status_code}")
        for item in response.json():
            names = str(item.get("name_value", "")).splitlines()
            for name in names:
                hostname = name.lower().strip().strip("*.").strip(".")
                if hostname and is_same_registered_domain(hostname, root):
                    results[hostname] = {"hostname": hostname, "source": "certificate_transparency", "same_registered_domain": True}
    except Exception as exc:
        write_json(output_path, {"subdomains": [], "status": "skipped_or_failed", "reason": str(exc)})
        return []
    values = sorted(results.values(), key=lambda item: str(item["hostname"]))
    write_json(output_path, {"subdomains": values, "status": "collected"})
    return values
