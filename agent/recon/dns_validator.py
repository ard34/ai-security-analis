from __future__ import annotations

from pathlib import Path

from agent.recon.recon_progress import log_step
from agent.report.json_writer import read_json, write_json


def _resolve(hostname: str) -> dict[str, object]:
    record_types = {"A": [], "AAAA": [], "CNAME": []}
    status = "unresolved"
    try:
        import dns.resolver

        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(hostname, record_type, lifetime=4)
                record_types[record_type] = [answer.to_text().strip('"') for answer in answers]
            except Exception:
                continue
        status = "resolved" if any(record_types.values()) else "unresolved"
    except Exception:
        import socket

        try:
            record_types["A"] = [socket.gethostbyname(hostname)]
            status = "resolved"
        except Exception:
            status = "unresolved"
    return {"resolved": status == "resolved", "resolver_status": status, **record_types}


def validate_dns(input_path: str = "outputs/recon/subdomains.txt", output_path: str = "outputs/recon/dns_validated_hosts.json") -> list[dict[str, object]]:
    log_step("Validasi DNS", "running", "Validasi DNS dimulai.")
    hosts = [line.strip() for line in Path(input_path).read_text(encoding="utf-8").splitlines() if line.strip()] if Path(input_path).exists() else []
    source_items = read_json("outputs/recon/subdomains_all_sources.json", default=[]) or []
    by_host = {item.get("hostname"): item for item in source_items if isinstance(item, dict)}
    results = []
    for hostname in hosts:
        resolved = _resolve(hostname)
        source = by_host.get(hostname, {})
        results.append(
            {
                "hostname": hostname,
                "resolved": resolved["resolved"],
                "record_types_found": [key for key in ["A", "AAAA", "CNAME"] if resolved.get(key)],
                "A": resolved["A"],
                "AAAA": resolved["AAAA"],
                "CNAME": resolved["CNAME"],
                "resolver_status": resolved["resolver_status"],
                "sources": source.get("sources", []),
                "confidence": source.get("confidence", ""),
            }
        )
    write_json(output_path, results)
    log_step("Validasi DNS", "done", "Validasi DNS selesai.", {"total_candidates": len(hosts), "resolved": sum(1 for item in results if item["resolved"]), "unresolved": sum(1 for item in results if not item["resolved"])})
    return results
