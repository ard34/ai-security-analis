from __future__ import annotations

from agent.report.json_writer import write_json
from agent.utils.command_runner import command_exists, run_command

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]


def _dnspython_records(domain: str) -> list[dict[str, object]]:
    import dns.resolver

    resolver = dns.resolver.Resolver()
    records: list[dict[str, object]] = []
    for record_type in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, record_type, lifetime=5)
        except Exception:
            continue
        for answer in answers:
            records.append({"type": record_type, "name": domain, "value": answer.to_text().strip('"'), "ttl": answers.rrset.ttl if answers.rrset else ""})
    return records


def _dig_records(domain: str) -> list[dict[str, object]]:
    if not command_exists("dig"):
        return []
    records: list[dict[str, object]] = []
    for record_type in RECORD_TYPES:
        completed = run_command(["dig", "+short", domain, record_type], timeout=15)
        if completed.returncode != 0:
            continue
        for line in completed.stdout.splitlines():
            value = line.strip()
            if value:
                records.append({"type": record_type, "name": domain, "value": value, "ttl": ""})
    return records


def collect_dns_records(domain: str, output_path: str = "outputs/recon/dns_records.json") -> list[dict[str, object]]:
    try:
        records = _dnspython_records(domain)
    except Exception:
        records = _dig_records(domain)
    write_json(output_path, records)
    return records
