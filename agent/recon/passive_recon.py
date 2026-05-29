from __future__ import annotations

from agent.recon.certificate_transparency import collect_ct_subdomains
from agent.recon.dns_records import collect_dns_records
from agent.recon.public_repo_recon import run_public_repo_recon
from agent.report.json_writer import write_json
from agent.utils.command_runner import command_exists, run_command
from agent.utils.tool_runner import record_tool_skipped, run_tool


def _whois(domain: str, output_path: str) -> dict[str, object]:
    if not command_exists("whois"):
        record_tool_skipped("whois", "Tool not installed", domain)
        result = {"status": "skipped", "reason": "whois not installed", "raw": ""}
        write_json(output_path, result)
        return result
    completed = run_tool(["whois", domain], timeout=30, tool_name="whois", target=domain)
    result = {"status": "collected" if completed.get("status") == "Done" else "failed", "reason": completed.get("reason", ""), "raw": str(completed.get("stdout", ""))[:20000]}
    write_json(output_path, result)
    return result


def run_passive_recon(config: dict[str, object], domain: str, output_dir: str = "outputs/recon") -> dict[str, object]:
    dns_records = collect_dns_records(domain, f"{output_dir}/dns_records.json")
    ct_subdomains = collect_ct_subdomains(domain, f"{output_dir}/ct_subdomains.json")
    repo = run_public_repo_recon(config, f"{output_dir}/public_repo_recon.json")
    whois = _whois(domain, f"{output_dir}/whois.json")
    result = {
        "dns_records": len(dns_records),
        "ct_subdomains": len(ct_subdomains),
        "public_repo_recon": repo.get("status"),
        "whois": whois.get("status"),
    }
    write_json(f"{output_dir}/passive_recon.json", result)
    return result
