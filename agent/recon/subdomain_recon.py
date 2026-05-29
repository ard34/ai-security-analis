from __future__ import annotations

from pathlib import Path

from agent.core.scope_validator import get_hostname, get_registered_domain, is_same_registered_domain
from agent.core.target_normalizer import normalize_target
from agent.report.json_writer import write_json
from agent.utils.command_runner import command_exists, run_command


def derive_root_domain(target: str, configured_root_domain: str = "") -> str:
    return get_registered_domain(configured_root_domain or target)


def discover_subdomains(
    target: str,
    config: dict[str, object],
    output_path: str = "outputs/discovered_subdomains.json",
    text_output_path: str = "outputs/subdomains.txt",
) -> list[dict[str, object]]:
    target_config = config.get("target", {}) if isinstance(config.get("target"), dict) else {}
    assessment_config = config.get("assessment", {}) if isinstance(config.get("assessment"), dict) else {}
    scope_config = config.get("scope", {}) if isinstance(config.get("scope"), dict) else {}
    tools_config = config.get("tools", {}) if isinstance(config.get("tools"), dict) else {}
    normalized = normalize_target(target, str(assessment_config.get("type") or assessment_config.get("profile") or "Pre-Launch Black Box Testing"))
    root_domain = normalized.registered_domain
    subfinder = str(tools_config.get("subfinder", "subfinder"))
    include_root = bool(scope_config.get("include_root_domain", True))
    include_discovered = bool(scope_config.get("include_discovered_subdomains", True))

    host_sources: dict[str, str] = {}
    if normalized.direct_scope:
        results = [{"hostname": normalized.hostname, "source": "target_input", "same_registered_domain": True, "url": normalized.normalized_url}]
        write_json(output_path, results)
        Path(text_output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(text_output_path).write_text(normalized.hostname + "\n", encoding="utf-8")
        return results
    if include_root:
        host_sources[root_domain] = "root_domain"
    input_hostname = normalized.hostname
    if is_same_registered_domain(input_hostname, root_domain):
        host_sources.setdefault(input_hostname, "target_input")

    if include_discovered and normalized.subfinder_allowed and command_exists(subfinder):
        raw_path = Path(text_output_path)
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        completed = run_command([subfinder, "-d", root_domain, "-silent", "-o", str(raw_path)], timeout=300)
        if completed.returncode == 0 and raw_path.exists():
            for line in raw_path.read_text(encoding="utf-8").splitlines():
                hostname = line.strip().lower().strip(".")
                if hostname:
                    host_sources.setdefault(hostname, "subfinder")
    elif include_discovered and normalized.subfinder_allowed:
        print("[!] subfinder not available. Falling back to root domain only.")

    results = []
    for hostname, source in sorted(host_sources.items()):
        same_registered = is_same_registered_domain(hostname, root_domain)
        if same_registered:
            results.append({"hostname": hostname, "source": source, "same_registered_domain": True})

    write_json(output_path, results)
    Path(text_output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(text_output_path).write_text("\n".join(item["hostname"] for item in results) + "\n", encoding="utf-8")
    return results
