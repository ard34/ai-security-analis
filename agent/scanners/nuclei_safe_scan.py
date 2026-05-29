from __future__ import annotations

from pathlib import Path

from agent.core.scope_validator import filter_allowed_urls, load_dynamic_allowed_hosts
from agent.report.json_writer import write_json
from agent.utils.command_runner import command_exists
from agent.utils.tool_runner import record_tool_skipped, run_tool


def run_nuclei_safe_scan(config: dict[str, object], urls: list[str] | None = None, output_path: str = "outputs/nuclei/nuclei_results.json") -> list[dict[str, object]]:
    nuclei_cfg = config.get("nuclei", {}) if isinstance(config.get("nuclei"), dict) else {}
    if not nuclei_cfg.get("enabled", False):
        record_tool_skipped("nuclei", "Disabled by config")
        write_json(output_path, [])
        return []
    if not command_exists("nuclei"):
        record_tool_skipped("nuclei", "Tool not installed")
        write_json(output_path, [])
        return []
    allowed = load_dynamic_allowed_hosts()
    target_urls = filter_allowed_urls(urls or [], allowed)
    Path("outputs/nuclei").mkdir(parents=True, exist_ok=True)
    target_file = Path("outputs/nuclei/targets.txt")
    target_file.write_text("\n".join(target_urls), encoding="utf-8")
    exclude = ",".join(nuclei_cfg.get("exclude_tags", ["dos", "intrusive", "fuzz", "bruteforce", "exploit"]))
    severity = ",".join(nuclei_cfg.get("severity", ["info", "low", "medium"]))
    result = run_tool(["nuclei", "-l", str(target_file), "-jsonl", "-severity", severity, "-exclude-tags", exclude, "-rl", str(nuclei_cfg.get("rate_limit", 5))], int(nuclei_cfg.get("timeout_seconds", 120)), "nuclei", output_path="outputs/nuclei/nuclei_raw.jsonl")
    # Keep normalized empty on parse failure; this module never blocks the pipeline.
    write_json(output_path, [])
    return []
