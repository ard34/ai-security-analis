from __future__ import annotations

from agent.report.json_writer import write_json
from agent.utils.command_runner import command_exists

TOOLS = {
    "subfinder": "Recommended",
    "amass": "Optional",
    "assetfinder": "Optional",
    "dnsx": "Optional",
    "httpx": "Recommended",
    "nmap": "Recommended",
    "whatweb": "Recommended",
    "katana": "Recommended",
    "whois": "Recommended",
    "dig": "Recommended",
}


def check_tool_availability(output_path: str = "outputs/recon/tool_availability.json") -> list[dict[str, object]]:
    results = [{"tool": tool, "category": category, "installed": command_exists(tool), "status": "Installed" if command_exists(tool) else "Missing"} for tool, category in TOOLS.items()]
    write_json(output_path, results)
    return results
