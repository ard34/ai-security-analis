from __future__ import annotations

from pathlib import Path
from xml.etree import ElementTree

from agent.core.target_normalizer import NormalizedTarget
from agent.recon.recon_progress import log_step
from agent.report.json_writer import write_json
from agent.utils.command_runner import command_exists, run_command
from agent.utils.tool_runner import record_tool_skipped, run_tool


def _profile(config: dict[str, object]) -> str:
    assessment = config.get("assessment", {}) if isinstance(config.get("assessment"), dict) else {}
    value = str(assessment.get("type") or assessment.get("profile") or "").lower()
    if "bug bounty" in value or "bug_bounty" in value:
        return "bug_bounty_public"
    if "local" in value or "lab" in value:
        return "local_lab"
    if "enterprise" in value:
        return "enterprise_authorized"
    return "pre_launch_testing"


def _port_scan_allowed(config: dict[str, object]) -> bool:
    if not bool((config.get("scan", {}) if isinstance(config.get("scan"), dict) else {}).get("safe_mode", True)):
        return False
    recon = config.get("recon", {}) if isinstance(config.get("recon"), dict) else {}
    if _profile(config) == "bug_bounty_public":
        return bool(recon.get("enable_public_bug_bounty_port_scan", False))
    return bool(recon.get("enable_port_scan", True))


def _parse_nmap_xml(path: Path, host: str) -> list[dict[str, object]]:
    if not path.exists():
        return []
    root = ElementTree.fromstring(path.read_text(encoding="utf-8", errors="ignore"))
    ports = []
    for port in root.findall(".//port"):
        state = port.find("state")
        service = port.find("service")
        if state is None or state.attrib.get("state") != "open":
            continue
        ports.append(
            {
                "host": host,
                "port": int(port.attrib.get("portid", 0)),
                "protocol": port.attrib.get("protocol", "tcp"),
                "state": "open",
                "service": service.attrib.get("name", "") if service is not None else "",
                "product": service.attrib.get("product", "") if service is not None else "",
                "version": service.attrib.get("version", "") if service is not None else "",
                "confidence": service.attrib.get("conf", "") if service is not None else "",
            }
        )
    return ports


def discover_ports(config: dict[str, object], hosts: list[str], normalized: NormalizedTarget, output_dir: str = "outputs/recon") -> dict[str, list[dict[str, object]]]:
    log_step("Port Discovery", "running", "Port discovery dimulai.")
    nmap_cmd = str((config.get("tools", {}) if isinstance(config.get("tools"), dict) else {}).get("nmap", "nmap"))
    if not _port_scan_allowed(config):
        record_tool_skipped("nmap", "Disabled by recon mode or safe mode", normalized.hostname)
        write_json(f"{output_dir}/open_ports.json", [])
        write_json(f"{output_dir}/services.json", [])
        log_step("Port Discovery", "skipped", "Port discovery dilewati oleh konfigurasi.")
        return {"open_ports": [], "services": []}
    if not command_exists(nmap_cmd):
        record_tool_skipped("nmap", "Tool not installed", normalized.hostname)
        write_json(f"{output_dir}/open_ports.json", [])
        write_json(f"{output_dir}/services.json", [])
        log_step("Port Discovery", "skipped", "nmap tidak tersedia.")
        return {"open_ports": [], "services": []}
    command = nmap_cmd
    open_ports: list[dict[str, object]] = []
    for host in sorted(set(hosts)):
        safe_name = host.replace(":", "_").replace("/", "_")
        xml_path = Path(output_dir) / f"nmap_{safe_name}.xml"
        run_tool([command, "-Pn", "-T2", "--top-ports", "100", "--open", "-sV", "--version-light", "-oX", str(xml_path), host], timeout=300, tool_name="nmap", target=host)
        try:
            open_ports.extend(_parse_nmap_xml(xml_path, host))
        except Exception:
            continue
    write_json(f"{output_dir}/open_ports.json", open_ports)
    write_json(f"{output_dir}/services.json", open_ports)
    log_step("Port Discovery", "done", "Port discovery selesai.", {"open_ports": len(open_ports)})
    return {"open_ports": open_ports, "services": open_ports}
