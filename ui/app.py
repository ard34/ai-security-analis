from __future__ import annotations

import html
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.core.config_loader import load_config
from agent.core.domain_input_normalizer import normalize_domain_input
from agent.recon.sequential_recon_runner import build_execution_plan, clear_recon_outputs, run_selected_recon_tools
from agent.recon.tool_registry import TOOL_REGISTRY, auto_select_dependencies, default_tool_ids
from agent.report.report_center import generate_pdf_from_html, generate_recon_report_html
from agent.utils.command_runner import command_exists
from ui.data_loader import (
    load_attack_surface_counts,
    load_last_scan_status,
    load_progress_events,
    load_recon_summary,
    load_tool_counts,
    read_output,
)
from ui.theme import inject_cyberpunk_theme, metric_card, neon_card, status_badge


MENU = ["Dashboard", "Reconnaissance", "Assets", "Attack Surface", "OWASP ZAP", "Reports", "Settings", "Debug"]

MODE_DURATION = {
    "Quick Recon": "30 detik - 2 menit",
    "Standard Recon": "2 - 7 menit",
    "Full Recon": "5 - 20+ menit",
}


def _esc(value: object) -> str:
    return html.escape(str(value if value is not None else ""))


def safe_scalar(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    return json.dumps(value, ensure_ascii=False, default=str)


def normalize_table_rows(data: object) -> list[dict[str, object]]:
    if isinstance(data, dict):
        rows = [data]
    elif isinstance(data, list):
        rows = data
    else:
        rows = [{"value": data}]
    safe_rows = []
    for row in rows:
        if isinstance(row, dict):
            safe_rows.append({str(key): safe_scalar(value) for key, value in row.items()})
        else:
            safe_rows.append({"value": safe_scalar(row)})
    return safe_rows


def safe_table(data: object) -> list[dict[str, object]]:
    return normalize_table_rows(data)


def _list_data(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


class TechnologyNameList(list[str]):
    def __eq__(self, other: object) -> bool:
        if isinstance(other, set):
            return set(self) == other
        return super().__eq__(other)


def _as_items(value: object) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, (tuple, set)):
        return list(value)
    return [value]


def _collect_technology_names(names: set[str], value: object) -> None:
    for item in _as_items(value):
        if item is None:
            continue
        if isinstance(item, str):
            for part in item.split(","):
                text = part.strip()
                if text:
                    names.add(text)
            continue
        if isinstance(item, dict):
            named = False
            for key in ("name", "technology", "title"):
                candidate = item.get(key)
                if isinstance(candidate, str) and candidate.strip():
                    _collect_technology_names(names, candidate)
                    named = True
            if named:
                continue
            for key in ("detected", "technologies", "technology"):
                if key in item:
                    _collect_technology_names(names, item.get(key))
                    named = True
            if named:
                continue
            for key, candidate in item.items():
                if isinstance(candidate, (str, dict, list, tuple, set)):
                    before = len(names)
                    _collect_technology_names(names, candidate)
                    if isinstance(candidate, dict) and len(names) == before and str(key).strip():
                        names.add(str(key).strip())
                elif str(key).strip():
                    names.add(str(key).strip())


def _technology_names(*technologies: object) -> list[str]:
    names: set[str] = set()
    for value in technologies:
        _collect_technology_names(names, value)
    return TechnologyNameList(sorted(names, key=str.lower))


def _count_items(value: object) -> int:
    if value is None:
        return 0
    if isinstance(value, dict):
        return len(value)
    if isinstance(value, (list, tuple, set)):
        return len(value)
    return 1


def _ip_count(rows: object) -> int:
    ips: set[str] = set()
    for item in _as_items(rows):
        if not isinstance(item, dict):
            continue
        for key in ("ip", "address"):
            if item.get(key):
                ips.add(str(item[key]))
        for value in _as_items(item.get("ips") or item.get("addresses")):
            if value:
                ips.add(str(value))
    return len(ips)


def load_recon_data() -> dict[str, Any]:
    return {
        "summary": read_output("outputs/recon/recon_summary.json", {}),
        "subdomains_all_sources": _list_data(read_output("outputs/recon/subdomains_all_sources.json", [])),
        "dns_validated_hosts": _list_data(read_output("outputs/recon/dns_validated_hosts.json", [])),
        "live_hosts": _list_data(read_output("outputs/recon/live_hosts.json", [])),
        "open_ports": _list_data(read_output("outputs/recon/open_ports.json", [])),
        "services": _list_data(read_output("outputs/recon/services.json", [])),
        "technologies": _list_data(read_output("outputs/recon/technologies.json", [])),
        "important_endpoints": _list_data(read_output("outputs/recon/important_endpoints.json", [])),
        "endpoints": _list_data(read_output("outputs/recon/endpoints.json", [])),
    }


def summarize_recon_data(data: dict[str, Any] | None) -> dict[str, Any]:
    recon_data = data if isinstance(data, dict) else {}
    subdomains = recon_data.get("subdomains")
    if subdomains is None:
        subdomains = recon_data.get("subdomains_all_sources") or recon_data.get("discovered_subdomains") or []
    live_hosts = recon_data.get("live_hosts") or []
    open_ports = recon_data.get("open_ports") or []
    technologies = _technology_names(recon_data.get("technologies"), live_hosts)
    endpoints = recon_data.get("endpoints")
    if not endpoints:
        endpoints = recon_data.get("important_endpoints") or []
    findings = recon_data.get("findings") or recon_data.get("potential_findings") or []
    services = recon_data.get("services") or []
    summary = {
        "subdomain_count": _count_items(subdomains),
        "live_host_count": _count_items(live_hosts),
        "open_port_count": _count_items(open_ports),
        "technology_count": len(technologies),
        "endpoint_count": _count_items(endpoints),
        "finding_count": _count_items(findings),
        "technologies": technologies,
    }
    summary.update(
        {
            "Hostnames": summary["subdomain_count"],
            "IP Addresses": _ip_count(recon_data.get("dns_validated_hosts")),
            "Live Hosts": summary["live_host_count"],
            "Ports": summary["open_port_count"],
            "Services": _count_items(services),
            "Technologies": summary["technology_count"],
            "Endpoints": summary["endpoint_count"],
            "Potential Findings": summary["finding_count"],
        }
    )
    return summary


def _attack_surface_cards_html(recon_data: dict[str, Any] | None) -> str:
    summary = summarize_recon_data(recon_data)
    cards = [
        ("Subdomains", summary["subdomain_count"]),
        ("Live Hosts", summary["live_host_count"]),
        ("Open Ports", summary["open_port_count"]),
        ("Technologies", summary["technology_count"]),
        ("Endpoints", summary["endpoint_count"]),
        ("Potential Findings", summary["finding_count"]),
    ]
    items = "\n".join(
        f'<div class="attack-surface-card"><div class="attack-surface-value">{_esc(value)}</div><div class="attack-surface-label">{_esc(label)}</div></div>'
        for label, value in cards
    )
    return f'<div class="attack-surface-grid">\n{items}\n</div>'


def _render_attack_surface_card_widgets(st: object, cards: object) -> int:
    rows = _as_items(cards)
    rendered = 0
    for card in rows:
        if not isinstance(card, dict):
            continue
        rendered += 1
        with st.container(border=True):
            st.subheader(str(card.get("category") or "Attack Surface"))
            assets = card.get("assets") or []
            endpoints = card.get("endpoints") or []
            technologies = _technology_names(card.get("technology"), card.get("technologies"))
            risk_hints = card.get("risk_hints") or []
            manual_checks = card.get("recommended_manual_checks") or []
            if assets:
                st.markdown("Assets: " + ", ".join(safe_scalar(item.get("hostname") or item.get("url") or item) if isinstance(item, dict) else safe_scalar(item) for item in _as_items(assets)))
            if endpoints:
                st.markdown("Endpoints: " + ", ".join(safe_scalar(item.get("url") or item) if isinstance(item, dict) else safe_scalar(item) for item in _as_items(endpoints)))
            if technologies:
                st.markdown("Technologies: " + ", ".join(technologies))
            if risk_hints:
                st.write("Risk hints: " + ", ".join(safe_scalar(item) for item in _as_items(risk_hints)))
            if manual_checks:
                st.write("Manual checks: " + ", ".join(safe_scalar(item) for item in _as_items(manual_checks)))
    if not rendered:
        st.info("Belum ada attack surface.")
    return rendered


def render_attack_surface_cards(*args: object) -> str | int:
    if len(args) == 1:
        recon_data = args[0] if isinstance(args[0], dict) else None
        return _attack_surface_cards_html(recon_data)
    if len(args) == 2:
        return _render_attack_surface_card_widgets(args[0], args[1])
    raise TypeError("render_attack_surface_cards expects recon_data or st, cards")


def parse_comma_separated_values(value: str) -> list[str]:
    seen: set[str] = set()
    items: list[str] = []
    for item in str(value or "").split(","):
        text = item.strip()
        if text and text not in seen:
            seen.add(text)
            items.append(text)
    return items


def summarize_pipeline_result(result: dict[str, Any] | None) -> dict[str, int]:
    payload = result if isinstance(result, dict) else {}
    audit_log = payload.get("audit_log") if isinstance(payload.get("audit_log"), dict) else {}
    return {
        "assets": _count_items(payload.get("assets")),
        "endpoints": _count_items(payload.get("endpoints")),
        "findings": _count_items(payload.get("findings")),
        "commands_executed": _count_items(audit_log.get("commands_executed")),
        "modules_enabled": _count_items(audit_log.get("modules_enabled")),
    }


def _finding_value(finding: object, key: str) -> object:
    if isinstance(finding, dict):
        return finding.get(key, "")
    return getattr(finding, key, "")


def findings_to_table_rows(findings: list[object] | object | None) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for finding in _as_items(findings):
        if not finding:
            continue
        rows.append(
            {
                "title": _finding_value(finding, "title"),
                "severity": _finding_value(finding, "severity"),
                "confidence": _finding_value(finding, "confidence"),
                "asset": _finding_value(finding, "asset"),
                "endpoint": _finding_value(finding, "endpoint"),
                "evidence": _finding_value(finding, "evidence"),
                "recommendation": _finding_value(finding, "recommendation"),
                "source": _finding_value(finding, "source"),
                "is_potential": _finding_value(finding, "is_potential"),
            }
        )
    return rows


def build_report_filename(scan_result: dict[str, Any], extension: str) -> str:
    ext = str(extension or "").strip().lower().lstrip(".")
    if ext not in {"html", "pdf"}:
        raise ValueError("Report extension must be html or pdf.")
    scan_id = str((scan_result or {}).get("scan_id") or "unknown")
    safe_scan_id = re.sub(r"[^A-Za-z0-9._-]+", "-", scan_id).strip(".-_") or "unknown"
    return f"ai-security-analyst-report-{safe_scan_id}.{ext}"


def can_export_report(scan_result: dict[str, Any] | None) -> bool:
    return bool(isinstance(scan_result, dict) and scan_result.get("status") and scan_result.get("target"))


def generate_html_report_bytes(scan_result: dict[str, Any]) -> bytes:
    from reporting.html_report import generate_html_report

    return generate_html_report(scan_result).encode("utf-8")


def generate_pdf_report_bytes(scan_result: dict[str, Any]) -> bytes:
    from reporting.pdf_report import generate_pdf_report

    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "report.pdf"
        generated = generate_pdf_report(scan_result, str(output_path))
        return Path(generated).read_bytes()


def render_report_export(st: object) -> None:
    section(st, "Report Export")
    scan_result = st.session_state.get("last_scan_result")
    if not can_export_report(scan_result):
        st.warning("Run a dummy scan before exporting a report.")
        return

    st.caption(f"Report scan ID: {scan_result.get('scan_id', 'unknown')}")
    html_bytes = generate_html_report_bytes(scan_result)
    st.download_button(
        label="Download HTML Report",
        data=html_bytes,
        file_name=build_report_filename(scan_result, "html"),
        mime="text/html",
        width="stretch",
    )
    pdf_bytes = generate_pdf_report_bytes(scan_result)
    st.download_button(
        label="Download PDF Report",
        data=pdf_bytes,
        file_name=build_report_filename(scan_result, "pdf"),
        mime="application/pdf",
        width="stretch",
    )


def _render_dummy_pipeline_result(st: object, result: dict[str, Any]) -> None:
    status = str(result.get("status", ""))
    st.markdown(status_badge(status or "unknown"), unsafe_allow_html=True)
    summary = summarize_pipeline_result(result)
    cols = st.columns(5)
    for col, (label, key) in zip(
        cols,
        [
            ("Assets", "assets"),
            ("Endpoints", "endpoints"),
            ("Potential Findings", "findings"),
            ("Commands Executed", "commands_executed"),
            ("Modules Enabled", "modules_enabled"),
        ],
    ):
        with col:
            st.markdown(metric_card(label, summary[key]), unsafe_allow_html=True)

    if status == "rejected":
        st.warning(str(result.get("reason", "Target rejected by scope validation.")))
        section(st, "Audit Log")
        st.json(result.get("audit_log", {}))
        return

    if status != "success":
        st.error(str(result.get("reason", "Dummy scan failed.")))
        section(st, "Audit Log")
        st.json(result.get("audit_log", {}))
        return

    section(st, "Scan Metadata")
    render_safe_table(
        st,
        [
            {
                "scan_id": result.get("scan_id", ""),
                "normalized_target": result.get("normalized_target", ""),
                "scan_mode": result.get("scan_mode", ""),
                "started_at": result.get("started_at", ""),
                "ended_at": result.get("ended_at", ""),
            }
        ],
    )
    section(st, "Assets")
    render_safe_table(st, result.get("assets", []))
    section(st, "Endpoints")
    render_safe_table(st, result.get("endpoints", []))
    section(st, "Findings")
    render_safe_table(st, findings_to_table_rows(result.get("findings", [])))
    section(st, "Audit Log")
    st.json(result.get("audit_log", {}))


def render_dummy_scan_panel(st: object) -> None:
    section(st, "Safe Dummy Scan")
    st.caption("Local-only pipeline: scope validation, dummy asset generation, and passive header analysis. No external scanners are run.")
    col_left, col_right = st.columns([1.2, 1])
    with col_left:
        target = st.text_input("Target domain / URL", key="dummy_target", placeholder="example.com or https://app.example.com")
        allowed_domains_raw = st.text_input("Allowed domains", key="dummy_allowed_domains", placeholder="example.com, example.org")
        allowed_ips_raw = st.text_input("Allowed IPs optional", key="dummy_allowed_ips", placeholder="8.8.8.8")
    with col_right:
        scan_mode = st.selectbox("Scan mode", ["strict", "safe", "standard"], index=1, key="dummy_scan_mode")
        run_clicked = st.button("Run Dummy Scan", type="primary", width="stretch")

    if run_clicked:
        allowed_domains = parse_comma_separated_values(allowed_domains_raw)
        allowed_ips = parse_comma_separated_values(allowed_ips_raw)
        if not target.strip():
            st.error("Target wajib diisi.")
        elif not allowed_domains and not allowed_ips:
            st.error("Isi minimal satu allowed domain atau allowed IP.")
        else:
            from core.pipeline import run_dummy_pipeline

            try:
                result = run_dummy_pipeline(
                    target=target,
                    allowed_domains=allowed_domains,
                    allowed_ips=allowed_ips,
                    scan_mode=scan_mode,
                )
                st.session_state["dummy_pipeline_result"] = result
                st.session_state["last_scan_result"] = result
            except Exception as exc:
                result = {
                    "status": "error",
                    "target": target,
                    "reason": str(exc),
                    "assets": [],
                    "endpoints": [],
                    "findings": [],
                    "audit_log": {
                        "modules_enabled": [],
                        "commands_executed": [],
                        "errors": [str(exc)],
                        "findings_generated": 0,
                    },
                }
                st.session_state["dummy_pipeline_result"] = result
                st.session_state["last_scan_result"] = result

    result = st.session_state.get("dummy_pipeline_result")
    if isinstance(result, dict):
        _render_dummy_pipeline_result(st, result)
    render_report_export(st)


def render_safe_table(st: object, data: object, empty: str = "Belum ada data.") -> int:
    rows = normalize_table_rows(data)
    if rows:
        st.dataframe(rows, width="stretch", hide_index=True)
    else:
        st.info(empty)
    return len(rows)


def section(st: object, title: str) -> None:
    st.markdown(f'<div class="cy-section">{_esc(title)}</div>', unsafe_allow_html=True)


def hero(st: object, title: str, subtitle: str, status: str = "") -> None:
    st.markdown(
        f"""
        <div class="cy-hero">
            <div class="cy-title">{_esc(title)}</div>
            <div class="cy-subtitle">{_esc(subtitle)}</div>
            <div style="margin-top:14px">{status_badge(status or "Ready")}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_sidebar(st: object) -> str:
    latest = load_last_scan_status()
    counts = load_attack_surface_counts()
    with st.sidebar:
        st.markdown(
            """
            <div class="cy-brand">
                <div class="cy-logo">PGI</div>
                <div class="cy-brand-title">Pasifik Global Integrity</div>
                <div class="cy-brand-sub">AI Security Analyst Platform</div>
                <div class="cy-brand-sub">Black Box Reconnaissance & Attack Surface Mapping</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        page = st.radio("Navigation", MENU, index=MENU.index(st.session_state.get("page", "Dashboard")), label_visibility="collapsed")
        st.session_state["page"] = page
        st.divider()
        workspace = st.selectbox("Current Workspace", ["Default Workspace", "Local Lab", "Pre-Launch", "Enterprise"], key="workspace")
        st.caption("Current scan status")
        st.markdown(status_badge(latest.get("status", "Ready")), unsafe_allow_html=True)
        st.caption("Quick result summary")
        st.markdown(
            neon_card(
                "Results",
                counts.get("Total Hostnames", 0),
                f"Live {counts.get('Live Hosts', 0)} / Ports {counts.get('Open Ports', 0)}",
            ),
            unsafe_allow_html=True,
        )
        confirm = st.checkbox("Saya yakin ingin menghapus hasil recon sebelumnya.", key="sidebar_confirm_clear")
        if st.button("Clear Results", width="stretch"):
            if confirm:
                removed = clear_recon_outputs()
                st.success(f"Hasil recon dihapus. Files: {removed['files']}, directories: {removed['directories']}.")
                st.rerun()
            else:
                st.warning("Centang konfirmasi sebelum menghapus hasil.")
    return workspace


def render_dashboard(st: object) -> None:
    latest = load_last_scan_status()
    counts = load_tool_counts()
    attack_counts = load_attack_surface_counts()
    has_results = any(item["count"] for item in counts) or bool(load_recon_summary())
    hero(st, "AI Security Analyst Dashboard", "Cyber Reconnaissance & Attack Surface Intelligence", str(latest.get("status", "Ready")))
    render_dummy_scan_panel(st)
    if not has_results:
        st.info("Belum ada hasil recon. Jalankan Reconnaissance terlebih dahulu.")
        return

    section(st, "Tool Summary Cards")
    for start in range(0, len(counts), 5):
        cols = st.columns(5)
        for col, item in zip(cols, counts[start : start + 5]):
            with col:
                st.markdown(
                    neon_card(item["tool"], item["count"], f"{item['status']} {item.get('last_run') or ''}"),
                    unsafe_allow_html=True,
                )

    section(st, "Attack Surface Summary")
    for start in range(0, len(attack_counts), 4):
        cols = st.columns(4)
        for col, (label, value) in zip(cols, list(attack_counts.items())[start : start + 4]):
            with col:
                st.markdown(metric_card(label, value), unsafe_allow_html=True)

    section(st, "Recent Recon Activity")
    selected = latest.get("selected_tools", [])
    rows = [{
        "target domain": latest.get("target", ""),
        "recon mode": latest.get("mode", ""),
        "selected tools": ", ".join(selected) if isinstance(selected, list) else selected,
        "started time": latest.get("started_at", ""),
        "finished time": latest.get("finished_at", ""),
        "duration": latest.get("duration_seconds", ""),
        "status": latest.get("status", ""),
    }]
    render_safe_table(st, rows)

    section(st, "Tool Execution Timeline")
    render_timeline(st, load_progress_events()[-30:])


def _domain_preview(st: object, raw: str) -> dict[str, Any] | None:
    if not raw:
        return None
    try:
        preview = normalize_domain_input(raw)
    except ValueError as exc:
        st.error(str(exc))
        return None
    scope_mode = "Dynamic subdomain reconnaissance" if preview.get("subdomain_recon_enabled") else "Direct target scope"
    st.markdown(
        f"""
        <div class="cy-panel">
            <div class="cy-label">Normalized Preview</div>
            <div><b>Input asli:</b> {_esc(preview.get("input"))}</div>
            <div><b>Target domain:</b> {_esc(preview.get("target_domain"))}</div>
            <div><b>Root domain:</b> {_esc(preview.get("root_domain") or preview.get("target_domain"))}</div>
            <div><b>Subdomain recon enabled:</b> {_esc(preview.get("subdomain_recon_enabled"))}</div>
            <div><b>Scope mode:</b> {_esc(scope_mode)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    return preview


def selected_tool_ids_from_checks(selected_tools: dict[str, bool]) -> list[str]:
    return auto_select_dependencies([tool_id for tool_id, enabled in selected_tools.items() if enabled])


def _mode_default_map(mode: str) -> dict[str, bool]:
    defaults = set(default_tool_ids(mode))
    return {str(tool["id"]): str(tool["id"]) in defaults for tool in TOOL_REGISTRY}


def _apply_mode_defaults_to_session(st: object, mode: str) -> None:
    for tool_id, enabled in _mode_default_map(mode).items():
        st.session_state[f"tool_{tool_id}"] = enabled
    st.session_state["tool_defaults_initialized"] = True
    st.session_state["tool_defaults_mode"] = mode


def _tool_checkbox(st: object, tool: dict[str, Any]) -> bool:
    tool_id = str(tool["id"])
    requires = [str(item) for item in tool.get("requires", [])]
    installed = all(command_exists(command) for command in requires) if requires else True
    label = f"{tool['display_name']} [{'installed' if installed else 'missing'}]"
    checked = st.checkbox(label, key=f"tool_{tool_id}", help=str(tool.get("description", "")))
    st.caption(f"{tool.get('description', '')} | Estimasi: {tool.get('runtime', '')} | Output: {tool.get('output', '')}")
    return checked


def selected_tools_from_state(mode: str) -> list[str]:
    import streamlit as st

    if not st.session_state.get("tool_defaults_initialized"):
        _apply_mode_defaults_to_session(st, mode)
    selected = {str(tool["id"]): bool(st.session_state.get(f"tool_{tool['id']}", False)) for tool in TOOL_REGISTRY}
    return selected_tool_ids_from_checks(selected)


def render_recon(st: object, config: dict[str, Any]) -> None:
    latest = load_last_scan_status()
    hero(st, "Reconnaissance", "Sequential authorized recon workflow. Active scan remains OFF by default.", str(latest.get("status", "Ready")))
    col_left, col_right = st.columns([1.1, 1])
    with col_left:
        section(st, "Domain Input Panel")
        raw_target = st.text_input(
            "Target Domain",
            placeholder="contoh: fahram.dev",
            help="Masukkan domain utama saja. Contoh: fahram.dev. AI agent akan mencari subdomain dan memetakan attack surface berdasarkan scope domain tersebut.",
            key="recon_target_domain",
        )
        preview = _domain_preview(st, raw_target)
        section(st, "Authorization Panel")
        authorized = st.checkbox("Saya memiliki izin untuk melakukan reconnaissance pada target ini.", key="recon_authorized")
        section(st, "Recon Mode")
        mode = st.selectbox("Recon Mode", list(MODE_DURATION), key="recon_mode")
        st.info(f"Estimasi durasi: {MODE_DURATION[mode]}")
        if not st.session_state.get("tool_defaults_initialized"):
            _apply_mode_defaults_to_session(st, mode)
        if st.button("Apply Mode Defaults", width="stretch"):
            _apply_mode_defaults_to_session(st, mode)
            st.rerun()
        if st.button("New Scan / Reset Form", width="stretch"):
            for tool in TOOL_REGISTRY:
                st.session_state.pop(f"tool_{tool['id']}", None)
            for key in ["recon_target_domain", "recon_authorized", "tool_defaults_initialized", "tool_defaults_mode"]:
                st.session_state.pop(key, None)
            st.rerun()
    with col_right:
        section(st, "Tool Checklist")
        selected_tools: dict[str, bool] = {}
        for tool in TOOL_REGISTRY:
            selected_tools[str(tool["id"])] = _tool_checkbox(st, tool)
        selected = selected_tool_ids_from_checks(selected_tools)
        debug_payload = {"selected_tool_ids": selected, "selected_tools": selected_tools, "recon_mode": mode, "target_domain": raw_target}
        with st.expander("Debug: Selected Tool IDs", expanded=False):
            st.json(debug_payload)

    section(st, "Execution Actions")
    a, b, c = st.columns(3)
    run_full = a.button("Start Full Reconnaissance", type="primary", width="stretch")
    run_selected = b.button("Run Selected Tools", width="stretch")
    confirm_clear = st.checkbox("Saya yakin ingin menghapus hasil recon sebelumnya.", key="recon_confirm_clear")
    clear_clicked = c.button("Hapus Hasil Recon Sebelumnya", width="stretch")

    if clear_clicked:
        if confirm_clear:
            removed = clear_recon_outputs()
            st.success(f"Hasil recon sebelumnya dihapus. Files: {removed['files']}, directories: {removed['directories']}.")
            st.rerun()
        else:
            st.warning("Centang konfirmasi sebelum menghapus hasil recon.")

    if run_full or run_selected:
        if not preview:
            st.error("Target domain wajib valid sebelum recon berjalan.")
        elif not authorized:
            st.warning("Recon tidak dapat berjalan sebelum authorization dicentang.")
        else:
            chosen = default_tool_ids("Full Recon") if run_full else selected
            safe_config = _safe_recon_config(config)
            with st.spinner("Menjalankan recon berurutan satu per satu..."):
                summary = run_selected_recon_tools(safe_config, str(preview["target_domain"]), chosen, mode)
            st.success(f"Recon selesai dengan status: {summary.get('run_status', 'Completed')}")
            st.rerun()

    section(st, "Current Running Tool")
    events = load_progress_events()
    current = next((item for item in reversed(events) if str(item.get("status")).lower() == "running"), None)
    if current:
        st.markdown(neon_card(current.get("step") or current.get("tool"), "Running", current.get("message", "")), unsafe_allow_html=True)
    else:
        st.markdown(neon_card("No active tool", latest.get("status", "Ready"), "Sequential runner idle."), unsafe_allow_html=True)

    section(st, "Sequential Progress Timeline")
    status_rows = read_output("outputs/recon/recon_status.json", build_execution_plan(selected))
    render_timeline(st, status_rows if isinstance(status_rows, list) else [])

    section(st, "Tool Output Preview")
    preview_counts = {item["tool"]: item["count"] for item in load_tool_counts()}
    cols = st.columns(6)
    for col, label in zip(cols, ["Subfinder Results", "Amass Results", "DNSx Validated Hosts", "HTTPx Live Hosts", "OWASP ZAP URLs", "Nmap Open Ports"]):
        with col:
            st.markdown(metric_card(label, preview_counts.get(label, 0)), unsafe_allow_html=True)

    section(st, "Logs Panel")
    render_timeline(st, events[-20:])

    section(st, "Tool Result Tabs")
    tabs = st.tabs(["Subdomains", "DNS", "Live Hosts", "Ports", "Technologies", "Endpoints", "ZAP", "Logs"])
    with tabs[0]:
        render_safe_table(st, read_output("outputs/recon/subdomains_all_sources.json", []))
    with tabs[1]:
        render_safe_table(st, read_output("outputs/recon/dns_records.json", []))
    with tabs[2]:
        render_safe_table(st, read_output("outputs/recon/live_hosts.json", []))
    with tabs[3]:
        render_safe_table(st, read_output("outputs/recon/open_ports.json", []))
    with tabs[4]:
        render_safe_table(st, read_output("outputs/recon/technologies.json", []))
    with tabs[5]:
        render_safe_table(st, read_output("outputs/recon/endpoints.json", []))
    with tabs[6]:
        render_safe_table(st, read_output("outputs/zap/zap_urls.json", []))
        render_safe_table(st, read_output("outputs/zap/zap_passive_alerts.json", []))
    with tabs[7]:
        render_safe_table(st, events[-100:])


def _safe_recon_config(config: dict[str, Any]) -> dict[str, Any]:
    safe = dict(config)
    assessment = safe.setdefault("assessment", {})
    if isinstance(assessment, dict):
        assessment["authorization_confirmed"] = True
        assessment["type"] = "Pre-Launch Black Box Testing"
    scan = safe.setdefault("scan", {})
    if isinstance(scan, dict):
        scan["safe_mode"] = True
        scan["active_scan"] = False
        scan["active_exploitation"] = False
        scan["destructive_tests"] = False
    return safe


def render_timeline(st: object, rows: list[dict[str, Any]]) -> None:
    if not rows:
        st.info("Belum ada timeline recon.")
        return
    st.markdown('<div class="cy-timeline">', unsafe_allow_html=True)
    for item in rows:
        if not isinstance(item, dict):
            continue
        title = item.get("step") or item.get("stage") or item.get("tool") or "Event"
        status = item.get("status", "Pending")
        message = item.get("message") or item.get("reason") or item.get("output_path") or ""
        stamp = item.get("timestamp") or item.get("finished_at") or item.get("started_at") or ""
        st.markdown(
            f'<div class="cy-event"><b>{_esc(title)}</b> {status_badge(status)}<div class="cy-log">{_esc(stamp)} {_esc(message)}</div></div>',
            unsafe_allow_html=True,
        )
    st.markdown("</div>", unsafe_allow_html=True)


def render_assets(st: object) -> None:
    hero(st, "Assets", "Recon-derived asset inventory", str(load_last_scan_status().get("status", "Ready")))
    counts = load_attack_surface_counts()
    cols = st.columns(4)
    for col, label in zip(cols, ["Total Hostnames", "Live Hosts", "Technologies", "External Dependencies"]):
        with col:
            st.markdown(metric_card(label, counts.get(label, 0)), unsafe_allow_html=True)
    section(st, "Hostnames")
    render_safe_table(st, read_output("outputs/recon/subdomains_all_sources.json", []))
    section(st, "Live Hosts")
    render_safe_table(st, read_output("outputs/recon/live_hosts.json", []))


def render_attack_surface(st: object) -> None:
    hero(st, "Attack Surface", "Mapped services, endpoints, technologies, and exposure categories", str(load_last_scan_status().get("status", "Ready")))
    counts = load_attack_surface_counts()
    cols = st.columns(4)
    for col, label in zip(cols, ["Open Ports", "Services", "Endpoints", "WAF/CDN Detected"]):
        with col:
            st.markdown(metric_card(label, counts.get(label, 0)), unsafe_allow_html=True)
    section(st, "Attack Surface Evidence")
    render_safe_table(st, read_output("outputs/recon/attack_surface.json", []))


def render_zap(st: object) -> None:
    hero(st, "OWASP ZAP", "Passive ZAP inventory view. No exploit automation and no active scan.", "Passive Only")
    zap_status = read_output("outputs/zap/zap_status.json", {})
    status_rows = read_output("outputs/recon/recon_status.json", [])
    status_map = {str(item.get("step")): item for item in status_rows if isinstance(item, dict)} if isinstance(status_rows, list) else {}
    urls = read_output("outputs/zap/zap_urls.json", []) or []
    alerts = read_output("outputs/zap/zap_passive_alerts.json", []) or []
    cols = st.columns(3)
    cols[0].markdown(metric_card("ZAP Daemon Status", zap_status.get("status", "Pending") if isinstance(zap_status, dict) else "Pending", f"{zap_status.get('version', '') if isinstance(zap_status, dict) else ''} {zap_status.get('api_url', '') if isinstance(zap_status, dict) else ''}"), unsafe_allow_html=True)
    cols[1].markdown(metric_card("Traditional Spider", len(urls), str(status_map.get("zap_traditional_spider", {}).get("status", "Pending"))), unsafe_allow_html=True)
    cols[2].markdown(metric_card("Passive Scan", len(alerts), str(status_map.get("zap_passive_scan", {}).get("status", "Pending"))), unsafe_allow_html=True)
    st.markdown(metric_card("Active Scan", "OFF", "Default and enforced by UI"), unsafe_allow_html=True)
    section(st, "ZAP URLs")
    render_safe_table(st, read_output("outputs/zap/zap_urls.json", []))
    section(st, "ZAP Passive Alerts")
    render_safe_table(st, read_output("outputs/zap/zap_passive_alerts.json", []))


def render_reports(st: object, config: dict[str, Any]) -> None:
    hero(st, "Reports", "Download Report / Laporan Recon", str(load_last_scan_status().get("status", "Ready")))
    html_path = Path("reports/recon_report.html")
    pdf_path = Path("reports/recon_report.pdf")
    section(st, "Recon Report")
    a, b, c, d = st.columns(4)
    if a.button("Generate HTML", type="primary", width="stretch"):
        generate_recon_report_html(config)
        st.success("HTML report dibuat.")
        st.rerun()
    if b.button("Generate PDF", width="stretch"):
        if not html_path.exists():
            generate_recon_report_html(config)
        ok = generate_pdf_from_html(str(html_path), str(pdf_path))
        st.success("PDF report dibuat.") if ok else st.warning("PDF belum tersedia. Pastikan dependency PDF terpasang.")
        st.rerun()
    c.write(f"Open report path: `{html_path}`")
    d.write(f"PDF path: `{pdf_path}`")
    if html_path.exists():
        st.download_button("Download HTML", html_path.read_bytes(), file_name="recon_report.html", mime="text/html")
    else:
        st.info("HTML report belum tersedia.")
    if pdf_path.exists():
        st.download_button("Download PDF", pdf_path.read_bytes(), file_name="recon_report.pdf", mime="application/pdf")
    else:
        st.info("PDF report belum tersedia.")

    section(st, "Report Contents Preview")
    contents = [
        "Ringkasan Eksekutif", "Target dan Scope", "Tools yang Dijalankan", "Hasil Subfinder", "Hasil Amass",
        "Hasil Assetfinder", "Hasil Certificate Transparency", "Hasil DNS", "Hasil DNSx", "Hasil HTTPx",
        "Hasil Nmap", "Hasil WhatWeb", "Hasil WAF/CDN", "Hasil Security Header", "Hasil Katana",
        "Hasil OWASP ZAP", "Hasil Nuclei", "Endpoint Penting", "Attack Surface", "Evidence", "Rekomendasi Lanjutan",
    ]
    render_safe_table(st, [{"Isi Laporan": item} for item in contents])

    section(st, "Report Status")
    rows = []
    for label, path in [("HTML", html_path), ("PDF", pdf_path)]:
        rows.append({
            "report": label,
            "status": "available" if path.exists() else "missing",
            "last generated": path.stat().st_mtime if path.exists() else "",
            "file size": path.stat().st_size if path.exists() else 0,
            "path": str(path),
        })
    render_safe_table(st, rows)


def render_settings(st: object, config: dict[str, Any]) -> None:
    hero(st, "Settings", "Minimal platform configuration", "Cyberpunk Neon")
    proxy = config.get("proxy", {}) if isinstance(config.get("proxy"), dict) else {}
    scan = config.get("scan", {}) if isinstance(config.get("scan"), dict) else {}
    rows = [
        {"setting": "ZAP host", "value": proxy.get("host", "127.0.0.1")},
        {"setting": "ZAP port", "value": proxy.get("port", 8080)},
        {"setting": "Default recon mode", "value": "Standard Recon"},
        {"setting": "Default timeout", "value": scan.get("timeout_seconds", 300)},
        {"setting": "Report language", "value": "Indonesian"},
        {"setting": "Theme", "value": "Cyberpunk Neon"},
    ]
    render_safe_table(st, rows)


def render_debug(st: object) -> None:
    hero(st, "Debug", "Raw JSON output inspection lives here only", "Debug")
    paths = [
        "outputs/recon/recon_summary.json",
        "outputs/recon/tool_run_log.json",
        "outputs/recon/recon_progress.jsonl",
        "outputs/recon/subdomains_by_source.json",
        "outputs/recon/live_hosts.json",
        "outputs/zap/zap_status.json",
        "outputs/zap/zap_urls.json",
        "outputs/zap/zap_messages.json",
        "outputs/zap/zap_alerts_raw.json",
        "outputs/zap/zap_passive_alerts.json",
        "outputs/zap/zap_endpoint_inventory.json",
        "outputs/zap/zap_spider_summary.json",
    ]
    for path in paths:
        with st.expander(path, expanded=False):
            file_path = Path(path)
            if not file_path.exists():
                st.info("missing")
            elif path.endswith(".jsonl"):
                st.code(file_path.read_text(encoding="utf-8", errors="ignore")[-12000:], language="json")
            else:
                st.json(read_output(path, {}))


def main() -> None:
    try:
        import streamlit as st
    except Exception:
        print("Streamlit is not installed. Install streamlit to run the dashboard UI.")
        return

    st.set_page_config(page_title="AI Security Analyst Platform", layout="wide")
    inject_cyberpunk_theme(st)
    config = load_config("config/config.yaml")
    workspace = render_sidebar(st)
    page = st.session_state.get("page", "Dashboard")
    st.caption(f"Workspace: {workspace} | Safety: authorized targets only, no exploit automation, no brute force, no DoS.")

    if page == "Dashboard":
        render_dashboard(st)
    elif page == "Reconnaissance":
        render_recon(st, config)
    elif page == "Assets":
        render_assets(st)
    elif page == "Attack Surface":
        render_attack_surface(st)
    elif page == "OWASP ZAP":
        render_zap(st)
    elif page == "Reports":
        render_reports(st, config)
    elif page == "Settings":
        render_settings(st, config)
    elif page == "Debug":
        render_debug(st)


if __name__ == "__main__":
    main()
