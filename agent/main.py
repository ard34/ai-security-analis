from __future__ import annotations

import argparse


MODES = {
    "headers",
    "crawl",
    "recon",
    "open-browser",
    "launch-auth-browser",
    "authenticated-crawl",
    "import-burp-history",
    "analyze-history",
    "report",
    "full",
    "nuclei",
}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AI Security Analyst Platform")
    parser.add_argument("--config", default="config/config.yaml", help="Path to config.yaml")
    parser.add_argument("--target", default=None, help="Authorized target URL")
    parser.add_argument("--mode", required=True, choices=sorted(MODES), help="Execution mode")
    parser.add_argument("--har", default="tmp/burp_history.har", help="HAR path for import-burp-history")
    return parser


def _target_config(config: dict[str, object]) -> dict[str, object]:
    return config.get("target", {}) if isinstance(config.get("target"), dict) else {}


def _scan_config(config: dict[str, object]) -> dict[str, object]:
    return config.get("scan", {}) if isinstance(config.get("scan"), dict) else {}


def _tools_config(config: dict[str, object]) -> dict[str, object]:
    return config.get("tools", {}) if isinstance(config.get("tools"), dict) else {}


def _run_crawl(scope: dict[str, object], config: dict[str, object]) -> list[str]:
    from agent.recon.auth_endpoint_detector import detect_auth_endpoints
    from agent.recon.katana_runner import run_katana

    allowed_urls = [str(url) for url in scope.get("allowed_urls", [])] if isinstance(scope.get("allowed_urls"), list) else []
    allowed_hosts = [str(host) for host in scope.get("allowed_hosts", [])] if isinstance(scope.get("allowed_hosts"), list) else []
    endpoints = run_katana(
        allowed_urls,
        allowed_hosts,
        max_urls_per_host=int(_scan_config(config).get("max_urls_per_host", 200)),
        command=str(_tools_config(config).get("katana", "katana")),
    )
    detect_auth_endpoints()
    return endpoints


def _build_scope(target_url: str, config: dict[str, object], force: bool = False) -> dict[str, object]:
    from agent.core.dynamic_scope import ensure_dynamic_scope
    from agent.core.scope_validator import enforce_url_scope

    scope = ensure_dynamic_scope(target_url, config, force=force)
    allowed_hosts = [str(host) for host in scope.get("allowed_hosts", [])] if isinstance(scope.get("allowed_hosts"), list) else []
    enforce_url_scope(target_url, allowed_hosts)
    return scope


def _run_recon_all(scope: dict[str, object], config: dict[str, object]) -> None:
    from agent.recon.header_analyzer import analyze_headers
    from agent.recon.technology_fingerprint import fingerprint
    from agent.report.json_writer import write_json
    from agent.core.scope_validator import get_hostname

    allowed_urls = [str(url) for url in scope.get("allowed_urls", [])] if isinstance(scope.get("allowed_urls"), list) else []
    header_results = []
    header_findings = []
    fingerprint_results = []
    for url in allowed_urls:
        hostname = get_hostname(url)
        header_result = analyze_headers(url, output_path=f"outputs/security_headers/{hostname}.json")
        header_results.append(header_result)
        header_findings.extend(header_result.get("findings", []))
        fingerprint_results.append(
            fingerprint(url, str(_tools_config(config).get("whatweb", "whatweb")), output_path=f"outputs/technology_fingerprint/{hostname}.json")
        )
    write_json("outputs/security_headers.json", {"hosts": header_results, "findings": header_findings})
    write_json("outputs/technology_fingerprint.json", {"hosts": fingerprint_results, "note": "Fingerprint evidence only. CVE correlation is potential until manually validated."})


def _run_har_pipeline(har_path: str, allowed_hosts: list[str]) -> dict[str, object]:
    from agent.analysis.finding_builder import build_findings
    from agent.analysis.potential_bug_analyzer import analyze_potential_bugs
    from agent.traffic.endpoint_classifier import classify_history
    from agent.traffic.har_importer import import_har
    from agent.report.json_writer import write_json

    history = import_har(har_path, allowed_hosts=allowed_hosts)
    classify_history()
    findings = analyze_potential_bugs(evidence_source="Authenticated Browser Crawl" if "authenticated_session" in har_path else "Burp HAR")
    write_json("outputs/alerts.json", [{"title": item.get("title"), "severity": item.get("severity"), "url": item.get("url"), "status": "Potential", "manual_validation_required": True} for item in findings])
    summary = build_findings()
    return {"history_count": len(history), "summary": summary}


def _auth_start_url(target_url: str) -> str:
    from agent.report.json_writer import read_json

    auth_endpoints = read_json("outputs/auth_endpoints.json", default=[]) or []
    return str(auth_endpoints[0]) if auth_endpoints else target_url


def _launch_auth_browser(target_url: str, config: dict[str, object]) -> bool:
    from agent.crawler.crawl_state import set_state
    from agent.integrations.burp_controller import ensure_burp_running
    from agent.integrations.playwright_controller import launch_browser_for_login

    proxy_ready = ensure_burp_running(config)
    set_state("burp_proxy_ready", proxy_ready)
    if not proxy_ready:
        return False
    proxy = config.get("proxy", {}) if isinstance(config.get("proxy"), dict) else {}
    browser = config.get("browser", {}) if isinstance(config.get("browser"), dict) else {}
    launch_browser_for_login(_auth_start_url(target_url), proxy, str(browser.get("user_data_dir", "")))
    set_state("browser_opened", True)
    set_state("waiting_for_manual_login", True)
    return True


def main() -> None:
    args = _parser().parse_args()

    from agent.core.config_loader import load_config
    from agent.core.logger import setup_logger

    logger = setup_logger()
    config = load_config(args.config)
    target_url = args.target or str(_target_config(config).get("base_url", ""))
    scope = {}
    if args.mode not in {"report", "analyze-history"}:
        scope = _build_scope(target_url, config, force=args.mode in {"full", "recon", "crawl"})

    if args.mode == "headers":
        from agent.recon.header_analyzer import analyze_headers

        logger.info("Running security header analysis")
        analyze_headers(target_url)
    elif args.mode == "crawl":
        logger.info("Running safe crawl")
        _run_crawl(scope, config)
    elif args.mode == "recon":
        from agent.analysis.finding_builder import build_findings

        logger.info("Running recon")
        _run_recon_all(scope, config)
        _run_crawl(scope, config)
        build_findings()
    elif args.mode == "open-browser":
        from agent.integrations.browser_launcher import launch_browser
        from agent.report.json_writer import read_json

        auth_endpoints = read_json("outputs/auth_endpoints.json", default=[]) or []
        launch_browser(auth_endpoints[0] if auth_endpoints else target_url, config)
    elif args.mode == "launch-auth-browser":
        logger.info("Launching Burp-backed authenticated browser")
        if _launch_auth_browser(target_url, config):
            print("Login/register manually in the opened browser. After login and landing on dashboard/user area, return here and run authenticated-crawl.")
    elif args.mode == "import-burp-history":
        allowed_hosts = [str(host) for host in scope.get("allowed_hosts", [])] if isinstance(scope.get("allowed_hosts"), list) else []
        _run_har_pipeline(args.har, allowed_hosts)
    elif args.mode == "authenticated-crawl":
        from agent.crawler.authenticated_crawler import run_authenticated_crawl
        from agent.crawler.crawl_state import set_state
        from agent.integrations.burp_controller import ensure_burp_running

        allowed_hosts = [str(host) for host in scope.get("allowed_hosts", [])] if isinstance(scope.get("allowed_hosts"), list) else []
        proxy_ready = ensure_burp_running(config)
        set_state("burp_proxy_ready", proxy_ready)
        if not proxy_ready:
            return
        set_state("manual_login_completed", True)
        summary = run_authenticated_crawl(target_url, config)
        _run_har_pipeline(str(summary.get("har_path", "tmp/authenticated_session.har")), allowed_hosts)
        set_state("authenticated_crawl_completed", True)
        set_state("waiting_for_manual_login", False)
    elif args.mode == "analyze-history":
        from agent.analysis.finding_builder import build_findings
        from agent.analysis.potential_bug_analyzer import analyze_potential_bugs
        from agent.traffic.endpoint_classifier import classify_history

        classify_history()
        analyze_potential_bugs()
        build_findings()
    elif args.mode == "report":
        from agent.report.report_generator import generate_report

        generate_report(config, target_url)
    elif args.mode == "full":
        from agent.analysis.finding_builder import build_findings
        from agent.crawler.crawl_state import reset_state, set_state
        from agent.report.json_writer import read_json

        reset_state()
        _run_recon_all(scope, config)
        _run_crawl(scope, config)
        build_findings()
        auth_endpoints = read_json("outputs/auth_endpoints.json", default=[]) or []
        set_state("auth_endpoint_detected", bool(auth_endpoints))
        if auth_endpoints:
            print("Login/register endpoint found. Run mode launch-auth-browser to continue manual login.")
        else:
            print("No login/register endpoint detected. Manual HAR import remains available.")
    elif args.mode == "nuclei":
        from agent.scanners.nuclei_runner import run_nuclei

        run_nuclei(scope.get("allowed_urls", []), str(_tools_config(config).get("nuclei", "nuclei")))


if __name__ == "__main__":
    main()
