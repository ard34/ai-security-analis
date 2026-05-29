from __future__ import annotations

from agent.recon.security_header_reviewer import review_security_headers
from agent.recon.waf_cdn_detector import detect_waf_cdn
from agent.recon.web_fingerprint import fingerprint_web_hosts


def run_web_recon(config: dict[str, object], live_hosts: list[dict[str, object]], output_dir: str = "outputs/recon") -> dict[str, object]:
    tools = config.get("tools", {}) if isinstance(config.get("tools"), dict) else {}
    headers = review_security_headers(live_hosts, f"{output_dir}/security_headers.json")
    technologies = fingerprint_web_hosts(live_hosts, str(tools.get("whatweb", "whatweb")), f"{output_dir}/technologies.json")
    waf = detect_waf_cdn(headers, technologies, f"{output_dir}/waf_cdn.json")
    return {"security_headers": headers, "technologies": technologies, "waf_cdn": waf}
