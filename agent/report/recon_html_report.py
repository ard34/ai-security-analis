from __future__ import annotations

import html
from pathlib import Path

from agent.report.json_writer import read_json
from agent.report.feature_section_mapper import build_feature_sections


def _esc(value: object) -> str:
    return html.escape(str(value if value is not None else ""))


STATUS_ID = {
    "Done": "Selesai",
    "Skipped": "Dilewati",
    "Failed": "Gagal",
    "Timeout": "Waktu Habis",
    "Pending": "Menunggu",
    "Skipped or No Evidence": "Dilewati atau tidak ada evidence",
    "Skipped or No Open Ports": "Dilewati atau tidak ada port terbuka",
    "Skipped or No Services": "Dilewati atau tidak ada layanan",
}


def _status_id(value: object) -> str:
    return STATUS_ID.get(str(value), str(value if value is not None else ""))


def _table(items: list[dict[str, object]], columns: list[str]) -> str:
    labels = {
        "stage": "Tahap",
        "status": "Status",
        "purpose": "Tujuan",
        "output_summary": "Ringkasan Hasil",
        "output_path": "Output",
        "input_target": "Target Input",
        "normalized_target": "Target Normalisasi",
        "target_type": "Tipe Target",
        "registered_domain": "Registered Domain",
        "scope_mode": "Mode Scope",
        "allowed_hosts": "Host Diizinkan",
        "source": "Sumber",
        "type": "Tipe",
        "name": "Nama",
        "value": "Nilai",
        "ttl": "TTL",
        "hostname": "Hostname",
        "alive": "Aktif",
        "url": "URL",
        "status_code": "Status Code",
        "title": "Judul",
        "webserver": "Web Server",
        "content_type": "Content-Type",
        "response_time": "Response Time",
        "host": "Host",
        "port": "Port",
        "protocol": "Protokol",
        "service": "Layanan",
        "product": "Produk",
        "version": "Versi",
        "provider": "Provider",
        "method": "Metode",
        "bypass_attempted": "Bypass Dicoba",
        "missing_csp": "CSP Tidak Ada",
        "missing_hsts": "HSTS Tidak Ada",
        "missing_x_frame_options": "X-Frame-Options Tidak Ada",
        "missing_x_content_type_options": "X-Content-Type-Options Tidak Ada",
        "cookie_issues": "Masalah Cookie",
        "cors_notes": "Catatan CORS",
        "category": "Kategori",
        "screenshot": "Screenshot",
        "technologies": "Teknologi",
        "tool": "Tool",
        "duration_seconds": "Durasi",
        "result_count": "Jumlah Hasil",
        "reason": "Alasan",
        "notes": "Catatan",
        "count": "Jumlah Hasil",
        "sources": "Sumber",
        "confidence": "Confidence",
        "resolved": "DNS Resolved",
    }
    rows = []
    for item in items:
        rows.append("<tr>" + "".join(f"<td>{_esc(', '.join(value) if isinstance(value := item.get(col), list) else value)}</td>" for col in columns) + "</tr>")
    headers = "".join(f"<th>{_esc(labels.get(col, col.replace('_', ' ').title()))}</th>" for col in columns)
    empty = f"<tr><td colspan='{len(columns)}'>No data observed.</td></tr>"
    return f"<table><thead><tr>{headers}</tr></thead><tbody>{''.join(rows) or empty}</tbody></table>"


def _coverage_rows(items: list[dict[str, object]], prefix: str) -> list[dict[str, object]]:
    return [
        {
            "category": item.get("owasp_category"),
            "status": item.get("status"),
            "count": item.get("findings_count", 0),
            "modules": item.get("detection_modules_used", []),
            "notes": item.get("notes"),
        }
        for item in items
        if isinstance(item, dict) and str(item.get("owasp_category", "")).startswith(prefix)
    ]


def _tech_groups(technologies: list[dict[str, object]]) -> dict[str, set[str]]:
    groups = {"server": set(), "framework": set(), "js_libraries": set(), "backend_language_indicators": set(), "cms": set(), "waf_cdn": set()}
    for item in technologies:
        detected = item.get("detected", []) if isinstance(item, dict) else []
        for tech in detected if isinstance(detected, list) else []:
            name = str(tech.get("technology", "")) if isinstance(tech, dict) else ""
            lower = name.lower()
            if lower in {"nginx", "apache", "iis"}:
                groups["server"].add(name)
            elif lower in {"laravel", "express", "next.js", "react", "vue", "angular"}:
                groups["framework"].add(name)
            elif lower in {"jquery", "bootstrap"}:
                groups["js_libraries"].add(name)
            elif lower in {"php", "node.js"}:
                groups["backend_language_indicators"].add(name)
            elif lower == "wordpress":
                groups["cms"].add(name)
            elif lower in {"cloudflare", "akamai", "fastly", "sucuri"}:
                groups["waf_cdn"].add(name)
    return groups


def _asset_rows(live_hosts: list[dict[str, object]], waf: list[dict[str, object]], screenshots: list[dict[str, object]]) -> list[dict[str, object]]:
    waf_by_host = {str(item.get("host")): item.get("provider", "") for item in waf}
    shot_by_host = {str(item.get("host")): item.get("path", "") for item in screenshots}
    return [
        {
            "hostname": item.get("hostname"),
            "url": item.get("url"),
            "status_code": item.get("status_code"),
            "title": item.get("title"),
            "webserver": item.get("webserver"),
            "waf_cdn": waf_by_host.get(str(item.get("hostname")), ""),
            "technologies": item.get("technologies", []),
            "screenshot": shot_by_host.get(str(item.get("hostname")), ""),
        }
        for item in live_hosts
    ]


def _agent_actions(summary: dict[str, object], header_issues: int) -> list[dict[str, object]]:
    statuses = {str(item.get("stage")): item for item in summary.get("status", []) if isinstance(item, dict)}
    def status(stage: str, default: str = "Done") -> str:
        return str(statuses.get(stage, {}).get("status", default))
    return [
        {"stage": "Normalisasi target", "status": _status_id(status("Target Normalization")), "purpose": "Menormalisasi target berizin, mempertahankan port, dan menghapus fragment URL.", "output_summary": str((summary.get("target") or {}).get("normalized_url", "")), "output_path": "outputs/recon/target_normalized.json"},
        {"stage": "Definisi scope", "status": _status_id(status("Scope Definition")), "purpose": "Membangun batas host dan URL yang boleh dianalisis.", "output_summary": f"{len((summary.get('scope') or {}).get('allowed_hosts', []))} host diizinkan", "output_path": "outputs/dynamic_allowed_hosts.json"},
        {"stage": "Passive recon", "status": _status_id(status("Passive Recon")), "purpose": "Mengumpulkan metadata publik non-intrusif.", "output_summary": "WHOIS, CT, DNS, dan public repo recon opsional.", "output_path": "outputs/recon/passive_recon.json"},
        {"stage": "Penemuan subdomain", "status": _status_id(status("Subdomain Discovery")), "purpose": "Menemukan subdomain pada registered domain yang sama jika profil dan izin mengizinkan.", "output_summary": f"{summary.get('total_subdomains', 0)} subdomain", "output_path": "outputs/recon/discovered_subdomains.json"},
        {"stage": "Pengumpulan DNS record", "status": _status_id(status("DNS Record Collection")), "purpose": "Mengumpulkan record DNS standar untuk domain.", "output_summary": "A, AAAA, CNAME, MX, NS, TXT, SOA jika tersedia.", "output_path": "outputs/recon/dns_records.json"},
        {"stage": "Validasi DNS", "status": _status_id(status("DNS Record Collection")), "purpose": "Memvalidasi record DNS yang terlihat secara pasif.", "output_summary": "Record DNS dicatat untuk review manual.", "output_path": "outputs/recon/dns_records.json"},
        {"stage": "HTTP probing / live host discovery", "status": _status_id(status("Host Discovery / HTTP Probing")), "purpose": "Mengidentifikasi host web aktif dalam scope.", "output_summary": f"{summary.get('total_live_hosts', 0)} host aktif", "output_path": "outputs/recon/live_hosts.json"},
        {"stage": "Port discovery", "status": _status_id(status("Port Discovery", "Skipped")), "purpose": "Menjalankan top-port discovery aman jika diizinkan.", "output_summary": f"{summary.get('total_open_ports', 0)} port terbuka", "output_path": "outputs/recon/open_ports.json"},
        {"stage": "Enumerasi layanan", "status": _status_id(status("Service Enumeration", "Skipped")), "purpose": "Identifikasi ringan layanan pada port terbuka.", "output_summary": f"{summary.get('total_services', 0)} layanan", "output_path": "outputs/recon/services.json"},
        {"stage": "Web reconnaissance", "status": _status_id(status("Web Reconnaissance")), "purpose": "Mengumpulkan header, title, metadata response, dan evidence halaman.", "output_summary": f"{summary.get('total_live_hosts', 0)} host web", "output_path": "outputs/recon/live_hosts.json"},
        {"stage": "Fingerprinting teknologi", "status": _status_id(status("Technology Fingerprinting")), "purpose": "Mengindikasikan teknologi dari evidence web pasif dan WhatWeb jika tersedia.", "output_summary": f"{summary.get('total_web_technologies', 0)} indikator teknologi", "output_path": "outputs/recon/technologies.json"},
        {"stage": "Deteksi WAF/CDN", "status": _status_id(status("WAF/CDN Detection")), "purpose": "Mengidentifikasi indikator CDN/WAF secara pasif tanpa bypass.", "output_summary": "Signature pasif saja.", "output_path": "outputs/recon/waf_cdn.json"},
        {"stage": "Pemeriksaan security header", "status": _status_id(status("Security Header Review")), "purpose": "Memeriksa security header browser dan atribut cookie.", "output_summary": f"{header_issues} isu header/cookie", "output_path": "outputs/recon/security_headers.json"},
        {"stage": "Crawling endpoint", "status": "Selesai", "purpose": "Melakukan crawl pada URL yang diizinkan dan memisahkan dependensi eksternal.", "output_summary": f"{summary.get('total_important_endpoints', 0)} endpoint penting", "output_path": "outputs/recon/endpoints.json"},
        {"stage": "Pengambilan screenshot/evidence", "status": _status_id(status("Screenshot / Evidence Collection", "Skipped")), "purpose": "Mengambil screenshot homepage untuk host aktif dalam scope jika Playwright tersedia.", "output_summary": "Screenshot dibuat atau dilewati dengan aman.", "output_path": "outputs/recon/screenshots/"},
        {"stage": "Pemetaan attack surface", "status": _status_id(status("Attack Surface Mapping")), "purpose": "Mengelompokkan asset, endpoint, teknologi, dan layanan untuk validasi manual.", "output_summary": f"{summary.get('total_attack_surface_categories', 0)} kategori", "output_path": "outputs/recon/attack_surface.json"},
        {"stage": "Pembuatan alert potensi bug", "status": "Menunggu", "purpose": "Membuat alert potensial setelah evidence crawl/HAR tersedia.", "output_summary": "Dikerjakan pada workflow assessment penuh.", "output_path": "outputs/potential_findings.json"},
        {"stage": "Pembuatan queue validasi manual", "status": "Menunggu", "purpose": "Membuat daftar validasi manual untuk temuan potensial.", "output_summary": "Dikerjakan pada workflow assessment penuh.", "output_path": "outputs/manual_validation_queue.json"},
    ]


def generate_recon_report(summary: dict[str, object], output_path: str = "reports/recon_report.html") -> dict[str, object]:
    target = summary.get("target", {})
    scope = summary.get("scope", {})
    passive = summary.get("passive_recon", {})
    live_hosts = read_json("outputs/recon/live_hosts.json", default=[]) or []
    dns_records = read_json("outputs/recon/dns_records.json", default=[]) or []
    subdomains = read_json("outputs/recon/discovered_subdomains.json", default=[]) or []
    ports = read_json("outputs/recon/open_ports.json", default=[]) or []
    services = read_json("outputs/recon/services.json", default=[]) or []
    technologies = read_json("outputs/recon/technologies.json", default=[]) or []
    waf = read_json("outputs/recon/waf_cdn.json", default=[]) or []
    headers = read_json("outputs/recon/security_headers.json", default=[]) or []
    endpoints = read_json("outputs/recon/important_endpoints.json", default=[]) or []
    attack_surface = read_json("outputs/recon/attack_surface.json", default=[]) or []
    screenshots_index = read_json("outputs/recon/screenshot_index.json", default={}) or {}
    source_breakdown = read_json("outputs/recon/subdomains_by_source.json", default={}) or {}
    all_sources = read_json("outputs/recon/subdomains_all_sources.json", default=[]) or []
    dns_validated = read_json("outputs/recon/dns_validated_hosts.json", default=[]) or []
    tool_runs = read_json("outputs/recon/tool_run_log.json", default=[]) or []
    coverage = read_json("outputs/detection_coverage_matrix.json", default=[]) or []
    cve_correlations = read_json("outputs/cve_correlations.json", default=[]) or []
    vulnerable_components = read_json("outputs/potential_vulnerable_components.json", default=[]) or []
    screenshots = screenshots_index.get("screenshots", []) if isinstance(screenshots_index, dict) else []
    tech_groups = _tech_groups(technologies)
    header_issues = sum(int(item.get("issue_count", 0) or 0) for item in headers if isinstance(item, dict))
    assets = _asset_rows(live_hosts, waf, screenshots)
    actions = _agent_actions(summary, header_issues)
    feature_sections = build_feature_sections()

    endpoint_groups = {}
    for item in endpoints:
        endpoint_groups.setdefault(str(item.get("category", "important")), []).append(item)

    tool_rows = [
        {"tool": item.get("tool"), "status": _status_id(item.get("status")), "duration_seconds": item.get("duration_seconds"), "result_count": item.get("result_count"), "reason": item.get("reason")}
        for item in tool_runs
    ] or [
        {"tool": "subfinder", "status": _status_id(summary.get("subdomain_discovery_status", "")), "duration_seconds": "", "result_count": "", "reason": ""},
        {"tool": "httpx / requests", "status": "Selesai" if live_hosts else "Dilewati", "duration_seconds": "", "result_count": len(live_hosts), "reason": ""},
    ]
    source_rows = [{"source": source, "status": "Selesai", "count": len(values), "notes": "Sumber dijalankan atau dicatat eksplisit."} for source, values in source_breakdown.items()]
    validation_rows = []
    dns_by_host = {item.get("hostname"): item for item in dns_validated if isinstance(item, dict)}
    live_by_host = {item.get("hostname"): item for item in live_hosts if isinstance(item, dict)}
    for item in all_sources:
        if not isinstance(item, dict) or not item.get("accepted", True):
            continue
        host = item.get("hostname")
        live = live_by_host.get(host, {})
        dns = dns_by_host.get(host, {})
        validation_rows.append({"hostname": host, "sources": item.get("sources", []), "confidence": item.get("confidence", ""), "resolved": dns.get("resolved", False), "alive": bool(live), "status_code": live.get("status_code", ""), "url": live.get("url", "")})

    css = """
    body{font-family:Arial,sans-serif;margin:0;background:#f6f7f9;color:#16212f}header{background:#1c2938;color:white;padding:28px 36px}main{padding:24px 36px}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}.card,.metric{background:white;border:1px solid #d8dee6;border-radius:8px;padding:14px;margin:10px 0}
    table{width:100%;border-collapse:collapse;background:white;margin:10px 0 24px}th,td{border:1px solid #d8dee6;padding:8px;text-align:left;vertical-align:top}th{background:#edf1f5}
    img{max-width:240px;border:1px solid #d8dee6}.muted{color:#5f6b7a}
    """
    html_doc = f"""<!doctype html><html><head><meta charset="utf-8"><title>Recon Report</title><style>{css}</style></head><body>
<header><h1>Laporan Reconnaissance</h1><p>Black Box Recon. Recon aman, berizin, dan non-destruktif.</p></header><main>
<div class="card"><p>Laporan ini dibuat berdasarkan metodologi black box. AI agent hanya menganalisis informasi yang terlihat dari sisi eksternal seperti domain, subdomain, DNS, HTTP response, header, endpoint, teknologi, dan traffic browser/HAR. Semua temuan bersifat potensial sampai dilakukan validasi manual oleh analis keamanan yang berwenang.</p><p>Pengujian hanya boleh dilakukan pada target yang memiliki izin resmi. Agent tidak melakukan exploit destruktif, brute force, DoS, pencurian kredensial, upload shell, atau eksfiltrasi data.</p></div>
<h2>Ringkasan Eksekutif</h2><div class="grid">
<div class="metric"><b>Target</b><br>{_esc(target.get('normalized_url'))}</div><div class="metric"><b>Assessment Type</b><br>{_esc(summary.get('assessment_type'))}</div>
<div class="metric"><b>Total Subdomain</b><br>{len(subdomains)}</div><div class="metric"><b>Total Host Aktif</b><br>{len(live_hosts)}</div>
<div class="metric"><b>Total Port Terbuka</b><br>{len(ports)}</div><div class="metric"><b>Total Teknologi</b><br>{sum(len(v) for v in tech_groups.values())}</div>
<div class="metric"><b>Endpoint Penting</b><br>{len(endpoints)}</div><div class="metric"><b>Isu Header</b><br>{header_issues}</div></div>
<h2>Normalisasi Target</h2><div class="card">AI agent menormalisasi input target agar proses subdomain discovery berjalan pada domain utama yang benar.</div>{_table([{'input_user_asli': target.get('input'), 'domain_yang_dinormalisasi': target.get('registered_domain'), 'root_domain': target.get('registered_domain'), 'hostname_awal': target.get('hostname'), 'subdomain_recon': 'enabled' if target.get('subfinder_allowed') else 'disabled', 'alasan_jika_disabled': '; '.join(target.get('notes', [])) if isinstance(target.get('notes'), list) else target.get('notes', '')}], ['input_user_asli','domain_yang_dinormalisasi','root_domain','hostname_awal','subdomain_recon','alasan_jika_disabled'])}
<h2>Target dan Ruang Lingkup</h2>{_table([{'input_target': target.get('input'), 'normalized_target': target.get('normalized_url'), 'target_type': target.get('target_kind'), 'registered_domain': target.get('registered_domain'), 'scope_mode': scope.get('mode'), 'allowed_hosts': scope.get('allowed_hosts')}], ['input_target','normalized_target','target_type','registered_domain','scope_mode','allowed_hosts'])}<p class="muted">Dependensi eksternal dicatat saja dan tidak discan secara mendalam.</p>
<h2>Aktivitas Recon yang Dilakukan AI Agent</h2>{_table(actions, ['stage','status','purpose','output_summary','output_path'])}
<h2>Ringkasan Eksekusi Tools</h2>{_table(tool_rows, ['tool','status','duration_seconds','result_count','reason'])}
<h2>Hasil Passive Recon</h2>{_table([{'source':'WHOIS','status':_status_id(passive.get('whois'))},{'source':'DNS records','status':passive.get('dns_records')},{'source':'Certificate Transparency','status':passive.get('ct_subdomains')},{'source':'Subfinder','status':_status_id(summary.get('subdomain_discovery_status'))},{'source':'Public repo recon','status':_status_id(passive.get('public_repo_recon'))},{'source':'Technology fingerprinting','status':'Selesai' if technologies else 'Dilewati'}], ['source','status'])}
<h2>Hasil Subfinder</h2><div class="card">Status: {_esc(feature_sections['subfinder']['status'])}. Jumlah subdomain: {_esc(feature_sections['subfinder']['summary_metrics'].get('jumlah_hasil', 0))}. Catatan: {_esc(feature_sections['subfinder']['notes'])}</div>{_table([{'hostname': item} for item in feature_sections['subfinder']['table_data']], ['hostname'])}
<h2>Hasil Amass Passive</h2><div class="card">Status: {_esc(feature_sections['amass']['status'])}. Jumlah hasil: {_esc(feature_sections['amass']['summary_metrics'].get('jumlah_hasil', 0))}. Catatan: {_esc(feature_sections['amass']['notes'])}</div>{_table([{'hostname': item} for item in feature_sections['amass']['table_data']], ['hostname'])}
<h2>Hasil Assetfinder</h2><div class="card">Status: {_esc(feature_sections['assetfinder']['status'])}. Jumlah hasil: {_esc(feature_sections['assetfinder']['summary_metrics'].get('jumlah_hasil', 0))}. Catatan: {_esc(feature_sections['assetfinder']['notes'])}</div>{_table([{'hostname': item} for item in feature_sections['assetfinder']['table_data']], ['hostname'])}
<h2>Hasil Certificate Transparency</h2><div class="card">Status: {_esc(feature_sections['certificate_transparency']['status'])}. Jumlah hasil: {_esc(feature_sections['certificate_transparency']['summary_metrics'].get('jumlah_hasil', 0))}.</div>{_table([{'hostname': item} for item in feature_sections['certificate_transparency']['table_data']], ['hostname'])}
<h2>Penemuan Subdomain Berdasarkan Sumber</h2>{_table(source_rows, ['source','status','count','notes'])}
<h2>Penemuan Subdomain</h2>{_table(subdomains, ['hostname','source','alive','url','status_code'])}
<h2>Validasi Subdomain</h2>{_table(validation_rows, ['hostname','sources','confidence','resolved','alive','status_code','url'])}
<h2>Hasil DNS Records</h2>{_table(dns_records, ['type','name','value','ttl'])}
<h2>Hasil DNS Validation</h2>{_table(read_json("outputs/recon/dns_validated_hosts.json", default=[]) or [], ['hostname','resolved','record_types_found','sources','confidence'])}
<h2>Host Aktif</h2>{_table(live_hosts, ['hostname','url','status_code','title','webserver','content_type','response_time','target_type','source'])}
<h2>Hasil HTTPx / Live Host Discovery</h2><div class="card">{_esc(feature_sections['httpx']['summary_metrics'])}</div>{_table(live_hosts, ['hostname','url','status_code','title','webserver','content_type','response_time','target_type','source'])}
<h2>Port dan Layanan</h2>
<h2>Hasil Nmap / Port Discovery</h2>{_table(services, ['host','port','protocol','service','product','version'])}
<h2>Teknologi yang Terdeteksi</h2>
<h2>Hasil WhatWeb / Technology Fingerprint</h2>{''.join(f'<div class="card"><b>{_esc(key.replace("_"," ").title())}</b><br>{_esc(", ".join(sorted(values)) if values else "Tidak ada data.")}</div>' for key, values in tech_groups.items())}
<h2>Deteksi WAF/CDN</h2>
<h2>Hasil WAF/CDN Detection</h2>{_table(waf, ['host','provider','method','bypass_attempted'])}
<h2>Pemeriksaan Security Header</h2>
<h2>Hasil Security Header Review</h2>{_table(headers, ['host','missing_csp','missing_hsts','missing_x_frame_options','missing_x_content_type_options','cookie_issues','cors_notes'])}
<h2>Hasil OWASP ZAP Spider</h2><div class="card">Status: {_esc(feature_sections['zap']['status'])}. Source: outputs/zap/zap_spider_summary.json</div>
<h2>Hasil OWASP ZAP Passive Scan</h2>{_table(feature_sections['zap']['table_data'], ['alert','risk','confidence','url','param'])}
<h2>Endpoint Penting</h2>{''.join(f'<h3>{_esc(category)}</h3>{_table(items, ["url","hostname","category"])}' for category, items in endpoint_groups.items()) or '<div class="card">Tidak ada endpoint penting yang terlihat.</div>'}
<h2>Pemetaan Attack Surface</h2>{''.join(f'<div class="card"><h3>{_esc(item.get("category"))}</h3><p><b>Asset terdampak:</b> {_esc(len(item.get("assets", [])))}</p><p><b>Risk hint:</b> {_esc("; ".join(item.get("risk_hints", [])))}</p><p><b>Validasi manual:</b> {_esc("; ".join(item.get("recommended_manual_checks", [])))}</p></div>' for item in attack_surface)}
<h2>Ringkasan OWASP Top 10</h2>{_table(_coverage_rows(coverage if isinstance(coverage, list) else [], "A"), ['category','status','count','modules','notes'])}
<h2>Ringkasan OWASP API Top 10</h2>{_table(_coverage_rows(coverage if isinstance(coverage, list) else [], "API"), ['category','status','count','modules','notes'])}
<h2>Korelasi CVE</h2>{_table(cve_correlations if isinstance(cve_correlations, list) else [], ['cve_id','affected_asset','detected_product','detected_version','cvss_score','severity','confidence','cve_source','validation_guidance','remediation_guidance'])}
<h2>Komponen Rentan dan Outdated</h2>{_table(vulnerable_components if isinstance(vulnerable_components, list) else [], ['product','version','host','related_cves','highest_severity','confidence','remediation'])}
<h2>Screenshot dan Evidence</h2>{''.join(f'<div class="card"><b>{_esc(item.get("host"))}</b><br><span>{_esc(item.get("path"))}</span></div>' for item in screenshots) or '<div class="card">Screenshot/evidence dilewati atau tidak tersedia.</div>'}
<h2>Langkah Lanjutan</h2><div class="card">Lanjutkan ke authenticated crawl, lakukan login manual melalui Burp/browser, validasi potensi IDOR/BOLA, logic autentikasi, dan business logic secara aman, lalu buat laporan assessment penuh.</div>
</main></body></html>"""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(html_doc, encoding="utf-8")
    return {"html": output_path, "header_issues": header_issues}
