from __future__ import annotations

import html
from pathlib import Path
from urllib.parse import urlparse

from agent.analysis.finding_builder import build_findings
from agent.report.asset_inventory_builder import build_asset_inventory
from agent.report.json_writer import read_json


def _esc(value: object) -> str:
    return html.escape(str(value if value is not None else ""))


def _severity_counts(findings: list[dict[str, object]]) -> dict[str, int]:
    counts = {"High": 0, "Medium": 0, "Low": 0}
    for finding in findings:
        severity = str(finding.get("severity", "Low")).title()
        if severity in counts:
            counts[severity] += 1
    return counts


ALERT_TITLE_ID = {
    "Potential IDOR/BOLA": "Potensi IDOR/BOLA",
    "Potential BFLA": "Potensi BFLA",
    "Potential Business Logic Flaw": "Potensi Kelemahan Business Logic",
    "Potential Business Logic Weakness": "Potensi Kelemahan Business Logic",
    "Potential Authentication Weakness": "Potensi Kelemahan Autentikasi",
    "Potential Injection Point": "Potensi Titik Injection",
    "Potential Open Redirect": "Potensi Open Redirect",
    "Potential File Access Risk": "Potensi Risiko Akses File",
    "Potential Sensitive Data Exposure": "Potensi Kebocoran Data Sensitif",
    "Potential Security Misconfiguration": "Potensi Kesalahan Konfigurasi Keamanan",
    "Potential Vulnerable Component": "Potensi Komponen Rentan",
}


STATUS_ID = {
    "Done": "Selesai",
    "Skipped": "Dilewati",
    "Failed": "Gagal",
    "Timeout": "Waktu Habis",
    "Pending": "Menunggu",
    "Potential": "Potensial",
}


def _status_id(value: object) -> str:
    return STATUS_ID.get(str(value), str(value if value is not None else ""))


def _rows(items: list[dict[str, object]], columns: list[str]) -> str:
    body = []
    for item in items:
        body.append("<tr>" + "".join(f"<td>{_esc(', '.join(value) if isinstance(value := item.get(col), list) else value)}</td>" for col in columns) + "</tr>")
    return "".join(body) or f"<tr><td colspan='{len(columns)}'>No data observed.</td></tr>"


def _list_text(value: object) -> str:
    if isinstance(value, list):
        return ", ".join(str(item) for item in value if item)
    if isinstance(value, dict):
        return ", ".join(f"{key}: {val}" for key, val in value.items())
    return str(value if value is not None else "")


def _coverage_rows(items: list[dict[str, object]], prefix: str) -> str:
    rows = []
    for item in items:
        category = str(item.get("owasp_category", ""))
        if not category.startswith(prefix):
            continue
        rows.append(
            "<tr>"
            f"<td>{_esc(category)}</td>"
            f"<td>{_esc(item.get('status'))}</td>"
            f"<td>{_esc(item.get('findings_count', 0))}</td>"
            f"<td>{_esc(_list_text(item.get('detection_modules_used')))}</td>"
            f"<td>{_esc(item.get('notes'))}</td>"
            "</tr>"
        )
    return "".join(rows) or "<tr><td colspan='5'>Belum ada data coverage.</td></tr>"


def _cve_rows(items: list[dict[str, object]]) -> str:
    rows = []
    for item in items:
        rows.append(
            "<tr>"
            f"<td>{_esc(item.get('cve_id'))}</td>"
            f"<td>{_esc(item.get('affected_asset'))}</td>"
            f"<td>{_esc(item.get('detected_product'))}</td>"
            f"<td>{_esc(item.get('detected_version'))}</td>"
            f"<td>{_esc(item.get('cvss_score'))}</td>"
            f"<td>{_esc(item.get('severity'))}</td>"
            f"<td>{_esc(item.get('confidence'))}</td>"
            f"<td>{_esc(item.get('cve_source'))}</td>"
            f"<td>{_esc(item.get('validation_guidance'))}</td>"
            f"<td>{_esc(item.get('remediation_guidance'))}</td>"
            "</tr>"
        )
    return "".join(rows) or "<tr><td colspan='10'>Tidak ada potensi korelasi CVE yang tersedia.</td></tr>"


def _component_rows(items: list[dict[str, object]]) -> str:
    rows = []
    for item in items:
        rows.append(
            "<tr>"
            f"<td>{_esc(item.get('product'))}</td>"
            f"<td>{_esc(item.get('version'))}</td>"
            f"<td>{_esc(item.get('host'))}</td>"
            f"<td>{_esc(_list_text(item.get('related_cves')))}</td>"
            f"<td>{_esc(item.get('highest_severity'))}</td>"
            f"<td>{_esc(item.get('confidence'))}</td>"
            f"<td>{_esc(item.get('remediation'))}</td>"
            "</tr>"
        )
    return "".join(rows) or "<tr><td colspan='7'>Tidak ada komponen rentan yang terindikasi.</td></tr>"


def _alert_card(finding: dict[str, object]) -> str:
    endpoint = str(finding.get("endpoint") or finding.get("url") or "")
    title = ALERT_TITLE_ID.get(str(finding.get("title")), str(finding.get("title", "")))
    request = finding.get("request_summary", {}) if isinstance(finding.get("request_summary"), dict) else {}
    response = finding.get("response_summary", {}) if isinstance(finding.get("response_summary"), dict) else {}
    return f"""
    <article class="card alert">
      <div><strong>{_esc(title)}</strong><span>{_esc(finding.get('severity'))} / {_esc(finding.get('confidence'))}</span></div>
      <p><b>Status:</b> Potensial. <b>Host Terdampak:</b> {_esc(urlparse(endpoint).hostname or '')}</p>
      <p><b>Tingkat Risiko:</b> {_esc(finding.get('severity'))}. <b>Tingkat Keyakinan:</b> {_esc(finding.get('confidence'))}</p>
      <p><b>Endpoint:</b> {_esc(endpoint)}. <b>Method:</b> {_esc(finding.get('method'))}</p>
      <p><b>Parameter:</b> {_esc(_list_text(finding.get('suspicious_parameters')))}</p>
      <p><b>Terlihat di:</b> {_esc(_list_text(finding.get('observed_in')))}</p>
      <p><b>Request:</b> {_esc(request.get('method', finding.get('method')))} {_esc(request.get('path', endpoint))}</p>
      <p><b>Response:</b> status {_esc(response.get('status_code'))}, content-type {_esc(response.get('content_type'))}, length {_esc(response.get('response_length'))}</p>
      <p><b>Evidence ringkas:</b> {_esc(response.get('evidence_snippet_masked') or finding.get('evidence') or finding.get('evidence_source'))}</p>
      <p><b>OWASP Web:</b> {_esc(finding.get('owasp_web'))}. <b>OWASP API:</b> {_esc(finding.get('owasp_api'))}</p>
      <p><b>CVE/CWE:</b> {_esc(_list_text(finding.get('cve_ids')))} {_esc(_list_text(finding.get('cwe_ids') or finding.get('cwe_optional')))}</p>
      <p><b>Fokus testing manual:</b> {_esc(_list_text(finding.get('manual_test_focus')))}</p>
      <p><b>Langkah Validasi Manual:</b> {_esc(_list_text(finding.get('validation_steps')))}</p>
      <p><b>Expected secure behavior:</b> {_esc(finding.get('expected_secure_behavior'))}</p>
      <p><b>Vulnerable behavior:</b> {_esc(finding.get('vulnerable_behavior'))}</p>
      <p><b>Rekomendasi:</b> {_esc(finding.get('remediation') or finding.get('recommendation'))}</p>
      <p><b>Catatan Pengujian Aman:</b> {_esc(finding.get('safe_testing_note', 'Validasi manual saja; jangan brute force, exploit, DoS, upload shell, atau eksfiltrasi data.'))}</p>
    </article>
    """


def _agent_actions(summary: dict[str, object], recon_summary: dict[str, object], auth_summary: dict[str, object], findings: list[dict[str, object]], manual_queue: list[dict[str, object]]) -> list[dict[str, object]]:
    recon_status = {str(item.get("stage")): item for item in recon_summary.get("status", []) if isinstance(item, dict)}
    def status(stage: str, default: str = "Done") -> str:
        return str(recon_status.get(stage, {}).get("status", default))
    history = read_json("outputs/http_history.json", default=[]) or []
    return [
        {"stage": "Normalisasi target", "status": _status_id(status("Target Normalization")), "purpose": "Menormalisasi target dan menghapus fragment sambil mempertahankan host, scheme, dan port.", "output_summary": str((recon_summary.get("target") or {}).get("normalized_url", "")), "output_path": "outputs/target_normalized.json"},
        {"stage": "Definisi scope", "status": _status_id(status("Scope Definition")), "purpose": "Mendefinisikan dynamic scope yang berizin.", "output_summary": f"{len((recon_summary.get('scope') or {}).get('allowed_hosts', []))} host diizinkan", "output_path": "outputs/dynamic_allowed_hosts.json"},
        {"stage": "Passive recon", "status": _status_id(status("Passive Recon")), "purpose": "Mengumpulkan metadata publik tanpa pengujian intrusif.", "output_summary": "WHOIS, DNS, CT, public repo recon opsional.", "output_path": "outputs/recon/passive_recon.json"},
        {"stage": "Penemuan subdomain", "status": _status_id(status("Subdomain Discovery")), "purpose": "Menemukan subdomain dalam domain yang sama jika diizinkan.", "output_summary": f"{recon_summary.get('total_subdomains', 0)} subdomain", "output_path": "outputs/recon/discovered_subdomains.json"},
        {"stage": "Pengumpulan DNS record", "status": _status_id(status("DNS Record Collection")), "purpose": "Mengumpulkan DNS record standar.", "output_summary": "DNS record dikumpulkan jika tersedia.", "output_path": "outputs/recon/dns_records.json"},
        {"stage": "Validasi DNS", "status": _status_id(status("DNS Record Collection")), "purpose": "Memvalidasi data DNS yang terlihat untuk konteks recon.", "output_summary": "DNS dicatat untuk review manual.", "output_path": "outputs/recon/dns_records.json"},
        {"stage": "HTTP probing / live host discovery", "status": _status_id(status("Host Discovery / HTTP Probing")), "purpose": "Mengidentifikasi host web aktif.", "output_summary": f"{recon_summary.get('total_live_hosts', 0)} host aktif", "output_path": "outputs/recon/live_hosts.json"},
        {"stage": "Port discovery", "status": _status_id(status("Port Discovery", "Skipped")), "purpose": "Top-port discovery aman jika diizinkan.", "output_summary": f"{recon_summary.get('total_open_ports', 0)} port terbuka", "output_path": "outputs/recon/open_ports.json"},
        {"stage": "Enumerasi layanan", "status": _status_id(status("Service Enumeration", "Skipped")), "purpose": "Identifikasi ringan layanan.", "output_summary": f"{recon_summary.get('total_services', 0)} layanan", "output_path": "outputs/recon/services.json"},
        {"stage": "Web reconnaissance", "status": _status_id(status("Web Reconnaissance")), "purpose": "Mereview metadata web, header, dan evidence halaman.", "output_summary": f"{recon_summary.get('total_live_hosts', 0)} host", "output_path": "outputs/recon/live_hosts.json"},
        {"stage": "Fingerprinting teknologi", "status": _status_id(status("Technology Fingerprinting")), "purpose": "Mengidentifikasi teknologi web yang terlihat.", "output_summary": f"{recon_summary.get('total_web_technologies', 0)} indikator", "output_path": "outputs/recon/technologies.json"},
        {"stage": "Deteksi WAF/CDN", "status": _status_id(status("WAF/CDN Detection")), "purpose": "Mengidentifikasi indikator CDN/WAF pasif.", "output_summary": "Tidak ada bypass WAF.", "output_path": "outputs/recon/waf_cdn.json"},
        {"stage": "Pemeriksaan security header", "status": _status_id(status("Security Header Review")), "purpose": "Mereview security header browser dan atribut cookie.", "output_summary": "Isu hardening potensial saja.", "output_path": "outputs/recon/security_headers.json"},
        {"stage": "Crawling endpoint", "status": "Selesai", "purpose": "Melakukan crawl URL yang diizinkan dan mengklasifikasikan endpoint penting.", "output_summary": f"{summary.get('total_endpoints', 0)} endpoint", "output_path": "outputs/recon/endpoints.json"},
        {"stage": "Pengambilan screenshot/evidence", "status": _status_id(status("Screenshot / Evidence Collection", "Skipped")), "purpose": "Mengambil screenshot host dalam scope jika tersedia.", "output_summary": "Evidence selesai atau dilewati dengan aman.", "output_path": "outputs/recon/screenshots/"},
        {"stage": "Pemetaan attack surface", "status": _status_id(status("Attack Surface Mapping")), "purpose": "Memetakan evidence recon menjadi area validasi manual.", "output_summary": f"{recon_summary.get('total_attack_surface_categories', 0)} kategori", "output_path": "outputs/recon/attack_surface.json"},
        {"stage": "Pembuatan alert potensi bug", "status": "Selesai", "purpose": "Membuat alert potensial dari evidence black box.", "output_summary": f"{len(findings)} alert", "output_path": "outputs/potential_findings.json"},
        {"stage": "Pembuatan queue validasi manual", "status": "Selesai", "purpose": "Membuat daftar tugas validasi analis untuk temuan potensial.", "output_summary": f"{len(manual_queue)} item queue", "output_path": "outputs/manual_validation_queue.json"},
        {"stage": "Analisis request/response", "status": "Selesai" if history else "Menunggu", "purpose": "Menganalisis traffic HAR/browser yang berada dalam scope.", "output_summary": f"{len(history)} request", "output_path": "outputs/http_history.json"},
        {"stage": "Authenticated crawl", "status": "Selesai" if auth_summary else "Menunggu", "purpose": "Menggunakan sesi browser terautentikasi milik analis untuk crawl aman.", "output_summary": f"{auth_summary.get('total_urls_crawled', 0) if isinstance(auth_summary, dict) else 0} URL", "output_path": "outputs/authenticated_crawl_summary.json"},
    ]


def generate_dashboard(config: dict[str, object], target: str, assessment_type: str, output_path: str = "reports/assessment.html") -> dict[str, object]:
    summary = build_findings()
    inventory = build_asset_inventory()
    assets = inventory.get("assets", []) if isinstance(inventory.get("assets"), list) else []
    endpoints = inventory.get("important_endpoints", []) if isinstance(inventory.get("important_endpoints"), list) else []
    findings = summary.get("all_findings", []) if isinstance(summary.get("all_findings"), list) else []
    counts = _severity_counts(findings)
    auth_summary = read_json("outputs/authenticated_crawl_summary.json", default={}) or {}
    forms = read_json("outputs/forms_discovered.json", default=[]) or []
    auth_urls = read_json("outputs/authenticated_crawl_urls.json", default=[]) or []
    external = summary.get("external_dependencies", []) if isinstance(summary.get("external_dependencies"), list) else []
    headers = read_json("outputs/security_headers.json", default={}) or {}
    recon_summary = read_json("outputs/recon/recon_summary.json", default={}) or {}
    manual_queue = read_json("outputs/manual_validation_queue.json", default=[]) or []
    coverage = read_json("outputs/detection_coverage_matrix.json", default=[]) or []
    api_candidates = read_json("outputs/api_top10_candidates.json", default=[]) or []
    cve_correlations = read_json("outputs/cve_correlations.json", default=[]) or []
    vulnerable_components = read_json("outputs/potential_vulnerable_components.json", default=[]) or []
    actions = _agent_actions(summary, recon_summary, auth_summary if isinstance(auth_summary, dict) else {}, findings, manual_queue if isinstance(manual_queue, list) else [])
    final_recommendation = "Needs Manual Validation" if findings else "Ready"
    if counts["High"]:
        final_recommendation = "Needs Fix Before Launch"

    css = """
    body{font-family:Arial,sans-serif;margin:0;color:#17202a;background:#f7f8fa}header{background:#17202a;color:#fff;padding:28px 36px}
    main{padding:24px 36px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}.metric,.card{background:#fff;border:1px solid #d8dee6;border-radius:8px;padding:14px}
    table{width:100%;border-collapse:collapse;background:#fff;margin:10px 0 24px}th,td{border:1px solid #d8dee6;padding:8px;text-align:left;vertical-align:top}th{background:#eef1f5}
    h2{margin-top:28px}.alert{margin:12px 0}.alert div{display:flex;justify-content:space-between;gap:16px}.muted{color:#5f6b7a}
    """
    html_doc = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Assessment Report</title><style>{css}</style></head>
<body>
<header><h1>Laporan Assessment AI Security Analyst</h1><p>Metodologi Black Box. Semua alert bersifat potensial dan perlu validasi manual.</p></header>
<main>
<div class="card"><p>Laporan ini dibuat berdasarkan metodologi black box. AI agent hanya menganalisis informasi yang terlihat dari sisi eksternal seperti domain, subdomain, DNS, HTTP response, header, endpoint, teknologi, dan traffic browser/HAR. Semua temuan bersifat potensial sampai dilakukan validasi manual oleh analis keamanan yang berwenang.</p><p>Pengujian hanya boleh dilakukan pada target yang memiliki izin resmi. Agent tidak melakukan exploit destruktif, brute force, DoS, pencurian kredensial, upload shell, atau eksfiltrasi data.</p></div>
<h2>Ringkasan Eksekutif</h2>
<div class="grid">
<div class="metric"><b>Target</b><br>{_esc(target)}</div><div class="metric"><b>Assessment Type</b><br>{_esc(assessment_type)}</div>
<div class="metric"><b>Total Asset</b><br>{len(assets)}</div><div class="metric"><b>Total Endpoint</b><br>{summary.get('total_endpoints', 0)}</div>
<div class="metric"><b>Alert Potensial</b><br>{len(findings)}</div><div class="metric"><b>Ringkasan Risiko</b><br>High {counts['High']} / Medium {counts['Medium']} / Low {counts['Low']}</div>
</div>
<h2>Target dan Ruang Lingkup</h2><div class="card"><p>Target: <b>{_esc(target)}</b></p><p>Assessment Type: {_esc(assessment_type)}</p><p>Scope mengikuti dynamic allowed hosts yang dibangun pada fase recon.</p></div>
<h2>Metodologi Black Box</h2><div class="card">AI agent hanya menggunakan evidence eksternal: domain, subdomain, DNS, HTTP response, header, endpoint, teknologi, screenshot, dan traffic browser/HAR. Tidak ada akses source code, database, konfigurasi internal, atau exploit destruktif.</div>
<h2>Aktivitas yang Dilakukan AI Agent</h2><table><thead><tr>{"".join(f"<th>{_esc(col)}</th>" for col in ["Tahap","Status","Tujuan","Ringkasan Hasil","Output"])}</tr></thead><tbody>{_rows(actions, ["stage","status","purpose","output_summary","output_path"])}</tbody></table>
<h2>Ringkasan Recon</h2><div class="card"><p>Laporan recon: <b>reports/recon_report.html</b></p><p>Total host aktif: {_esc(recon_summary.get('total_live_hosts', 0))}. Port terbuka: {_esc(recon_summary.get('total_open_ports', 0))}. Endpoint penting: {_esc(recon_summary.get('total_important_endpoints', 0))}. Kategori attack surface: {_esc(recon_summary.get('total_attack_surface_categories', 0))}.</p></div>
<h2>Ringkasan Authenticated Crawl</h2><div class="card"><p>Browser dibuka melalui Burp: {_esc(bool(auth_summary))}. Login manual diperlukan: true.</p><p>URL authenticated crawl: {len(auth_urls)}. Form ditemukan: {len(forms)}. Aksi berisiko dilewati: {len(auth_summary.get("risky_actions_skipped", []) if isinstance(auth_summary, dict) else [])}. Sumber HAR: {_esc(auth_summary.get("har_path", "tmp/authenticated_session.har") if isinstance(auth_summary, dict) else "tmp/authenticated_session.har")}.</p></div>
<h2>Ringkasan Analisis Request/Response</h2><div class="card"><p>Total request dianalisis: {_esc(len(read_json("outputs/http_history.json", default=[]) or []))}. Klasifikasi endpoint disimpan internal dan digunakan untuk alert potensial serta queue validasi manual.</p></div>
<h2>Ringkasan OWASP Top 10</h2>
<table><thead><tr><th>Kategori</th><th>Status Coverage</th><th>Jumlah Temuan</th><th>Module Deteksi</th><th>Catatan</th></tr></thead><tbody>{_coverage_rows(coverage if isinstance(coverage, list) else [], "A")}</tbody></table>
<h2>Ringkasan OWASP API Top 10</h2>
<table><thead><tr><th>Kategori</th><th>Status Coverage</th><th>Jumlah Kandidat</th><th>Module Deteksi</th><th>Area Validasi Manual</th></tr></thead><tbody>{_coverage_rows(coverage if isinstance(coverage, list) else [], "API")}</tbody></table>
<div class="card"><b>Kandidat risiko API:</b> {len(api_candidates if isinstance(api_candidates, list) else [])}. Semua kandidat perlu validasi manual dan tidak otomatis dianggap rentan.</div>
<h2>Korelasi CVE</h2>
<table><thead><tr><th>CVE ID</th><th>Aset Terdampak</th><th>Produk</th><th>Versi Terdeteksi</th><th>CVSS</th><th>Severity</th><th>Confidence</th><th>Sumber Korelasi</th><th>Validasi Manual</th><th>Rekomendasi</th></tr></thead><tbody>{_cve_rows(cve_correlations if isinstance(cve_correlations, list) else [])}</tbody></table>
<h2>Komponen Rentan dan Outdated</h2>
<table><thead><tr><th>Produk</th><th>Versi</th><th>Host</th><th>Related CVEs</th><th>Severity</th><th>Confidence</th><th>Remediation</th></tr></thead><tbody>{_component_rows(vulnerable_components if isinstance(vulnerable_components, list) else [])}</tbody></table>
<h2>Alert Potensi Bug</h2>{''.join(_alert_card(item) for item in findings) or '<div class="card">Tidak ada alert potensial yang dibuat.</div>'}
<h2>Queue Validasi Manual</h2>{''.join(f'<div class="card"><b>{_esc(ALERT_TITLE_ID.get(str(item.get("title")), item.get("title")))}</b><p>Apa yang diuji: {_esc(item.get("type"))}</p><p>Cara validasi aman: {_esc(item.get("recommendation"))}</p><p>Perilaku aman yang diharapkan: akses tidak sah atau lintas role ditolak; input divalidasi server-side.</p><p>Perilaku rentan: akses, redirect, kebocoran data, atau perubahan state terjadi di luar otorisasi yang dimaksud.</p><p>Catatan pengujian aman: {_esc(item.get("safe_testing_note", "Gunakan akun uji berizin saja; jangan exploit atau eksfiltrasi data."))}</p></div>' for item in findings) or '<div class="card">Tidak ada item validasi manual.</div>'}
<h2>Rekomendasi Perbaikan</h2><div class="card">Prioritaskan validasi manual terhadap alert berisiko High dan Medium, hardening security header, review autentikasi, dan uji authorization boundary menggunakan akun uji yang berizin.</div>
<h2>Kesimpulan</h2><div class="card"><b>{_esc(final_recommendation)}</b><p class="muted">Temuan potensial memerlukan validasi manual sebelum keputusan acceptance atau remediation.</p></div>
</main></body></html>"""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(html_doc, encoding="utf-8")
    return {"html": output_path, "final_recommendation": final_recommendation, "total_alerts": len(findings)}
