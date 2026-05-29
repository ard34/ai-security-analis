from __future__ import annotations

import html
from pathlib import Path

from agent.report.json_writer import read_json


def _esc(value: object) -> str:
    return html.escape(str(value if value is not None else ""))


def _table(items: list[dict[str, object]], columns: list[str]) -> str:
    rows = []
    for item in items:
        rows.append("<tr>" + "".join(f"<td>{_esc(item.get(col, ''))}</td>" for col in columns) + "</tr>")
    headers = "".join(f"<th>{_esc(col)}</th>" for col in columns)
    return f"<table><thead><tr>{headers}</tr></thead><tbody>{''.join(rows) or f'<tr><td colspan={len(columns)}>Tidak ada data.</td></tr>'}</tbody></table>"


def generate_zap_report(output_path: str = "reports/zap_report.html") -> str:
    spider = read_json("outputs/zap/zap_spider_summary.json", default={}) or {}
    endpoints = read_json("outputs/zap/zap_endpoint_inventory.json", default=[]) or []
    alerts = read_json("outputs/zap/zap_passive_alerts.json", default=[]) or []
    alert_rows = []
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        alert_rows.append(
            {
                "Nama alert": alert.get("alert") or alert.get("name"),
                "Risk": alert.get("risk"),
                "Confidence": alert.get("confidence"),
                "URL": alert.get("url"),
                "Method": alert.get("method", ""),
                "Parameter": alert.get("param", ""),
                "Evidence": alert.get("evidence", ""),
                "Description": alert.get("description", ""),
                "Solution": alert.get("solution", ""),
                "Reference": alert.get("reference", ""),
                "CWE/WASC": f"{alert.get('cweid', '')}/{alert.get('wascid', '')}",
                "Status": "Potensial",
                "Validasi": "Perlu validasi manual",
            }
        )
    risk_counts: dict[str, int] = {}
    host_counts: dict[str, int] = {}
    for row in alert_rows:
        risk_counts[str(row.get("Risk", ""))] = risk_counts.get(str(row.get("Risk", "")), 0) + 1
        from urllib.parse import urlparse

        host = urlparse(str(row.get("URL", ""))).hostname or ""
        host_counts[host] = host_counts.get(host, 0) + 1

    css = "body{font-family:Arial,sans-serif;background:#f7f8fa;color:#17202a;margin:0}header{background:#17202a;color:white;padding:28px 36px}main{padding:24px 36px}.card{background:white;border:1px solid #d8dee6;border-radius:8px;padding:14px;margin:10px 0}table{width:100%;border-collapse:collapse;background:white}th,td{border:1px solid #d8dee6;padding:8px;text-align:left;vertical-align:top}th{background:#eef1f5}"
    html_doc = f"""<!doctype html><html><head><meta charset="utf-8"><title>Laporan OWASP ZAP</title><style>{css}</style></head><body><header><h1>Laporan OWASP ZAP</h1></header><main>
<h2>Ringkasan OWASP ZAP</h2><div class="card">Alert pasif: {len(alert_rows)}. Endpoint: {len(endpoints)}.</div>
<h2>Status ZAP Daemon</h2><div class="card">{_esc(spider.get('daemon_status', 'Tidak tersedia'))}</div>
<h2>Context dan Scope ZAP</h2><div class="card">{_esc(spider.get('context', 'Tidak tersedia'))}</div>
<h2>Hasil Traditional Spider</h2><div class="card">{_esc(spider.get('traditional_spider', spider))}</div>
<h2>Hasil AJAX Spider</h2><div class="card">{_esc(spider.get('ajax_spider', 'Tidak tersedia'))}</div>
<h2>URL/Endpoint yang Ditemukan</h2>{_table([{'URL': item} if isinstance(item, str) else item for item in endpoints], ['URL'])}
<h2>HTTP Messages yang Dianalisis</h2><div class="card">{_esc(spider.get('http_messages', 'Tidak tersedia'))}</div>
<h2>Passive Scan Alerts</h2>{_table(alert_rows, ['Nama alert','Risk','Confidence','URL','Method','Parameter','Evidence','Description','Solution','Reference','CWE/WASC','Status','Validasi'])}
<h2>Alert berdasarkan Risiko</h2>{_table([{'Risk': key, 'Jumlah': value} for key, value in risk_counts.items()], ['Risk','Jumlah'])}
<h2>Alert berdasarkan Host</h2>{_table([{'Host': key, 'Jumlah': value} for key, value in host_counts.items()], ['Host','Jumlah'])}
<h2>Rekomendasi Manual Validation</h2><div class="card">Validasi setiap alert secara manual dalam scope berizin. Jangan melakukan exploit destruktif, brute force, DoS, pencurian kredensial, upload shell, atau eksfiltrasi data.</div>
</main></body></html>"""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(html_doc, encoding="utf-8")
    return output_path
