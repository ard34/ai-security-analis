from __future__ import annotations

import html


def _esc(value: object) -> str:
    return html.escape(str(value if value is not None else ""))


def inject_cyberpunk_theme(st: object) -> None:
    st.markdown(
        """
        <style>
        :root {
            --cy-bg-a:#050816; --cy-bg-b:#0b1026; --cy-bg-c:#130f40;
            --cy-cyan:#00e5ff; --cy-cyan-soft:#22d3ee; --cy-violet:#7c3aed;
            --cy-purple:#a855f7; --cy-gold:#facc15; --cy-text:#e5f7ff;
            --cy-muted:#94a3b8; --cy-card:rgba(15,23,42,.75);
            --cy-border:rgba(34,211,238,.25);
        }
        .stApp {
            color: var(--cy-text);
            background:
                radial-gradient(circle at 15% 10%, rgba(0,229,255,.18), transparent 28%),
                radial-gradient(circle at 85% 12%, rgba(168,85,247,.16), transparent 26%),
                linear-gradient(135deg, var(--cy-bg-a), var(--cy-bg-b) 45%, var(--cy-bg-c));
        }
        .stApp:before {
            content:""; position:fixed; inset:0; pointer-events:none; opacity:.24; z-index:0;
            background-image:
                linear-gradient(rgba(34,211,238,.18) 1px, transparent 1px),
                linear-gradient(90deg, rgba(34,211,238,.18) 1px, transparent 1px);
            background-size:44px 44px; animation:gridMove 18s linear infinite;
            mask-image:linear-gradient(to bottom, rgba(0,0,0,.9), rgba(0,0,0,.18));
        }
        .stApp:after {
            content:""; position:fixed; inset:0; pointer-events:none; z-index:0;
            background:
                radial-gradient(circle at 30% 30%, rgba(250,204,21,.18) 0 1px, transparent 2px),
                radial-gradient(circle at 68% 58%, rgba(0,229,255,.24) 0 1px, transparent 2px),
                radial-gradient(circle at 80% 35%, rgba(168,85,247,.22) 0 1px, transparent 2px);
            background-size:220px 220px, 260px 260px, 310px 310px;
            animation:particleDrift 16s ease-in-out infinite alternate;
        }
        @keyframes gridMove { from { background-position:0 0; } to { background-position:44px 44px; } }
        @keyframes particleDrift { from { transform:translate3d(0,0,0); } to { transform:translate3d(18px,-22px,0); } }
        .block-container { position:relative; z-index:1; padding-top:1.7rem; }
        section[data-testid="stSidebar"] {
            background: linear-gradient(180deg, rgba(5,8,22,.96), rgba(11,16,38,.96));
            border-right:1px solid rgba(0,229,255,.25);
            box-shadow: 12px 0 40px rgba(0,229,255,.08);
        }
        section[data-testid="stSidebar"] * { color: var(--cy-text); }
        section[data-testid="stSidebar"] .stButton > button {
            width:100%; border-radius:8px; border:1px solid rgba(34,211,238,.22);
            background:rgba(15,23,42,.58); color:var(--cy-text);
            transition:all .18s ease;
        }
        section[data-testid="stSidebar"] .stButton > button:hover {
            border-color:var(--cy-cyan); box-shadow:0 0 18px rgba(0,229,255,.25);
        }
        .cy-brand { padding:8px 0 18px; margin-bottom:14px; border-bottom:1px solid rgba(34,211,238,.2); }
        .cy-logo {
            display:inline-flex; align-items:center; justify-content:center; width:46px; height:46px;
            border-radius:8px; margin-bottom:10px; color:#07111f; font-weight:900;
            background:linear-gradient(135deg,var(--cy-gold),var(--cy-cyan));
            box-shadow:0 0 24px rgba(0,229,255,.35);
        }
        .cy-brand-title { font-weight:900; line-height:1.15; font-size:15px; }
        .cy-brand-sub { color:var(--cy-cyan-soft); font-size:12px; margin-top:4px; }
        .cy-hero, .cy-card, .cy-metric, .cy-panel {
            background:var(--cy-card); border:1px solid var(--cy-border); border-radius:8px;
            backdrop-filter:blur(14px); box-shadow:0 0 0 1px rgba(124,58,237,.08), 0 16px 46px rgba(0,0,0,.22);
        }
        .cy-hero { padding:24px 26px; margin-bottom:18px; position:relative; overflow:hidden; }
        .cy-hero:after { content:""; position:absolute; inset:auto -20% 0 35%; height:2px; background:linear-gradient(90deg,transparent,var(--cy-cyan),var(--cy-purple),transparent); box-shadow:0 0 22px var(--cy-cyan); }
        .cy-title { font-size:32px; font-weight:900; margin:0; color:var(--cy-text); letter-spacing:0; }
        .cy-subtitle { color:#b7c7d8; font-size:14px; margin-top:6px; }
        .cy-card, .cy-panel { padding:16px; margin-bottom:12px; }
        .cy-card:hover, .cy-metric:hover { border-color:rgba(0,229,255,.55); box-shadow:0 0 24px rgba(0,229,255,.13); }
        .cy-label { color:var(--cy-muted); font-size:12px; text-transform:uppercase; letter-spacing:.04em; }
        .cy-value { color:var(--cy-cyan); font-size:30px; font-weight:900; margin-top:4px; text-shadow:0 0 18px rgba(0,229,255,.28); }
        .cy-note { color:#b7c7d8; font-size:12px; margin-top:4px; }
        .cy-section { font-size:18px; font-weight:900; color:var(--cy-text); margin:22px 0 10px; }
        .cy-badge {
            display:inline-flex; align-items:center; gap:6px; border-radius:999px; padding:4px 10px;
            border:1px solid rgba(34,211,238,.28); background:rgba(15,23,42,.8);
            font-size:12px; font-weight:800; color:var(--cy-text);
        }
        .cy-badge:before { content:""; width:7px; height:7px; border-radius:50%; background:var(--cy-cyan); box-shadow:0 0 10px var(--cy-cyan); }
        .cy-ready:before,.cy-pending:before { background:#94a3b8; box-shadow:0 0 8px #94a3b8; }
        .cy-running:before { background:var(--cy-gold); box-shadow:0 0 10px var(--cy-gold); }
        .cy-done:before,.cy-completed:before { background:#22c55e; box-shadow:0 0 10px #22c55e; }
        .cy-failed:before { background:#fb7185; box-shadow:0 0 10px #fb7185; }
        .cy-timeout:before,.cy-skipped:before { background:#f97316; box-shadow:0 0 10px #f97316; }
        .cy-timeline { border-left:2px solid rgba(34,211,238,.35); padding-left:16px; margin-left:8px; }
        .cy-event { position:relative; padding:10px 12px; margin:8px 0; border:1px solid rgba(34,211,238,.18); border-radius:8px; background:rgba(2,6,23,.55); }
        .cy-event:before { content:""; position:absolute; left:-22px; top:16px; width:10px; height:10px; border-radius:50%; background:var(--cy-cyan); box-shadow:0 0 12px var(--cy-cyan); }
        .cy-log { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px; color:#dbeafe; }
        .stButton > button, .stDownloadButton > button {
            border-radius:8px; border:1px solid rgba(34,211,238,.35); background:rgba(15,23,42,.82);
            color:var(--cy-text); transition:all .18s ease;
        }
        .stButton > button:hover, .stDownloadButton > button:hover {
            border-color:var(--cy-cyan); box-shadow:0 0 20px rgba(0,229,255,.22); color:white;
        }
        .stButton > button[kind="primary"] {
            background:linear-gradient(135deg,var(--cy-gold),#f59e0b); color:#111827; border-color:var(--cy-gold); font-weight:900;
        }
        div[data-testid="stMetric"] {
            background:var(--cy-card); border:1px solid var(--cy-border); border-radius:8px;
            padding:14px 16px; backdrop-filter:blur(14px);
        }
        div[data-testid="stMetricValue"] { color:var(--cy-cyan); text-shadow:0 0 16px rgba(0,229,255,.25); }
        .stDataFrame, .stTable { color:var(--cy-text); }
        </style>
        """,
        unsafe_allow_html=True,
    )


def status_badge(status: object) -> str:
    raw = str(status or "Ready")
    key = raw.lower().replace(" ", "-").replace("/", "-")
    if "complete" in key:
        key = "completed"
    elif "run" in key:
        key = "running"
    elif "fail" in key or "error" in key:
        key = "failed"
    elif "time" in key:
        key = "timeout"
    elif "skip" in key:
        key = "skipped"
    elif "done" in key:
        key = "done"
    elif "pending" in key:
        key = "pending"
    else:
        key = "ready"
    return f'<span class="cy-badge cy-{key}">{_esc(raw)}</span>'


def neon_card(title: str, value: object = "", note: str = "") -> str:
    return (
        '<div class="cy-card">'
        f'<div class="cy-label">{_esc(title)}</div>'
        f'<div class="cy-value">{_esc(value)}</div>'
        f'<div class="cy-note">{_esc(note)}</div>'
        "</div>"
    )


def metric_card(title: str, value: object, note: str = "") -> str:
    return neon_card(title, value, note)


def cyber_button_style() -> str:
    return "primary"
