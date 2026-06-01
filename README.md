# AI Security Analyst / AI Red Team Copilot

AI Security Analyst is a safe, authorized-only assistant for internal pre-production web and API security assessment.

It has two workflows:

1. **Type 1: Source Code / Folder Project Assessment**
   Local white-box review of a folder. It maps project structure, route/API hints, auth/config hints, security smells, evidence, potential findings, and manual validation recommendations.

2. **Type 2: Domain / Website Target Assessment**
   Guarded safe-live passive recon for approved in-scope domains only. It performs DNS A/AAAA lookup, safe HTTP GET/HEAD requests, security header review, robots.txt, sitemap.xml, and light HTTP fingerprinting.

## Safety Boundaries

- Authorized use only.
- Every finding is a potential finding until manually validated.
- No exploit generation or autonomous exploitation.
- No brute force, DoS, aggressive crawling, fuzzing, scanner orchestration, credential theft, or auth bypass.
- Type 1 has no network behavior and no subprocess execution.
- Type 2 defaults to no network and requires approval, scope validation, `--allow-network`, `--confirm-safe-live`, budget, timeout, rate limit, audit logging, and safe-live policy gates.
- Sensitive values such as Authorization, cookies, tokens, passwords, API keys, and secrets are redacted from logs, exports, and reports.

## Install

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

## Test

```bash
pytest -q
```

## CLI Usage

Type 1 local source assessment:

```bash
python cli.py scan-source --path /path/to/project --save-result
python cli.py report-source --path /path/to/project --html-out reports/source.html --pdf-out reports/source.pdf
```

JSON and history:

```bash
python cli.py history
python cli.py show --scan-id scan_x
python cli.py export-json --scan-id scan_x --out exports/scan.json
python cli.py import-json --path exports/scan.json
```

Type 2 gated safe-live assessment:

```bash
python cli.py create-assessment --name preprod-example --target example.com --out assessment.json
python cli.py approve-assessment --assessment-json assessment.json
python cli.py scan-domain \
  --target example.com \
  --assessment-json assessment.json \
  --allow-network \
  --confirm-safe-live \
  --audit-log-path logs/audit.jsonl
```

`scan-domain` rejects unapproved assessments, out-of-scope targets, missing `--allow-network`, missing `--confirm-safe-live`, and missing audit logging.

## Dashboard

```bash
streamlit run app/dashboard.py
```

The dashboard provides a mode selector for Type 1 source folder and Type 2 domain workflows. Type 1 runs only the local source pipeline. Type 2 includes an Assessment Workflow section for creating draft assessments, reviewing scope and authorization notes, approving authorized work, and archiving assessments. Safe-live scans require an approved, non-archived, in-scope assessment JSON or dashboard assessment, explicit authorization confirmation, safe-live passive recon enablement, limited network action approval, and an audit log path before the Run Safe-Live Scan button is enabled. The dashboard calls the guarded domain pipeline and does not implement direct network logic.

## Reports

Reports can be exported as HTML, PDF, or JSON. HTML output escapes user-controlled content. PDF uses `reportlab` when available and falls back to a safe byte representation of the HTML report.

## Project Layout

```text
app/            Streamlit dashboard entrypoint
ui/             UI helper functions and local chat routing
core/           assessment models, safety policies, scope, pipelines
modules/        passive source and live-safe modules
reporting/      HTML/PDF reporting
storage/        SQLite and JSON persistence
tests/          safety and behavior tests
```
