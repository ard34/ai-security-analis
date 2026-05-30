# AI Security Analyst

AI Security Analyst adalah platform untuk authorized black-box web/API reconnaissance yang aman dan semi-otomatis. Project ini membantu analyst melakukan reconnaissance, asset discovery, passive security analysis, attack surface mapping, potential finding analysis, dashboard visualization, dan reporting.

This tool is intended only for authorized security testing, defensive assessment, lab environments, and security reporting. It does not perform active exploitation, brute force, denial-of-service, credential theft, or unauthorized access.

## Safety Boundaries

- Tidak melakukan exploit aktif.
- Tidak melakukan brute force.
- Tidak melakukan denial-of-service.
- Tidak melakukan credential theft.
- Tidak melakukan bypass authentication.
- Tidak melakukan persistence.
- Tidak membaca source code, server, database, atau internal log target.
- Tidak menjalankan payload destruktif.
- Semua temuan adalah potential finding sampai divalidasi manual.
- Semua scanning wajib berada dalam authorized scope.

## MVP Scope

Alur target MVP:

```text
Input target
-> Scope validation
-> Subdomain discovery
-> DNS resolution
-> Live host check
-> Port/service detection
-> Web technology fingerprinting
-> Security headers review
-> WAF/CDN detection
-> Endpoint crawling with Katana
-> OWASP ZAP spider and passive scan
-> Nuclei safe templates
-> Burp/HAR import
-> Normalize findings
-> Attack surface mapping
-> Streamlit dashboard
-> HTML/PDF report
```

Tahap fondasi saat ini hanya berisi guardrail inti dan unit test. Dashboard dan pipeline awal harus memakai dummy pipeline sampai guardrail stabil.

## Current Foundation

- `core/scope.py`: target normalization dan scope validation tanpa network request.
- `core/policies.py`: scan mode strict/safe/standard dengan exploit, brute force, dan active ZAP selalu disabled.
- `core/models.py`: dataclass standar untuk target, asset, endpoint, finding, session, tool result, dan report metadata.
- `core/risk.py`: severity/confidence normalization dan passive risk scoring.
- `tests/test_scope.py`: coverage scope validation.
- `tests/test_policies.py`: coverage safety policy.

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## Running Tests

```bash
pytest -q
```

Optional coverage:

```bash
pytest --cov=.
```

## Running Streamlit Dashboard

Dashboard utama:

```bash
streamlit run ui/app.py
```

Untuk tahap awal, dashboard hanya boleh menjalankan dummy pipeline dan tidak boleh memanggil Nmap, Katana, ZAP, Nuclei, atau tool eksternal lain.

## Configuration

Project menggunakan environment variables dengan prefix:

```text
AI_SECURITY_ANALYST_
```

File `.env.example` disediakan sebagai dokumentasi konfigurasi lokal:

```bash
cp .env.example .env
```

Tahap ini belum otomatis membaca file `.env`; konfigurasi dibaca dari environment variables proses Python. Contoh override:

```bash
AI_SECURITY_ANALYST_DEFAULT_SCAN_MODE=strict python cli.py scan --target example.com --allowed-domain example.com
```

Default path lokal:

```text
data/
reports/
exports/
data/ai_security_analyst.sqlite3
```

Konfigurasi bersifat local-only. Project tidak menggunakan remote database, external scanner, exploitation module, brute force, denial-of-service, atau active testing pada fase saat ini.

## CLI Usage

CLI lokal saat ini hanya menjalankan safe dummy pipeline dan komponen lokal yang sudah ada. CLI tidak menjalankan external scanner, exploitation, brute force, denial-of-service, credential theft, atau active testing.

Run dummy scan dan simpan ke SQLite:

```bash
python cli.py scan --target example.com --allowed-domain example.com --scan-mode safe --save
```

Lihat history:

```bash
python cli.py history
```

Tampilkan scan result:

```bash
python cli.py show --scan-id <scan_id>
```

Export report HTML:

```bash
python cli.py export-html --scan-id <scan_id> --output reports/report.html
```

Export report PDF:

```bash
python cli.py export-pdf --scan-id <scan_id> --output reports/report.pdf
```

Export scan result JSON:

```bash
python cli.py export-json --scan-id <scan_id> --output exports/scan.json
```

Import scan result JSON:

```bash
python cli.py import-json --input exports/scan.json --save
```

## Logging and Audit Trail

AI Security Analyst writes local audit events in JSON Lines format.

Default audit log path:

```bash
logs/audit.jsonl
```

Example CLI usage:

```bash
python cli.py scan \
  --target example.com \
  --allowed-domain example.com \
  --save \
  --audit-log-path logs/audit.jsonl
```

Audit events may include:

* scan_started
* scan_completed
* scan_rejected
* report_exported
* json_imported
* json_exported
* history_saved
* cli_action
* dashboard_action
* error

Sensitive values such as passwords, tokens, API keys, cookies, authorization headers, sessions, and credentials are redacted before being written.

The audit trail is local-only and does not send data to any remote service.

## Safe Module Interface

AI Security Analyst uses a safe module interface for all future reconnaissance components.

Each module must:

- receive a `ModuleContext`
- return a `ModuleResult`
- respect scan policy flags
- avoid network access unless explicitly implemented in a future authorized module
- avoid external command execution unless explicitly implemented with strict guardrails in a future stage
- return potential findings only
- avoid secrets in metadata, errors, evidence, or logs

Current module interface stage includes only local/dummy modules and passive analyzers.

## AI Red Team Copilot Layer

AI Security Analyst includes an agent orchestrator that helps authorized red team and pentest teams:

- create assessment context
- enforce authorized scope
- classify user intent
- reject unsafe requests
- run safe dummy analysis
- analyze potential findings
- generate manual testing guidance
- prepare report workflows

The agent does not perform exploitation, brute force, denial-of-service, credential theft, authentication bypass, or external scanner execution.

All findings remain potential findings until manually validated by a human pentester.

## Assessment Project Model

Each assessment includes:

- assessment ID
- project name
- owner
- operator
- authorization note
- allowed domains
- allowed IPs
- denied patterns
- environment
- scan mode
- status

A scan action should only run when the assessment is approved and the target is in scope.

## AI Red Team Copilot Chat UI

The dashboard includes a local chat-style interface for the AI Red Team Copilot.

The chat UI can:

- explain available capabilities
- classify user intent
- reject unsafe requests
- use the active assessment context
- analyze local scan results
- generate safe manual testing guidance
- help prepare report workflows

Current limitations:

- no external LLM API calls
- no live scanning
- no external scanner execution
- no exploitation
- no brute force
- no denial-of-service
- no credential theft
- no authentication bypass

All outputs are intended to support authorized human pentesters. Findings remain potential until manually validated.

## Evidence Store and Finding Deduplication

AI Security Analyst stores normalized local evidence for each assessment and scan result.

Evidence may include:

- HTTP header observations
- DNS records
- endpoints
- technology observations
- finding evidence
- audit events
- manual notes
- imported artifacts

Sensitive values such as passwords, tokens, API keys, cookies, authorization headers, credentials, sessions, and private keys are redacted before evidence is stored.

Findings are deduplicated using deterministic fingerprints based on:

- target
- asset
- endpoint
- module
- finding type
- title

Deduplicated findings remain potential findings until manually validated by a human pentester.

## Manual Testing Recommendation Engine

AI Security Analyst can convert findings and evidence into safe manual testing recommendations for authorized pentesters.

The recommendation engine helps prioritize:

- security headers review
- authentication controls
- authorization and access control checks
- session management review
- API security review
- information disclosure review
- transport security review
- DNS security review
- rate limiting review
- file upload review
- business logic review

All recommendations are designed for non-destructive manual validation by authorized testers.

The engine does not generate exploit payloads, brute force instructions, denial-of-service steps, credential theft instructions, authentication bypass instructions, or scanner commands.

Every recommendation defaults to:

`needs_manual_validation`

## Safe Execution Engine

AI Security Analyst includes a Safe Execution Engine that acts as a mandatory guardrail before any future live reconnaissance action.

The execution engine enforces:

- authorized scope validation
- scan budget
- request budget
- timeout configuration
- rate limiting configuration
- concurrency limits
- error limits
- kill switch
- dangerous action blocking
- audit event generation
- metadata redaction

By default, network actions are disabled.

Blocked by default:

- live HTTP requests
- DNS lookups
- external scanner execution
- exploit attempts
- brute force
- denial-of-service
- credential theft
- active ZAP scan
- aggressive fuzzing

The current stage does not perform live scanning. It only prepares safety controls for future safe-live modules.

## Scan Modes

- `strict`: recon sangat rendah risiko, port scan dan crawler eksternal disabled.
- `safe`: safe reconnaissance dengan passive ZAP dan safe templates.
- `standard`: mode aman yang lebih lengkap, tetap tanpa exploit/bruteforce/active scan.

Capability berikut selalu dilarang:

- `allow_zap_active`
- `allow_bruteforce`
- `allow_exploit`

## Reporting Output

Report HTML/PDF akan memuat:

- Project name
- Target dan scope
- Scan mode dan scan time
- Executive summary
- Attack surface summary
- Findings table
- Evidence dan recommendation
- Disclaimer bahwa findings adalah potential findings dan perlu validasi manual
