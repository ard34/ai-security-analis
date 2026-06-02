# AI Security Analyst / AI Red Team Copilot

AI Security Analyst is a safe-by-default assistant for authorized internal security review. The product vision is to help operators collect structured evidence, identify potential findings, prepare defensive reports, and keep every live action inside explicit authorization and scope gates.

## Release Candidate Status

This repository is prepared as `v0.3.0-beta1`, an Internal Beta release for controlled internal usage and review. It is not an autonomous exploitation platform, not an external scanner wrapper, and not intended for unauthorized targets.

## Authorized-Only Usage Warning

- Use only with written authorization and confirmed scope.
- Findings are potential findings until manual validation is complete.
- Manual validation is required before reporting impact.
- Do not use on unauthorized targets.
- No exploit, brute force, DoS, aggressive scanner, credential theft, auth bypass, malware, reverse shell, or persistence activity is supported.
- Sensitive values such as bearer headers, cookies, tokens, passwords, keys, and secrets must not be stored in logs, evidence, or reports.

## Workflows

### Type 1 — Source Code / Folder Project Assessment

Type 1 is a local-only white-box workflow. It maps project structure, route/API hints, auth/config hints, security smells, evidence, potential findings, finding deduplication, and manual validation recommendations. It does not perform network activity.

### Type 2 — Domain / Website Target Assessment

Type 2 is a gated safe-live passive workflow for approved in-scope domains. It uses the safe execution engine and requires approved assessment scope, explicit `allow_network`, explicit `confirm_safe_live`, timeout, rate limit, scan budget, audit log path, and kill switch support. It does not run by default.

## Safety Boundaries

- Type 1 is local-only.
- Type 2 defaults to no network.
- Domain scans reject unapproved assessments.
- Out-of-scope targets are rejected.
- Live actions are constrained by timeout, rate limit, scan budget, and audit logging.
- Reports and display helpers redact sensitive values.
- All findings remain potential until manually validated.

## Release Candidate Scope

- Local source assessment.
- Safe-live passive domain assessment.
- Assessment workflow.
- Report generation.
- Evidence store.
- Finding deduplication.
- Manual testing recommendation.
- Audit trail.
- Internal beta checklist.

## Install

Core mode installs only the dependencies needed for the CLI, reports, storage, pipelines, and safety checks. It intentionally does not install Streamlit or its dashboard dependency tree.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-core.txt
```

`requirements.txt` is an alias for core mode:

```bash
python -m pip install -r requirements.txt
```

## Dev / Test Install

Install the core dependencies plus test and lint tools:

```bash
python -m pip install -r requirements-dev.txt
```

## Test

```bash
pytest -q
make test
make safety
```

## Lint And Format

```bash
make lint
make format
```

## CLI Usage

Type 1 local source assessment:

```bash
python cli.py scan-source --path /path/to/project --save-result
python cli.py scan-source --path /path/to/project --logic-analysis --save-result
python cli.py report-source --path /path/to/project --html-out reports/source.html --pdf-out reports/source.pdf
```

JSON import/export and history:

```bash
python cli.py history
python cli.py show --scan-id scan_x
python cli.py export-json --scan-id scan_x --out exports/scan.json
python cli.py export-html --scan-id scan_x --out exports/scan.html
python cli.py export-pdf --scan-id scan_x --out exports/scan.pdf
python cli.py import-json --path exports/scan.json
```

`--logic-analysis` is optional and local-only. It analyzes source code logic patterns and can produce `validation_ready` findings with manual validation steps, expected evidence, false-positive checks, and remediation guidance. These findings still require manual confirmation by an authorized tester. See `docs/source-logic-analysis.md` and `docs/manual-validation-workflow.md`.

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

`scan-domain` rejects unsafe/default execution, missing approval, out-of-scope targets, missing `--allow-network`, missing `--confirm-safe-live`, and missing audit logging.

## Dashboard Usage

Dashboard UI dependencies are optional. Install them only when you need to run Streamlit:

```bash
python -m pip install -r requirements-ui.txt
```

```bash
streamlit run app/dashboard.py
make run-dashboard
```

The dashboard has a mode selector for Type 1 and Type 2 workflows. Type 2 includes an Assessment Workflow section for creating draft assessments, reviewing scope and authorization notes, approving authorized work, and archiving assessments. The dashboard does not bypass approval, scope validation, safe execution, confirmation, audit log, timeout, rate limit, or scan budget gates.

## Docker Usage

```bash
docker compose up --build dashboard
```

The container starts only the dashboard. It does not run live scans automatically and does not bake secrets into the image.

## Report Export Usage

Reports can be exported as JSON, HTML, or PDF. HTML output escapes user-controlled content. PDF uses `reportlab` when available and falls back to a safe byte representation of the HTML report.

## Python 3.15 Compatibility

Core mode is designed to run on Python 3.15 without installing Streamlit, pyarrow, pandas, numpy, or other dashboard dependencies that may not yet publish stable wheels. Use `requirements-core.txt` for CLI/report/storage/pipeline/safety workflows and `requirements-dev.txt` for pytest and ruff. Use `requirements-ui.txt` only on environments where the Streamlit dependency stack is supported.

## Known Limitations

- Findings are potential only.
- Manual validation is required.
- Safe-live recon is intentionally limited.
- No exploit validation.
- No active scanner integration.
- No aggressive crawling.
- No credentialed testing design is included.
- False positives and false negatives are possible.
- DNS support may be minimal.
- HTTP fingerprinting is conservative.

## Internal Beta Pack

The `samples/` directory contains safe sample assessments, source and safe-live scan results, and a sample HTML report. The `docs/` directory contains the internal beta checklist, pre-live safety checklist, manual validation checklist, operator SOP, safety review, known limitations, release notes, and acceptance criteria.

## Internal Beta

Use `docs/internal-beta-release.md` for beta release instructions, `docs/internal-beta-pilot-plan.md` for controlled tester runs, and `docs/internal-beta-feedback-template.md` for feedback capture.

## Project Layout

```text
app/            Streamlit dashboard entrypoint
ui/             UI helper functions and local chat routing
core/           assessment models, safety policies, scope, pipelines
modules/        passive source and live-safe modules
reporting/      HTML/PDF reporting
storage/        SQLite and JSON persistence
samples/        Safe sample assessments and scan artifacts
docs/           Internal beta operator checklists and criteria
tests/          safety and behavior tests
```
