# Internal Beta Pilot Runbook

## Section 1 — Pre-flight

- Confirm `pytest -q` passes.
- Confirm `git status` clean.
- Confirm tag `v0.3.0-beta1` exists.
- Confirm tester has authorization.
- Confirm target is lab/staging/pre-production.
- Confirm scope is documented.

## Section 2 — Type 1 Test

Commands:

```bash
python cli.py scan-source --path . --save-result
python cli.py history
python cli.py show --scan-id <scan_id>
python cli.py export-json --scan-id <scan_id> --out exports/source-scan.json
python cli.py report-source --path . --html-out reports/source-report.html --pdf-out reports/source-report.pdf
```

Expected:

- Local-only.
- No network required.
- Findings are potential.
- Evidence available.
- Report generated.

## Section 3 — Type 2 Reject Test

Commands:

```bash
python cli.py scan-domain --target example.com
```

Expected:

- Rejected because required gated args are missing.

## Section 4 — Type 2 Safe-Live Test

Use only authorized target. Commands must follow current CLI argument names from `--help`.

Commands:

```bash
python cli.py create-assessment --name "Pilot Assessment" --target example.com --out data/pilot-assessment.json
python cli.py approve-assessment --assessment-json data/pilot-assessment.json
python cli.py scan-domain --target example.com --assessment-json data/pilot-assessment.json --allow-network --confirm-safe-live --audit-log-path logs/pilot-audit.jsonl --save-result
```

Expected:

- Runs only if approved and in-scope.
- Creates audit log.
- No exploit, brute force, or DoS.
- No secret leakage.
- Result can be reviewed/exported.

## Section 5 — Review

- Review findings.
- Review evidence.
- Review report.
- Review audit log.
- Fill feedback templates.

## Section 6 — Stop Conditions

- Stop if authorization unclear.
- Stop if scope unclear.
- Stop if unexpected network behavior.
- Stop if report/audit log contains secret.
- Stop if any guardrail is bypassed.
