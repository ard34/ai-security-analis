# Release Notes

## v0.3.0-beta1

### Summary

Internal beta release prepared after RC review, pilot planning, and stabilization planning. This release is intended for controlled internal usage by authorized testers.

### Changes Since RC

- Added internal RC review checklist.
- Added internal beta pilot plan and feedback template.
- Added bugfix and stabilization process.
- Added internal beta release guide.

### Included Features

- Type 1 local source folder assessment.
- Type 2 gated safe-live passive domain assessment.
- Dashboard assessment workflow.
- Report export.
- Evidence handling.
- Finding deduplication.
- Manual testing recommendations.
- Audit trail.

### Safety Controls

- Approved assessment required.
- In-scope target required.
- Explicit `allow_network` required.
- Explicit `confirm_safe_live` required.
- Safe execution engine required.
- Timeout, rate limit, scan budget, audit log, and kill switch support required.
- Findings remain potential until manual validation.
- Secret redaction applies to evidence, logs, display, and reports.

### Known Limitations

- Findings are potential only.
- Manual validation is required.
- Safe-live recon is intentionally limited.
- False positives and false negatives are possible.
- DNS support may be minimal.
- HTTP fingerprinting is conservative.

### Internal Beta Instructions

Use `docs/internal-beta-release.md`, `docs/internal-beta-pilot-plan.md`, and `docs/internal-beta-feedback-template.md`. Run `pytest -q` before pilot use and stop on unclear authorization, uncertain scope, or unexpected network behavior.

### Not Included / Intentionally Blocked Features

- Exploit automation.
- Brute force.
- DoS.
- Aggressive crawling.
- External scanners.
- Credential theft.
- Auth bypass tooling.
- Malware, reverse shell, or persistence.

## Version

`v0.3.0-rc1`

## Release Type

Internal Release Candidate

## Summary

This release candidate stabilizes AI Security Analyst for internal review. It includes local source assessment, gated safe-live passive domain assessment, dashboard assessment workflow, reporting, storage, and internal beta documentation.

## Included Features

- Type 1 local source folder assessment.
- Type 2 guarded safe-live domain assessment.
- Assessment creation, approval, archive, and scope display in the dashboard.
- Potential findings and manual testing recommendations.
- Finding deduplication.
- Evidence capture.
- Audit trail for guarded live actions.
- JSON, HTML, and PDF report export.
- Sample data and internal beta checklists.

## Safety Controls

- Approved assessment required.
- Target must be in scope.
- Explicit network permission required.
- Explicit safe-live confirmation required.
- Audit log path required.
- Timeout, rate limit, and scan budget enforced.
- Kill switch support in the safe execution engine.
- Secret and report redaction.
- Findings remain potential until manual validation.

## CLI Workflows

- `scan-source`
- `report-source`
- `create-assessment`
- `approve-assessment`
- `scan-domain`
- JSON import/export and history commands

## Dashboard Workflows

- Mode selector for Type 1 and Type 2.
- Assessment Workflow section.
- Gated Run Safe-Live Scan button.
- Scan result display.
- JSON, HTML, and PDF export controls.

## Reporting

Reports include potential findings, evidence, and manual recommendations. HTML output escapes content and report data is redacted before display/export.

## Storage

SQLite stores scan history. JSON import/export supports internal artifact exchange. Runtime data belongs in local `data/`, `reports/`, `exports/`, and `logs/` folders.

## Known Limitations

- Findings are potential only.
- Manual validation is required.
- Safe-live recon is intentionally limited.
- DNS support may be minimal.
- HTTP fingerprinting is conservative.
- False positives and false negatives are possible.

## Upgrade Notes

Run `pip install -r requirements.txt`, then `pytest -q`. Review `.env.example` for local directory settings. Do not reuse older assessment artifacts without checking scope and status.

## Validation Checklist

- Run `pytest -q`.
- Run safety static tests.
- Complete `docs/internal-rc-review.md`.
- Confirm Type 1 source scan works local-only.
- Confirm Type 2 rejects unsafe/default execution.
- Confirm dashboard does not bypass gates.
- Confirm reports do not leak sensitive values.

## Not Included / Intentionally Blocked Features

- Exploit automation.
- Brute force.
- DoS.
- Aggressive crawling.
- External scanners.
- Credential theft.
- Auth bypass tooling.
- Malware, reverse shell, or persistence.
