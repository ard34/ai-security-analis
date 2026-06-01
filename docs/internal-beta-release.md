# AI Security Analyst Internal Beta

## Version

`v0.3.0-beta1`

## Release Status

Internal Beta

## Intended Users

- Internal security engineers.
- Internal application security reviewers.
- Internal pentesters working under written authorization.

## Authorized Usage Only

Use only on authorized internal, lab, sample, or pre-production targets. Manual validation is required for every potential finding. Do not use the platform for exploit, brute force, DoS, aggressive crawling, external scanner activity, credential theft, auth bypass tooling, malware, reverse shell, or persistence.

## Included Workflows

- Type 1 Source Code / Folder Project Assessment.
- Type 2 Domain / Website Target Assessment.

## Safety Model

Type 1 is local-only. Type 2 is safe-live passive and requires approved assessment, in-scope target, explicit network permission, explicit safe-live confirmation, safe execution engine, timeout, rate limit, scan budget, audit log, and kill switch support. There is no live scan default.

## Installation

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

## Running Tests

```bash
pytest -q
```

## CLI Usage

Use `python cli.py --help` for commands. Use `scan-source` for Type 1. Use `create-assessment`, `approve-assessment`, and gated `scan-domain` for Type 2.

## Dashboard Usage

Run `streamlit run app/dashboard.py`. Use the mode selector for Type 1 and Type 2. Type 2 dashboard scans remain gated and require explicit operator confirmation.

## Pilot Usage

Use `docs/internal-beta-pilot-plan.md` and collect feedback with `docs/internal-beta-feedback-template.md`.

## Reporting

Export JSON, HTML, or PDF reports. Reports contain potential findings and manual recommendations. Review artifacts before sharing.

## Storage

Runtime scan history, exports, reports, and logs are stored in local runtime folders. Do not store sensitive values in evidence, audit logs, feedback, or reports.

## Known Limitations

See `docs/known-limitations.md`. Findings are potential only, false positives and false negatives are possible, DNS support may be minimal, and HTTP fingerprinting is conservative.

## Support And Feedback Process

Use the internal beta feedback template. File blocker and high safety issues immediately. Stabilization follows `docs/bugfix-stabilization-plan.md`.

## Upgrade Notes

Install current dependencies, rerun `pytest -q`, and review release notes before pilot usage.

## Rollback Notes

Return to the previous tagged release if blocker or high safety issues are found. Preserve audit logs and feedback for triage.

## Final Checklist

- [ ] `pytest -q` passes.
- [ ] Safety static test passes.
- [ ] Type 1 works local-only.
- [ ] Type 2 rejects unsafe/default execution.
- [ ] Dashboard does not bypass gating.
- [ ] Reports and audit logs contain no sensitive values.
- [ ] Manual validation process is understood by testers.
