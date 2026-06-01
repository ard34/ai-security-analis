# Bugfix And Stabilization Plan

## Stabilization Objective

Process internal RC review and beta pilot feedback without expanding product scope. Fix bugs, improve clarity, and prevent safety regressions while preserving safe-by-default behavior.

## Bug Intake Process

1. Collect feedback with the internal beta feedback template.
2. Record reproduction steps, workflow, expected behavior, actual behavior, and safety impact.
3. Assign severity.
4. Triage with an operator and maintainer.
5. Fix only approved stabilization items.
6. Retest before release.

## Severity Levels

- blocker: prevents safe internal use or causes safety boundary failure.
- high: creates material safety risk, data leakage risk, or broken core workflow.
- medium: confusing or incorrect behavior with workaround.
- low: minor copy, formatting, or documentation issue.
- note: observation or future consideration.

## Triage Rules

- Safety regression issues outrank usability issues.
- Any sensitive value leakage is at least high severity.
- Any gate bypass is blocker severity.
- Any live action outside approved scope is blocker severity.
- Unclear docs can be fixed when it reduces operator risk.

## What Can Be Fixed In Stabilization

- Bugfix small.
- Error message improvement.
- Docs improvement.
- Report formatting fix.
- CLI/dashboard UX clarity.
- Test coverage improvement.
- Sample data cleanup.
- Safety regression prevention.

## What Must Be Deferred

- Exploit automation.
- Active scanner integration.
- Brute force tooling.
- Aggressive crawling.
- Credentialed testing without future guarded design.
- Auth bypass tooling.
- Malware, reverse shell, or persistence.
- Large new features outside internal beta scope.

## Safety Regression Rules

- Do not weaken approval, scope, network, confirmation, timeout, rate limit, scan budget, audit log, or kill switch gates.
- Do not introduce external scanner execution.
- Do not store credential, token, cookie, password, API key, or session values.
- Do not change findings from potential to confirmed automatically.

## Testing Requirements

- Run `pytest -q`.
- Run safety static test.
- Retest Type 1 local-only behavior.
- Retest Type 2 default unsafe execution rejection.
- Retest out-of-scope rejection.
- Retest report and audit redaction.

## Release Candidate Retest Process

1. Re-run RC review checklist.
2. Re-run pilot smoke checks.
3. Re-run CLI help checks.
4. Re-run safety grep.
5. Confirm docs and release notes are updated.

## Exit Criteria

- No blocker bugs open.
- No high safety bugs open.
- `pytest -q` passes.
- Safety static test passes.
- Type 1 local-only still works.
- Type 2 default unsafe execution still rejected.
- Docs updated.
- Release notes updated.
