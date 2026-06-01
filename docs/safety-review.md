# Safety Review

## Safety Model Overview

AI Security Analyst is designed as an authorized-only, safe-by-default assessment assistant. It supports local source review and limited passive safe-live domain review. It does not perform autonomous exploitation and does not validate impact through offensive activity.

## What The Platform Allows

- Local source folder assessment.
- Approved and in-scope safe-live passive domain assessment.
- Evidence capture with redaction.
- Potential finding generation.
- Finding deduplication.
- Manual testing recommendations that are defensive only.
- Report generation for internal review.
- Audit trail for guarded live actions.

## What The Platform Blocks

- No autonomous exploitation.
- No credential theft.
- No brute force.
- No DoS.
- No external scanner orchestration.
- No out-of-scope target execution.
- No secret logging.
- No auth bypass tooling.
- No malware, reverse shell, or persistence workflow.

## Type 1 Safety Controls

Type 1 operates on local source folders only. It does not perform network activity and does not run external scanner commands. Findings are marked as potential and require manual validation.

## Type 2 Safety Controls

Type 2 is gated by assessment approval, scope validation, explicit network permission, explicit safe-live confirmation, timeout, rate limit, scan budget, audit logging, and the safe execution engine. There is no live scan default.

## Scope Validation

Targets must be inside the approved assessment scope. Out-of-scope targets are rejected before a live action can run.

## Safe Execution Engine

The safe execution engine enforces approval, safe-live mode, network permission, confirmation, budget, rate limit, timeout, audit logging, and kill switch behavior.

## Rate Limit, Budget, And Timeout

Live actions are bounded by conservative rate limits, scan budgets, and timeouts. These controls reduce accidental overreach and keep safe-live behavior passive.

## Audit Trail

Guarded live actions are written to an audit log. Audit entries are intended for operator accountability and internal review.

## Secret Redaction

Sensitive keys and common secret-like values are redacted before display, evidence, log, export, and report usage.

## Report Redaction

Reports escape user-controlled content and use redacted result data. Operators must review report artifacts before sharing.

## Known Residual Risks

- False positives are possible.
- False negatives are possible.
- Passive checks may miss environment-specific behavior.
- Minimal DNS support may limit asset evidence.
- Operators can still misuse exported data outside the tool.

## Manual Operator Responsibilities

- Confirm written authorization.
- Confirm allowed scope.
- Stop if scope or authorization is unclear.
- Validate potential findings manually.
- Remove false positives.
- Keep reports and audit logs in approved internal storage.
- Ensure no sensitive value is shared in evidence or reports.
