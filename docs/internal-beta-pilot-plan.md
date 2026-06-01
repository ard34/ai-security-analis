# Internal Beta Pilot Plan

## Pilot Objective

Validate AI Security Analyst with 1-3 internal testers using authorized sample, lab, or pre-production targets. Confirm safe-by-default behavior, operator workflow clarity, reporting usefulness, and documentation completeness.

## Tester Roles

- Internal security engineer.
- Internal application security reviewer.
- Internal pentester operating within written authorization.

## Authorized-Only Requirement

Use only authorized targets. Prefer sample, lab, or pre-production target environments. Stop if scope is unclear, authorization is unclear, or unexpected network behavior occurs.

## Environment Requirement

- Local workstation or approved internal container runtime.
- No production target testing unless explicitly authorized.
- No secrets in sample data, feedback, reports, evidence, or audit logs.

## Pilot Scope

- Type 1 local source assessment.
- Type 2 gated safe-live passive assessment.
- Dashboard assessment workflow.
- CLI workflow.
- Report export.
- Evidence and audit review.

## Type 1 Test Scenario

1. Select an approved local source folder.
2. Run `scan-source`.
3. Review potential findings and evidence.
4. Export report artifacts.
5. Record false positives, false negatives, and confusing output.

## Type 2 Test Scenario

1. Create an assessment for an authorized pre-production target.
2. Define allowed scope.
3. Approve the assessment.
4. Run safe-live scan only with explicit `allow_network`, explicit `confirm_safe_live`, audit log path, timeout, rate limit, and scan budget.
5. Review potential findings and evidence.

## Safety Validation Scenario

- Confirm unsafe/default Type 2 execution is rejected.
- Confirm unapproved assessment is rejected.
- Confirm out-of-scope target is rejected.
- Confirm missing audit log path is rejected.
- Do not run exploit.
- Do not brute force.
- Do not run DoS.
- Do not use external scanner.

## Report Export Scenario

- Export JSON, HTML, and PDF.
- Confirm findings remain potential.
- Confirm report artifacts do not contain sensitive values.

## Evidence Review Scenario

- Review evidence for relevance.
- Confirm no credential, token, cookie, password, API key, or session value is present.

## Audit Log Review Scenario

- Review audit log for guarded live actions.
- Confirm audit log contains no sensitive values.

## Feedback Collection Process

Each tester completes `docs/internal-beta-feedback-template.md` after each workflow. File issues internally with severity, reproduction steps, expected behavior, actual behavior, and safety impact.

## Stop Conditions

- Scope is unclear.
- Authorization is unclear.
- Unexpected network behavior occurs.
- Any sensitive value appears in evidence, audit log, or report.
- Any behavior appears to enable exploit, brute force, DoS, aggressive crawling, external scanner use, credential theft, or auth bypass.

## Success Criteria

- Pilot testers can complete Type 1 and Type 2 workflows safely.
- Gating behavior is clear and blocks unsafe defaults.
- Reports are usable for internal review.
- Evidence and audit data are redacted.
- Feedback items are triaged for stabilization.
