# Operator SOP

Use AI Security Analyst for authorized-only internal and pre-production assessment work. Stop immediately when authorization, scope, or network behavior is uncertain.

## Type 1 — Source Code / Folder Project Assessment

1. Prepare a local source folder that is approved for review.
2. Run `scan-source` against the local folder.
3. Review potential findings.
4. Review evidence for relevance and sensitive data.
5. Deduplicate findings before reporting.
6. Complete manual validation.
7. Export JSON, HTML, or PDF report artifacts.
8. Store results securely in approved internal storage.

## Type 2 — Domain / Website Target Assessment

1. Create an assessment.
2. Define allowed scope.
3. Approve assessment only after authorization and scope are confirmed.
4. Confirm authorization before running a safe-live scan.
5. Run safe-live scan with explicit flags for allowed network activity and safe-live confirmation.
6. Review audit log.
7. Review potential findings.
8. Complete manual validation.
9. Export JSON, HTML, or PDF report artifacts.
10. Archive assessment when work is complete.

## Emergency Stop

- Use kill switch if available.
- Stop if scope is uncertain.
- Stop if authorization is unclear.
- Stop if unexpected network behavior occurs.

## Prohibited Operator Behavior

- Do not use the project for autonomous exploitation.
- Do not run brute force, DoS, fuzzing, or external scanner workflows.
- Do not attempt credential theft, auth bypass, persistence, malware, reverse shell, or shell access.
- Treat all findings as potential until manual validation is complete.
- Remove or redact sensitive values before sharing any artifact.
