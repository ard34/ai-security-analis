# Internal Beta Pilot Execution

## Pilot Objective

Run a controlled internal pilot with 1-3 internal testers to validate Type 1, Type 2, CLI, dashboard, report export, evidence review, and audit log review workflows without adding offensive capability.

## Pilot Participants

- 1-3 internal tester/pentester.
- Testers must understand authorized-only usage and manual validation requirements.

## Allowed Environments

- Local sample project.
- Lab target.
- Staging/pre-production target with authorization.

## Not Allowed

- Public target without authorization.
- Production target without explicit approval.
- Out-of-scope domain/IP.
- Exploit, brute force, DoS, or aggressive scan.

## Pilot Workflows

- Type 1 source folder assessment.
- Type 2 safe-live domain assessment.
- CLI workflow.
- Dashboard workflow.
- Report export workflow.
- Audit log review workflow.

## Pilot Duration

`TBD`

## Stop Conditions

- Unclear authorization.
- Unclear scope.
- Unexpected network behavior.
- Possible secret exposure.
- Unsafe execution behavior.
- Audit log missing.
- Report contains sensitive data.

## Success Criteria

- Type 1 works local-only.
- Type 2 rejects unsafe/default scan.
- Type 2 runs only with approved assessment.
- Audit log created.
- Reports generated.
- No secret leakage.
- Feedback captured.
