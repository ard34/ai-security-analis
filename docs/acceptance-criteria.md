# Acceptance Criteria

- All tests pass with `pytest -q`.
- Static safety tests pass.
- Type 1 works local-only.
- Type 2 rejects unsafe/default execution.
- Dashboard does not bypass gating.
- Reports do not leak sensitive values.
- Findings are marked as potential until manual validation.
- Operators follow authorized-only usage and the pre-live safety checklist.
