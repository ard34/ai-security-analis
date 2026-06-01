# Small Bugfix Policy

## What Counts As Small Bugfix

- Typo.
- Unclear error message.
- CLI help mismatch.
- Dashboard display issue.
- Report formatting issue.
- Missing test.
- Sample data cleanup.
- Redaction improvement.

## What Is Not Allowed In This Phase

- Exploit automation.
- Brute force tooling.
- DoS testing.
- Aggressive crawler.
- Active scanner integration.
- Auth bypass tooling.
- Credential theft.
- Malware, reverse shell, or persistence.

## Bugfix Workflow

1. Reproduce.
2. Write/update test.
3. Fix.
4. Run `pytest -q`.
5. Update docs if needed.
6. Commit.

## Patch Version Rule

Patch tag after accumulated safe fixes, for example `v0.3.1-beta-patch`.
