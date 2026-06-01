# Internal RC Review

## RC Version

`v0.3.0-rc1`

## Review Date

`TBD`

## Reviewer

`TBD`

## Scope Of Review

Review the release candidate for controlled internal usage. Confirm Type 1 local-only assessment, Type 2 gated safe-live passive assessment, reporting, evidence handling, audit logging, documentation, samples, and safety boundaries.

## Project Structure Review

- Confirm `app/`, `ui/`, `core/`, `modules/`, `reporting/`, `storage/`, `tests/`, `docs/`, and `samples/` exist.
- Confirm runtime/generated folders are not used for committed artifacts except `.gitkeep`.

## CLI Review

- `python cli.py --help`
- `python cli.py scan-source --help`
- `python cli.py scan-domain --help`
- `python cli.py create-assessment --help`
- `python cli.py approve-assessment --help`

## Dashboard Review

- Dashboard import-safe.
- Type 1 mode remains local-only.
- Type 2 mode does not bypass gating.
- Export buttons require scan result availability.

## Type 1 Workflow Review

- Type 1 scan-source works local-only.
- Potential findings require manual validation.
- Evidence is reviewed before export.

## Type 2 Workflow Review

- Type 2 rejects unsafe/default execution.
- Type 2 requires approved assessment.
- Type 2 requires explicit `allow_network`.
- Type 2 requires explicit `confirm_safe_live`.
- Type 2 requires audit log path.
- Target must be in scope.

## Safety Boundary Review

- No exploit, brute force, or DoS.
- No aggressive crawling or fuzzing.
- No external scanner.
- No credential theft.
- No auth bypass tooling.
- No malware, reverse shell, or persistence.
- No live scan default.

## Report And Export Review

- Reports render JSON, HTML, and PDF.
- Reports do not contain secrets.
- Findings remain potential until validated manually.

## Evidence And Audit Redaction Review

- Evidence does not contain secrets.
- Audit log does not contain secrets.
- Secret redaction applies to display and export paths.

## Sample Data Review

- Sample findings have `is_potential=True`.
- Sample evidence contains no credential, token, cookie, password, API key, or session values.

## Known Limitations Review

- Findings are potential only.
- Manual validation is required.
- Safe-live recon is intentionally limited.
- False positives and false negatives are possible.
- DNS support may be minimal.
- HTTP fingerprinting is conservative.

## Checklist

- [ ] `pytest -q` passes.
- [ ] Safety static test passes.
- [ ] CLI help works.
- [ ] Dashboard import-safe.
- [ ] Type 1 scan-source works local-only.
- [ ] Type 2 rejects unsafe/default execution.
- [ ] Type 2 requires approved assessment.
- [ ] Type 2 requires `allow_network`.
- [ ] Type 2 requires `confirm_safe_live`.
- [ ] Type 2 requires audit log path.
- [ ] Reports do not contain secrets.
- [ ] Audit log does not contain secrets.
- [ ] Docs mention authorized-only usage.
- [ ] Docs mention manual validation.

## Open Issues

- `TBD`

## RC Decision

- [ ] Pass
- [ ] Pass with notes
- [ ] Fail
