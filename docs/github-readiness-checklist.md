# GitHub Readiness Checklist

- [ ] `pytest -q` passes.
- [ ] `git status` clean.
- [ ] No `.env` committed.
- [ ] No secrets in docs, samples, or tests.
- [ ] No runtime logs committed.
- [ ] No generated reports committed unless sample-safe.
- [ ] `.gitignore` covers runtime folders.
- [ ] README explains authorized-only usage.
- [ ] README explains Type 1 and Type 2 workflows.
- [ ] `docs/safety-review.md` exists.
- [ ] `docs/known-limitations.md` exists.
- [ ] `docs/release-notes.md` exists.
- [ ] `docs/internal-beta-release.md` exists.
- [ ] Tag `v0.3.0-beta1` exists.
- [ ] GitHub remote not required yet, but ready to add.

## Runtime And Generated Files

Before publishing, confirm these are ignored except intentional `.gitkeep` placeholders:

- `data/`
- `reports/`
- `exports/`
- `logs/`
- `.env`
- `.env.*`
- `.venv/`
- `venv/`
- `__pycache__/`
- `.pytest_cache/`
- `.coverage`
- `htmlcov/`
