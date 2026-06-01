# Internal Beta Checklist

- Install dependencies with `pip install -r requirements.txt`.
- Run `pytest -q`.
- Run a Type 1 local-only `scan-source` assessment against a test folder.
- Create an assessment for an authorized pre-production domain.
- Approve the assessment only after scope and authorization are confirmed.
- Verify `scan-domain` rejects unsafe/default execution until all gates are explicit.
- Export JSON, HTML, and PDF reports from a completed result.
- Review evidence for relevance and confirm no sensitive values are present.
- Confirm every finding remains a potential finding until manual validation is complete.
