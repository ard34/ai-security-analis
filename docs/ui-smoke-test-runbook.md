# UI Smoke Test Runbook

Use this runbook to validate the Claude-style Copilot UI manually before treating a patch as stable.

## 1. Pre-flight

Run from the repository root:

```bash
python -m pip install -r requirements-core.txt
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m ruff check .
git status --short
```

Expected pre-flight state:

- Core and dev dependencies install successfully.
- Tests pass.
- Ruff passes.
- Git status is clean before starting the smoke run.

Optional UI dependency install:

```bash
python -m pip install -r requirements-ui.txt
```

## 2. Start UI

```bash
streamlit run ui/app.py
```

Open the local Streamlit URL shown by the command.

## 3. Smoke Scenario

1. Open the UI and verify the sidebar loads.
2. Verify the safety banner is visible.
3. Go to Source Code Analysis.
4. Enter `tests\fixtures\source_logic_cases` as the local source path.
5. Enable logic analysis.
6. Run Source Code Analysis.
7. Select a saved scan from the sidebar if one is available.
8. Select a validation-ready finding.
9. Review source location, root cause, missing control, and manual validation steps.
10. Update validation status to `needs_more_review`.
11. Enter a validation note containing a fake secret such as `token=test-value` and verify it is redacted.
12. Send a chat message asking for manual validation guidance.
13. Export JSON, HTML, and PDF.

## 4. Expected Results

- UI does not crash.
- Sidebar, safety banner, chat area, finding detail panel, evidence, and export controls render.
- Source logic analysis produces validation-ready findings for the fixture.
- Manual validation steps are visible.
- No secret leakage appears in chat history, workspace data, evidence, report, or exported content.
- Finding status updates only after manual action.
- `manually_confirmed` is not assigned automatically.
- Workspace state persists enough to reload selected scans, chat history, and validation activity.
- JSON, HTML, and PDF export works after a scan is loaded.

## 5. Failure Handling

Stop the smoke test if a safety boundary fails.

For UI or behavior failures:

- Capture a screenshot.
- Capture the Streamlit traceback or terminal error.
- Record the current branch and commit.
- File a bug using the internal beta bug template.
- Include steps to reproduce, expected result, actual result, and whether any secret redaction failed.

Do not continue manual validation if the UI attempts to bypass scope, approval, safe execution, audit logging, network confirmation, timeout, rate limit, or scan budget controls.
