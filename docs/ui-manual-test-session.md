# UI Manual Test Session

Use this document to run and record a structured manual UI test session for the Copilot workspace.

## 1. Test Session Metadata

- Date:
- Tester:
- Version/tag:
- Environment:
- Python version:
- UI dependency install status:

## 2. Pre-flight

Run from the repository root:

```bash
python -m pytest -q
python -m ruff check .
git status --short
python -m pip install -r requirements-ui.txt
```

Python 3.15 core mode does not require Streamlit. UI mode requires the optional dependency install above. If UI install fails on a bleeding-edge Python version, use a supported Python version for UI testing or continue core CLI/testing mode only.

## 3. Start Command

```bash
streamlit run ui/app.py
```

## 4. Manual Test Checklist

- UI loads.
- Sidebar visible.
- Safety banner visible.
- Workspace initialized.
- Chat area visible.
- Source analysis form visible.
- Logic analysis checkbox works.
- Run source logic analysis.
- Findings table visible.
- Select finding.
- Finding detail visible.
- Manual validation steps visible.
- Validation status update works.
- Chat explains selected finding.
- Chat rejects unsafe request.
- Export JSON works.
- Export HTML works.
- Export PDF works.
- Workspace persists after refresh.

## 5. Pass/Fail Table

| Test item | Expected result | Actual result | Status | Notes |
| --- | --- | --- | --- | --- |
| UI loads | Copilot workspace renders without crash |  |  |  |
| Sidebar visible | Navigation and saved scans are visible |  |  |  |
| Safety banner visible | Local-only safety state is shown |  |  |  |
| Workspace initialized | Workspace id is shown and state is ready |  |  |  |
| Chat area visible | Chat messages and input render |  |  |  |
| Source analysis form visible | Local path field and logic analysis checkbox render |  |  |  |
| Logic analysis checkbox works | Checkbox can enable source logic analysis |  |  |  |
| Run source logic analysis | Local-only scan completes for fixture path |  |  |  |
| Findings table visible | Findings are listed after scan |  |  |  |
| Select finding | Finding detail updates for selected item |  |  |  |
| Finding detail visible | Source location and root cause are visible |  |  |  |
| Manual validation steps visible | Safe manual validation guidance is visible |  |  |  |
| Validation status update works | Status changes only after manual input |  |  |  |
| Chat explains selected finding | Chat response uses local finding data |  |  |  |
| Chat rejects unsafe request | Unsafe request is refused and redirected to safe guidance |  |  |  |
| Export JSON works | JSON export downloads after scan is loaded |  |  |  |
| Export HTML works | HTML export downloads after scan is loaded |  |  |  |
| Export PDF works | PDF export downloads after scan is loaded |  |  |  |
| Workspace persists after refresh | Chat, selected scan, and validation activity restore |  |  |  |

## 6. Bug Capture Format

- Summary:
- Screenshot:
- Traceback:
- Reproduction steps:
- Severity:

## 7. Stop Conditions

Stop immediately if any of these occur:

- Unsafe behavior.
- Unexpected network action.
- Secret appears in UI, report, log, workspace, or chat history.
- Validation status bypass.
- Crash blocks workflow.
