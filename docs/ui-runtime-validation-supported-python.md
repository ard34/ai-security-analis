# UI Runtime Validation On Supported Python

This stage validates the Streamlit Copilot UI on a Python version supported by the UI dependency stack.

## Local Interpreter Check

Current local interpreter availability:

- Python 3.15 alpha is available.
- Python 3.14 is available.
- Python 3.11-3.13 was not available during this validation session.

Because Streamlit pulls packages such as pyarrow, pandas, numpy, and pillow, UI dependency installation is intentionally skipped on bleeding-edge Python versions by `requirements-ui.txt`. Core CLI/testing mode remains available there.

## Supported UI Runtime Target

Use Python 3.11-3.13, or another Python version supported by the Streamlit dependency stack.

Recommended Windows flow:

```powershell
py -3.13 -m venv .venv-ui
.\.venv-ui\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-ui.txt
streamlit run ui/app.py
```

If Python 3.13 is not installed, use Python 3.12:

```powershell
py -3.12 -m venv .venv-ui
.\.venv-ui\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-ui.txt
streamlit run ui/app.py
```

## Smoke Scenario

After the Streamlit server starts:

- Confirm the Copilot UI loads without traceback.
- Confirm sidebar navigation is visible.
- Confirm the safety banner is visible.
- Run Source Code Analysis with `tests\fixtures\source_logic_cases`.
- Enable logic analysis.
- Confirm validation-ready findings appear.
- Select a finding and review source location, root cause, missing control, and manual validation steps.
- Send a safe chat prompt asking for finding explanation.
- Send an unsafe chat prompt and confirm it is rejected.
- Export JSON, HTML, and PDF after a scan is loaded.
- Refresh the browser and confirm workspace state is restored.

## Expected Result

- No crash or Streamlit traceback.
- No unexpected network action.
- No secret appears in chat history, workspace state, evidence, logs, or exported reports.
- `manually_confirmed` is not assigned automatically.
- Domain safe-live actions remain gated by assessment approval, scope, confirmation, network permission, audit log, timeout, rate limit, and scan budget.

## Current Session Result

Full Streamlit runtime validation was blocked because no supported Python 3.11-3.13 interpreter was installed locally. The fallback path was validated:

- `python -m pip install -r requirements-ui.txt` succeeds on Python 3.15 by skipping unsupported UI dependencies.
- `python ui\app.py` exits cleanly with the Streamlit optional dependency message.
- Core tests and ruff checks pass.

## Follow-up

Install Python 3.12 or 3.13 and rerun this document as the manual UI runtime validation checklist.
