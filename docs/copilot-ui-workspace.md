# Copilot UI Workspace

The Copilot UI is the main Streamlit workspace for local-first assessment review. It presents source analysis, chat guidance, finding detail, validation status, evidence, and report export in one place.

## Workspace Areas

- Sidebar navigation for assessment projects, source analysis, domain safe-live review, history, reports, and safety settings.
- Chat panel for local answers about the current scan and selected finding.
- Finding detail panel for source locations, affected routes and functions, vulnerable flow, root cause, missing control, validation steps, evidence, false-positive checks, and remediation.
- Export controls for JSON, HTML, and PDF reports.

## Safety Rules

The chat helper uses local scan data only and does not call an external LLM API. It refuses requests for automated harmful testing and redirects the operator to authorized manual validation.

The UI must not mark a finding as `manually_confirmed` automatically. Manual confirmation requires reviewer, validation note, and evidence note.

## Running

Install optional UI dependencies first:

```bash
python -m pip install -r requirements-ui.txt
streamlit run ui/app.py
```
