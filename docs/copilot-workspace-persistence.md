# Copilot Workspace Persistence

The Copilot workspace stores local UI state so operators can resume source assessment review without rerunning analysis.

## Stored Data

- Workspace id and timestamps.
- Optional assessment id.
- Active scan id and active finding id.
- Redacted chat history.
- Validation activity records with finding id, old status, new status, reviewer, redacted note, redacted evidence note, and timestamp.

## Scan History

Saved scans remain in the existing local SQLite scan repository. The workspace stores only the active scan id, then reloads the scan from local storage when available.

## Chat Persistence

Chat history is local and redacted before storage. Authorization headers, cookies, sessions, tokens, passwords, and API keys are replaced with `[REDACTED]`. Message length and history length are capped.

## Validation Activity

Validation activity is an audit-style local record of manual review status changes. The UI must not mark a finding as `manually_confirmed` automatically. Manual confirmation requires reviewer, note, and evidence note.

## Limitations

- Workspaces are local to the SQLite database.
- The workspace does not run scans automatically.
- The workspace does not bypass assessment approval, scope validation, safe execution, confirmation, audit log, timeout, rate limit, or scan budget controls.
- Streamlit remains optional; core and CLI workflows do not require UI dependencies.
