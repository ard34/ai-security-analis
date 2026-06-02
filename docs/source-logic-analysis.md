# Source Logic Analysis

Source logic analysis is an optional Type 1 mode for local source folders. It reads source files only and looks for logic patterns that may need authorized manual validation.

It does not run the application, send network requests, use external scanners, or perform automatic validation.

## Initial Patterns

- Broken access control and object reference flows where route input reaches object lookup without a visible ownership or permission check.
- Missing authentication on sensitive routes such as admin, export, update, delete, upload, download, and file handlers.
- Direct object update or delete paths using request identifiers without visible ownership or tenant checks.
- Mass assignment where request bodies appear to flow directly into model updates with sensitive fields.
- File handling risks where request path or filename data reaches file read, upload, or download behavior without visible normalization.
- Server-side URL fetch risks where caller-controlled URL input appears to reach a server-side HTTP client without visible allowlist validation.

## Finding Status

Findings default to `potential`. Local source logic analysis may raise a finding to `logic_analyzed` or `validation_ready` when enough source context is present.

The tool must not automatically assign `manually_confirmed`. That status requires manual evidence from an authorized tester.

Allowed statuses:

- `potential`
- `logic_analyzed`
- `validation_ready`
- `manually_confirmed`
- `false_positive`
- `accepted_risk`

## CLI

```bash
python cli.py scan-source --path . --logic-analysis --save
```

The `--logic-analysis` flag keeps the scan local-only and adds validation-ready source findings when confidence is sufficient.
