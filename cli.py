from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from core.config import load_config
from core.logging import create_audit_event, write_audit_event
from core.pipeline import run_dummy_pipeline
from reporting.html_report import save_html_report
from reporting.pdf_report import generate_pdf_report
from storage.json_io import export_scan_result_to_json, import_scan_result_from_json
from storage.repositories import ScanResultRepository


DEFAULT_AUDIT_LOG_PATH = "logs/audit.jsonl"


def _json_default(value: object) -> object:
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if hasattr(value, "__dict__"):
        return dict(value.__dict__)
    return str(value)


def _commands_executed_count(scan_result: dict[str, Any]) -> int:
    audit_log = scan_result.get("audit_log") if isinstance(scan_result.get("audit_log"), dict) else {}
    commands = audit_log.get("commands_executed")
    return len(commands) if isinstance(commands, list) else 0


def format_scan_summary(scan_result: dict[str, Any]) -> str:
    return "\n".join(
        [
            f"Scan ID: {scan_result.get('scan_id', '')}",
            f"Target: {scan_result.get('target', '')}",
            f"Status: {scan_result.get('status', '')}",
            f"Scan mode: {scan_result.get('scan_mode', '')}",
            f"Findings: {len(scan_result.get('findings') or [])}",
            f"Commands executed: {_commands_executed_count(scan_result)}",
        ]
    )


def format_history_rows(items: list[dict[str, Any]]) -> str:
    if not items:
        return "No scan history found."
    lines = ["scan_id | target | scan_mode | status | created_at"]
    for item in items:
        lines.append(
            " | ".join(
                [
                    str(item.get("scan_id", "")),
                    str(item.get("target", "")),
                    str(item.get("scan_mode", "")),
                    str(item.get("status", "")),
                    str(item.get("created_at", "")),
                ]
            )
        )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    config = load_config()
    parser = argparse.ArgumentParser(description="AI Security Analyst local CLI")
    parser.add_argument("--audit-log-path", default=DEFAULT_AUDIT_LOG_PATH)
    audit_parent = argparse.ArgumentParser(add_help=False)
    audit_parent.add_argument("--audit-log-path", default=argparse.SUPPRESS)
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Run the safe dummy scan pipeline", parents=[audit_parent])
    scan.add_argument("--target", required=True)
    scan.add_argument("--allowed-domain", action="append", required=True, dest="allowed_domains")
    scan.add_argument("--allowed-ip", action="append", default=[], dest="allowed_ips")
    scan.add_argument("--scan-mode", default=config.default_scan_mode, choices=["strict", "safe", "standard"])
    scan.add_argument("--db-path", default=str(config.database_path))
    scan.add_argument("--save", action="store_true")
    scan.add_argument("--json-output")
    scan.add_argument("--html-output")
    scan.add_argument("--pdf-output")

    history = subparsers.add_parser("history", help="List saved scan history", parents=[audit_parent])
    history.add_argument("--db-path", default=str(config.database_path))
    history.add_argument("--limit", type=int, default=config.max_history_limit)

    show = subparsers.add_parser("show", help="Show a saved scan result", parents=[audit_parent])
    show.add_argument("--scan-id", required=True)
    show.add_argument("--db-path", default=str(config.database_path))
    show.add_argument("--full", action="store_true")

    export_html = subparsers.add_parser("export-html", help="Export a saved scan to HTML", parents=[audit_parent])
    export_html.add_argument("--scan-id", required=True)
    export_html.add_argument("--output", required=True)
    export_html.add_argument("--db-path", default=str(config.database_path))

    export_pdf = subparsers.add_parser("export-pdf", help="Export a saved scan to PDF", parents=[audit_parent])
    export_pdf.add_argument("--scan-id", required=True)
    export_pdf.add_argument("--output", required=True)
    export_pdf.add_argument("--db-path", default=str(config.database_path))

    export_json = subparsers.add_parser("export-json", help="Export a saved scan to JSON", parents=[audit_parent])
    export_json.add_argument("--scan-id", required=True)
    export_json.add_argument("--output", required=True)
    export_json.add_argument("--db-path", default=str(config.database_path))

    import_json = subparsers.add_parser("import-json", help="Import a scan result JSON", parents=[audit_parent])
    import_json.add_argument("--input", required=True)
    import_json.add_argument("--db-path", default=str(config.database_path))
    import_json.add_argument("--save", action="store_true")

    return parser


def _repository(db_path: str) -> ScanResultRepository:
    return ScanResultRepository(Path(db_path))


def _write_cli_audit(
    args: argparse.Namespace,
    event_type: str,
    message: str,
    scan_id: str | None = None,
    target: str | None = None,
    status: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    event = create_audit_event(
        event_type,
        message,
        scan_id=scan_id,
        target=target,
        status=status,
        source="cli",
        metadata=metadata,
    )
    write_audit_event(event, args.audit_log_path)


def _load_scan_or_error(repository: ScanResultRepository, scan_id: str) -> dict[str, Any] | None:
    scan_result = repository.get_scan_result(scan_id)
    if scan_result is None:
        print(f"Scan result not found: {scan_id}")
    return scan_result


def _handle_scan(args: argparse.Namespace) -> int:
    result = run_dummy_pipeline(
        target=args.target,
        allowed_domains=args.allowed_domains,
        allowed_ips=args.allowed_ips,
        scan_mode=args.scan_mode,
    )
    if args.save:
        _repository(args.db_path).save_scan_result(result)
        _write_cli_audit(
            args,
            "history_saved",
            "Scan result saved to history",
            scan_id=result.get("scan_id"),
            target=result.get("normalized_target") or result.get("target"),
            status=result.get("status"),
            metadata={"db_path": args.db_path},
        )
    if args.json_output:
        print(f"JSON exported: {export_scan_result_to_json(result, args.json_output)}")
        _write_cli_audit(
            args,
            "json_exported",
            "Scan result exported to JSON",
            scan_id=result.get("scan_id"),
            target=result.get("normalized_target") or result.get("target"),
            status=result.get("status"),
            metadata={"output": args.json_output},
        )
    if args.html_output:
        print(f"HTML exported: {save_html_report(result, args.html_output)}")
        _write_cli_audit(
            args,
            "report_exported",
            "HTML report exported",
            scan_id=result.get("scan_id"),
            target=result.get("normalized_target") or result.get("target"),
            status=result.get("status"),
            metadata={"output": args.html_output, "format": "html"},
        )
    if args.pdf_output:
        print(f"PDF exported: {generate_pdf_report(result, args.pdf_output)}")
        _write_cli_audit(
            args,
            "report_exported",
            "PDF report exported",
            scan_id=result.get("scan_id"),
            target=result.get("normalized_target") or result.get("target"),
            status=result.get("status"),
            metadata={"output": args.pdf_output, "format": "pdf"},
        )
    print(format_scan_summary(result))
    return 0


def _handle_history(args: argparse.Namespace) -> int:
    items = _repository(args.db_path).list_scan_results(limit=args.limit)
    _write_cli_audit(
        args,
        "history_loaded",
        "Scan history loaded",
        status="success",
        metadata={"limit": args.limit, "count": len(items), "db_path": args.db_path},
    )
    print(format_history_rows(items))
    return 0


def _handle_show(args: argparse.Namespace) -> int:
    result = _load_scan_or_error(_repository(args.db_path), args.scan_id)
    if result is None:
        _write_cli_audit(
            args,
            "history_loaded",
            "Scan result lookup failed",
            scan_id=args.scan_id,
            status="not_found",
            metadata={"db_path": args.db_path},
        )
        return 1
    _write_cli_audit(
        args,
        "history_loaded",
        "Scan result loaded",
        scan_id=result.get("scan_id"),
        target=result.get("normalized_target") or result.get("target"),
        status="success",
        metadata={"db_path": args.db_path},
    )
    if args.full:
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True, default=_json_default))
    else:
        print(format_scan_summary(result))
        print(f"Normalized target: {result.get('normalized_target', '')}")
        print(f"Assets: {len(result.get('assets') or [])}")
        print(f"Endpoints: {len(result.get('endpoints') or [])}")
        audit_log = result.get("audit_log") if isinstance(result.get("audit_log"), dict) else {}
        print(f"Modules enabled: {len(audit_log.get('modules_enabled') or [])}")
    return 0


def _handle_export_html(args: argparse.Namespace) -> int:
    result = _load_scan_or_error(_repository(args.db_path), args.scan_id)
    if result is None:
        return 1
    output = save_html_report(result, args.output)
    _write_cli_audit(
        args,
        "report_exported",
        "HTML report exported",
        scan_id=result.get("scan_id"),
        target=result.get("normalized_target") or result.get("target"),
        status=result.get("status"),
        metadata={"output": output, "format": "html"},
    )
    print(output)
    return 0


def _handle_export_pdf(args: argparse.Namespace) -> int:
    result = _load_scan_or_error(_repository(args.db_path), args.scan_id)
    if result is None:
        return 1
    output = generate_pdf_report(result, args.output)
    _write_cli_audit(
        args,
        "report_exported",
        "PDF report exported",
        scan_id=result.get("scan_id"),
        target=result.get("normalized_target") or result.get("target"),
        status=result.get("status"),
        metadata={"output": output, "format": "pdf"},
    )
    print(output)
    return 0


def _handle_export_json(args: argparse.Namespace) -> int:
    result = _load_scan_or_error(_repository(args.db_path), args.scan_id)
    if result is None:
        return 1
    output = export_scan_result_to_json(result, args.output)
    _write_cli_audit(
        args,
        "json_exported",
        "Scan result exported to JSON",
        scan_id=result.get("scan_id"),
        target=result.get("normalized_target") or result.get("target"),
        status=result.get("status"),
        metadata={"output": output},
    )
    print(output)
    return 0


def _handle_import_json(args: argparse.Namespace) -> int:
    result = import_scan_result_from_json(args.input)
    _write_cli_audit(
        args,
        "json_imported",
        "Scan result imported from JSON",
        scan_id=result.get("scan_id"),
        target=result.get("normalized_target") or result.get("target"),
        status=result.get("status"),
        metadata={"input": args.input},
    )
    if args.save:
        _repository(args.db_path).save_scan_result(result)
        _write_cli_audit(
            args,
            "history_saved",
            "Imported scan result saved to history",
            scan_id=result.get("scan_id"),
            target=result.get("normalized_target") or result.get("target"),
            status=result.get("status"),
            metadata={"db_path": args.db_path},
        )
    print(format_scan_summary(result))
    return 0


def run_cli(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args: argparse.Namespace | None = None
    try:
        args = parser.parse_args(argv)
        _write_cli_audit(
            args,
            "cli_action",
            "CLI command executed",
            target=getattr(args, "target", None),
            status="started",
            metadata={"command": args.command},
        )
        handlers = {
            "scan": _handle_scan,
            "history": _handle_history,
            "show": _handle_show,
            "export-html": _handle_export_html,
            "export-pdf": _handle_export_pdf,
            "export-json": _handle_export_json,
            "import-json": _handle_import_json,
        }
        return int(handlers[args.command](args))
    except SystemExit as exc:
        return int(exc.code or 0)
    except Exception as exc:
        if args is not None:
            try:
                _write_cli_audit(
                    args,
                    "error",
                    "CLI command failed",
                    target=getattr(args, "target", None),
                    status="error",
                    metadata={"command": getattr(args, "command", ""), "error": str(exc)},
                )
            except Exception:
                pass
        print(f"Error: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(run_cli())
