from __future__ import annotations

import argparse
from pathlib import Path

from core.assessment import Assessment, load_assessment, save_assessment
from core.pipeline_domain import run_domain_assessment
from core.pipeline_source import run_source_assessment
from core.policies import DomainRunPolicy, PolicyViolation
from reporting.html_report import render_html_report
from reporting.pdf_report import render_pdf_report
from storage.database import connect
from storage.json_io import read_json, write_json
from storage.repositories import ScanRepository

DB_PATH = Path("data/ai_security_analyst.sqlite3")


def _repo() -> ScanRepository:
    return ScanRepository(connect(DB_PATH))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ai-security-analyst")
    sub = parser.add_subparsers(dest="command", required=True)
    scan_source = sub.add_parser("scan-source")
    scan_source.add_argument("--path", required=True)
    scan_source.add_argument("--save-result", action="store_true")
    scan_source.add_argument("--logic-analysis", action="store_true")
    report_source = sub.add_parser("report-source")
    report_source.add_argument("--path", required=True)
    report_source.add_argument("--html-out")
    report_source.add_argument("--pdf-out")
    export_json = sub.add_parser("export-json")
    export_json.add_argument("--scan-id", required=True)
    export_json.add_argument("--out", required=True)
    export_html = sub.add_parser("export-html")
    export_html.add_argument("--scan-id", required=True)
    export_html.add_argument("--out", required=True)
    export_pdf = sub.add_parser("export-pdf")
    export_pdf.add_argument("--scan-id", required=True)
    export_pdf.add_argument("--out", required=True)
    import_json = sub.add_parser("import-json")
    import_json.add_argument("--path", required=True)
    sub.add_parser("history")
    show = sub.add_parser("show")
    show.add_argument("--scan-id", required=True)
    create = sub.add_parser("create-assessment")
    create.add_argument("--name", required=True)
    create.add_argument("--target", action="append", required=True)
    create.add_argument("--out", required=True)
    approve = sub.add_parser("approve-assessment")
    approve.add_argument("--assessment-json", required=True)
    scan_domain = sub.add_parser("scan-domain")
    scan_domain.add_argument("--target", required=True)
    scan_domain.add_argument("--assessment-json", required=True)
    scan_domain.add_argument("--allow-network", action="store_true")
    scan_domain.add_argument("--confirm-safe-live", action="store_true")
    scan_domain.add_argument("--audit-log-path", required=True)
    scan_domain.add_argument("--timeout", type=float, default=5.0)
    scan_domain.add_argument("--rate-limit", type=float, default=1.0)
    scan_domain.add_argument("--scan-budget", type=int, default=8)
    scan_domain.add_argument("--save-result", action="store_true")
    scan_domain.add_argument("--html-out")
    scan_domain.add_argument("--pdf-out")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan-source":
        result = run_source_assessment(args.path, logic_analysis=args.logic_analysis)
        if args.save_result:
            _repo().save(result)
        print(result.id)
        return 0
    if args.command == "report-source":
        result = run_source_assessment(args.path)
        if args.html_out:
            Path(args.html_out).write_text(render_html_report(result), encoding="utf-8")
        if args.pdf_out:
            Path(args.pdf_out).write_bytes(render_pdf_report(result))
        print(result.id)
        return 0
    if args.command == "export-json":
        result = _repo().get(args.scan_id)
        if not result:
            raise SystemExit("scan not found")
        write_json(args.out, result.to_dict())
        return 0
    if args.command == "export-html":
        result = _repo().get(args.scan_id)
        if not result:
            raise SystemExit("scan not found")
        Path(args.out).write_text(render_html_report(result), encoding="utf-8")
        return 0
    if args.command == "export-pdf":
        result = _repo().get(args.scan_id)
        if not result:
            raise SystemExit("scan not found")
        Path(args.out).write_bytes(render_pdf_report(result))
        return 0
    if args.command == "import-json":
        from core.models import ScanResult

        result = ScanResult.from_dict(read_json(args.path))
        _repo().save(result)
        print(result.id)
        return 0
    if args.command == "history":
        for row in _repo().list():
            print(f"{row['id']} {row['workflow']} {row['target']}")
        return 0
    if args.command == "show":
        result = _repo().get(args.scan_id)
        if not result:
            raise SystemExit("scan not found")
        print(result.to_dict())
        return 0
    if args.command == "create-assessment":
        assessment = Assessment(name=args.name, allowed_targets=args.target)
        save_assessment(assessment, args.out)
        print(args.out)
        return 0
    if args.command == "approve-assessment":
        assessment = load_assessment(args.assessment_json).approve()
        save_assessment(assessment, args.assessment_json)
        print("approved")
        return 0
    if args.command == "scan-domain":
        if not args.allow_network:
            raise SystemExit("--allow-network is required")
        if not args.confirm_safe_live:
            raise SystemExit("--confirm-safe-live is required")
        assessment = load_assessment(args.assessment_json)
        policy = DomainRunPolicy(
            safe_live=True,
            allow_network=args.allow_network,
            confirm_safe_live=args.confirm_safe_live,
            timeout_seconds=args.timeout,
            rate_limit_per_second=args.rate_limit,
            scan_budget=args.scan_budget,
            audit_log_path=args.audit_log_path,
        )
        try:
            result = run_domain_assessment(args.target, assessment, policy)
        except PolicyViolation as exc:
            raise SystemExit(str(exc)) from exc
        if args.save_result:
            _repo().save(result)
        if args.html_out:
            Path(args.html_out).write_text(render_html_report(result), encoding="utf-8")
        if args.pdf_out:
            Path(args.pdf_out).write_bytes(render_pdf_report(result))
        print(result.id)
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
