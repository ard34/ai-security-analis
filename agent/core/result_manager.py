from __future__ import annotations

import tarfile
from datetime import datetime
from pathlib import Path
from typing import Any


ROOTS = {
    "outputs": Path("outputs"),
    "reports": Path("reports"),
    "tmp": Path("tmp"),
    "logs": Path("logs"),
}


def _files(path: Path, patterns: list[str] | None = None) -> list[Path]:
    if not path.exists():
        return []
    if patterns:
        results: list[Path] = []
        for pattern in patterns:
            results.extend(item for item in path.glob(pattern) if item.is_file())
        return sorted(set(results))
    return sorted(item for item in path.rglob("*") if item.is_file())


def list_result_files() -> dict[str, list[str]]:
    return {
        "outputs": [str(item) for item in _files(ROOTS["outputs"])],
        "reports": [str(item) for item in _files(ROOTS["reports"])],
        "tmp_har_session": [str(item) for item in _files(ROOTS["tmp"], ["*.har", "browser_state.json", "authenticated_session.har"])],
        "logs": [str(item) for item in _files(ROOTS["logs"], ["*.log"])],
    }


def backup_results() -> str:
    backup_dir = Path("backups")
    backup_dir.mkdir(parents=True, exist_ok=True)
    archive = backup_dir / f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        for root in ["outputs", "reports", "tmp", "logs"]:
            path = Path(root)
            if path.exists():
                for file_path in _files(path):
                    if root == "tmp" and not (file_path.suffix == ".har" or file_path.name in {"browser_state.json", "authenticated_session.har"}):
                        continue
                    if root == "logs" and file_path.suffix != ".log":
                        continue
                    tar.add(file_path, arcname=str(file_path))
    return str(archive)


def _unlink_files(files: list[Path]) -> int:
    removed = 0
    for file_path in files:
        if file_path.exists() and file_path.is_file():
            file_path.unlink()
            removed += 1
    return removed


def _prune_empty_dirs(root: Path) -> None:
    if not root.exists():
        return
    for directory in sorted((item for item in root.rglob("*") if item.is_dir()), reverse=True):
        try:
            directory.rmdir()
        except OSError:
            pass


def clear_previous_results(clear_tmp: bool = False, clear_logs: bool = False, backup: bool = False) -> dict[str, Any]:
    archive = backup_results() if backup else ""
    removed = {
        "outputs": _unlink_files(_files(ROOTS["outputs"])),
        "reports": _unlink_files(_files(ROOTS["reports"])),
        "tmp": 0,
        "logs": 0,
    }
    if clear_tmp:
        removed["tmp"] = _unlink_files(_files(ROOTS["tmp"], ["*.har", "browser_state.json", "authenticated_session.har"]))
    if clear_logs:
        removed["logs"] = _unlink_files(_files(ROOTS["logs"], ["*.log"]))
    for path in ROOTS.values():
        _prune_empty_dirs(path)
    return {"removed": removed, "backup": archive}


def get_result_summary() -> dict[str, Any]:
    files = list_result_files()
    reports = [Path(item) for item in files["reports"]]
    latest_report = max((item.stat().st_mtime for item in reports if item.exists()), default=0)
    return {
        "outputs_files_count": len(files["outputs"]),
        "reports_files_count": len(files["reports"]),
        "tmp_har_files_count": len(files["tmp_har_session"]),
        "logs_files_count": len(files["logs"]),
        "last_report_generated_time": datetime.fromtimestamp(latest_report).isoformat() if latest_report else "",
    }
