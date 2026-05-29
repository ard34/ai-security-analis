from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def report_status(path: str) -> dict[str, object]:
    file_path = Path(path)
    return {
        "path": str(file_path),
        "available": file_path.exists(),
        "size": file_path.stat().st_size if file_path.exists() else 0,
    }


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        Path("reports").mkdir()
        missing = report_status("reports/recon_report.pdf")
        check(missing["available"] is False, "missing report handled")
        Path("reports/recon_report.html").write_text("<html>Laporan Recon</html>", encoding="utf-8")
        html = report_status("reports/recon_report.html")
        check(html["available"] is True, "html report available")
        check(html["size"] > 0, "html file size recorded")
    print("report_download_paths tests passed")


if __name__ == "__main__":
    main()
