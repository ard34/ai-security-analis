from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.report.report_center import generate_pdf_from_html


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        Path("reports").mkdir()
        Path("reports/a.html").write_text("<html><body>x</body></html>", encoding="utf-8")
        with patch.dict("sys.modules", {"weasyprint": None}):
            ok = generate_pdf_from_html("reports/a.html", "reports/a.pdf")
        check(ok is False, "pdf fallback returns false and does not crash")
    print("pdf_generation_fallback tests passed")


if __name__ == "__main__":
    main()
