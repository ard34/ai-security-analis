from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.core.result_manager import backup_results, clear_previous_results, get_result_summary


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        Path("outputs/recon").mkdir(parents=True)
        Path("reports").mkdir()
        Path("tmp").mkdir()
        Path("logs").mkdir()
        Path("outputs/recon/a.json").write_text("{}", encoding="utf-8")
        Path("reports/a.html").write_text("<html></html>", encoding="utf-8")
        Path("tmp/a.har").write_text("{}", encoding="utf-8")
        Path("logs/a.log").write_text("x", encoding="utf-8")
        archive = backup_results()
        check(Path(archive).exists(), "backup archive created")
        summary = get_result_summary()
        check(summary["outputs_files_count"] == 1, "summary counts outputs")
        result = clear_previous_results(clear_tmp=True, clear_logs=False, backup=False)
        check(result["removed"]["outputs"] == 1, "outputs removed")
        check(not Path("reports/a.html").exists(), "reports removed")
        check(not Path("tmp/a.har").exists(), "tmp har removed")
        check(Path("logs/a.log").exists(), "logs preserved by default")
    print("result_manager tests passed")


if __name__ == "__main__":
    main()
