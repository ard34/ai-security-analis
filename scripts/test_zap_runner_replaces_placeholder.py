from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    needle = "ZAP passive connector not configured in this runner"
    offenders = []
    for folder in [ROOT / "agent", ROOT / "ui"]:
        for path in folder.rglob("*.py"):
            if needle in path.read_text(encoding="utf-8", errors="ignore"):
                offenders.append(str(path))
    if offenders:
        raise AssertionError(f"placeholder still exists: {offenders}")
    print("zap_runner_replaces_placeholder tests passed")


if __name__ == "__main__":
    main()
