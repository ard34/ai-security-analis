from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ui.app import normalize_table_rows, safe_scalar, safe_table


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    row = {"host": "app.example.com", "nested": [{"name": "React"}], "meta": {"server": "nginx"}}
    normalized = normalize_table_rows([row])
    check(isinstance(normalized[0]["nested"], str), "list rendered as string")
    check(isinstance(normalized[0]["meta"], str), "dict rendered as string")
    check(safe_table(row)[0]["host"] == "app.example.com", "dict normalized")
    check(safe_scalar(None) == "", "none safe scalar")
    print("safe_rendering_helpers tests passed")


if __name__ == "__main__":
    main()
