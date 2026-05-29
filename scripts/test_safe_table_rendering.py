from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ui.app import safe_scalar, safe_table


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    nested = [
        {"category": "API Assets", "assets": [{"hostname": "app.example.com"}], "risk_hints": ["Review auth"]},
        {"category": "Public Web Assets", "assets": "app.example.com", "risk_hints": None},
    ]
    table = safe_table(nested)
    check(table[0]["assets"] == json.dumps([{"hostname": "app.example.com"}], ensure_ascii=False), "list converted to JSON string")
    check(table[0]["risk_hints"] == json.dumps(["Review auth"], ensure_ascii=False), "nested list converted")
    check(table[1]["risk_hints"] == "", "None converted to blank")
    check(safe_scalar({"a": 1}) == '{"a": 1}', "dict scalar converted")
    print("safe_table_rendering tests passed")


if __name__ == "__main__":
    main()
