from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write_json(path: str | Path, data: Any) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def read_json(path: str | Path, default: Any = None) -> Any:
    input_path = Path(path)
    if not input_path.exists():
        return default
    return json.loads(input_path.read_text(encoding="utf-8"))
