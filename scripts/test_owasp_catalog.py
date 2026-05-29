from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.standards.owasp_catalog import get_owasp_api_catalog, get_owasp_web_catalog


def main() -> None:
    web = get_owasp_web_catalog()
    api = get_owasp_api_catalog()
    assert len(web) == 10
    assert len(api) == 10
    for item in web + api:
        for key in ["id", "name", "explanation_id", "detection_signals", "example_affected_surfaces", "manual_validation_guidance", "safe_testing_note"]:
            assert key in item, (item, key)
    assert web[0]["id"] == "A01"
    assert api[0]["id"] == "API1"
    print("ok")


if __name__ == "__main__":
    main()
