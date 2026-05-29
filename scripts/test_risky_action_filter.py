from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent.crawler.authenticated_crawler import is_risky_action, is_sensitive_admin_like


def main() -> None:
    cases = [
        ("/delete/1", True, "delete path should be risky"),
        ("/profile/edit", False, "profile edit should not be destructive"),
        ("/checkout/confirm", True, "checkout confirm should be risky"),
        ("/search?q=test", False, "search should be safe"),
        ("/admin/users", True, "admin users should be sensitive/admin-like"),
    ]
    for value, expected, message in cases:
        if value == "/admin/users":
            actual = is_sensitive_admin_like(value)
        else:
            actual = is_risky_action(value)
        assert actual is expected, f"{message}: expected {expected}, got {actual}"
    print("risky action filter tests passed")


if __name__ == "__main__":
    main()
