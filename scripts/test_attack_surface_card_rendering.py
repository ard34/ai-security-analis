from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ui.app import render_attack_surface_cards


class Container:
    def __enter__(self) -> "Container":
        return self

    def __exit__(self, *_args: object) -> None:
        return None


class FakeStreamlit:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def container(self, border: bool = False) -> Container:
        self.calls.append(("container", str(border)))
        return Container()

    def subheader(self, value: str) -> None:
        self.calls.append(("subheader", value))

    def markdown(self, value: str) -> None:
        self.calls.append(("markdown", value))

    def write(self, value: str) -> None:
        self.calls.append(("write", value))

    def info(self, value: str) -> None:
        self.calls.append(("info", value))


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    fake = FakeStreamlit()
    count = render_attack_surface_cards(
        fake,
        [
            {
                "category": "API Assets",
                "assets": [{"hostname": "app.example.com"}],
                "endpoints": [{"url": "https://app.example.com/api/orders"}],
                "technology": [{"technology": "React"}],
                "risk_hints": ["API authorization boundary"],
                "recommended_manual_checks": ["Validate BOLA safely"],
            }
        ],
    )
    check(count == 1, "one card rendered")
    check(("subheader", "API Assets") in fake.calls, "category rendered")
    check(any("app.example.com" in call[1] for call in fake.calls), "asset rendered")
    check(any("Validate BOLA safely" in call[1] for call in fake.calls), "manual check rendered")
    print("attack_surface_card_rendering tests passed")


if __name__ == "__main__":
    main()
