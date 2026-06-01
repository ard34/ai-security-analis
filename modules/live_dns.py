from __future__ import annotations

from core.execution import ExecutionEngine
from modules.dns_parser import parse_a_aaaa


def resolve_a_aaaa(host: str, engine: ExecutionEngine) -> dict[str, list[str]]:
    return parse_a_aaaa(engine.dns_a_aaaa(host))

