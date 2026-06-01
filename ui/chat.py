from __future__ import annotations

from core.agent import local_copilot_response
from core.models import ScanResult


def build_chat_context(result: ScanResult | None = None) -> dict[str, object]:
    return {"has_result": result is not None, "finding_count": len(result.findings) if result else 0}


def respond(message: str, result: ScanResult | None = None) -> str:
    return local_copilot_response(message, result)

