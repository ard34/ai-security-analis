from __future__ import annotations


def score_risk(entry: dict[str, object], classification: str, has_sensitive_data: bool = False) -> tuple[str, str]:
    score = 0
    url = str(entry.get("url", "")).lower()
    status = int(entry.get("status_code") or 0)
    params = entry.get("query_params") if isinstance(entry.get("query_params"), dict) else {}

    if classification in {"profile", "account", "order", "invoice", "payment", "admin-like"}:
        score += 2
    if "/api/" in url or classification == "api":
        score += 1
    if any(key in params for key in ["id", "user_id", "order_id", "invoice_id", "account_id"]):
        score += 2
    if any(key in params for key in ["token", "role", "is_admin", "price", "discount"]):
        score += 2
    if status == 200:
        score += 1
    if status in {401, 403}:
        score -= 1
    if status >= 500:
        score += 2
    if has_sensitive_data:
        score += 2

    if score >= 7:
        return "High", "Medium"
    if score >= 4:
        return "Medium", "Medium"
    if score >= 2:
        return "Low", "Low"
    return "Info", "Low"
