from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from typing import Any


VALID_SCAN_MODES = {"strict", "safe", "standard"}
VALID_STATUSES = {"success", "rejected", "error"}
VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
VALID_CONFIDENCES = {"low", "medium", "high"}
REQUIRED_FIELDS = {"scan_id", "target", "scan_mode", "status", "findings", "audit_log", "started_at", "ended_at"}
REQUIRED_FINDING_FIELDS = {"title", "severity", "confidence", "evidence", "recommendation", "is_potential"}


def ensure_parent_directory(path: str | Path) -> None:
    Path(path).expanduser().parent.mkdir(parents=True, exist_ok=True)


def validate_json_output_path(output_path: str | Path) -> Path:
    path = Path(output_path)
    if path.suffix.lower() != ".json":
        raise ValueError("JSON output path must end with .json.")
    return path


def validate_json_input_path(input_path: str | Path) -> Path:
    path = Path(input_path)
    if path.suffix.lower() != ".json":
        raise ValueError("JSON input path must end with .json.")
    if not path.exists():
        raise FileNotFoundError(f"JSON input file not found: {path}")
    return path


def _require_non_empty_string(scan_result: dict[str, Any], key: str) -> None:
    if not isinstance(scan_result.get(key), str) or not scan_result.get(key, "").strip():
        raise ValueError(f"scan_result.{key} must be a non-empty string.")


def validate_scan_result_json(scan_result: dict[str, Any]) -> None:
    if not isinstance(scan_result, dict):
        raise ValueError("scan_result must be a dict.")
    missing = sorted(REQUIRED_FIELDS - set(scan_result))
    if missing:
        raise ValueError(f"scan_result missing required fields: {', '.join(missing)}")
    _require_non_empty_string(scan_result, "scan_id")
    _require_non_empty_string(scan_result, "target")
    if scan_result.get("scan_mode") not in VALID_SCAN_MODES:
        raise ValueError("scan_result.scan_mode is invalid.")
    if scan_result.get("status") not in VALID_STATUSES:
        raise ValueError("scan_result.status is invalid.")
    if not isinstance(scan_result.get("findings"), list):
        raise ValueError("scan_result.findings must be a list.")
    if not isinstance(scan_result.get("audit_log"), dict):
        raise ValueError("scan_result.audit_log must be a dict.")
    if not isinstance(scan_result.get("started_at"), str):
        raise ValueError("scan_result.started_at must be a string.")
    if not isinstance(scan_result.get("ended_at"), str):
        raise ValueError("scan_result.ended_at must be a string.")
    for index, finding in enumerate(scan_result["findings"]):
        if not isinstance(finding, dict):
            raise ValueError(f"finding[{index}] must be a dict.")
        missing_finding_fields = sorted(REQUIRED_FINDING_FIELDS - set(finding))
        if missing_finding_fields:
            raise ValueError(f"finding[{index}] missing required fields: {', '.join(missing_finding_fields)}")
        if finding.get("severity") not in VALID_SEVERITIES:
            raise ValueError(f"finding[{index}].severity is invalid.")
        if finding.get("confidence") not in VALID_CONFIDENCES:
            raise ValueError(f"finding[{index}].confidence is invalid.")
        if finding.get("is_potential") is not True:
            raise ValueError(f"finding[{index}].is_potential must be True.")


def scan_result_to_json_bytes(scan_result: dict[str, Any]) -> bytes:
    result = deepcopy(scan_result)
    validate_scan_result_json(result)
    return json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")


def scan_result_from_json_bytes(data: bytes) -> dict[str, Any]:
    try:
        parsed = json.loads(data.decode("utf-8"))
    except Exception as exc:
        raise ValueError(f"Invalid JSON bytes: {exc}") from exc
    validate_scan_result_json(parsed)
    return parsed


def export_scan_result_to_json(scan_result: dict[str, Any], output_path: str | Path) -> str:
    path = validate_json_output_path(output_path)
    payload = scan_result_to_json_bytes(scan_result)
    ensure_parent_directory(path)
    path.write_bytes(payload)
    return str(path)


def import_scan_result_from_json(input_path: str | Path) -> dict[str, Any]:
    path = validate_json_input_path(input_path)
    return scan_result_from_json_bytes(path.read_bytes())

