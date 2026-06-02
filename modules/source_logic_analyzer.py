from __future__ import annotations

import re
from dataclasses import dataclass

from core.models import Finding

ID_NAMES = ("user_id", "account_id", "org_id", "tenant_id", "project_id", "id")
SENSITIVE_ROUTE_WORDS = ("admin", "export", "delete", "update", "upload", "download", "file")
AUTH_CONTROLS = (
    "require_auth",
    "require_admin",
    "login_required",
    "permission",
    "authorize",
    "current_user",
    "session",
    "owner_id",
    "tenant_id",
    "org_id",
    "is_admin",
)
OBJECT_LOOKUPS = (".get(", ".find(", "find_by_id", "get_by_id", "query.get", "findone")
UPDATE_DELETE_WORDS = ("update", "delete", "destroy", "remove", "patch", "put")
MASS_ASSIGNMENT_PATTERNS = (
    "**request.json",
    "**request.get_json",
    "update(request.json",
    "update(req.body",
    "assign(req.body",
    "new user(req.body",
    "model(**",
)
SENSITIVE_FIELDS = ("role", "is_admin", "balance", "status", "owner_id")
FILE_PATTERNS = ("send_file(", "open(", "read_file", "download")
FETCH_PATTERNS = ("requests.get(", "requests.post(", "fetch(", "http.get(", "axios.get(")


@dataclass(slots=True)
class RouteContext:
    method: str
    path: str
    function: str
    line: int
    block: str


def analyze_source_text(text: str, *, file_path: str) -> list[Finding]:
    contexts = _route_contexts(text)
    findings: list[Finding] = []
    for context in contexts:
        findings.extend(_analyze_route_context(context, file_path))
    findings.extend(_analyze_file_wide_patterns(text, file_path))
    return findings


def _route_contexts(text: str) -> list[RouteContext]:
    lines = text.splitlines()
    contexts: list[RouteContext] = []
    for index, line in enumerate(lines):
        route = _route_from_line(line)
        if not route:
            continue
        method, route_path = route
        function = _function_after(lines, index)
        block = "\n".join(lines[index : min(len(lines), index + 18)])
        contexts.append(RouteContext(method=method, path=route_path, function=function, line=index + 1, block=block))
    return contexts


def _route_from_line(line: str) -> tuple[str, str] | None:
    decorator = re.search(r"@(?:app|router)\.(get|post|put|patch|delete)\(['\"]([^'\"]+)['\"]", line)
    if decorator:
        return decorator.group(1).upper(), decorator.group(2)
    express = re.search(r"(?:app|router)\.(get|post|put|patch|delete)\(['\"]([^'\"]+)['\"]", line)
    if express:
        return express.group(1).upper(), express.group(2)
    return None


def _function_after(lines: list[str], route_index: int) -> str:
    for line in lines[route_index + 1 : min(len(lines), route_index + 6)]:
        python_func = re.search(r"\bdef\s+([A-Za-z_][A-Za-z0-9_]*)", line)
        if python_func:
            return python_func.group(1)
        js_func = re.search(r"\b(?:function\s+)?([A-Za-z_][A-Za-z0-9_]*)?\s*\(?[^)]*\)?\s*=>", line)
        if js_func and js_func.group(1):
            return js_func.group(1)
    return "route_handler"


def _analyze_route_context(context: RouteContext, file_path: str) -> list[Finding]:
    findings: list[Finding] = []
    lowered_block = context.block.lower()
    lowered_path = context.path.lower()
    has_auth_control = any(control in lowered_block for control in AUTH_CONTROLS)
    has_id_input = any(name in lowered_path or name in lowered_block for name in ID_NAMES)
    has_lookup = any(pattern in lowered_block for pattern in OBJECT_LOOKUPS)
    has_write = context.method in {"PUT", "PATCH", "DELETE", "POST"} or any(
        word in lowered_path for word in UPDATE_DELETE_WORDS
    )

    if has_id_input and has_lookup and not has_auth_control:
        findings.append(
            _build_finding(
                title="Validation-ready broken access control / object reference review",
                category="broken_access_control",
                context=context,
                file_path=file_path,
                root_cause=(
                    "Route uses caller-controlled object identifiers and reads objects "
                    "without a visible ownership check."
                ),
                missing_control=(
                    "Missing ownership, tenant, role, or permission validation before returning the object."
                ),
                vulnerable_flow="Request route parameter or body id flows into an object lookup and response.",
                confidence_score=0.86,
            )
        )

    if has_write and has_id_input and not has_auth_control:
        findings.append(
            _build_finding(
                title="Validation-ready direct object update or delete review",
                category="direct_object_mutation",
                context=context,
                file_path=file_path,
                root_cause="Write route appears to use caller-controlled identifiers without a visible boundary check.",
                missing_control="Missing ownership or tenant boundary check before update or delete behavior.",
                vulnerable_flow="Request id reaches a write operation without visible authorization enforcement.",
                confidence_score=0.84,
            )
        )

    if any(word in lowered_path for word in SENSITIVE_ROUTE_WORDS) and not has_auth_control:
        findings.append(
            _build_finding(
                title="Validation-ready missing authentication review",
                category="missing_authentication",
                context=context,
                file_path=file_path,
                root_cause=(
                    "Sensitive route lacks a visible authentication or authorization control in the handler block."
                ),
                missing_control="Missing auth middleware, decorator, or current user/session check.",
                vulnerable_flow="Sensitive route can reach handler logic without a visible auth gate.",
                confidence_score=0.82,
            )
        )

    if _contains_any(lowered_block, MASS_ASSIGNMENT_PATTERNS) and _contains_any(lowered_block, SENSITIVE_FIELDS):
        findings.append(
            _build_finding(
                title="Validation-ready mass assignment review",
                category="mass_assignment",
                context=context,
                file_path=file_path,
                root_cause="Request body appears to be assigned directly to model fields including sensitive names.",
                missing_control="Missing explicit allowlist of writable fields.",
                vulnerable_flow="Request body can influence model update input without visible filtering.",
                confidence_score=0.88,
            )
        )

    if _contains_any(lowered_block, FILE_PATTERNS) and ("filename" in lowered_block or "path" in lowered_block):
        has_file_control = (
            "secure_filename" in lowered_block or "resolve()" in lowered_block or "safe_join" in lowered_block
        )
        if not has_file_control:
            findings.append(
                _build_finding(
                    title="Validation-ready insecure file handling review",
                    category="insecure_file_handling",
                    context=context,
                    file_path=file_path,
                    root_cause="File path or name from request context appears to reach file handling logic.",
                    missing_control=(
                        "Missing filename normalization, extension validation, or safe directory enforcement."
                    ),
                    vulnerable_flow=(
                        "Request-controlled path data reaches file read, write, upload, or download behavior."
                    ),
                    confidence_score=0.83,
                )
            )

    if _contains_any(lowered_block, FETCH_PATTERNS) and ("url" in lowered_block or "target" in lowered_block):
        has_url_control = (
            "allowlist" in lowered_block or "allowed_hosts" in lowered_block or "urlparse" in lowered_block
        )
        if not has_url_control:
            findings.append(
                _build_finding(
                    title="Validation-ready server-side URL fetch review",
                    category="server_side_url_fetch",
                    context=context,
                    file_path=file_path,
                    root_cause="Server-side HTTP client appears to consume caller-controlled URL input.",
                    missing_control="Missing URL scheme, host allowlist, and internal address validation.",
                    vulnerable_flow="Request URL parameter flows into a server-side fetch call.",
                    confidence_score=0.85,
                )
            )
    return findings


def _analyze_file_wide_patterns(text: str, file_path: str) -> list[Finding]:
    lowered = text.lower()
    if not _contains_any(lowered, FETCH_PATTERNS) or not ("request" in lowered and "url" in lowered):
        return []
    if "allowlist" in lowered or "allowed_hosts" in lowered or "urlparse" in lowered:
        return []
    context = RouteContext(method="UNKNOWN", path="file-wide", function="file_scope", line=1, block=text[:900])
    return [
        _build_finding(
            title="Validation-ready server-side URL fetch review",
            category="server_side_url_fetch",
            context=context,
            file_path=file_path,
            root_cause="Server-side HTTP client appears to consume caller-controlled URL input.",
            missing_control="Missing URL scheme, host allowlist, and internal address validation.",
            vulnerable_flow="Caller-provided URL-like input reaches a server-side fetch call.",
            confidence_score=0.8,
        )
    ]


def _build_finding(
    *,
    title: str,
    category: str,
    context: RouteContext,
    file_path: str,
    root_cause: str,
    missing_control: str,
    vulnerable_flow: str,
    confidence_score: float,
) -> Finding:
    steps = _manual_steps(category, context)
    return Finding(
        title=title,
        severity="high" if confidence_score >= 0.85 else "medium",
        description="Static local source analysis found a logic flow that is ready for authorized manual validation.",
        source_locations=[{"file": file_path, "line": context.line}],
        affected_routes=[context.path] if context.path != "file-wide" else [],
        affected_functions=[context.function],
        vulnerable_flow=vulnerable_flow,
        root_cause=root_cause,
        missing_control=missing_control,
        attacker_model="authorized tester using approved comparison roles",
        preconditions=[
            "Written authorization and source assessment scope are approved.",
            "Use only approved test accounts and staging or lab data.",
        ],
        exploitability_reasoning=(
            "The issue is plausible when route input reaches sensitive logic before the expected control."
        ),
        manual_validation_steps=steps,
        expected_evidence=[
            "Source file and line reference for the handler.",
            "Manual request and response pair from the approved test environment.",
            "Observed application log or reviewer note confirming the control decision.",
        ],
        false_positive_checks=[
            "Check framework-level middleware and router-level guards not visible in the handler block.",
            "Check model policies, service-layer guards, and database tenant constraints.",
            "Confirm the route is reachable in the tested deployment.",
        ],
        remediation_guidance=_remediation_for(category),
        confidence_score=confidence_score,
        validation_status="validation_ready" if confidence_score >= 0.8 else "logic_analyzed",
        metadata={"logic_category": category},
    )


def _manual_steps(category: str, context: RouteContext) -> list[str]:
    route = context.path
    common = [
        "Confirm the route is in the authorized staging or lab scope.",
        "Log in with the approved lowest-privilege test role and prepare a second approved comparison role if needed.",
        f"Manually exercise {route} through browser, Burp, or Postman using only approved test data.",
        "Record the response, relevant headers, timestamps, and source line reference.",
    ]
    if category in {"broken_access_control", "direct_object_mutation"}:
        return [
            *common,
            "Compare behavior for an object owned by the first test role and an object owned by the second test role.",
            "Confirm whether the application enforces ownership, tenant, role, or permission boundaries.",
        ]
    if category == "missing_authentication":
        return [
            *common,
            "Repeat the same manual request after signing out or using an approved unauthenticated session.",
            "Confirm whether the application blocks the sensitive route before handler behavior runs.",
        ]
    if category == "mass_assignment":
        return [
            *common,
            "Submit only approved benign field changes and observe whether sensitive fields are accepted or ignored.",
            "Confirm whether server-side allowlisted fields are enforced before persistence.",
        ]
    if category == "insecure_file_handling":
        return [
            *common,
            "Use approved benign filenames and allowed sample files only.",
            "Confirm whether extension, content type, normalized path, and storage directory controls are enforced.",
        ]
    return [
        *common,
        "Use only approved benign external URLs or internal lab endpoints designated for validation.",
        "Confirm whether scheme, host allowlist, redirect, and internal address controls are enforced.",
    ]


def _remediation_for(category: str) -> str:
    return {
        "broken_access_control": "Enforce object ownership, tenant, role, or permission checks before object access.",
        "direct_object_mutation": (
            "Authorize each write against the current user and object boundary before persistence."
        ),
        "missing_authentication": "Add route-level authentication and authorization middleware or decorators.",
        "mass_assignment": "Map request bodies through an explicit allowlist before model updates.",
        "insecure_file_handling": (
            "Normalize filenames, validate type and extension, and enforce a safe storage directory."
        ),
        "server_side_url_fetch": "Validate URL scheme and host against an allowlist and block internal address ranges.",
    }.get(category, "Add the missing control at the route, service, or model boundary.")


def _contains_any(text: str, needles: tuple[str, ...]) -> bool:
    return any(needle in text for needle in needles)
