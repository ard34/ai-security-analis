from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
import ipaddress
import socket

from core.execution import ExecutionPolicy, SafeExecutionContext, create_execution_decision, enforce_scope_before_action
from core.logging import redact_sensitive_data


SUPPORTED_RECORD_TYPES = {"A", "AAAA", "CNAME", "MX", "TXT", "NS", "CAA"}
NETWORK_SUPPORTED_RECORD_TYPES = {"A", "AAAA"}


@dataclass(frozen=True)
class SafeDNSQuery:
    name: str
    record_type: str
    allowed_domains: list[str]
    allowed_ips: list[str] = field(default_factory=list)
    scan_id: str = "manual"
    scan_mode: str = "safe"


@dataclass
class SafeDNSResult:
    name: str
    record_type: str
    records: list[dict[str, Any]]
    error: str | None
    in_scope: bool
    commands_executed: list[str] = field(default_factory=list)
    audit_events: list[dict[str, Any]] = field(default_factory=list)


def normalize_dns_name(name: str) -> str:
    normalized = str(name or "").strip().lower().rstrip(".")
    if not normalized:
        raise ValueError("DNS name must be non-empty.")
    if any(token in normalized for token in ("/", "\\", "..", ":", " ")):
        raise ValueError("DNS name contains invalid characters.")
    return normalized


def validate_dns_record_type(record_type: str) -> str:
    normalized = str(record_type or "").strip().upper()
    if normalized not in SUPPORTED_RECORD_TYPES:
        raise ValueError(f"Unsupported DNS record type: {record_type}")
    return normalized


def build_dns_execution_context(
    query: SafeDNSQuery,
    allow_network: bool = False,
) -> SafeExecutionContext:
    name = normalize_dns_name(query.name)
    record_type = validate_dns_record_type(query.record_type)
    return SafeExecutionContext(
        scan_id=query.scan_id,
        target=name,
        allowed_domains=list(query.allowed_domains or []),
        allowed_ips=list(query.allowed_ips or []),
        scan_mode=query.scan_mode,
        policy=ExecutionPolicy(allow_network=allow_network),
        metadata={"component": "safe_dns_resolver", "record_type": record_type, "name": name},
    )


def resolve_a_aaaa_with_socket(
    name: str,
    record_type: str,
    resolver: Any | None = None,
) -> list[dict[str, Any]]:
    safe_name = normalize_dns_name(name)
    safe_type = validate_dns_record_type(record_type)
    if safe_type not in NETWORK_SUPPORTED_RECORD_TYPES:
        raise ValueError("Only A and AAAA are supported by the standard-library resolver.")
    family = socket.AF_INET if safe_type == "A" else socket.AF_INET6
    getaddrinfo = resolver or socket.getaddrinfo
    rows = getaddrinfo(safe_name, 0, family=family, type=socket.SOCK_STREAM)
    seen: set[str] = set()
    records: list[dict[str, Any]] = []
    for row in rows or []:
        sockaddr = row[4] if len(row) > 4 else ()
        if not sockaddr:
            continue
        value = str(sockaddr[0])
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            continue
        if safe_type == "A" and ip.version != 4:
            continue
        if safe_type == "AAAA" and ip.version != 6:
            continue
        if value in seen:
            continue
        seen.add(value)
        records.append({"name": safe_name, "type": safe_type, "value": value, "ttl": None, "source": "safe_dns_resolver"})
    return records


def perform_safe_dns_query(
    query: SafeDNSQuery,
    allow_network: bool = False,
    resolver: Any | None = None,
) -> SafeDNSResult:
    audit_events: list[dict[str, Any]] = []
    try:
        name = normalize_dns_name(query.name)
        record_type = validate_dns_record_type(query.record_type)
        scope_decision = enforce_scope_before_action(name, query.allowed_domains, query.allowed_ips)
        if not scope_decision.allowed:
            return _dns_result(name, record_type, [], scope_decision.reason, False, audit_events)
        context = build_dns_execution_context(query, allow_network=allow_network)
        decision = create_execution_decision("network:dns_lookup", name, context, metadata={"record_type": record_type})
        if decision.audit_event:
            audit_events.append(decision.audit_event)
        if not decision.allowed:
            return _dns_result(name, record_type, [], decision.reason, True, audit_events)
        if record_type not in NETWORK_SUPPORTED_RECORD_TYPES:
            return _dns_result(
                name,
                record_type,
                [],
                "Record type is not supported by the standard-library resolver in this stage.",
                True,
                audit_events,
            )
        records = resolve_a_aaaa_with_socket(name, record_type, resolver=resolver)
        return _dns_result(name, record_type, records, None, True, audit_events)
    except Exception as exc:
        safe_name = str(redact_sensitive_data(query.name or ""))
        safe_type = str(redact_sensitive_data(query.record_type or ""))
        return _dns_result(safe_name, safe_type, [], str(redact_sensitive_data(str(exc))), False, audit_events)


def _dns_result(
    name: str,
    record_type: str,
    records: list[dict[str, Any]],
    error: str | None,
    in_scope: bool,
    audit_events: list[dict[str, Any]],
) -> SafeDNSResult:
    return SafeDNSResult(
        name=name,
        record_type=record_type,
        records=redact_sensitive_data(records),
        error=str(redact_sensitive_data(error)) if error else None,
        in_scope=in_scope,
        commands_executed=[],
        audit_events=redact_sensitive_data(audit_events),
    )
