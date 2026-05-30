from __future__ import annotations

from typing import Any

from core.dns_resolver import SafeDNSQuery, perform_safe_dns_query, validate_dns_record_type
from core.modules import BaseReconModule, ModuleContext, ModuleResult


class LiveDNSModule(BaseReconModule):
    name = "live_dns"
    description = "Performs explicit, authorized DNS lookups through SafeDNSResolver."
    required_policy_flags = ("allow_network",)

    def run(self, context: ModuleContext) -> ModuleResult:
        allow_network = bool(context.policy.get("allow_network", False))
        if not allow_network:
            return ModuleResult(
                module_name=self.name,
                status="skipped",
                errors=["Network access is disabled by policy."],
                findings=[_finding(context, "DNS query blocked by policy", "info", "low", "Safe live DNS module did not run because allow_network is false.")],
            )

        resolver = context.metadata.get("dns_resolver")
        record_types = context.metadata.get("dns_record_types", ["A", "AAAA"])
        if not isinstance(record_types, list):
            record_types = ["A", "AAAA"]

        records: list[dict[str, Any]] = []
        evidence: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        errors: list[str] = []
        audit_events: list[dict[str, Any]] = []

        for raw_type in record_types:
            try:
                record_type = validate_dns_record_type(str(raw_type))
            except ValueError as exc:
                errors.append(str(exc))
                findings.append(_finding(context, "Unsupported DNS record type", "info", "low", str(exc)))
                continue
            result = perform_safe_dns_query(
                SafeDNSQuery(
                    name=context.normalized_target,
                    record_type=record_type,
                    allowed_domains=context.allowed_domains,
                    allowed_ips=context.allowed_ips,
                    scan_id=context.scan_id,
                    scan_mode=context.scan_mode,
                ),
                allow_network=allow_network,
                resolver=resolver,
            )
            audit_events.extend(result.audit_events)
            if result.records:
                records.extend(result.records)
                findings.append(_finding(context, "DNS query completed", "info", "medium", f"{record_type} query returned {len(result.records)} record(s)."))
            if result.error:
                errors.append(result.error)
                findings.append(_finding(context, "DNS query blocked or unsupported", "info", "low", result.error))

        assets = sorted({str(record.get("value")) for record in records if record.get("value")})
        status = "success" if records or findings else "failed"
        return ModuleResult(
            module_name=self.name,
            status=status,
            assets=assets,
            findings=findings,
            evidence=[{"type": "dns_records", "records": records, "audit_events": audit_events}],
            errors=errors,
            metadata={"record_count": len(records), "audit_event_count": len(audit_events)},
        )


def _finding(context: ModuleContext, title: str, severity: str, confidence: str, evidence: str) -> dict[str, Any]:
    return {
        "target": context.normalized_target,
        "asset": context.normalized_target,
        "endpoint": "",
        "module": LiveDNSModule.name,
        "finding_type": "dns_observation",
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "evidence": evidence,
        "recommendation": "Review DNS records manually within the authorized assessment scope.",
        "source": "live_dns",
        "is_potential": True,
    }
