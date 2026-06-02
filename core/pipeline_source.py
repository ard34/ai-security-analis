from __future__ import annotations

from pathlib import Path

from core.config import load_config
from core.evidence import collect_local_evidence
from core.finding_dedup import deduplicate_findings
from core.manual_testing import recommendations_for_findings
from core.models import Asset, Endpoint, Finding, ScanResult
from core.source_logic_analysis import analyze_source_logic
from modules.source_mapper import map_source_folder


def run_source_assessment(
    path: str | Path, *, max_file_bytes: int | None = None, logic_analysis: bool = False
) -> ScanResult:
    config = load_config()
    source_map = map_source_folder(path, max_file_bytes=max_file_bytes or config.max_file_bytes)
    result = ScanResult(target=source_map.root, workflow="type1_source")
    root_asset = Asset(type="source_folder", value=source_map.root)
    result.assets.append(root_asset)
    evidence = collect_local_evidence("source_map", str(source_map.to_dict()))
    result.evidence.append(evidence)
    for route in source_map.routes:
        result.endpoints.append(Endpoint(method=route["method"], path=route["path"], source=route["file"]))
    findings: list[Finding] = []
    for smell in source_map.security_smells:
        findings.append(
            Finding(
                title=f"Potential security smell: {smell['smell']}",
                severity="medium",
                description="Static source review identified a pattern that needs manual validation.",
                asset_id=root_asset.id,
                evidence_ids=[evidence.id],
                recommendations=["Validate the configuration with the application owner before changing behavior."],
            )
        )
    if source_map.auth_hints and not source_map.routes:
        findings.append(
            Finding(
                title="Potential auth logic without mapped routes",
                severity="info",
                description="Auth-related code was found but no route declarations were mapped by passive parsing.",
                asset_id=root_asset.id,
                evidence_ids=[evidence.id],
            )
        )
    if logic_analysis:
        logic_result = analyze_source_logic(path, max_file_bytes=max_file_bytes or config.max_file_bytes)
        logic_evidence = collect_local_evidence("source_logic_analysis", str(logic_result.to_dict()))
        result.evidence.append(logic_evidence)
        for finding in logic_result.findings:
            finding.asset_id = root_asset.id
            finding.evidence_ids.append(logic_evidence.id)
            findings.append(finding)
        result.metadata["source_logic_analysis"] = logic_result.to_dict()
    result.findings = deduplicate_findings(findings)
    result.recommendations = recommendations_for_findings(result.findings)
    result.metadata["source_map"] = source_map.to_dict()
    return result.complete()

