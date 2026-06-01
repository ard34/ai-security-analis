from __future__ import annotations

from core.assessment import Assessment
from core.pipeline_domain import run_domain_assessment
from core.pipeline_source import run_source_assessment
from core.policies import DomainRunPolicy


def route_tool(name: str, **kwargs: object) -> object:
    if name == "scan_source":
        return run_source_assessment(str(kwargs["path"]))
    if name == "scan_domain":
        return run_domain_assessment(
            str(kwargs["target"]),
            kwargs["assessment"],  # type: ignore[arg-type]
            kwargs["policy"],  # type: ignore[arg-type]
        )
    raise ValueError(f"unknown local tool: {name}")


__all__ = ["Assessment", "DomainRunPolicy", "route_tool"]

