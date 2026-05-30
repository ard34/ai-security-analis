from __future__ import annotations

from core.modules import BaseReconModule, ModuleContext, ModuleResult


class DummyPassiveModule(BaseReconModule):
    name = "dummy_passive"
    description = "Dummy passive module for testing the module interface."
    required_policy_flags = ()

    def run(self, context: ModuleContext) -> ModuleResult:
        asset = f"https://{context.normalized_target}"
        return ModuleResult(
            module_name=self.name,
            status="success",
            assets=[asset],
            endpoints=["/"],
            findings=[
                {
                    "module": self.name,
                    "finding_type": "informational",
                    "title": "Dummy Passive Observation",
                    "severity": "info",
                    "confidence": "low",
                    "evidence": "Dummy module executed without network access.",
                    "recommendation": "Replace this module with a real passive analyzer later.",
                    "source": "dummy_module",
                    "is_potential": True,
                }
            ],
            evidence=[
                {
                    "source": "dummy_module",
                    "detail": "Dummy module executed without network access.",
                }
            ],
        )
