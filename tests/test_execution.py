import pytest

from core.execution import ExecutionEngine
from core.logging import AuditLogger
from core.policies import DomainRunPolicy, PolicyViolation


def policy(path):
    return DomainRunPolicy(
        safe_live=True,
        allow_network=True,
        confirm_safe_live=True,
        audit_log_path=str(path),
        scan_budget=1,
    )


def test_execution_requires_approval(tmp_path):
    with pytest.raises(PolicyViolation):
        ExecutionEngine(
            policy=policy(tmp_path / "a.jsonl"),
            assessment_approved=False,
            audit=AuditLogger(tmp_path / "a.jsonl"),
        )


def test_execution_budget_guard(tmp_path):
    engine = ExecutionEngine(
        policy=policy(tmp_path / "a.jsonl"),
        assessment_approved=True,
        audit=AuditLogger(tmp_path / "a.jsonl"),
    )
    assert engine.guarded_call("one", lambda: "ok") == "ok"
    with pytest.raises(PolicyViolation):
        engine.guarded_call("two", lambda: "no")

