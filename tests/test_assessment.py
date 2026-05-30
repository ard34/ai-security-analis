from __future__ import annotations

import os
import socket
import subprocess
from dataclasses import replace

import pytest

from core.assessment import (
    AssessmentProject,
    approve_assessment_project,
    archive_assessment_project,
    assessment_project_from_dict,
    assessment_project_to_dict,
    create_assessment_project,
    is_assessment_approved,
    validate_assessment_project,
)


def make_project(**overrides) -> AssessmentProject:
    data = {
        "name": "Preprod API Assessment",
        "owner": "Security Team",
        "operator": "Internal Pentester",
        "authorization_note": "Approved ticket RT-001 for pre-production assessment.",
        "allowed_domains": ["Example.COM"],
        "environment": "staging",
        "scan_mode": "safe",
    }
    data.update(overrides)
    return create_assessment_project(**data)


def test_create_assessment_project_valid() -> None:
    project = make_project()

    assert project.metadata.name == "Preprod API Assessment"


def test_assessment_has_assessment_id() -> None:
    assert make_project().metadata.assessment_id


def test_assessment_default_status_draft() -> None:
    assert make_project().status == "draft"


def test_approval_changes_status_to_approved() -> None:
    assert approve_assessment_project(make_project()).status == "approved"


def test_archive_changes_status_to_archived() -> None:
    assert archive_assessment_project(make_project()).status == "archived"


def test_reject_assessment_without_name() -> None:
    with pytest.raises(ValueError):
        make_project(name="")


def test_reject_assessment_without_owner() -> None:
    with pytest.raises(ValueError):
        make_project(owner="")


def test_reject_assessment_without_operator() -> None:
    with pytest.raises(ValueError):
        make_project(operator="")


def test_reject_assessment_without_authorization_note() -> None:
    with pytest.raises(ValueError):
        make_project(authorization_note="")


def test_reject_assessment_without_scope() -> None:
    with pytest.raises(ValueError):
        make_project(allowed_domains=[], allowed_ips=[])


def test_reject_invalid_environment() -> None:
    with pytest.raises(ValueError):
        make_project(environment="internet")


def test_reject_invalid_scan_mode() -> None:
    with pytest.raises(ValueError):
        make_project(scan_mode="aggressive")


def test_reject_invalid_status() -> None:
    project = make_project()

    with pytest.raises(ValueError):
        validate_assessment_project(replace(project, status="invalid"))


def test_domain_scope_normalized_lowercase() -> None:
    assert make_project().scope.allowed_domains == ["example.com"]


def test_to_dict_from_dict_roundtrip() -> None:
    project = make_project(tags=["api"], notes="Internal authorized assessment.")

    restored = assessment_project_from_dict(assessment_project_to_dict(project))

    assert restored == project


def test_is_assessment_approved_false_for_draft() -> None:
    assert is_assessment_approved(make_project()) is False


def test_is_assessment_approved_true_for_approved() -> None:
    assert is_assessment_approved(approve_assessment_project(make_project())) is True


def test_reject_sensitive_metadata() -> None:
    with pytest.raises(ValueError):
        make_project(authorization_note="Approved with token=abc")


def test_assessment_does_not_use_network(monkeypatch) -> None:
    def fail_socket(*args, **kwargs):
        raise AssertionError("Network access is not allowed in assessment model")

    monkeypatch.setattr(socket, "socket", fail_socket)

    assert make_project().metadata.assessment_id


def test_assessment_does_not_use_subprocess(monkeypatch) -> None:
    def fail_run(*args, **kwargs):
        raise AssertionError("subprocess is not allowed in assessment model")

    monkeypatch.setattr(subprocess, "run", fail_run)

    assert make_project().metadata.assessment_id


def test_assessment_does_not_use_os_system(monkeypatch) -> None:
    def fail_system(*args, **kwargs):
        raise AssertionError("os.system is not allowed in assessment model")

    monkeypatch.setattr(os, "system", fail_system)

    assert make_project().metadata.assessment_id
