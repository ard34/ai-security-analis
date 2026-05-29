from __future__ import annotations

from copy import deepcopy
import os
import pickle
import socket
import subprocess

from storage.repositories import ScanResultRepository


def make_scan_result(scan_id: str = "scan-001", target: str = "example.com", status: str = "success") -> dict:
    return {
        "scan_id": scan_id,
        "target": target,
        "normalized_target": target,
        "scan_mode": "safe",
        "allowed_scope": {"domains": ["example.com"], "ips": []},
        "assets": [f"https://{target}"] if status == "success" else [],
        "endpoints": ["/"] if status == "success" else [],
        "findings": [],
        "audit_log": {
            "scan_id": scan_id,
            "target": target,
            "scan_mode": "safe",
            "modules_enabled": ["security_headers"],
            "commands_executed": [],
            "errors": [],
            "findings_generated": 0,
        },
        "started_at": "2026-01-01T00:00:00Z",
        "ended_at": "2026-01-01T00:00:01Z",
        "status": status,
    }


def repo(tmp_path) -> ScanResultRepository:
    return ScanResultRepository(tmp_path / "test.sqlite3")


def test_save_scan_result_stores_scan_result(tmp_path) -> None:
    repository = repo(tmp_path)
    repository.save_scan_result(make_scan_result())
    assert repository.count_scan_results() == 1


def test_save_scan_result_returns_scan_id(tmp_path) -> None:
    assert repo(tmp_path).save_scan_result(make_scan_result("scan-abc")) == "scan-abc"


def test_get_scan_result_returns_saved_result(tmp_path) -> None:
    repository = repo(tmp_path)
    result = make_scan_result()
    repository.save_scan_result(result)
    assert repository.get_scan_result("scan-001") == result


def test_get_scan_result_returns_none_when_missing(tmp_path) -> None:
    assert repo(tmp_path).get_scan_result("missing") is None


def test_list_scan_results_returns_metadata_list(tmp_path) -> None:
    repository = repo(tmp_path)
    repository.save_scan_result(make_scan_result())
    rows = repository.list_scan_results()
    assert rows
    assert rows[0]["scan_id"] == "scan-001"


def test_list_scan_results_excludes_result_json(tmp_path) -> None:
    repository = repo(tmp_path)
    repository.save_scan_result(make_scan_result())
    assert "result_json" not in repository.list_scan_results()[0]


def test_list_scan_results_newest_first(tmp_path) -> None:
    repository = repo(tmp_path)
    repository.save_scan_result(make_scan_result("scan-old"))
    repository.save_scan_result(make_scan_result("scan-new"))
    assert repository.list_scan_results()[0]["scan_id"] == "scan-new"


def test_list_scan_results_respects_limit(tmp_path) -> None:
    repository = repo(tmp_path)
    for index in range(3):
        repository.save_scan_result(make_scan_result(f"scan-{index}"))
    assert len(repository.list_scan_results(limit=2)) == 2


def test_list_scan_results_clamps_limit_to_100(tmp_path) -> None:
    repository = repo(tmp_path)
    for index in range(105):
        repository.save_scan_result(make_scan_result(f"scan-{index}"))
    assert len(repository.list_scan_results(limit=500)) == 100


def test_delete_scan_result_returns_true_if_deleted(tmp_path) -> None:
    repository = repo(tmp_path)
    repository.save_scan_result(make_scan_result())
    assert repository.delete_scan_result("scan-001") is True


def test_delete_scan_result_returns_false_if_missing(tmp_path) -> None:
    assert repo(tmp_path).delete_scan_result("missing") is False


def test_count_scan_results_counts_rows(tmp_path) -> None:
    repository = repo(tmp_path)
    repository.save_scan_result(make_scan_result("scan-1"))
    repository.save_scan_result(make_scan_result("scan-2"))
    assert repository.count_scan_results() == 2


def test_duplicate_scan_id_updates_existing_row(tmp_path) -> None:
    repository = repo(tmp_path)
    repository.save_scan_result(make_scan_result("scan-1", target="example.com"))
    repository.save_scan_result(make_scan_result("scan-1", target="updated.example.com"))
    assert repository.count_scan_results() == 1
    assert repository.get_scan_result("scan-1")["target"] == "updated.example.com"


def test_repository_does_not_mutate_input_scan_result(tmp_path) -> None:
    repository = repo(tmp_path)
    result = make_scan_result()
    original = deepcopy(result)
    repository.save_scan_result(result)
    assert result == original


def test_repository_does_not_use_pickle(monkeypatch, tmp_path) -> None:
    def fail_dumps(*_args, **_kwargs):
        raise AssertionError("pickle is not allowed in storage layer")

    monkeypatch.setattr(pickle, "dumps", fail_dumps)
    repository = repo(tmp_path)
    repository.save_scan_result(make_scan_result())
    assert repository.count_scan_results() == 1


def test_repository_does_not_use_network(monkeypatch, tmp_path) -> None:
    def fail_socket(*_args, **_kwargs):
        raise AssertionError("Network access is not allowed in storage layer")

    monkeypatch.setattr(socket, "socket", fail_socket)
    repository = repo(tmp_path)
    repository.save_scan_result(make_scan_result())
    assert repository.count_scan_results() == 1


def test_repository_does_not_use_subprocess(monkeypatch, tmp_path) -> None:
    def fail_run(*_args, **_kwargs):
        raise AssertionError("subprocess is not allowed in storage layer")

    monkeypatch.setattr(subprocess, "run", fail_run)
    repository = repo(tmp_path)
    repository.save_scan_result(make_scan_result())
    assert repository.count_scan_results() == 1


def test_repository_does_not_use_os_system(monkeypatch, tmp_path) -> None:
    def fail_system(*_args, **_kwargs):
        raise AssertionError("os.system is not allowed in storage layer")

    monkeypatch.setattr(os, "system", fail_system)
    repository = repo(tmp_path)
    repository.save_scan_result(make_scan_result())
    assert repository.count_scan_results() == 1


def test_rejected_scan_result_can_be_saved(tmp_path) -> None:
    repository = repo(tmp_path)
    result = make_scan_result("scan-rejected", status="rejected")
    repository.save_scan_result(result)
    assert repository.get_scan_result("scan-rejected")["status"] == "rejected"


def test_scan_result_with_empty_findings_can_be_saved(tmp_path) -> None:
    repository = repo(tmp_path)
    result = make_scan_result("scan-empty")
    result["findings"] = []
    repository.save_scan_result(result)
    assert repository.get_scan_result("scan-empty")["findings"] == []
