from __future__ import annotations

import os
import socket
import sqlite3
import subprocess

from storage.database import get_connection, initialize_database


def table_names(db_path) -> set[str]:
    with sqlite3.connect(str(db_path)) as connection:
        rows = connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
    return {row[0] for row in rows}


def index_names(db_path) -> set[str]:
    with sqlite3.connect(str(db_path)) as connection:
        rows = connection.execute("SELECT name FROM sqlite_master WHERE type = 'index'").fetchall()
    return {row[0] for row in rows}


def test_initialize_database_creates_sqlite_file(tmp_path) -> None:
    db_path = tmp_path / "test.sqlite3"
    initialize_database(db_path)
    assert db_path.exists()


def test_initialize_database_creates_parent_directory(tmp_path) -> None:
    db_path = tmp_path / "nested" / "db" / "test.sqlite3"
    initialize_database(db_path)
    assert db_path.parent.exists()


def test_scan_results_table_exists(tmp_path) -> None:
    db_path = tmp_path / "test.sqlite3"
    initialize_database(db_path)
    assert "scan_results" in table_names(db_path)


def test_indexes_exist(tmp_path) -> None:
    db_path = tmp_path / "test.sqlite3"
    initialize_database(db_path)
    indexes = index_names(db_path)
    assert "idx_scan_results_scan_id" in indexes
    assert "idx_scan_results_created_at" in indexes


def test_get_connection_returns_sqlite_connection(tmp_path) -> None:
    connection = get_connection(tmp_path / "test.sqlite3")
    try:
        assert isinstance(connection, sqlite3.Connection)
        assert connection.row_factory is sqlite3.Row
    finally:
        connection.close()


def test_database_helper_does_not_use_network(monkeypatch, tmp_path) -> None:
    def fail_socket(*_args, **_kwargs):
        raise AssertionError("Network access is not allowed in storage layer")

    monkeypatch.setattr(socket, "socket", fail_socket)
    initialize_database(tmp_path / "test.sqlite3")


def test_database_helper_does_not_use_subprocess(monkeypatch, tmp_path) -> None:
    def fail_run(*_args, **_kwargs):
        raise AssertionError("subprocess is not allowed in storage layer")

    monkeypatch.setattr(subprocess, "run", fail_run)
    initialize_database(tmp_path / "test.sqlite3")


def test_database_helper_does_not_use_os_system(monkeypatch, tmp_path) -> None:
    def fail_system(*_args, **_kwargs):
        raise AssertionError("os.system is not allowed in storage layer")

    monkeypatch.setattr(os, "system", fail_system)
    initialize_database(tmp_path / "test.sqlite3")

