from storage.database import connect, initialize


def test_database_initializes(tmp_path):
    connection = connect(tmp_path / "db.sqlite3")
    initialize(connection)
    assert connection.execute("SELECT name FROM sqlite_master WHERE name='scans'").fetchone()

