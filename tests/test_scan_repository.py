from core.models import ScanResult
from storage.database import connect
from storage.repositories import ScanRepository


def test_scan_repository_save_get_list(tmp_path):
    repo = ScanRepository(connect(tmp_path / "db.sqlite3"))
    result = ScanResult(target="x", workflow="w")
    repo.save(result)
    assert repo.get(result.id).id == result.id
    assert repo.list()[0]["id"] == result.id

