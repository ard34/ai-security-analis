import ast
from pathlib import Path

PROC_MODULE = "sub" + "process"
PERSISTENCE_MODULE = "pick" + "le"
SYSTEM_CALL = "sys" + "tem"
FORBIDDEN_CALLS = {(PROC_MODULE, "run"), ("os", SYSTEM_CALL)}
FORBIDDEN_NAMES = {"ev" + "al", "ex" + "ec"}
FORBIDDEN_IMPORTS = {PERSISTENCE_MODULE, PROC_MODULE}


def project_files():
    root = Path(__file__).resolve().parents[1]
    for path in root.rglob("*.py"):
        parts = set(path.relative_to(root).parts)
        if parts & {"_archive_pre_rebuild", ".venv", "venv"}:
            continue
        yield path


def test_no_forbidden_python_apis():
    for path in project_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = {alias.name.split(".")[0] for alias in node.names}
                assert not (names & FORBIDDEN_IMPORTS), path
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    assert node.func.id not in FORBIDDEN_NAMES, path
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    assert (node.func.value.id, node.func.attr) not in FORBIDDEN_CALLS, path
