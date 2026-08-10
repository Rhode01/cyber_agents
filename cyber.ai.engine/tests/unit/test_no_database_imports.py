"""The ai.engine must contain zero database code.

Persistence belongs to the backend. This is the enforcement, not a convention:
every module under ``ai_engine`` is parsed and any import of a database library
fails the build. The declared dependencies are checked too, so a database library
cannot even be added to the virtualenv without this test noticing.
"""

from __future__ import annotations

import ast
import tomllib
from pathlib import Path

FORBIDDEN_MODULES = frozenset(
    {
        "sqlalchemy",
        "asyncpg",
        "alembic",
        "psycopg",
        "psycopg2",
        "aiosqlite",
        "sqlite3",
        "sqlmodel",
        "databases",
        "tortoise",
        "peewee",
        "pymongo",
        "motor",
        "redis",
        "arq",
    }
)

AI_ENGINE_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = AI_ENGINE_ROOT / "ai_engine"


def _imported_root_modules(source: str) -> set[str]:
    tree = ast.parse(source)
    roots: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])

    return roots


def test_no_module_imports_a_database_library() -> None:
    offenders: dict[str, set[str]] = {}

    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        imported = _imported_root_modules(path.read_text(encoding="utf-8"))
        forbidden = imported & FORBIDDEN_MODULES
        if forbidden:
            offenders[str(path.relative_to(AI_ENGINE_ROOT))] = forbidden

    assert offenders == {}, f"database libraries imported inside ai.engine: {offenders}"


def test_no_database_library_is_declared_as_a_dependency() -> None:
    manifest = tomllib.loads((AI_ENGINE_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    declared = {
        requirement.split("[")[0].split(">")[0].split("<")[0].split("=")[0].strip().lower()
        for requirement in manifest["project"]["dependencies"]
    }
    dev = {name.lower() for name in manifest["tool"]["poetry"]["group"]["dev"]["dependencies"]}

    assert declared & FORBIDDEN_MODULES == set()
    assert dev & FORBIDDEN_MODULES == set()


def test_the_only_route_to_persistence_is_the_backend_client() -> None:
    client = (PACKAGE_ROOT / "clients" / "backend.py").read_text(encoding="utf-8")

    assert "httpx" in client
    assert _imported_root_modules(client) & FORBIDDEN_MODULES == set()
