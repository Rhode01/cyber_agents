"""Migration sanity checks that do not need a database.

``make migrate-sql`` renders the same migrations offline; these assertions keep
the baseline revision honest without standing PostgreSQL up in CI.
"""

from __future__ import annotations

import contextlib
import io
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import Table

from app.models.finding import Finding as FindingModel

BACKEND_ROOT = Path(__file__).resolve().parents[1]


def _config() -> Config:
    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_ROOT / "alembic"))
    return config


def _script_directory() -> ScriptDirectory:
    return ScriptDirectory.from_config(_config())


def _render_sql() -> str:
    """Render every migration as SQL without connecting to anything."""
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        command.upgrade(_config(), "head", sql=True)
    return buffer.getvalue()


def test_there_is_exactly_one_baseline_revision() -> None:
    scripts = _script_directory()
    revisions = list(scripts.walk_revisions())

    assert len(revisions) == 1
    baseline = revisions[0]
    assert baseline.revision == "0001"
    assert baseline.down_revision is None


def test_head_is_reachable() -> None:
    scripts = _script_directory()

    assert scripts.get_current_head() == "0001"


def test_migration_ddl_matches_the_orm_model() -> None:
    """Guards against the model and the baseline drifting apart.

    Both sides run through Base's naming convention, so a constraint named in
    only one of them shows up here rather than as a surprise autogenerate diff.
    """
    sql = _render_sql()
    table = FindingModel.__table__
    assert isinstance(table, Table)

    assert "CREATE TABLE findings" in sql

    for column in table.columns:
        assert f"{column.name} " in sql, f"column {column.name} missing from the migration"

    for constraint in table.constraints:
        assert f"CONSTRAINT {constraint.name}" in sql, f"constraint {constraint.name} missing"

    for index in table.indexes:
        assert f"CREATE INDEX {index.name}" in sql, f"index {index.name} missing"
