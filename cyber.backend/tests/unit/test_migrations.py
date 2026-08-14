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
from app.models.message import Message as MessageModel
from app.models.run import Run as RunModel
from app.models.scan import Scan as ScanModel

# tests/unit/ -> tests/ -> the module root
BACKEND_ROOT = Path(__file__).resolve().parents[2]
HEAD_REVISION = "0008"


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


def test_the_revision_chain_is_linear_and_rooted() -> None:
    scripts = _script_directory()
    revisions = list(scripts.walk_revisions())

    # 0004 (settings table) and 0005 (the jsonb->text[] rewrite) were removed in
    # the restructure: the first stored plaintext secrets, and the second called
    # jsonb_typeof() on a column 0002 already creates as text[], which fails on
    # any fresh database. The runs migrations were renumbered to close the gap.
    expected = ["0008", "0007", "0006", "0005", "0004", "0003", "0002", "0001"]
    assert [r.revision for r in revisions] == expected
    assert revisions[-1].down_revision is None
    # Derived from `expected` rather than hardcoded: this assertion previously
    # named the old head's parent, so every new migration silently broke it in a
    # way that read as a chain problem rather than a stale test.
    assert [r.down_revision for r in revisions] == [*expected[1:], None]


def test_head_is_reachable() -> None:
    scripts = _script_directory()

    assert scripts.get_current_head() == HEAD_REVISION


def test_migration_ddl_matches_the_orm_models() -> None:
    """Guards against the models and the migrations drifting apart.

    Both sides run through Base's naming convention, so a constraint named in
    only one of them shows up here rather than as a surprise autogenerate diff.
    Covers every table, so adding a model without a migration fails here.
    """
    sql = _render_sql()

    for model in (FindingModel, MessageModel, RunModel, ScanModel):
        table = model.__table__
        assert isinstance(table, Table)

        assert f"CREATE TABLE {table.name}" in sql

        for column in table.columns:
            assert f"{column.name} " in sql, f"{table.name}.{column.name} missing"

        for constraint in table.constraints:
            assert f"CONSTRAINT {constraint.name}" in sql, (
                f"{table.name} constraint {constraint.name} missing"
            )

        for index in table.indexes:
            assert f"CREATE INDEX {index.name}" in sql, (
                f"{table.name} index {index.name} missing"
            )
