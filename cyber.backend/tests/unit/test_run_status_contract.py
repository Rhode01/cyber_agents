"""The run-status contract.

`runs.agent_statuses` has two writers - the Run page and the arq worker - over one
unvalidated JSONB column, and they drifted: the worker wrote
``{"state": "completed", "findings": n}`` while the UI read
``{"state": "done", "count": n}``, so a background run rendered as an unknown state
with an undefined count.

These are schema-level tests deliberately, not route-level. Validation is the whole
mechanism, and asserting it here needs no PostgreSQL, so it runs everywhere rather
than skipping with the rest of the DB-backed suite.
"""

from __future__ import annotations

import pytest
from cyber_contracts import AgentKind
from pydantic import ValidationError

from app.schemas.run import AgentStatusSnapshot, RunUpdate


def test_the_shape_the_frontend_writes_is_accepted() -> None:
    """Mirrors cyber.frontend/src/app/run/page.tsx."""
    update = RunUpdate.model_validate(
        {
            "agent_statuses": {
                "vulnerability": {"state": "running", "count": 0},
                "phishing": {"state": "done", "count": 4},
                "network": {"state": "skipped", "count": 0},
                "webapp": {"state": "error", "count": 0, "error": "upstream 502"},
            }
        }
    )

    assert update.agent_statuses is not None
    assert update.agent_statuses[AgentKind.webapp].error == "upstream 502"
    assert update.agent_statuses[AgentKind.phishing].count == 4


def test_the_shape_the_worker_writes_is_accepted() -> None:
    """Mirrors app/tasks/scan_tasks.py::agent_run."""
    snapshot = AgentStatusSnapshot(state="done", count=2, job_id="arq:job:abc")

    assert snapshot.model_dump(mode="json", exclude_none=True) == {
        "state": "done",
        "count": 2,
        "job_id": "arq:job:abc",
    }


def test_optional_fields_stay_out_of_the_stored_blob() -> None:
    """`error` and `job_id` are optional on the frontend's mirror of this type."""
    dumped = AgentStatusSnapshot(state="pending").model_dump(mode="json", exclude_none=True)

    assert dumped == {"state": "pending", "count": 0}


@pytest.mark.parametrize(
    "bad",
    [
        # The exact drift that caused the bug: the worker's old key names.
        {"state": "completed", "findings": 3},
        {"state": "failed", "count": 0},
        # A plausible typo that used to be accepted silently.
        {"state": "Done", "count": 1},
        {"state": "finished", "count": 1},
        # Unknown keys must not be stored, or the next reader invents a meaning.
        {"state": "done", "count": 1, "findings": 1},
        # A negative count is not a count.
        {"state": "done", "count": -1},
        {},
    ],
)
def test_a_drifted_snapshot_is_rejected(bad: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        RunUpdate.model_validate({"agent_statuses": {"vulnerability": bad}})


def test_an_unknown_agent_name_is_rejected() -> None:
    """Keying on AgentKind means a typo cannot create a phantom agent in the UI."""
    with pytest.raises(ValidationError):
        RunUpdate.model_validate(
            {"agent_statuses": {"vulnrability": {"state": "done", "count": 1}}}
        )


def test_every_state_the_frontend_declares_is_valid() -> None:
    """Kept in step with the union in cyber.frontend/src/types/index.ts."""
    for state in ("pending", "running", "skipped", "done", "error"):
        assert AgentStatusSnapshot(state=state).state == state


def test_agent_statuses_stays_optional() -> None:
    """A PATCH that only sets `status` must not be forced to resend the snapshot."""
    update = RunUpdate.model_validate({"status": "completed"})

    assert update.agent_statuses is None
    assert update.discovery is None
