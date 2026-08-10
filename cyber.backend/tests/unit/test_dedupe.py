"""Deduplication key tests.

These are pure-function tests over ``crud_finding.dedupe_key`` - no database - so
they run in CI without PostgreSQL. They exist because the previous key was
``(agent, asset, title)``, which had two failure modes that a database test would
have been slower to catch and easier to misread:

  * a re-scan of the same host persisted nothing, so the new run rendered empty
    and therefore looked clean;
  * two genuinely different findings on the same host that shared a title
    collapsed into one, because port and service were not part of the key.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from cyber_contracts import AgentKind, FindingCreate, FindingType, Severity

from app.crud.crud_finding import dedupe_key


def make_finding(**overrides: object) -> FindingCreate:
    """A finding with everything the dedupe key reads set to a known value."""
    fields: dict[str, object] = {
        "agent": AgentKind.vulnerability,
        "finding_type": FindingType.risky_exposed_service,
        "title": "Telnet exposed on 10.0.0.5",
        "description": "Telnet carries credentials in cleartext.",
        "severity": Severity.high,
        "confidence": 0.9,
        "source": "nmap",
        "asset": "10.0.0.5",
        "service": "telnet",
        "port": 23,
        "protocol": "tcp",
        "detected_at": datetime.now(UTC),
    }
    fields.update(overrides)
    return FindingCreate.model_validate(fields)


def test_identical_observations_share_a_key() -> None:
    assert dedupe_key(make_finding()) == dedupe_key(make_finding())


def test_a_different_port_is_a_different_finding() -> None:
    """The regression that mattered most: same host, same title, different port."""
    telnet = make_finding(port=23)
    alt = make_finding(port=2323)

    assert dedupe_key(telnet) != dedupe_key(alt)


def test_a_different_service_is_a_different_finding() -> None:
    assert dedupe_key(make_finding(service="telnet")) != dedupe_key(make_finding(service="ftp"))


def test_a_different_kind_is_a_different_finding() -> None:
    outdated = make_finding(finding_type=FindingType.outdated_service)
    risky = make_finding(finding_type=FindingType.risky_exposed_service)

    assert dedupe_key(outdated) != dedupe_key(risky)


def test_a_different_agent_is_a_different_finding() -> None:
    assert dedupe_key(make_finding(agent=AgentKind.vulnerability)) != dedupe_key(
        make_finding(agent=AgentKind.network)
    )


def test_a_new_run_never_collides_with_an_old_one() -> None:
    """Re-scanning must record what it saw.

    Suppressing across runs is what made a repeat scan render as an empty - and
    therefore apparently clean - run.
    """
    first = make_finding(run_id=uuid4())
    second = make_finding(run_id=uuid4())

    assert dedupe_key(first) != dedupe_key(second)


def test_a_new_scan_never_collides_with_an_old_one() -> None:
    assert dedupe_key(make_finding(scan_id=uuid4())) != dedupe_key(make_finding(scan_id=uuid4()))


def test_duplicates_within_one_run_do_collide() -> None:
    """Suppression inside a single run is the behaviour we do want."""
    run_id = uuid4()

    assert dedupe_key(make_finding(run_id=run_id)) == dedupe_key(make_finding(run_id=run_id))


def test_an_absent_asset_is_part_of_the_key_not_a_hole_in_it() -> None:
    """A None asset must still take part in comparison.

    The old SQL filtered `asset IN (...)`, which never matches `asset IS NULL`, so
    any finding without an asset escaped deduplication whenever the same batch
    also contained findings that had one. The key now carries None explicitly and
    the asset filter has been removed from the query entirely.
    """
    without = make_finding(asset=None)

    assert dedupe_key(without) == dedupe_key(make_finding(asset=None))
    assert dedupe_key(without) != dedupe_key(make_finding(asset="10.0.0.5"))
    assert dedupe_key(without)[1] is None


def test_fields_outside_the_key_do_not_affect_it() -> None:
    """Severity, confidence and prose are the LLM's output and may vary between
    runs; they must not make an otherwise identical observation look new."""
    base = make_finding()
    reworded = make_finding(
        severity=Severity.critical,
        confidence=0.35,
        description="Reworded by the model on a later pass.",
        recommendation="Disable telnet.",
    )

    assert dedupe_key(base) == dedupe_key(reworded)
