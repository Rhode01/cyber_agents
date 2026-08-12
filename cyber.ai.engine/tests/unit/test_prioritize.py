"""Remediation ranking.

The order has to be defensible, so every test here asserts a property an analyst
would recognise rather than a specific number.
"""

from __future__ import annotations

from cyber_contracts import FindingType, Severity

from app.agents.vulnerability.candidates import Candidate, derive_candidate_id
from app.agents.vulnerability.prioritize import (
    MAX_SCORE,
    PriorityInputs,
    infer_asset_type,
    prioritize,
    rank_assets,
    score_candidate,
)


def _candidate(
    *,
    severity: Severity = Severity.medium,
    host: str = "10.0.0.5",
    port: int | None = 22,
    service: str | None = "ssh",
    rule_id: str = "outdated-openssh",
    finding_type: FindingType = FindingType.outdated_service,
) -> Candidate:
    return Candidate(
        candidate_id=derive_candidate_id(rule_id, host, port),
        rule_id=rule_id,
        finding_type=finding_type,
        host=host,
        port=port,
        protocol="tcp",
        service=service,
        product="OpenSSH",
        version="8.9",
        fact="fact",
        rule_severity=severity,
        remediation="Upgrade it.",
    )


def test_every_score_carries_its_factors() -> None:
    """An unexplained ranking is one nobody trusts."""
    score, factors = score_candidate(_candidate(), PriorityInputs())

    assert 0 < score <= MAX_SCORE
    assert set(factors) == {
        "severity",
        "internet_exposure",
        "exploit_availability",
        "authentication_required",
        "business_criticality",
        "asset_type",
    }
    for factor in factors.values():
        assert 0 <= factor["points"] <= factor["max_points"]
    assert sum(f["points"] for f in factors.values()) == score


def test_the_factor_ceilings_sum_to_the_maximum() -> None:
    _score, factors = score_candidate(_candidate(), PriorityInputs())

    assert sum(f["max_points"] for f in factors.values()) == MAX_SCORE


def test_internet_exposure_outranks_a_higher_severity_nobody_can_reach() -> None:
    """The reason severity alone is not the ranking."""
    unreachable_critical, _ = score_candidate(
        _candidate(severity=Severity.critical),
        PriorityInputs(exposure="internal", exploit="none", authentication="multiple"),
    )
    exposed_high, _ = score_candidate(
        _candidate(severity=Severity.high),
        PriorityInputs(exposure="internet", exploit="known-exploited", authentication="none"),
    )

    assert exposed_high > unreachable_critical


def test_unknown_exposure_scores_above_internal() -> None:
    """"We could not tell" is a reason to look sooner, not to assume it is safe."""
    unknown, _ = score_candidate(_candidate(), PriorityInputs(exposure="unknown"))
    internal, _ = score_candidate(_candidate(), PriorityInputs(exposure="internal"))

    assert unknown > internal


def test_a_known_exploited_vulnerability_outranks_an_unexploited_one() -> None:
    exploited, _ = score_candidate(_candidate(), PriorityInputs(exploit="known-exploited"))
    quiet, _ = score_candidate(_candidate(), PriorityInputs(exploit="none"))

    assert exploited > quiet


def test_ranking_is_dense_stable_and_worst_first() -> None:
    candidates = [
        _candidate(severity=Severity.low, rule_id="a", port=1),
        _candidate(severity=Severity.critical, rule_id="b", port=2),
        _candidate(severity=Severity.medium, rule_id="c", port=3),
    ]

    ranked = prioritize(candidates)

    assert [p.rank for p in ranked] == [1, 2, 3]
    assert ranked[0].score >= ranked[1].score >= ranked[2].score
    # Same inputs, same order: the ranking must be reproducible.
    assert [p.candidate_id for p in prioritize(candidates)] == [
        p.candidate_id for p in ranked
    ]


def test_equal_scores_keep_their_incoming_order() -> None:
    """Ties must not depend on dict iteration order."""
    candidates = [_candidate(rule_id=f"rule-{i}", port=i + 1) for i in range(5)]

    ranked = prioritize(candidates)

    assert len({p.score for p in ranked}) == 1
    assert [p.candidate_id for p in ranked] == [c.candidate_id for c in candidates]


def test_per_candidate_inputs_override_the_default() -> None:
    exposed = _candidate(rule_id="exposed", port=80)
    internal = _candidate(rule_id="internal", port=81)

    ranked = prioritize(
        [internal, exposed],
        inputs_for={exposed.candidate_id: PriorityInputs(exposure="internet")},
        default_inputs=PriorityInputs(exposure="internal"),
    )

    assert ranked[0].candidate_id == exposed.candidate_id


def test_evidence_states_that_the_score_is_not_model_output() -> None:
    evidence = prioritize([_candidate()])[0].evidence()

    assert evidence["max_score"] == MAX_SCORE
    assert "not model output" in evidence["note"]


# --------------------------------------------------------- asset ranking --


def test_assets_are_ranked_by_their_single_worst_finding() -> None:
    """Ten mediums are a backlog; one critical is an incident."""
    noisy = [
        _candidate(severity=Severity.medium, host="10.0.0.1", rule_id=f"r{i}", port=i + 1)
        for i in range(6)
    ]
    one_critical = [_candidate(severity=Severity.critical, host="10.0.0.2", port=6379)]
    candidates = noisy + one_critical

    risks = rank_assets(candidates, prioritize(candidates))

    assert risks[0].asset == "10.0.0.2"
    assert risks[0].worst_severity is Severity.critical
    assert risks[1].asset == "10.0.0.1"
    assert risks[1].finding_count == 6


def test_asset_risk_reports_a_severity_tally() -> None:
    candidates = [
        _candidate(severity=Severity.high, host="10.0.0.1", rule_id="a", port=1),
        _candidate(severity=Severity.high, host="10.0.0.1", rule_id="b", port=2),
        _candidate(severity=Severity.low, host="10.0.0.1", rule_id="c", port=3),
    ]

    risk = rank_assets(candidates, prioritize(candidates))[0]

    assert risk.as_dict()["severities"] == {"high": 2, "low": 1}


# ------------------------------------------------------------ asset type --


def test_asset_type_is_inferred_from_the_port_when_unstated() -> None:
    assert infer_asset_type(_candidate(port=5432, service="postgresql")) == "database"
    assert infer_asset_type(_candidate(port=3389, service="ms-wbt-server")) == "gateway"
    assert infer_asset_type(_candidate(port=389, service="ldap")) == "directory"
    assert infer_asset_type(_candidate(port=22, service="ssh")) == "server"
    # No port at all means a package manifest, i.e. an image rather than a host.
    assert infer_asset_type(_candidate(port=None, service="openssl")) == "container"


def test_an_explicit_asset_type_wins_over_inference() -> None:
    _score, factors = score_candidate(
        _candidate(port=22), PriorityInputs(asset_type="database")
    )

    assert factors["asset_type"]["value"] == "database"
