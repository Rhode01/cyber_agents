"""The strict-mode guard.

OpenAI's strict Structured Outputs mode forwards a Pydantic schema's constraints to the
endpoint unvalidated, where an unsupported keyword fails the call outright, and it rewrites
``required`` to every property so a default can never fire. Both facts were read out of the
installed packages rather than remembered.

That makes "the LLM-facing schema carries no constraints and no defaults" a real
requirement, and a comment saying so is worth very little - the first person to add
``max_length=200`` to a title field would break every call, and the failure would arrive as
a 400 from the provider rather than as anything pointing here.

So this module walks the schemas and fails the build instead. It is the mechanism that turns
a documented fact into an enforced one.
"""

from __future__ import annotations

from types import UnionType
from typing import Any, Union, get_args, get_origin

import pytest
from pydantic import BaseModel
from pydantic_core import PydanticUndefined

from app.agents.common.assessment_schema import (
    CONFIDENCE_VALUES,
    ConfidenceBand,
    InjectionReport,
    InjectionSignal,
)
from app.agents.phishing.assessment_schema import PhishingAssessment, PhishingVerdict

# Constraint keywords that either fail the call or are silently dropped under strict mode.
FORBIDDEN_CONSTRAINTS = (
    "ge",
    "le",
    "gt",
    "lt",
    "min_length",
    "max_length",
    "pattern",
    "multiple_of",
    "max_digits",
    "decimal_places",
)


def models_reachable_from(model: type[BaseModel]) -> list[type[BaseModel]]:
    """Every nested model, so a constraint cannot hide one level down."""
    found: list[type[BaseModel]] = []
    pending: list[type[BaseModel]] = [model]
    while pending:
        current = pending.pop()
        if current in found:
            continue
        found.append(current)
        for field in current.model_fields.values():
            for candidate in (field.annotation, *get_args(field.annotation or Any)):
                if isinstance(candidate, type) and issubclass(candidate, BaseModel):
                    pending.append(candidate)
    return found


SCHEMAS = [
    pytest.param(model, id=model.__name__)
    for model in models_reachable_from(PhishingAssessment)
]


@pytest.mark.parametrize("model", SCHEMAS)
def test_no_field_carries_a_default(model: type[BaseModel]) -> None:
    """Strict mode marks every property required, so a default can never be applied.

    Leaving one in is worse than useless: it reads as "this field is optional" to whoever
    edits the prompt next, while the model is in fact always required to supply it.
    """
    with_defaults = [
        name
        for name, field in model.model_fields.items()
        if field.default is not PydanticUndefined or field.default_factory is not None
    ]

    assert with_defaults == [], (
        f"{model.__name__} fields {with_defaults} have defaults. Strict mode makes every "
        f"field required, so type them `X | None` instead."
    )


@pytest.mark.parametrize("model", SCHEMAS)
def test_no_field_carries_a_constraint(model: type[BaseModel]) -> None:
    """A constraint here reaches the wire unvalidated and can 400 every call.

    Bounds belong on our side of the boundary - `nodes.emit_findings` clips the title and
    `resolve_severity` maps the severity, after the model has answered.
    """
    offenders: list[str] = []
    for name, field in model.model_fields.items():
        for item in field.metadata:
            for keyword in FORBIDDEN_CONSTRAINTS:
                if hasattr(item, keyword):
                    offenders.append(f"{name}.{keyword}")

    assert offenders == [], (
        f"{model.__name__} carries constraints {offenders}, which strict mode forwards "
        f"unvalidated. Apply bounds after parsing instead."
    )


@pytest.mark.parametrize("model", SCHEMAS)
def test_no_field_is_optional_via_a_union_with_none(model: type[BaseModel]) -> None:
    """`X | None` is how an optional field is expressed; none of these should need one.

    Not forbidden by strict mode - it is the *recommended* form - but every field on these
    schemas is genuinely required, so a None union would mean the model can decline to
    answer something the finding depends on.
    """
    nullable = [
        name
        for name, field in model.model_fields.items()
        if get_origin(field.annotation) in (Union, UnionType)
        and type(None) in get_args(field.annotation)
    ]

    assert nullable == [], f"{model.__name__} fields {nullable} allow None"


@pytest.mark.parametrize("model", SCHEMAS)
def test_extra_fields_are_forbidden(model: type[BaseModel]) -> None:
    """A model that invents a field should fail parsing, not have it silently ignored."""
    assert model.model_config.get("extra") == "forbid"


def test_field_order_puts_reasoning_before_conclusions() -> None:
    """Strict generation is sequential, so schema order is thinking order.

    `injection` first means a model that has just recorded "this content addressed me"
    reads the rest more carefully. `explanation` before `verdict` means it reasons and then
    concludes - the other way round turns the explanation into justification for a decision
    already made.
    """
    order = list(PhishingAssessment.model_fields)

    assert order.index("injection") == 0
    assert order.index("key_indicator_ids") < order.index("explanation")
    assert order.index("explanation") < order.index("verdict")
    assert order.index("verdict") < order.index("severity")
    assert order.index("severity") < order.index("confidence")


def test_severity_is_a_free_string_not_an_enum() -> None:
    """Models write "Medium" and "informational" as readily as "medium".

    Mapping afterwards through `resolve_severity`, which falls back to the rule floor, is
    more robust than a schema the model has to match exactly.
    """
    assert PhishingAssessment.model_fields["severity"].annotation is str


def test_confidence_is_a_band_not_a_float() -> None:
    """With `ge`/`le` unavailable a float is unbounded on the wire.

    A model meaning 85% writes `85` about as readily as `0.85`, and clamping that gives
    1.0 - wrong in the direction that overstates certainty.
    """
    assert PhishingAssessment.model_fields["confidence"].annotation is ConfidenceBand


def test_the_confidence_mapping_covers_every_band_and_never_reaches_certainty() -> None:
    assert set(CONFIDENCE_VALUES) == set(ConfidenceBand)
    assert all(0.0 < value < 1.0 for value in CONFIDENCE_VALUES.values())
    # The model explains a deterministic detection; it does not certify it.
    assert max(CONFIDENCE_VALUES.values()) < 1.0


def test_the_enums_are_the_vocabulary_the_findings_use() -> None:
    assert [band.value for band in ConfidenceBand] == ["low", "medium", "high"]
    assert [signal.value for signal in InjectionSignal] == ["none", "suspected", "confirmed"]
    assert [verdict.value for verdict in PhishingVerdict] == ["clean", "suspicious", "phishing"]


def test_the_injection_report_is_reachable_and_guarded() -> None:
    """It is nested, so the guards above must have walked into it."""
    assert InjectionReport in models_reachable_from(PhishingAssessment)


def test_the_schema_imports_nothing_from_langchain() -> None:
    """Kept as plain Pydantic so it is fully typed and directly constructible in tests.

    Depending on LangChain here would make the contract with the model hostage to a
    library's generic parameters, which move between minor releases.
    """
    import app.agents.phishing.assessment_schema as module

    source = module.__file__
    assert source is not None
    text = open(source, encoding="utf-8").read()
    assert "langchain" not in text
    assert "openai" not in text
