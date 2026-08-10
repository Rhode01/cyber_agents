"""Helper for building the linear three-node graph every agent starts from.

The ``vulnerability`` agent wires its own StateGraph explicitly so the pattern is
visible in one file. The other three agents share this factory because their
Phase 1 shape is identical - each will grow its own edges, branches, and tool
nodes as its detection logic lands.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from itertools import pairwise
from typing import Any

from langgraph.graph import END, START, StateGraph


def build_linear_graph(
    state_schema: type[Any],
    nodes: Sequence[tuple[str, Callable[..., Any]]],
) -> Any:
    """Compile a graph that runs ``nodes`` in order from START to END."""
    if not nodes:
        msg = "a graph needs at least one node"
        raise ValueError(msg)

    builder = StateGraph(state_schema)

    for name, function in nodes:
        builder.add_node(name, function)

    builder.add_edge(START, nodes[0][0])
    for (current, _), (following, _) in pairwise(nodes):
        builder.add_edge(current, following)
    builder.add_edge(nodes[-1][0], END)

    return builder.compile()
