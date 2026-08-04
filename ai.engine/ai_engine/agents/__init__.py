"""LangGraph detection agents.

One self-contained package per agent, each with the same five modules:

    state.py    the graph's state schema
    prompts.py  prompt text, isolated from graph wiring
    tools.py    tools the agent may call
    nodes.py    node functions
    graph.py    the StateGraph, its edges, and the compiled graph

``vulnerability`` is written out longhand as the reference implementation; the
other three build the same shape through ``agents.common.graph``.
"""
