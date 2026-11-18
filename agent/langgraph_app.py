"""The same nodes wired into LangGraph, with a checkpointer and an interrupt
before `remediate` (human approval).

Status: written against the LangGraph StateGraph API but NOT executed in the
build environment (the package could not be installed offline). The tested
path is agent/pipeline.py, which runs the identical node functions.
"""

from __future__ import annotations

from typing import Any

from agent import pipeline as p


def build(deps: p.Deps) -> Any:  # pragma: no cover - requires langgraph
    from langgraph.checkpoint.memory import MemorySaver
    from langgraph.graph import END, StateGraph

    g = StateGraph(dict)
    for name, fn in p.PRE_APPROVAL:
        g.add_node(name, lambda s, fn=fn: fn(s, deps))
    g.add_node("remediate", lambda s: p.remediate(s, deps))
    names = [n for n, _ in p.PRE_APPROVAL]
    g.set_entry_point(names[0])
    for a, b in zip(names, names[1:]):
        g.add_edge(a, b)
    g.add_edge(names[-1], "remediate")
    g.add_edge("remediate", END)
    return g.compile(checkpointer=MemorySaver(), interrupt_before=["remediate"])
