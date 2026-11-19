"""The same nodes wired into LangGraph, with a checkpointer and an interrupt
before `remediate` (human approval).

`agent/pipeline.py` remains the primary runner (it persists state as JSON so
approval can happen in another process); this module runs the identical node
functions under LangGraph and is exercised by tests/test_langgraph.py.

    g = build(deps)
    cfg = {"configurable": {"thread_id": "inc-42"}}
    g.invoke({"_incident": inc, "t_det": t, "ranking": ranking}, cfg)  # stops before remediate
    decide(g, cfg, deps, approver="alice", approved=True)              # audited, then resumes
"""

from __future__ import annotations

import itertools
import time
from typing import Any

from agent import pipeline as p

# Types that live in graph state and therefore pass through the checkpointer.
# LangGraph refuses to deserialise unregistered types in strict mode, so they
# are allow-listed explicitly rather than relying on the permissive default.
CHECKPOINT_TYPES = [
    ("faults.sim", "Incident"),
    ("agent.schema", "Context"),
    ("agent.schema", "ContextItem"),
    ("agent.retrieval", "Chunk"),
    ("agent.retrieval", "Hit"),
]


def build(deps: p.Deps, checkpointer: Any = None) -> Any:
    """Compile the graph. Execution pauses before `remediate` on every thread."""
    from langgraph.checkpoint.memory import InMemorySaver
    from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
    from langgraph.graph import END, StateGraph

    # A plain dict root channel: nodes return the whole state, exactly as in
    # pipeline.run. (A TypedDict schema would silently drop undeclared keys.)
    g = StateGraph(dict)  # type: ignore[type-var]
    for name, fn in p.PRE_APPROVAL:
        g.add_node(name, lambda s, fn=fn, name=name: p._timed(name, fn)(s, deps))
    g.add_node("remediate", lambda s: p._timed("remediate", p.remediate)(s, deps))
    names = [n for n, _ in p.PRE_APPROVAL]
    g.set_entry_point(names[0])
    for a, b in itertools.pairwise(names):
        g.add_edge(a, b)
    g.add_edge(names[-1], "remediate")
    g.add_edge("remediate", END)
    if checkpointer is None:
        checkpointer = InMemorySaver(serde=JsonPlusSerializer(allowed_msgpack_modules=CHECKPOINT_TYPES))
    return g.compile(checkpointer=checkpointer, interrupt_before=["remediate"])


def decide(graph: Any, config: dict[str, Any], deps: p.Deps, approver: str, approved: bool, reason: str = "") -> p.State:
    """Record a human decision on a paused thread; resume only if approved.

    Mirrors pipeline.resume: the decision is audited before anything runs, and
    remediation.execute still re-checks the approver and the action hash.
    """
    snap = graph.get_state(config)
    if tuple(snap.next) != ("remediate",):
        raise RuntimeError(f"thread is not awaiting approval (next={snap.next!r})")
    s: p.State = snap.values
    approval = {"approved": approved, "approver": approver, "at": time.time(), "action_hash": s["action_hash"], "reason": reason}
    deps.audit.append(approver, "approval_decision", {"incident": s["incident_id"], **approval})
    if not approved:
        graph.update_state(config, {**s, "approval": approval, "status": "rejected"}, as_node="remediate")
        return dict(graph.get_state(config).values)
    graph.update_state(config, {**s, "approval": approval})
    return dict(graph.invoke(None, config))
