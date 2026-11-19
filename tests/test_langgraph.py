"""The LangGraph wiring runs the same nodes as agent.pipeline and keeps the
human-approval interrupt. Skipped when the optional langgraph dep is absent."""

import logging

import pytest

pytest.importorskip("langgraph")

from agent import langgraph_app as lg  # noqa: E402
from agent.audit import AuditLog  # noqa: E402
from agent.pipeline import Deps  # noqa: E402
from faults import sim  # noqa: E402


@pytest.fixture
def setup(tmp_path):
    d = Deps.default(audit=AuditLog(tmp_path / "audit.jsonl"), state_dir=tmp_path / "state")
    inc = sim.generate(3)
    ranking = [(inc.root, 1.0)] + [(x, 0.0) for x in sim.topo.SERVICES if x != inc.root]
    g = lg.build(d)
    cfg = {"configurable": {"thread_id": f"inc-{inc.seed}"}}
    s = g.invoke({"_incident": inc, "t_det": inc.t0, "ranking": ranking}, cfg)
    return d, g, cfg, s


def test_graph_pauses_before_remediate(setup):
    d, g, cfg, s = setup
    assert g.get_state(cfg).next == ("remediate",)
    assert s["status"] == "awaiting_approval" and "remediation" not in s
    assert d.executor.log == []
    assert set(s["timings"]) == {n for n, _ in lg.p.PRE_APPROVAL}


def test_graph_matches_plain_pipeline(setup, tmp_path):
    d, g, cfg, s = setup
    inc = s["_incident"]
    ref = lg.p.run(inc, s["t_det"], s["ranking"], Deps.default(audit=AuditLog(tmp_path / "ref.jsonl"), state_dir=tmp_path / "ref"))
    for k in ("diagnosis", "proposed_actions", "rejected_actions", "action_hash", "verification"):
        assert s[k] == ref[k], k


def test_approval_resumes_and_remediates(setup):
    d, g, cfg, _ = setup
    out = lg.decide(g, cfg, d, approver="george", approved=True)
    assert out["status"] == "remediated" and out["remediation"][0].startswith("dry-run: kubectl")
    assert g.get_state(cfg).next == ()
    events = [r["event"] for r in d.audit.records()]
    assert events.index("approval_decision") < events.index("remediation_executed")
    assert d.audit.verify()[0]


def test_rejection_never_remediates(setup):
    d, g, cfg, _ = setup
    out = lg.decide(g, cfg, d, approver="george", approved=False, reason="not convinced")
    assert out["status"] == "rejected" and "remediation" not in out
    assert d.executor.log == [] and g.get_state(cfg).next == ()
    with pytest.raises(RuntimeError, match="not awaiting approval"):
        lg.decide(g, cfg, d, approver="george", approved=True)


def test_agent_cannot_approve_itself(setup):
    d, g, cfg, _ = setup
    with pytest.raises(lg.p.rem.NotApproved):
        lg.decide(g, cfg, d, approver="clearpath-agent", approved=True)
    assert d.executor.log == []


def test_checkpoint_types_are_allow_listed(tmp_path, caplog):
    d = Deps.default(audit=AuditLog(tmp_path / "a.jsonl"), state_dir=tmp_path / "s")
    inc = sim.generate(4)
    g = lg.build(d)
    cfg = {"configurable": {"thread_id": "t"}}
    with caplog.at_level(logging.WARNING):
        g.invoke({"_incident": inc, "t_det": inc.t0, "ranking": [(inc.root, 1.0)]}, cfg)
        g.get_state(cfg)
    assert not [r for r in caplog.records if "unregistered type" in r.getMessage()]
