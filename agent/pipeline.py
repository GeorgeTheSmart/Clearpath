"""The agent graph: ingest -> gather_context -> sanitize -> retrieve -> diagnose
-> open_ticket -> await_approval (interrupt) -> remediate.

Nodes are plain functions over a state dict so they can be unit-tested and
wired into LangGraph unchanged (agent/langgraph_app.py). `run` executes up to
the approval interrupt and persists the state; `resume` continues after a
human decision. Per-node wall time is recorded for latency accounting.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np

from agent import context as cx
from agent import remediation as rem
from agent.audit import AuditLog
from agent.diagnose import diagnose
from agent.llm import LLM
from agent.retrieval import Retriever, load_runbooks
from agent.schema import Context, Diagnosis
from agent.servicenow import ServiceNow, open_ticket
from agent.verify import verify
from faults import sim
from faults import topology as topo

State = dict[str, Any]
SLO_TARGET = 0.999

# Incident IDs become file names under state_dir, so they are restricted to a
# conservative charset: no separators, no "..", no drive letters.
_INCIDENT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


class InvalidIncidentId(ValueError):
    pass


class UnknownIncident(LookupError):
    pass


class NotAwaitingApproval(RuntimeError):
    """A decision was submitted for an incident that is not paused for one
    (already remediated or rejected): approvals are single-use."""


def check_incident_id(incident_id: str) -> str:
    if not _INCIDENT_ID.fullmatch(incident_id) or ".." in incident_id:
        raise InvalidIncidentId(f"invalid incident id: {incident_id!r}")
    return incident_id


@dataclass
class Deps:
    retriever: Retriever
    llm: LLM | None = None
    sn: ServiceNow | None = None
    audit: AuditLog = field(default_factory=lambda: AuditLog(Path("var/audit.jsonl")))
    executor: rem.Executor = field(default_factory=rem.Executor)
    state_dir: Path = Path("var/state")
    use_rag: bool = True
    use_localizer: bool = True

    @staticmethod
    def default(**kw: Any) -> Deps:
        return Deps(retriever=Retriever(load_runbooks(Path(__file__).resolve().parent.parent / "runbooks")), **kw)


def _timed(name: str, fn: Callable[[State, Deps], State]) -> Callable[[State, Deps], State]:
    def wrapper(s: State, d: Deps) -> State:
        t0 = time.perf_counter()
        out = fn(s, d)
        out.setdefault("timings", {})[name] = time.perf_counter() - t0
        return out

    return wrapper


# ---------------------------------------------------------------- nodes
def ingest(s: State, d: Deps) -> State:
    """Accept an incident: a live one from the correlator (`_source` + id) or a recorded fixture."""
    if "incident_id" not in s:
        s["incident_id"] = f"inc-{s['_incident'].seed}"
    s.update(t_received=time.time(), status="ingested")
    d.audit.append("clearpath-agent", "incident_received", {"incident": s["incident_id"]})
    return s


def gather_context(s: State, d: Deps) -> State:
    src: cx.Source = s["_source"] if "_source" in s else cx.FixtureSource(s["_incident"])
    ranking = s["ranking"] if d.use_localizer else [(svc, 0.0) for svc in sorted(topo.SERVICES)]
    ctx = cx.gather(src, s["incident_id"], s["t_det"], ranking)
    if not d.use_localizer:
        ctx = ctx.model_copy(update={"items": [i for i in ctx.items if i.kind != "loc"]})
    err = src.series()[("frontend", "error_rate")][s["t_det"] : s["t_det"] + 10]
    s["burn_rate"] = float(np.nanmean(err) / (1 - SLO_TARGET)) if np.isfinite(err).any() else 0.0
    s["_ctx"] = ctx
    return s


def sanitize(s: State, d: Deps) -> State:
    ctx: Context = cx.sanitize(s["_ctx"])
    s["_ctx"] = ctx
    d.audit.append("clearpath-agent", "sanitized", {"incident": s["incident_id"], "redactions": ctx.redactions, "quarantined": ctx.quarantined})
    return s


def retrieve(s: State, d: Deps) -> State:
    ctx: Context = s["_ctx"]
    top = s["ranking"][0][0] if d.use_localizer else None
    hits = d.retriever.search(cx.retrieval_query(ctx, top), k=4) if d.use_rag else []
    s["_hits"] = hits
    if hits:
        from agent.schema import ContextItem

        ctx = ctx.model_copy(update={"items": ctx.items + [ContextItem(id=f"rb:{h.chunk.id}", kind="rb", text=h.chunk.text) for h in hits]})
        s["_ctx"] = ctx
    return s


def diagnose_node(s: State, d: Deps) -> State:
    ctx: Context = s["_ctx"]
    kinds = {"alert", "metric", "log", "event"} | ({"rb"} if d.use_rag else set()) | ({"loc"} if d.use_localizer else set())
    diag = diagnose(d.llm, ctx, list(topo.SERVICES), s["_hits"], kinds)
    s["diagnosis"] = diag.model_dump()
    rep = verify(diag, ctx)
    s["verification"] = {"total": rep.total, "unverified": rep.unverified, "hallucination_rate": rep.hallucination_rate, "unknown_service": rep.unknown_service}
    return s


def open_ticket_node(s: State, d: Deps) -> State:
    if d.sn is None:
        s["ticket"] = None
        return s
    diag = Diagnosis.model_validate(s["diagnosis"])
    t = open_ticket(d.sn, s["incident_id"], diag, s["burn_rate"], [x for x, _ in s["ranking"]])
    s["ticket"] = {"sys_id": t["sys_id"], "number": t["number"], "urgency": t["urgency"], "impact": t["impact"], "affected_cis": t["_affected_cis"]}
    s["time_to_ticket_s"] = time.time() - s["t_received"]
    d.audit.append("clearpath-agent", "ticket_opened", {"incident": s["incident_id"], "ticket": t["number"]})
    return s


def await_approval(s: State, d: Deps) -> State:
    diag = Diagnosis.model_validate(s["diagnosis"])
    proposed = [a.model_dump() for a in diag.proposed_actions]
    valid = [a for a in proposed if rem.validate(a)[0]]
    rejected = [{"action": a, "reason": rem.validate(a)[1]} for a in proposed if not rem.validate(a)[0]]
    s.update(proposed_actions=valid, rejected_actions=rejected, action_hash=rem.action_hash(s["incident_id"], valid), status="awaiting_approval")
    d.audit.append(
        "clearpath-agent", "approval_requested", {"incident": s["incident_id"], "actions": valid, "rejected": rejected, "action_hash": s["action_hash"]}
    )
    return s


def remediate(s: State, d: Deps) -> State:
    out = rem.execute(s["incident_id"], s["proposed_actions"], s.get("approval"), d.executor)
    s.update(remediation=out, status="remediated")
    d.audit.append("clearpath-agent", "remediation_executed", {"incident": s["incident_id"], "results": out})
    if d.sn and s.get("ticket"):
        d.sn.update_incident(s["ticket"]["sys_id"], {"work_notes": "Approved remediation executed:\n" + "\n".join(out), "state": "2"})
    return s


PRE_APPROVAL = [
    ("ingest", ingest),
    ("gather_context", gather_context),
    ("sanitize", sanitize),
    ("retrieve", retrieve),
    ("diagnose", diagnose_node),
    ("open_ticket", open_ticket_node),
    ("await_approval", await_approval),
]


def _persist(s: State, d: Deps) -> None:
    d.state_dir.mkdir(parents=True, exist_ok=True)
    pub = {k: v for k, v in s.items() if not k.startswith("_")}
    (d.state_dir / f"{s['incident_id']}.json").write_text(json.dumps(pub, indent=1, default=str), encoding="utf-8", newline="\n")


def run(inc: sim.Incident, t_det: int, ranking: list[tuple[str, float]], d: Deps) -> State:
    """Recorded incident (the evaluated path)."""
    return _run({"_incident": inc, "t_det": t_det, "ranking": ranking}, d)


def run_live(src: cx.Source, incident_id: str, t_det: int, ranking: list[tuple[str, float]], d: Deps) -> State:
    """Live incident from the correlator; `src` is an agent.live.LiveSource."""
    return _run({"_source": src, "incident_id": check_incident_id(incident_id), "t_det": t_det, "ranking": ranking}, d)


def triage_only(incident_id: str, triage: dict[str, Any], d: Deps) -> State:
    """Record a live incident that has no single service to blame (see
    LiveSource.triage): nothing is proposed, so there is nothing to approve.
    A fleet-wide anomaly still opens a ticket, pointing at shared infrastructure."""
    s: State = {"incident_id": check_incident_id(incident_id), "status": f"no_action:{triage['kind']}", "triage": triage, "proposed_actions": []}
    d.audit.append("clearpath-agent", "triaged", {"incident": incident_id, **triage})
    if triage["kind"] == "fleet_wide" and d.sn is not None:
        n, tot = len(triage["anomalous"]), triage["active_services"]
        t = d.sn.create_incident(
            {
                "short_description": f"[Clearpath] fleet-wide anomaly: {n} of {tot} services at once - likely shared infrastructure",
                "description": (
                    f"Clearpath incident {incident_id}\n\n{n} of {tot} active services became anomalous together "
                    f"({', '.join(f'{k}: {v}' for k, v in sorted(triage['anomalous'].items()))}).\n"
                    "A common-mode failure points outside the service graph (service mesh, network, node, DNS, a shared dependency). "
                    "No service-level remediation is proposed: restarting or rolling back one service would not help and could make it worse.\n"
                ),
                "urgency": "1",
                "impact": "1",
                "category": "software",
                "correlation_id": incident_id,
            }
        )
        s["ticket"] = {"sys_id": t["sys_id"], "number": t["number"], "urgency": t["urgency"], "impact": t["impact"], "affected_cis": 0}
        d.audit.append("clearpath-agent", "ticket_opened", {"incident": incident_id, "ticket": t["number"]})
    _persist(s, d)
    return s


def _run(s: State, d: Deps) -> State:
    for name, fn in PRE_APPROVAL:
        s = _timed(name, fn)(s, d)
    _persist(s, d)
    return s


def resume(incident_id: str, approver: str, approved: bool, d: Deps, reason: str = "") -> State:
    path = d.state_dir / f"{check_incident_id(incident_id)}.json"
    if not path.is_file():
        raise UnknownIncident(incident_id)
    s: State = json.loads(path.read_text(encoding="utf-8"))
    if s.get("status") != "awaiting_approval":
        raise NotAwaitingApproval(f"{incident_id} is {s.get('status')!r}, not awaiting approval")
    s["approval"] = {"approved": approved, "approver": approver, "at": time.time(), "action_hash": s["action_hash"], "reason": reason}
    d.audit.append(approver, "approval_decision", {"incident": incident_id, **s["approval"]})
    if approved:
        s = _timed("remediate", remediate)(s, d)
    else:
        s["status"] = "rejected"
    _persist(s, d)
    return s
