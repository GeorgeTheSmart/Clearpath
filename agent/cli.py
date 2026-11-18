"""Command-line entry points (the demo and the human approval step).

    python -m agent.cli replay --seed 10007          # run one recorded incident end to end
    python -m agent.cli approve inc-10007 --user george [--reject --reason "..."]
    python -m agent.cli audit-verify

Without --servicenow-url a local mock ServiceNow is started in-process.
"""

from __future__ import annotations

import argparse
import json
import os
import random
from pathlib import Path

from agent.audit import AuditLog
from agent.llm import from_env
from agent.pipeline import Deps, resume, run
from agent.servicenow import ServiceNow
from eval import datasets as ds
from localize import rca
from localize.evaluate import features
from mock_servicenow import server as mock

VAR = Path(os.environ.get("CLEARPATH_VAR", "var"))


def _sn(args: argparse.Namespace) -> ServiceNow:
    if args.servicenow_url:
        return ServiceNow(args.servicenow_url, os.environ["SN_USER"], os.environ["SN_PASSWORD"])
    port = random.randint(20000, 40000)
    mock.serve(port)
    return ServiceNow(f"http://127.0.0.1:{port}", "admin", "admin")


def cmd_replay(args: argparse.Namespace) -> None:
    inc = ds.incident(args.seed)
    A, E, t = features(inc, args.threshold)
    ranking = rca.rank(A, E, t)
    d = Deps.default(llm=from_env(), sn=_sn(args), audit=AuditLog(VAR / "audit.jsonl"), state_dir=VAR / "state")
    s = run(inc, t, ranking, d)
    dg = s["diagnosis"]
    print(f"\n=== {s['incident_id']}  (ground truth: {inc.fault_type} on {inc.root}) ===")
    print(f"localizer: {', '.join(f'{x} {v:.2f}' for x, v in ranking[:3])}")
    print(f"diagnosis: {dg['fault_type']} on {dg['root_cause_service']}  confidence={dg['confidence']:.2f}  degraded={dg['degraded']}")
    for e in dg["evidence"]:
        print(f"  evidence [{e['ref']}] {e['claim'][:100]}")
    print(f"unverified evidence: {s['verification']['unverified'] or 'none'}")
    if s["ticket"]:
        print(f"ticket: {s['ticket']['number']} urgency={s['ticket']['urgency']} impact={s['ticket']['impact']} affected CIs={s['ticket']['affected_cis']}")
    san = next(r for r in reversed(d.audit.records()) if r["event"] == "sanitized")["data"]
    print(f"redactions: {san['redactions']}  quarantined lines: {san['quarantined']}")
    print(f"proposed (awaiting human approval): {s['proposed_actions']}  rejected: {s['rejected_actions']}")
    print(f"timings (ms): {', '.join(f'{k}={v * 1000:.1f}' for k, v in s['timings'].items())}")
    print(f"\napprove with: python -m agent.cli approve {s['incident_id']} --user <you>")


def cmd_approve(args: argparse.Namespace) -> None:
    d = Deps.default(sn=None, audit=AuditLog(VAR / "audit.jsonl"), state_dir=VAR / "state")
    s = resume(args.incident, args.user, not args.reject, d, args.reason)
    print(json.dumps({k: s.get(k) for k in ("status", "approval", "remediation")}, indent=1))


def cmd_verify(_: argparse.Namespace) -> None:
    ok, bad = AuditLog(VAR / "audit.jsonl").verify()
    print("audit chain OK" if ok else f"audit chain BROKEN at record {bad}")
    raise SystemExit(0 if ok else 1)


def main() -> None:
    ap = argparse.ArgumentParser(prog="clearpath")
    sub = ap.add_subparsers(required=True)
    r = sub.add_parser("replay")
    r.add_argument("--seed", type=int, default=ds.TEST_SEEDS[7])
    r.add_argument("--threshold", type=float, default=8.373, help="seasonal detector threshold (from detection.json)")
    r.add_argument("--servicenow-url")
    r.set_defaults(fn=cmd_replay)
    a = sub.add_parser("approve")
    a.add_argument("incident")
    a.add_argument("--user", required=True)
    a.add_argument("--reject", action="store_true")
    a.add_argument("--reason", default="")
    a.set_defaults(fn=cmd_approve)
    v = sub.add_parser("audit-verify")
    v.set_defaults(fn=cmd_verify)
    sv = sub.add_parser("serve")
    sv.add_argument("--port", type=int, default=8000)
    sv.set_defaults(fn=lambda a: __import__("agent.server", fromlist=["serve"]).serve(a.port))
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
