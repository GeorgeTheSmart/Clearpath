"""HTTP surface for the agent (stdlib, no framework).

POST /incidents          correlator posts closed/opened incidents here
GET  /pending            incidents awaiting human approval
POST /approve/<id>       {"user": "...", "approve": true, "reason": "..."}
GET  /healthz

Approval identities come from the authenticating proxy header
X-Forwarded-User (oauth2-proxy / Slack signature verifier in front), never
from the request body, so a caller cannot approve as someone else.

Live path: with CLEARPATH_PROM set, each incident from the correlator is
diagnosed in the background - agent.live.LiveSource pulls metrics (Linkerd,
cAdvisor, kube-state-metrics), pod logs and events, the localizer ranks the
services, and the same pipeline as the offline evaluation drafts the ticket and
waits for approval. Configuration (all optional):
    CLEARPATH_PROM       Prometheus URL; unset = store incidents only
    CLEARPATH_LLM        anthropic | openai | ollama | none (agent.llm)
    CLEARPATH_SN_URL     ServiceNow base URL (+ SN_USER / SN_PASSWORD); unset = in-process mock
    CLEARPATH_EXECUTE    dry-run (default) | kube: approved actions via the Kubernetes API
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from agent.audit import AuditLog
from agent.pipeline import Deps, InvalidIncidentId, NotAwaitingApproval, UnknownIncident, check_incident_id, resume, run_live, triage_only
from agent.remediation import NotApproved

VAR = Path(os.environ.get("CLEARPATH_VAR", "var"))
_lock = threading.Lock()

Diagnoser = Callable[[str, dict[str, Any]], None]


def live_diagnoser(prom_url: str, deps: Deps, kube: Any | None) -> Diagnoser:
    """Incident payload -> LiveSource -> localizer -> pipeline (up to approval)."""
    from agent.live import LiveSource, PromClient

    def diagnose(iid: str, incident: dict[str, Any]) -> None:
        src = LiveSource(PromClient(prom_url), incident, time.time(), kube)
        triage = src.triage()
        with _lock:
            if triage["kind"] == "localized":
                run_live(src, iid, src.t_det, src.rank(), deps)
            else:  # nothing to blame on one service: record, never propose an action
                triage_only(iid, triage, deps)

    return diagnose


class Handler(BaseHTTPRequestHandler):
    deps: Deps
    diagnose: Diagnoser | None = None

    def _diagnose_in_background(self, iid: str, incident: dict[str, Any]) -> None:
        fn, deps = type(self).diagnose, self.deps
        if fn is None or (deps.state_dir / f"{iid}.json").exists():
            return  # live path off, or a redelivery of an incident already handled

        def work() -> None:
            try:
                fn(iid, incident)
            except Exception as e:  # a failed diagnosis must be visible in the audit log, never fatal
                deps.audit.append("clearpath-agent", "diagnosis_failed", {"incident": iid, "error": f"{type(e).__name__}: {e}"[:500]})

        threading.Thread(target=work, name=f"diagnose-{iid}", daemon=True).start()

    def log_message(self, *a: Any) -> None:
        pass

    def _json(self, code: int, body: Any) -> None:
        b = json.dumps(body, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _body(self) -> Any:
        n = int(self.headers.get("Content-Length", 0))
        if n > 1 << 20:
            raise ValueError("body too large")
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            return self._json(200, {"ok": True})
        if self.path == "/pending":
            out = []
            for p in sorted((VAR / "state").glob("*.json")):
                s = json.loads(p.read_text(encoding="utf-8"))
                if s.get("status") == "awaiting_approval":
                    out.append({k: s.get(k) for k in ("incident_id", "diagnosis", "proposed_actions", "ticket")})
            return self._json(200, out)
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        try:
            body = self._body()
            if not isinstance(body, dict):
                raise ValueError("body must be a JSON object")
        except ValueError as e:  # includes JSONDecodeError and a bad Content-Length
            return self._json(400, {"error": str(e)})
        if self.path == "/incidents":
            try:
                iid = check_incident_id(str(body.get("id", "")))
            except InvalidIncidentId as e:
                return self._json(400, {"error": str(e)})
            (VAR / "incoming").mkdir(parents=True, exist_ok=True)
            (VAR / "incoming" / f"{iid}.json").write_text(json.dumps(body), encoding="utf-8", newline="\n")
            self.deps.audit.append("correlator", "incident_received", {"incident": iid, "services": body.get("services")})
            self._diagnose_in_background(iid, body)
            return self._json(202, {"accepted": iid})
        if self.path.startswith("/approve/"):
            user = self.headers.get("X-Forwarded-User")
            if not user:
                return self._json(401, {"error": "approval requires an authenticated user (X-Forwarded-User)"})
            try:
                with _lock:
                    s = resume(self.path.split("/", 2)[2], user, bool(body.get("approve")), self.deps, str(body.get("reason", "")))
            except InvalidIncidentId as e:
                return self._json(400, {"error": str(e)})
            except UnknownIncident:
                return self._json(404, {"error": "unknown incident"})
            except NotAwaitingApproval as e:
                return self._json(409, {"error": str(e)})
            except NotApproved as e:  # e.g. the agent's own identity tried to approve
                return self._json(403, {"error": str(e)})
            return self._json(200, {k: s.get(k) for k in ("status", "remediation")})
        self._json(404, {"error": "not found"})


def _servicenow() -> Any:
    from agent.servicenow import ServiceNow

    if url := os.environ.get("CLEARPATH_SN_URL"):
        return ServiceNow(url, os.environ["SN_USER"], os.environ["SN_PASSWORD"])
    from mock_servicenow import server as mock

    srv = mock.serve(0)  # local / demo: in-process mock with the Online Boutique CMDB
    return ServiceNow(f"http://127.0.0.1:{srv.server_address[1]}", "admin", "admin")


def serve(port: int = 8000) -> None:
    from agent import remediation as rem
    from agent.kube import SA_DIR, KubeClient, KubeExecutor
    from agent.llm import from_env

    kube = KubeClient.in_cluster() if (SA_DIR / "token").exists() else None
    mode = os.environ.get("CLEARPATH_EXECUTE", "dry-run")
    if mode not in ("dry-run", "kube") or (mode == "kube" and kube is None):
        raise SystemExit(f"CLEARPATH_EXECUTE={mode!r}: expected dry-run, or kube when running in a cluster")
    executor: rem.Executor = KubeExecutor(kube=kube) if mode == "kube" and kube else rem.Executor()
    Handler.deps = Deps.default(llm=from_env(), sn=_servicenow(), executor=executor, audit=AuditLog(VAR / "audit.jsonl"), state_dir=VAR / "state")
    if prom := os.environ.get("CLEARPATH_PROM"):
        Handler.diagnose = live_diagnoser(prom, Handler.deps, kube)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()  # noqa: S104 - in-cluster, NetworkPolicy-restricted
