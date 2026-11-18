"""HTTP surface for the agent (stdlib, no framework).

POST /incidents          correlator posts closed/opened incidents here
GET  /pending            incidents awaiting human approval
POST /approve/<id>       {"user": "...", "approve": true, "reason": "..."}
GET  /healthz

Approval identities come from the authenticating proxy header
X-Forwarded-User (oauth2-proxy / Slack signature verifier in front), never
from the request body, so a caller cannot approve as someone else.

Status: incident intake, approval and audit work against replayed incidents.
Building context from a *live* incident needs agent.context.LiveSource
(PromQL/LogQL), which is the remaining cluster-integration step (phase 1/6).
"""

from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from agent.audit import AuditLog
from agent.pipeline import Deps, resume

VAR = Path(os.environ.get("CLEARPATH_VAR", "var"))
_lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    deps: Deps

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
                s = json.loads(p.read_text())
                if s.get("status") == "awaiting_approval":
                    out.append({k: s.get(k) for k in ("incident_id", "diagnosis", "proposed_actions", "ticket")})
            return self._json(200, out)
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        try:
            body = self._body()
        except ValueError as e:
            return self._json(400, {"error": str(e)})
        if self.path == "/incidents":
            (VAR / "incoming").mkdir(parents=True, exist_ok=True)
            iid = str(body.get("id", "unknown")).replace("/", "_")
            (VAR / "incoming" / f"{iid}.json").write_text(json.dumps(body))
            self.deps.audit.append("correlator", "incident_received", {"incident": iid, "services": body.get("services")})
            return self._json(202, {"accepted": iid})
        if self.path.startswith("/approve/"):
            user = self.headers.get("X-Forwarded-User")
            if not user:
                return self._json(401, {"error": "approval requires an authenticated user (X-Forwarded-User)"})
            with _lock:
                s = resume(self.path.split("/", 2)[2], user, bool(body.get("approve")), self.deps, str(body.get("reason", "")))
            return self._json(200, {k: s.get(k) for k in ("status", "remediation")})
        self._json(404, {"error": "not found"})


def serve(port: int = 8000) -> None:
    Handler.deps = Deps.default(audit=AuditLog(VAR / "audit.jsonl"), state_dir=VAR / "state")
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()  # noqa: S104 - in-cluster, NetworkPolicy-restricted
