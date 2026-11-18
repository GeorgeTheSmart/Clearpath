"""Allow-listed, reversible remediation, executed only after human approval.

This module is the security boundary that bounds what a compromised or wrong
model can do: whatever text arrives, `validate` accepts only three reversible
verbs on known services with bounded parameters, and `execute` refuses without
a matching approval from a human (not the agent's own identity).

The Kubernetes service account used by the executor can only
get/patch deployments and their scale subresource in one namespace
(deploy/helm/clearpath/templates/rbac.yaml) - no delete, no exec, no secrets.
"""

from __future__ import annotations

import hashlib
import json
import shlex
import subprocess
from dataclasses import dataclass, field
from typing import Any

from agent.context import known_services

ALLOWED = {"rollout_restart", "scale", "rollback"}
MIN_REPLICAS, MAX_REPLICAS = 1, 10
NAMESPACE = "boutique"
AGENT_IDENTITIES = {"clearpath-agent", "agent", "system"}


def validate(action: dict[str, Any] | Any) -> tuple[bool, str]:
    a = action if isinstance(action, dict) else action.model_dump()
    kind, target = a.get("kind"), a.get("target")
    if kind not in ALLOWED:
        return False, f"action kind {kind!r} not in allow-list"
    if target not in known_services():
        return False, f"unknown target {target!r}"
    if kind == "scale":
        r = a.get("replicas")
        if not isinstance(r, int) or not MIN_REPLICAS <= r <= MAX_REPLICAS:
            return False, f"replicas must be an int in [{MIN_REPLICAS}, {MAX_REPLICAS}]"
    extra = set(a) - {"kind", "target", "replicas"}
    if extra:
        return False, f"unexpected fields {sorted(extra)}"
    return True, "ok"


def action_hash(incident_id: str, actions: list[dict[str, Any]]) -> str:
    return hashlib.sha256(json.dumps([incident_id, actions], sort_keys=True).encode()).hexdigest()[:16]


def command(a: dict[str, Any]) -> list[str]:
    t = shlex.quote(a["target"])
    if a["kind"] == "rollout_restart":
        return ["kubectl", "-n", NAMESPACE, "rollout", "restart", f"deployment/{t}"]
    if a["kind"] == "scale":
        return ["kubectl", "-n", NAMESPACE, "scale", f"deployment/{t}", f"--replicas={int(a['replicas'])}"]
    return ["kubectl", "-n", NAMESPACE, "rollout", "undo", f"deployment/{t}"]


@dataclass
class Executor:
    dry_run: bool = True
    log: list[list[str]] = field(default_factory=list)

    def run(self, a: dict[str, Any]) -> str:
        cmd = command(a)
        self.log.append(cmd)
        if self.dry_run:
            return "dry-run: " + " ".join(cmd)
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)  # pragma: no cover
        return out.stdout + out.stderr  # pragma: no cover


class NotApproved(PermissionError):
    pass


def execute(incident_id: str, actions: list[dict[str, Any]], approval: dict[str, Any] | None, ex: Executor) -> list[str]:
    if approval is None or not approval.get("approved"):
        raise NotApproved("no human approval")
    if approval.get("approver") in AGENT_IDENTITIES:
        raise NotApproved("the agent cannot approve its own actions")
    if approval.get("action_hash") != action_hash(incident_id, actions):
        raise NotApproved("approval does not match these exact actions")
    out = []
    for a in actions:
        ok, why = validate(a)
        if not ok:
            raise NotApproved(f"rejected at execution: {why}")
        out.append(ex.run(a))
    return out
