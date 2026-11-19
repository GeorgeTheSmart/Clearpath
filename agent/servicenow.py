"""ServiceNow Table API client (incident, cmdb_ci_service, cmdb_rel_ci, task_ci).

Works unchanged against a real Personal Developer Instance or the local mock.
Impact/urgency come from the SLO burn rate, so priority reflects how fast the
error budget is burning rather than how loud the alerts are.
"""

from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from agent.schema import Diagnosis


def urgency_impact(burn_rate: float) -> tuple[str, str]:
    """Google SRE workbook thresholds: 14.4x burns 2% of a 30-day budget in 1 h,
    6x burns 5% in 6 h. Mapped to ServiceNow 1=High, 2=Medium, 3=Low."""
    if burn_rate >= 14.4:
        return "1", "1"
    if burn_rate >= 6:
        return "2", "2"
    if burn_rate >= 1:
        return "2", "3"
    return "3", "3"


@dataclass
class ServiceNow:
    base: str
    user: str
    password: str
    timeout: float = 10.0
    retries: int = 3

    def _req(self, method: str, path: str, body: dict[str, Any] | None = None, query: dict[str, str] | None = None) -> Any:
        url = f"{self.base.rstrip('/')}/api/now/table/{path}"
        if query:
            url += "?" + urllib.parse.urlencode(query)
        auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            url, data=data, method=method, headers={"Authorization": f"Basic {auth}", "Accept": "application/json", "Content-Type": "application/json"}
        )
        for attempt in range(self.retries):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    return json.load(r)["result"]
            except urllib.error.HTTPError as e:
                if e.code < 500 or attempt == self.retries - 1:
                    raise
            except urllib.error.URLError:
                if attempt == self.retries - 1:
                    raise
            time.sleep(0.2 * 2**attempt)
        raise RuntimeError("unreachable")

    def find_ci(self, name: str) -> dict[str, Any] | None:
        rows = self._req("GET", "cmdb_ci_service", query={"sysparm_query": f"name={name}", "sysparm_limit": "1"})
        return rows[0] if rows else None

    def relations(self, ci_sys_id: str) -> list[dict[str, Any]]:
        return list(self._req("GET", "cmdb_rel_ci", query={"sysparm_query": f"parent={ci_sys_id}^ORchild={ci_sys_id}"}))

    def create_incident(self, fields: dict[str, Any]) -> dict[str, Any]:
        return dict(self._req("POST", "incident", body=fields))

    def update_incident(self, sys_id: str, fields: dict[str, Any]) -> dict[str, Any]:
        return dict(self._req("PATCH", f"incident/{sys_id}", body=fields))

    def link_ci(self, incident_sys_id: str, ci_sys_id: str) -> None:
        self._req("POST", "task_ci", body={"task": incident_sys_id, "ci_item": ci_sys_id})


def open_ticket(sn: ServiceNow, incident_id: str, diag: Diagnosis, burn_rate: float, ranking: list[str]) -> dict[str, Any]:
    """Create the incident, link the root CI and its direct up/downstream CIs."""
    urgency, impact = urgency_impact(burn_rate)
    root_ci = sn.find_ci(diag.root_cause_service)
    affected: dict[str, str] = {}
    if root_ci:
        affected[root_ci["sys_id"]] = diag.root_cause_service
        for rel in sn.relations(root_ci["sys_id"]):
            for k in ("parent", "child"):
                affected.setdefault(rel[k], "")
    evidence = "\n".join(f"- [{e.ref}] {e.claim}" for e in diag.evidence)
    steps = "\n".join(f"{i}. {s}" for i, s in enumerate(diag.fix_steps, 1))
    desc = (
        f"Clearpath incident {incident_id}\n\nSummary: {diag.summary}\nFault type: {diag.fault_type} (confidence {diag.confidence:.2f})\n"
        f"Localizer ranking: {', '.join(ranking[:5])}\nSLO burn rate: {burn_rate:.1f}x\n\nEvidence:\n{evidence}\n\nSuggested fix (requires approval):\n{steps}\n"
        + ("\nNOTE: drafted without the LLM (degraded mode).\n" if diag.degraded else "")
    )
    inc = sn.create_incident(
        {
            "short_description": f"[Clearpath] {diag.fault_type} suspected on {diag.root_cause_service}",
            "description": desc,
            "urgency": urgency,
            "impact": impact,
            "category": "software",
            "cmdb_ci": root_ci["sys_id"] if root_ci else "",
            "correlation_id": incident_id,
        }
    )
    for ci in affected:
        sn.link_ci(inc["sys_id"], ci)
    inc["_affected_cis"] = len(affected)
    return inc
