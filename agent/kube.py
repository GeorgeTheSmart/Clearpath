"""Minimal Kubernetes API client (stdlib only) and an executor that performs
the three allow-listed remediations through the API instead of a kubectl
binary, so the agent image needs no extra tooling.

Every call stays inside the Role in deploy/helm/clearpath/templates/rbac.yaml:
get/patch deployments, patch deployments/scale, list replicasets, read pods,
pod logs and events - in ONE namespace. No delete, exec or secrets.
"""

from __future__ import annotations

import json
import ssl
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agent import remediation as rem

SA_DIR = Path("/var/run/secrets/kubernetes.io/serviceaccount")


@dataclass
class KubeClient:
    base: str
    token: str = ""
    ctx: ssl.SSLContext | None = None
    timeout: float = 10.0

    @classmethod
    def in_cluster(cls) -> KubeClient:
        """Credentials of the pod's service account (mounted by Kubernetes)."""
        ctx = ssl.create_default_context(cafile=str(SA_DIR / "ca.crt"))
        return cls("https://kubernetes.default.svc", (SA_DIR / "token").read_text(encoding="utf-8").strip(), ctx)

    def _req(self, method: str, path: str, params: dict[str, Any] | None = None, body: Any = None, ctype: str = "application/json") -> bytes:
        url = self.base.rstrip("/") + path + ("?" + urllib.parse.urlencode(params) if params else "")
        headers = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        data = None
        if body is not None:
            data, headers["Content-Type"] = json.dumps(body).encode(), ctype
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:
            return bytes(r.read())

    def get(self, path: str, **params: Any) -> Any:
        return json.loads(self._req("GET", path, params))

    def text(self, path: str, **params: Any) -> str:
        return self._req("GET", path, params).decode("utf-8", "replace")

    def patch(self, path: str, body: Any, ctype: str = "application/strategic-merge-patch+json") -> Any:
        return json.loads(self._req("PATCH", path, body=body, ctype=ctype))


def _deploy(ns: str, name: str) -> str:
    return f"/apis/apps/v1/namespaces/{ns}/deployments/{name}"


@dataclass
class KubeExecutor(rem.Executor):
    """Executes validated actions against the API. Same contract as
    remediation.Executor: `execute` has already checked approval + allow-list."""

    kube: KubeClient = field(default_factory=KubeClient.in_cluster)
    dry_run: bool = False
    namespace: str = rem.NAMESPACE

    def run(self, a: dict[str, Any]) -> str:
        self.log.append(rem.command(a))  # same audit shape as the kubectl executor
        ns, name = self.namespace, a["target"]
        if a["kind"] == "rollout_restart":
            # exactly what `kubectl rollout restart` does: bump a template annotation
            stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            self.kube.patch(_deploy(ns, name), {"spec": {"template": {"metadata": {"annotations": {"kubectl.kubernetes.io/restartedAt": stamp}}}}})
            return f"restarted deployment/{name} in {ns}"
        if a["kind"] == "scale":
            n = int(a["replicas"])
            self.kube.patch(_deploy(ns, name) + "/scale", {"spec": {"replicas": n}}, "application/merge-patch+json")
            return f"scaled deployment/{name} in {ns} to {n}"
        return self._rollback(ns, name)

    def _rollback(self, ns: str, name: str) -> str:
        """`kubectl rollout undo`: re-apply the pod template of the previous revision."""
        dep = self.kube.get(_deploy(ns, name))
        sel = ",".join(f"{k}={v}" for k, v in dep["spec"]["selector"]["matchLabels"].items())
        rss = self.kube.get(f"/apis/apps/v1/namespaces/{ns}/replicasets", labelSelector=sel)["items"]
        owned = [rs for rs in rss if any(o.get("uid") == dep["metadata"]["uid"] for o in rs["metadata"].get("ownerReferences", []))]
        revs = sorted(owned, key=lambda rs: int(rs["metadata"].get("annotations", {}).get("deployment.kubernetes.io/revision", "0")), reverse=True)
        if len(revs) < 2:
            raise rem.NotApproved(f"rollback of {name}: no previous revision to roll back to")
        tmpl = revs[1]["spec"]["template"]
        tmpl["metadata"].get("labels", {}).pop("pod-template-hash", None)
        self.kube.patch(_deploy(ns, name), [{"op": "replace", "path": "/spec/template", "value": tmpl}], "application/json-patch+json")
        rev = revs[1]["metadata"]["annotations"]["deployment.kubernetes.io/revision"]
        return f"rolled back deployment/{name} in {ns} to revision {rev}"
