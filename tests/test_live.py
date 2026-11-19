"""The live path (agent/live.py, agent/kube.py, server wiring) against fake
Prometheus / Kubernetes APIs, so it runs in CI without a cluster. The real
cluster run is recorded in docs/EVALUATION.md#live."""

import json
import threading
import time
import urllib.request
from http.server import ThreadingHTTPServer

import numpy as np
import pytest

from agent import live
from agent.audit import AuditLog
from agent.kube import KubeExecutor
from agent.pipeline import Deps, run_live
from faults import topology as topo

FIRST = 1_800_000_000.0  # first alert (epoch s)
NOW = FIRST + 6 * 60  # incident closed after the correlator window


class FakeProm:
    """Steady baseline for every service; from the first alert, cartservice is
    gone for 2 min (pod killed) and the frontend, its caller, errors and slows."""

    def __init__(self, root: str = "cartservice", seed: int = 0) -> None:
        self.root, self.rng = root, np.random.default_rng(seed)

    def _val(self, kind: str, svc: str, t: float) -> float | None:
        out = FIRST <= t < FIRST + 120
        if svc == self.root and out:
            return None  # no series at all: absent
        hit = svc == "frontend" and FIRST <= t < FIRST + 240
        noise = 1 + 0.03 * self.rng.standard_normal()
        if kind == "latency":
            return (400.0 if hit else 40.0) * noise
        if kind == "requests":
            return 5.0 * noise
        if kind == "failures":
            return 0.6 if hit else None  # no failure series while healthy
        return 0.3 * noise  # cpu / mem ratio of limit

    def range(self, q: str, start: float, end: float, step: int = 30) -> list[dict]:
        kind = (
            "latency"
            if "latency" in q
            else "failures"
            if 'classification="failure"' in q
            else "requests"
            if "response_total" in q
            else "cpu"
            if "cpu" in q
            else "mem"
        )
        out = []
        for s in topo.SERVICES:
            vals = []
            for t in np.arange(start, end + 1, step):
                v = self._val(kind, s, float(t))
                if v is not None:
                    vals.append([float(t), str(v)])
            if vals:
                out.append({"metric": {"service": s}, "values": vals})
        return out

    def instant(self, q: str, t: float) -> list[dict]:
        tcp = "tcp_open_total" in q
        return [
            {"metric": {"service": c, "dst_deployment": d}, "value": [t, "1" if tcp else "100"]}
            for c, d in topo.edges()
            if (d == "redis-cart") == tcp  # cart -> redis is only visible as a TCP connection
        ]


def _incident(svcs=("frontend", "cartservice")) -> dict:
    alerts = [
        {
            "fingerprint": "fp-fe",
            "name": "HighErrorRate",
            "service": "frontend",
            "severity": "critical",
            "count": 3,
            "first": FIRST * 1000,
            "last": FIRST * 1000,
        },
        {
            "fingerprint": "fp-cart",
            "name": "TargetDown",
            "service": "cartservice",
            "severity": "critical",
            "count": 1,
            "first": (FIRST + 60) * 1000,
            "last": FIRST * 1000,
        },
    ]
    return {"id": "inc-0123456789ab", "services": list(svcs), "alerts": alerts}


@pytest.mark.parametrize("root", sorted({d for c, d in topo.edges() if c == "frontend"}))
@pytest.mark.parametrize("seed", [0, 1, 2])
def test_live_localizer_blames_the_missing_callee_not_the_loud_caller(root, seed):
    src = live.LiveSource(FakeProm(root=root, seed=seed), _incident(), NOW)
    assert src.t_det == live.LOOKBACK_S // live.STEP_S
    ranking = src.rank()
    assert ranking[0][0] == root, ranking[:3]


class FleetWideProm(FakeProm):
    """Every service fails at once (a mesh / network outage): no single culprit."""

    def _val(self, kind, svc, t):
        hit = FIRST <= t < FIRST + 120
        noise = 1 + 0.03 * self.rng.standard_normal()
        if kind == "latency":
            return (2000.0 if hit else 40.0) * noise
        if kind == "requests":
            return 5.0 * noise
        if kind == "failures":
            return 5.0 if hit else None
        return 0.3 * noise


class HealthyProm(FakeProm):
    """Small noise only, plus one failed request at <1 req/s: not material."""

    def _val(self, kind, svc, t):
        noise = 1 + 0.03 * self.rng.standard_normal()
        if kind == "latency":
            return 40.0 * noise
        if kind == "requests":
            return 0.2
        if kind == "failures":
            return 0.2 / 60 if svc == "emailservice" and FIRST <= t < FIRST + 60 else None  # 1 failure in a minute
        return 0.3 * noise


def test_triage_localized_when_one_service_fails():
    t = live.LiveSource(FakeProm(), _incident(), NOW).triage()
    assert t["kind"] == "localized" and t["anomalous"]["cartservice"] == "absent"


def test_triage_fleet_wide_blames_no_single_service(tmp_path):
    from agent.pipeline import triage_only
    from agent.servicenow import ServiceNow
    from mock_servicenow import server as mock

    t = live.LiveSource(FleetWideProm(), _incident(), NOW).triage()
    assert t["kind"] == "fleet_wide" and len(t["anomalous"]) == t["active_services"]
    srv = mock.serve(0)
    try:
        d = Deps.default(
            sn=ServiceNow(f"http://127.0.0.1:{srv.server_address[1]}", "admin", "admin"), audit=AuditLog(tmp_path / "a.jsonl"), state_dir=tmp_path / "s"
        )
        s = triage_only("inc-fleet", t, d)
    finally:
        srv.shutdown()
    assert s["status"] == "no_action:fleet_wide" and s["proposed_actions"] == [] and s["ticket"]["number"].startswith("INC")
    from agent.pipeline import NotAwaitingApproval, resume

    with pytest.raises(NotAwaitingApproval):  # nothing to approve, so nothing can be executed
        resume("inc-fleet", "george", True, d)


def test_triage_no_anomaly_ignores_sparse_traffic_blips():
    t = live.LiveSource(HealthyProm(), _incident(), NOW).triage()
    assert t["kind"] == "no_anomaly", t


def test_live_error_rate_is_zero_not_missing_while_healthy():
    src = live.LiveSource(FakeProm(), _incident(), NOW)
    err = src.series()[("currencyservice", "error_rate")]
    assert np.all(err[np.isfinite(err)] == 0) and np.isfinite(err).sum() > 50
    assert np.nanmax(src.series()[("frontend", "error_rate")]) == pytest.approx(0.12, rel=0.1)


def test_live_absence_needs_a_baseline():
    src = live.LiveSource(FakeProm(), _incident(), NOW)
    absent = src.absent()
    assert absent["cartservice"][src.t_det : src.t_det + 4].all()
    assert not absent["cartservice"][: src.t_det].any() and not absent["frontend"].any()


def test_live_edges_include_long_lived_tcp():
    edges = live.LiveSource(FakeProm(), _incident(), NOW).trace_edges()
    assert ("cartservice", "redis-cart") in edges and ("frontend", "cartservice") in edges


@pytest.mark.parametrize(
    ("raw", "level", "msg"),
    [
        ('2026-11-19T05:27:40.546085088Z {"message":"payment went through","severity":"info"}', "INFO", "payment went through"),
        ('2026-11-19T05:27:40.5Z {"msg":"redis down","level":"warning"}', "WARN", "redis down"),
        ("2026-11-19T05:27:46.802605491Z Can't access cart storage. StackExchange.Redis.RedisConnectionException", "ERROR", None),
        ("2026-11-19T05:27:46Z GetCartAsync called with userId=2bbfec72", "INFO", None),
    ],
)
def test_parse_log_line(raw, level, msg):
    ts, lv, m = live.parse_log_line(raw)
    assert lv == level and (msg is None or m == msg)
    assert abs(ts - 1_795_066_060) < 120  # 2026-11-19T05:27Z, nanoseconds truncated


def test_service_of_pod_and_object_names():
    assert live.service_of("redis-cart-847557c9b8-t86rz") == "redis-cart"
    assert live.service_of("frontend") == "frontend"
    assert live.service_of("kube-proxy-x7k2p") is None


class FakeKube:
    def __init__(self) -> None:
        self.patches: list[tuple[str, object, str]] = []

    def get(self, path, **params):
        if path.endswith("/pods"):
            return {
                "items": [
                    {"metadata": {"name": "cartservice-56fcfbc4f8-hw7cg"}, "spec": {"containers": [{"name": "server"}]}},
                    {"metadata": {"name": "frontend-f9b6c7d85-ltsdm"}, "spec": {"containers": [{"name": "server"}, {"name": "linkerd-proxy"}]}},
                ]
            }
        if path.endswith("/events"):
            return {
                "items": [
                    {
                        "involvedObject": {"name": "cartservice-56fcfbc4f8-hw7cg"},
                        "reason": "Killing",
                        "message": "Stopping container server",
                        "lastTimestamp": "2026-01-15T08:00:10Z",
                        "metadata": {},
                    }
                ]
            }
        if path.endswith("/deployments/cartservice"):
            return {"metadata": {"uid": "u1"}, "spec": {"selector": {"matchLabels": {"app": "cartservice"}}}}
        if path.endswith("/replicasets"):
            rs = lambda rev, img: {  # noqa: E731
                "metadata": {"annotations": {"deployment.kubernetes.io/revision": rev}, "ownerReferences": [{"uid": "u1"}]},
                "spec": {"template": {"metadata": {"labels": {"app": "cartservice", "pod-template-hash": "h" + rev}}, "spec": {"image": img}}},
            }
            return {"items": [rs("3", "v3"), rs("1", "v1"), rs("2", "v2")]}
        raise AssertionError(path)

    def text(self, path, **params):
        assert params["container"] == "server" and params["timestamps"] == "true"
        return "2026-01-15T08:00:05.123456789Z Can't access cart storage: connection refused\n"

    def patch(self, path, body, ctype="application/strategic-merge-patch+json"):
        self.patches.append((path, body, ctype))
        return {}


def test_live_logs_and_events_from_the_kube_api():
    first = 1_768_464_000.0  # 2026-01-15T08:00:00Z
    inc = _incident()
    for a in inc["alerts"]:
        a["first"] = first * 1000
    src = live.LiveSource(FakeProm(), inc, first + 300, kube=FakeKube())
    logs = src.logs()
    assert [(x["service"], x["level"]) for x in logs] == [("cartservice", "ERROR"), ("frontend", "ERROR")]
    ev = src.events()
    assert ev[0]["service"] == "cartservice" and ev[0]["reason"] == "Killing" and ev[0]["ts"] == src.t_det


def test_live_pipeline_end_to_end_to_approval(tmp_path):
    src = live.LiveSource(FakeProm(), _incident(), NOW, kube=FakeKube())
    d = Deps.default(audit=AuditLog(tmp_path / "a.jsonl"), state_dir=tmp_path / "state")
    s = run_live(src, "inc-0123456789ab", src.t_det, src.rank(), d)
    assert s["status"] == "awaiting_approval" and s["diagnosis"]["root_cause_service"] == "cartservice"
    assert [a["kind"] for a in s["proposed_actions"]] and s["verification"]["unverified"] == []
    assert (tmp_path / "state" / "inc-0123456789ab.json").exists()


@pytest.mark.parametrize(
    ("action", "path_end", "ctype"),
    [
        ({"kind": "rollout_restart", "target": "cartservice", "replicas": None}, "/deployments/cartservice", "application/strategic-merge-patch+json"),
        ({"kind": "scale", "target": "cartservice", "replicas": 3}, "/deployments/cartservice/scale", "application/merge-patch+json"),
    ],
)
def test_kube_executor_uses_only_patch_on_deployments(action, path_end, ctype):
    k = FakeKube()
    out = KubeExecutor(kube=k).run(action)
    ((path, body, ct),) = k.patches
    assert path == f"/apis/apps/v1/namespaces/boutique{path_end}" and ct == ctype and "cartservice" in out
    if action["kind"] == "scale":
        assert body == {"spec": {"replicas": 3}}
    else:
        assert "kubectl.kubernetes.io/restartedAt" in body["spec"]["template"]["metadata"]["annotations"]


def test_kube_executor_rollback_reapplies_previous_revision_template():
    k = FakeKube()
    out = KubeExecutor(kube=k).run({"kind": "rollback", "target": "cartservice", "replicas": None})
    ((path, body, ct),) = k.patches
    assert ct == "application/json-patch+json" and body[0]["path"] == "/spec/template"
    assert body[0]["value"]["spec"]["image"] == "v2" and "pod-template-hash" not in body[0]["value"]["metadata"]["labels"]
    assert "revision 2" in out


def test_server_diagnoses_incidents_once_and_audits_failures(tmp_path, monkeypatch):
    from agent import server

    monkeypatch.setattr(server, "VAR", tmp_path)
    d = Deps.default(audit=AuditLog(tmp_path / "audit.jsonl"), state_dir=tmp_path / "state")
    calls: list[str] = []
    done = threading.Event()

    def fake_diagnose(iid, inc):
        calls.append(iid)
        done.set()
        if iid == "inc-bad":
            raise RuntimeError("prometheus unreachable")
        (d.state_dir).mkdir(parents=True, exist_ok=True)
        (d.state_dir / f"{iid}.json").write_text("{}", encoding="utf-8")

    monkeypatch.setattr(server.Handler, "deps", d, raising=False)
    monkeypatch.setattr(server.Handler, "diagnose", staticmethod(fake_diagnose))
    srv = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"

    def post(iid):
        req = urllib.request.Request(base + "/incidents", data=json.dumps({"id": iid, "services": ["cartservice"]}).encode(), method="POST")
        assert urllib.request.urlopen(req).status == 202

    try:
        post("inc-good")
        assert done.wait(5)
        deadline = time.time() + 5
        while not (d.state_dir / "inc-good.json").exists() and time.time() < deadline:
            time.sleep(0.05)
        post("inc-good")  # correlator redelivery: not diagnosed twice
        done.clear()
        post("inc-bad")
        assert done.wait(5)
        deadline = time.time() + 5
        while "diagnosis_failed" not in [r["event"] for r in d.audit.records()] and time.time() < deadline:
            time.sleep(0.05)
    finally:
        srv.shutdown()
    assert calls == ["inc-good", "inc-bad"]
    failed = [r for r in d.audit.records() if r["event"] == "diagnosis_failed"]
    assert failed and "prometheus unreachable" in failed[0]["data"]["error"]
