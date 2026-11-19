"""Context for a live incident from the running cluster.

`LiveSource` is the cluster counterpart of `context.FixtureSource`: the same
interface, filled from Prometheus (Linkerd + cAdvisor + kube-state-metrics),
the Kubernetes API (pod logs, events) and the correlator's incident payload.
Everything downstream - localizer, retrieval, diagnosis, guardrails - is the
code that the offline evaluation measures.

Time is a grid of 30 s steps (the simulator's resolution) from LOOKBACK before
the incident's first alert to "now". One difference from the offline path:
a fresh cluster has no multi-day history, so anomalies are robust z-scores
against the pre-incident baseline (median / MAD) instead of the seasonal
same-time-of-day baseline. See docs/DESIGN.md#live-path.
"""

from __future__ import annotations

import json
import re
import time
import urllib.parse
import urllib.request
import warnings
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import numpy as np

from detect import detectors as d
from faults import sim
from faults import topology as topo
from localize import rca

STEP_S = 30
LOOKBACK_S = 30 * 60
BASELINE_GUARD = 2  # steps just before the first alert are excluded from the baseline
MIN_BASELINE = 10  # fewer valid baseline points -> no z-score (NaN)
SIGMA_FLOOR = {"latency_ms": 0.05, "error_rate": 0.05, "cpu": 0.02, "mem": 0.02}  # transformed units
MAX_LOG_BYTES = 256_000
Z_SIGNIFICANT = 6.0  # same cut as the localizer's downstream heuristic (rca.downstream_most tau)
FLEET_WIDE_FRACTION = 0.7  # this share of active services anomalous together -> shared cause
TRIAGE_WINDOW = (-4, 20)  # steps around the first alert considered by triage


def min_effect(metric: str, baseline: float) -> float:
    """Smallest change in raw units that counts as an anomaly (practical significance)."""
    if metric == "latency_ms":
        return max(25.0, 0.5 * baseline)  # +50% and at least 25 ms of p99
    if metric == "error_rate":
        return 0.02  # 2 percentage points (HighErrorRate pages at 5%)
    return 0.10  # cpu / memory: 10 points of the container limit


POD_SERVICE = re.compile(r"^(.+)-[a-z0-9]+-[a-z0-9]{5}$")  # <deployment>-<replicaset-hash>-<suffix>
# "...Exception"/"...Error" usually end a class name (RedisConnectionException, RpcError)
ERROR_RE = re.compile(r"\b(?:fatal|panic|fail(?:ed|ure)?|refused|timeout|unavailable)\b|(?:exception|error)\b", re.I)
WARN_RE = re.compile(r"\bwarn(?:ing)?\b", re.I)


def _queries(ns: str) -> dict[str, str]:
    inb = f'namespace="{ns}",direction="inbound"'
    pod_svc = '"service", "$1", "pod", "(.+)-[a-z0-9]+-[a-z0-9]{5}"'
    app = f'namespace="{ns}",container!="",container!~"linkerd-.*"'
    return {
        "latency_ms": f"histogram_quantile(0.99, sum by (service, le) (rate(response_latency_ms_bucket{{{inb}}}[1m])))",
        "requests": f"sum by (service) (rate(response_total{{{inb}}}[1m]))",
        "failures": f'sum by (service) (rate(response_total{{{inb},classification="failure"}}[1m]))',
        "cpu": (
            f"sum by (service) (label_replace(rate(container_cpu_usage_seconds_total{{{app}}}[1m]), {pod_svc}))"
            f' / sum by (service) (label_replace(kube_pod_container_resource_limits{{namespace="{ns}",resource="cpu",container!~"linkerd-.*"}}, {pod_svc}))'
        ),
        "mem": (
            f"sum by (service) (label_replace(container_memory_working_set_bytes{{{app}}}, {pod_svc}))"
            f' / sum by (service) (label_replace(kube_pod_container_resource_limits{{namespace="{ns}",resource="memory",container!~"linkerd-.*"}}, {pod_svc}))'
        ),
    }


@dataclass
class PromClient:
    base: str
    timeout: float = 15.0

    def _get(self, path: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        url = f"{self.base.rstrip('/')}{path}?{urllib.parse.urlencode(params)}"
        with urllib.request.urlopen(url, timeout=self.timeout) as r:
            body = json.load(r)
        if body.get("status") != "success":
            raise RuntimeError(f"prometheus: {body.get('error')}")
        return list(body["data"]["result"])

    def range(self, q: str, start: float, end: float, step: int = STEP_S) -> list[dict[str, Any]]:
        return self._get("/api/v1/query_range", {"query": q, "start": start, "end": end, "step": step})

    def instant(self, q: str, t: float) -> list[dict[str, Any]]:
        return self._get("/api/v1/query", {"query": q, "time": t})


def service_of(pod_or_object: str) -> str | None:
    m = POD_SERVICE.match(pod_or_object)
    name = m.group(1) if m else pod_or_object
    return name if name in topo.SERVICES else None


RFC3339 = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?(Z|[+-]\d\d:\d\d)$")


def parse_rfc3339(s: str) -> float | None:
    """Kubernetes timestamps, including kubelet's nanosecond precision (which
    datetime cannot represent: fractions are truncated to microseconds)."""
    m = RFC3339.match(s)
    if not m:
        return None
    frac = (m.group(2) or "0")[:6].ljust(6, "0")
    tz = "+00:00" if m.group(3) == "Z" else m.group(3)
    return datetime.fromisoformat(f"{m.group(1)}.{frac}{tz}").timestamp()


def parse_log_line(raw: str) -> tuple[float, str, str] | None:
    """`<RFC3339 ts> <payload>` (kubelet --timestamps) -> (epoch, level, message).

    Online Boutique services log either JSON ({"severity"|"level", "message"|"msg"})
    or plain text; plain lines get a level from keywords.
    """
    ts_s, _, payload = raw.partition(" ")
    ts = parse_rfc3339(ts_s)
    if ts is None:
        return None
    level, msg = "", payload.strip()
    if msg.startswith("{"):
        try:
            obj = json.loads(msg)
            level = str(obj.get("severity") or obj.get("level") or "").upper()
            msg = str(obj.get("message") or obj.get("msg") or msg)
        except json.JSONDecodeError:
            pass
    level = {"WARNING": "WARN", "ERR": "ERROR", "FATAL": "ERROR", "CRITICAL": "ERROR"}.get(level, level)
    if level not in ("ERROR", "WARN", "INFO", "DEBUG"):
        level = "ERROR" if ERROR_RE.search(msg) else "WARN" if WARN_RE.search(msg) else "INFO"
    return ts, level, msg


class LiveSource:
    """Same interface as context.FixtureSource, from the running cluster."""

    def __init__(self, prom: PromClient, incident: dict[str, Any], now: float, kube: Any | None = None, namespace: str = "boutique") -> None:
        self.prom, self.kube, self.ns, self.incident = prom, kube, namespace, incident
        first = min((a["first"] for a in incident.get("alerts", [])), default=incident.get("first", now * 1000)) / 1000.0
        self.start = float(int((first - LOOKBACK_S) // STEP_S) * STEP_S)
        self.n = int((now - self.start) // STEP_S) + 1
        self.t_det = self.step_of(first)
        self._x = self._load_series()
        self._z = {k: self._robust_z(k[1], v) for k, v in self._x.items()}

    # --------------------------------------------------------------- time grid
    def step_of(self, epoch_s: float) -> int:
        return int(np.clip(round((epoch_s - self.start) / STEP_S), 0, max(self.n - 1, 0)))

    def _grid(self, results: list[dict[str, Any]]) -> dict[str, np.ndarray]:
        out: dict[str, np.ndarray] = {}
        for r in results:
            svc = r["metric"].get("service")
            if svc not in topo.SERVICES:
                continue
            arr = out.setdefault(svc, np.full(self.n, np.nan))
            for t, v in r["values"]:
                i = int(round((float(t) - self.start) / STEP_S))
                if 0 <= i < self.n and v not in ("NaN", "+Inf", "-Inf"):
                    arr[i] = float(v)
        return out

    # ------------------------------------------------------------ metrics
    def _load_series(self) -> dict[tuple[str, str], np.ndarray]:
        end = self.start + (self.n - 1) * STEP_S
        raw = {k: self._grid(self.prom.range(q, self.start, end)) for k, q in _queries(self.ns).items()}
        nan = np.full(self.n, np.nan)
        x: dict[tuple[str, str], np.ndarray] = {}
        for s in topo.SERVICES:
            req, fail = raw["requests"].get(s, nan), raw["failures"].get(s, nan)
            # no failure series yet = zero failures, wherever there was traffic
            err = np.where(np.isfinite(req) & (req > 0), np.nan_to_num(fail, nan=0.0) / np.where(req > 0, req, 1.0), np.nan)
            x[(s, "latency_ms")] = raw["latency_ms"].get(s, nan.copy())
            x[(s, "error_rate")] = err
            x[(s, "cpu")] = raw["cpu"].get(s, nan.copy())
            x[(s, "mem")] = raw["mem"].get(s, nan.copy())
        return x

    def _robust_z(self, metric: str, v: np.ndarray) -> np.ndarray:
        """Robust z against the pre-incident baseline, zeroed where the change is
        too small to matter: at <1 req/s one failed request is a large error
        *rate*, and a baseline with zero spread makes any blip a huge z."""
        tv = d.transform(metric, v)
        cut = max(0, self.t_det - BASELINE_GUARD)
        base, raw_base = tv[:cut], v[:cut]
        ok = np.isfinite(base)
        if ok.sum() < MIN_BASELINE:
            return np.full_like(v, np.nan)
        med = float(np.median(base[ok]))
        sigma = max(1.4826 * float(np.median(np.abs(base[ok] - med))), SIGMA_FLOOR[metric])
        z = (tv - med) / sigma
        raw_med = float(np.median(raw_base[ok]))
        small = np.abs(v - raw_med) < min_effect(metric, raw_med)
        return np.where(small & np.isfinite(z), 0.0, z)

    def absent(self) -> dict[str, np.ndarray]:
        """A service is absent at a step if it reported in the baseline but no
        metric at all exists now (killed, not scheduled, not scraped)."""
        out = {}
        for s in topo.SERVICES:
            stack = np.stack([self._x[(s, m)] for m in sim.METRICS])
            seen_before = np.isfinite(stack[:, : max(1, self.t_det)]).any()
            out[s] = np.isnan(stack).all(axis=0) & seen_before
        return out

    def trace_edges(self) -> dict[tuple[str, str], int]:
        """Caller->callee edges observed by the mesh in the window: HTTP/gRPC
        with traffic, plus open TCP connections (cartservice -> redis-cart is
        one long-lived connection, so its open counter never increases)."""
        end = self.start + (self.n - 1) * STEP_S
        win = f"{int(end - self.start)}s"
        http = self.prom.instant(f'sum by (service, dst_deployment) (increase(response_total{{namespace="{self.ns}",direction="outbound"}}[{win}])) > 0', end)
        tcp = self.prom.instant(f'count by (service, dst_deployment) (tcp_open_total{{namespace="{self.ns}",direction="outbound",dst_deployment!=""}})', end)
        edges: dict[tuple[str, str], int] = {}
        for r in http + tcp:
            c, dst = r["metric"].get("service"), r["metric"].get("dst_deployment")
            if c in topo.SERVICES and dst in topo.SERVICES and c != dst:
                edges[(c, dst)] = edges.get((c, dst), 0) + max(1, int(float(r["value"][1])))
        return edges

    def triage(self) -> dict[str, Any]:
        """Decide whether there is a service to blame before blaming one.

        localized   some services anomalous -> run the localizer and pipeline
        fleet_wide  most active services anomalous together -> a shared cause
                    outside the service graph (mesh, network, node, DNS); no
                    service-level remediation should be proposed
        no_anomaly  nothing material changed -> propose nothing
        """
        lo, hi = max(0, self.t_det + TRIAGE_WINDOW[0]), min(self.n, self.t_det + TRIAGE_WINDOW[1])
        absent = self.absent()
        active, anomalous = [], {}
        for s in topo.SERVICES:
            zs = np.stack([self._z[(s, m)][lo:hi] for m in sim.METRICS])
            if not np.isfinite(zs).any() and not absent[s][lo:hi].any():
                continue
            active.append(s)
            peak = float(np.nanmax(np.abs(zs))) if np.isfinite(zs).any() else 0.0
            if absent[s][lo:hi].any() or peak >= Z_SIGNIFICANT:
                anomalous[s] = round(peak, 1) if not absent[s][lo:hi].any() else "absent"
        if not anomalous:
            kind = "no_anomaly"
        elif len(active) >= 4 and len(anomalous) >= FLEET_WIDE_FRACTION * len(active):
            kind = "fleet_wide"
        else:
            kind = "localized"
        return {"kind": kind, "anomalous": anomalous, "active_services": len(active)}

    def rank(self) -> list[tuple[str, float]]:
        """The localizer, exactly as evaluated offline, on live anomalies."""
        z = {s: np.stack([self._z[(s, m)] for m in sim.METRICS]) for s in topo.SERVICES}
        with warnings.catch_warnings():
            # an absent service is all-NaN at those steps; anomaly_matrix scores it as absent
            warnings.simplefilter("ignore", RuntimeWarning)
            A = rca.anomaly_matrix(z, self.absent())
        return rca.rank(A, rca.build_graph(self.trace_edges()), self.t_det)

    # ------------------------------------------------- FixtureSource interface
    def alerts(self) -> list[dict[str, Any]]:
        return [
            {
                "ts": self.step_of(a["first"] / 1000.0),
                "fingerprint": a["fingerprint"],
                "labels": {"alertname": a["name"], "service": a["service"], "severity": a["severity"]},
            }
            for a in self.incident.get("alerts", [])
        ]

    def zscores(self) -> dict[tuple[str, str], np.ndarray]:
        return self._z

    def series(self) -> dict[tuple[str, str], np.ndarray]:
        return self._x

    def logs(self) -> list[dict[str, Any]]:
        if self.kube is None:
            return []
        out: list[dict[str, Any]] = []
        since = max(1, int(time.time() - self.start))
        for pod in self.kube.get(f"/api/v1/namespaces/{self.ns}/pods")["items"]:
            name, svc = pod["metadata"]["name"], service_of(pod["metadata"]["name"])
            app = [c["name"] for c in pod["spec"]["containers"] if not c["name"].startswith("linkerd-")]
            if svc is None or not app:
                continue
            try:
                text = self.kube.text(
                    f"/api/v1/namespaces/{self.ns}/pods/{name}/log", container=app[0], sinceSeconds=since, timestamps="true", limitBytes=MAX_LOG_BYTES
                )
            except OSError:
                continue  # pod gone or not started: its absence is already a signal
            for i, raw in enumerate(text.splitlines()):
                p = parse_log_line(raw)
                if p:
                    out.append({"id": f"{name}-{i}", "ts": self.step_of(p[0]), "service": svc, "level": p[1], "msg": p[2]})
        return out

    def events(self) -> list[dict[str, Any]]:
        if self.kube is None:
            return []
        out = []
        for e in self.kube.get(f"/api/v1/namespaces/{self.ns}/events")["items"]:
            svc = service_of(e.get("involvedObject", {}).get("name", ""))
            stamp = e.get("lastTimestamp") or e.get("eventTime") or e["metadata"].get("creationTimestamp")
            ts = parse_rfc3339(str(stamp)) if stamp else None
            if svc is None or ts is None:
                continue
            if ts >= self.start:
                out.append({"ts": self.step_of(ts), "service": svc, "reason": e.get("reason", ""), "message": e.get("message", "")})
        return sorted(out, key=lambda e: e["ts"])
