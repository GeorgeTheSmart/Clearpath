"""gather_context + sanitize nodes.

In production these issue PromQL/LogQL queries and read Kubernetes events and
deploy history; `FixtureSource` reads the same information from a recorded
incident so every run can be replayed deterministically. `LiveSource` (PromQL
and LogQL over HTTP) has the same interface and is used on the cluster.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from typing import Any, Protocol

import numpy as np

from agent.guardrails import injection, pii
from agent.schema import Context, ContextItem
from faults import sim
from faults import topology as topo

MAX_LOGS = 40
MAX_METRICS = 12


class Source(Protocol):
    def alerts(self) -> list[dict[str, Any]]: ...
    def zscores(self) -> dict[tuple[str, str], np.ndarray]: ...
    def series(self) -> dict[tuple[str, str], np.ndarray]: ...
    def logs(self) -> list[dict[str, Any]]: ...
    def events(self) -> list[dict[str, Any]]: ...


class FixtureSource:
    def __init__(self, inc: sim.Incident) -> None:
        from detect.evaluate import _seasonal_z_signed
        from eval import datasets as ds

        self.inc = inc
        today, hist = ds.stack(inc)
        z = _seasonal_z_signed(today, hist)
        self._z = {k: z[i] for i, k in enumerate(ds.SERIES)}
        self._x = {k: today[i] for i, k in enumerate(ds.SERIES)}

    def alerts(self) -> list[dict[str, Any]]:
        return self.inc.alerts

    def zscores(self) -> dict[tuple[str, str], np.ndarray]:
        return self._z

    def series(self) -> dict[tuple[str, str], np.ndarray]:
        return self._x

    def logs(self) -> list[dict[str, Any]]:
        return self.inc.logs

    def events(self) -> list[dict[str, Any]]:
        return self.inc.events


class LiveSource:  # pragma: no cover - needs a running cluster
    """PromQL / LogQL over HTTP. Same interface as FixtureSource."""

    def __init__(self, prom: str, loki: str, start: float, end: float) -> None:
        self.prom, self.loki, self.start, self.end = prom, loki, start, end

    def _get(self, url: str) -> Any:
        with urllib.request.urlopen(url, timeout=10) as r:
            return json.load(r)

    def query_range(self, q: str, step: str = "30s") -> Any:
        params = urllib.parse.urlencode({"query": q, "start": self.start, "end": self.end, "step": step})
        return self._get(f"{self.prom}/api/v1/query_range?{params}")

    def loki_range(self, q: str, limit: int = 500) -> Any:
        params = urllib.parse.urlencode({"query": q, "start": int(self.start * 1e9), "end": int(self.end * 1e9), "limit": limit})
        return self._get(f"{self.loki}/loki/api/v1/query_range?{params}")

    def alerts(self) -> list[dict[str, Any]]:
        raise NotImplementedError("read from the correlator incident payload")

    def zscores(self) -> dict[tuple[str, str], np.ndarray]:
        raise NotImplementedError

    def series(self) -> dict[tuple[str, str], np.ndarray]:
        raise NotImplementedError

    def logs(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    def events(self) -> list[dict[str, Any]]:
        raise NotImplementedError


def gather(src: Source, incident_id: str, t_det: int, ranking: list[tuple[str, float]], win: int = 20) -> Context:
    lo, hi = max(0, t_det - win), t_det + win
    items: list[ContextItem] = []
    # localizer evidence
    for r, (svc, sc) in enumerate(ranking[:5], 1):
        items.append(ContextItem(id=f"loc:{r}", kind="loc", service=svc, text=f"localizer rank {r}: {svc} (score {sc:.3f})"))
    # alerts, deduplicated by fingerprint
    agg: dict[str, dict[str, Any]] = {}
    for a in src.alerts():
        if lo <= a["ts"] < hi:
            g = agg.setdefault(a["fingerprint"], {"a": a, "n": 0, "first": a["ts"]})
            g["n"] += 1
    for fp, g in sorted(agg.items(), key=lambda kv: kv[1]["first"]):
        lab = g["a"]["labels"]
        items.append(
            ContextItem(
                id=f"alert:{fp}",
                kind="alert",
                service=lab["service"],
                text=f"{lab['alertname']} on {lab['service']} ({lab['severity']}), first at step {g['first']}, {g['n']} evaluations",
            )
        )
    # metrics: most anomalous series, summarised numerically
    z, x = src.zscores(), src.series()
    peaks = sorted(((float(np.nanmax(np.abs(v[t_det:hi]))) if np.isfinite(v[t_det:hi]).any() else 0.0, k) for k, v in z.items()), reverse=True)
    for pk, (svc, m) in peaks[:MAX_METRICS]:
        xs = x[(svc, m)]
        before = float(np.nanmedian(xs[lo:t_det])) if np.isfinite(xs[lo:t_det]).any() else float("nan")
        after = float(np.nanmax(xs[t_det:hi])) if np.isfinite(xs[t_det:hi]).any() else float("nan")
        txt = f"{m} on {svc}: median {before:.4g} before, peak {after:.4g} after detection (|z| peak {pk:.1f})"
        if not np.isfinite(xs[t_det:hi]).any():
            txt = f"{m} on {svc}: NO DATA after detection (target not scraped)"
        items.append(ContextItem(id=f"metric:{svc}:{m}", kind="metric", service=svc, text=txt))
    # logs: errors/warnings, suspects first
    suspects = [s for s, _ in ranking[:3]]
    logs = [line for line in src.logs() if lo <= line["ts"] < hi and line["level"] in ("ERROR", "WARN")]
    logs.sort(key=lambda line: (suspects.index(line["service"]) if line["service"] in suspects else 9, line["ts"]))
    for line in logs[:MAX_LOGS]:
        items.append(ContextItem(id=f"log:{line['id']}", kind="log", service=line["service"], text=line["msg"]))
    # kubernetes events
    for i, e in enumerate(src.events()):
        if lo - 20 <= e["ts"] < hi:
            items.append(
                ContextItem(id=f"event:{i}", kind="event", service=e["service"], text=f"{e['reason']} on {e['service']} at step {e['ts']}: {e['message']}")
            )
    return Context(incident_id=incident_id, window=(lo, hi), items=items)


def sanitize(ctx: Context) -> Context:
    """Quarantine likely injections, then redact PII, in every untrusted item.

    Only log and event text is attacker-reachable; it is all treated as data.
    """
    items = list(ctx.items)
    untrusted = [i for i, it in enumerate(items) if it.kind in ("log", "event")]
    verdicts = injection.score_lines([items[i].text for i in untrusted])
    quarantined: list[str] = []
    red: dict[str, int] = {}
    for i, v in zip(untrusted, verdicts, strict=True):
        it = items[i]
        if v.blocked:
            quarantined.append(it.id)
            items[i] = it.model_copy(update={"text": "[quarantined: possible prompt injection]"})
            continue
        text, spans = pii.redact(it.text)
        for s in spans:
            red[s.kind] = red.get(s.kind, 0) + 1
        items[i] = it.model_copy(update={"text": text})
    return ctx.model_copy(update={"items": items, "redactions": red, "quarantined": quarantined})


def retrieval_query(ctx: Context, service: str | None = None) -> str:
    """Query text for runbook search: signals about the suspected service."""
    parts = []
    for it in ctx.items:
        if it.kind in ("alert", "log", "event", "metric") and (service is None or it.service == service):
            if it.text.startswith("[quarantined"):
                continue
            parts.append(it.text)
    return " ".join(parts) or (service or "")


def known_services() -> set[str]:
    return set(topo.SERVICES)
