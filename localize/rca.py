"""Graph-based root-cause localisation.

Adapted from MicroRCA (Wu et al., NOMS 2020: anomaly-weighted personalised
PageRank on an attributed service graph) and the self/backward-edge idea from
CloudRanger (Wang et al., CCGrid 2018). Differences from the papers are listed in
docs/DESIGN.md#localizer.

Idea in one paragraph: anomalies flow upstream (callee -> caller), so a random
walker that starts at anomalous services and preferentially steps from a caller
to the callee whose anomaly *moves together* with the caller's ends up spending
most time at the most-downstream service that still explains what is upstream.
A self-loop keeps the walker at a service whose anomaly is not explained by any
callee; a weak backward edge lets it escape a wrong branch.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from faults import topology as topo

SVCS = list(topo.SERVICES)
IDX = {s: i for i, s in enumerate(SVCS)}
ABSENT_SCORE = 50.0  # a target with no scrapes is maximally anomalous


@dataclass(frozen=True)
class Params:
    alpha: float = 0.85  # PageRank damping (prob. of following an edge)
    rho: float = 0.2  # backward-edge weight relative to forward edges
    gamma: float = 1.0  # final score = pi * a^gamma
    use_corr: bool = True
    use_self: bool = True
    personalise: bool = True


def build_graph(trace_edges: dict[tuple[str, str], int], min_calls: int = 1) -> list[tuple[int, int]]:
    """Directed caller->callee edges observed in traces (no static topology)."""
    return [(IDX[c], IDX[d]) for (c, d), n in trace_edges.items() if n >= min_calls]


def anomaly_matrix(z: dict[str, np.ndarray], absent: dict[str, np.ndarray]) -> np.ndarray:
    """(n_services, n_steps) combined anomaly: max |z| over a service's metrics."""
    out = np.zeros((len(SVCS), next(iter(z.values())).shape[-1]))
    for s, i in IDX.items():
        a = np.nanmax(np.abs(z[s]), axis=0)
        a = np.nan_to_num(a, nan=0.0)
        out[i] = np.where(absent[s], ABSENT_SCORE, a)
    return out


def _corr(x: np.ndarray, y: np.ndarray) -> float:
    if x.std() < 1e-9 or y.std() < 1e-9:
        return 0.0
    return float(abs(np.corrcoef(x, y)[0, 1]))


def rank(A: np.ndarray, edges: list[tuple[int, int]], t_det: int, p: Params = Params(), win: int = 20) -> list[tuple[str, float]]:
    """Rank services; returns [(service, score)] best first.

    A: anomaly matrix (services, steps); t_det: detection step. The anomaly
    *level* a_s is the peak over [t_det, t_det+win); correlation uses the
    surrounding window so the pre-fault baseline anchors it.
    """
    n = len(SVCS)
    lo, hi = max(0, t_det - win), min(A.shape[1], t_det + win)
    a = A[:, t_det : min(A.shape[1], t_det + win)].max(axis=1)
    a_norm = a / max(a.max(), 1e-9)
    seg = A[:, lo:hi]
    W = np.zeros((n, n))
    for u, v in edges:  # u calls v
        w = _corr(seg[u], seg[v]) if p.use_corr else 1.0
        w = max(w, 0.01) * a_norm[v]  # step toward anomalous callees
        W[u, v] += w
        W[v, u] += p.rho * w  # weak escape back to the caller
    if p.use_self:
        for u in range(n):
            out_fwd = [W[u, v] for (x, v) in edges if x == u]
            explained = max(out_fwd) if out_fwd else 0.0
            W[u, u] = max(0.0, a_norm[u] - explained)
    row = W.sum(axis=1, keepdims=True)
    P = np.divide(W, row, out=np.zeros_like(W), where=row > 0)
    dangling = row[:, 0] == 0
    pers = a_norm / a_norm.sum() if p.personalise and a_norm.sum() > 0 else np.full(n, 1 / n)
    P[dangling] = pers  # dangling nodes teleport
    pi = pers.copy()
    for _ in range(200):  # power iteration
        new = (1 - p.alpha) * pers + p.alpha * pi @ P
        if np.abs(new - pi).sum() < 1e-12:
            pi = new
            break
        pi = new
    score = pi * np.power(np.maximum(a_norm, 1e-9), p.gamma)
    order = np.argsort(-score, kind="stable")
    return [(SVCS[i], float(score[i])) for i in order]


# ---------------------------------------------------------------- baselines
def most_alerting(alerts: list[dict[str, object]], t_from: int) -> list[str]:
    """Service with the most distinct firing alert rules; ties -> earliest."""
    names: dict[str, set[str]] = {}
    first: dict[str, int] = {}
    for al in alerts:
        ts = int(al["ts"])  # type: ignore[call-overload]
        if ts < t_from:
            continue
        labels = al["labels"]
        assert isinstance(labels, dict)
        s = labels["service"]
        names.setdefault(s, set()).add(labels["alertname"])
        first.setdefault(s, ts)
    ranked = sorted(names, key=lambda s: (-len(names[s]), first[s], s))
    return ranked + [s for s in SVCS if s not in names]


def most_anomalous(A: np.ndarray, t_det: int, win: int = 20) -> list[str]:
    a = A[:, t_det : t_det + win].max(axis=1)
    return [SVCS[i] for i in np.argsort(-a, kind="stable")]


def downstream_most(A: np.ndarray, edges: list[tuple[int, int]], t_det: int, tau: float = 6.0, win: int = 20) -> list[str]:
    """Heuristic SREs use: anomalous services with no anomalous callee, by anomaly."""
    a = A[:, t_det : t_det + win].max(axis=1)
    anom = a >= tau
    leafish = [i for i in range(len(SVCS)) if anom[i] and not any(anom[v] for (u, v) in edges if u == i)]
    rest = [i for i in np.argsort(-a, kind="stable") if i not in leafish]
    leafish.sort(key=lambda i: -a[i])
    return [SVCS[i] for i in leafish + rest]
