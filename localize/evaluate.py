"""Localisation evaluation: top-1/top-3 accuracy and mean rank vs baselines.

Protocol: hyper-parameters (alpha, rho, gamma) are grid-searched on DEV
incidents only, then frozen and applied once to TEST. Every method sees the
same detection time t_det: the first seasonal-detector alarm at or after
t0 - 10 steps (the detector's calibrated threshold is read from
detection.json, so `make eval` runs detection first).

Run: python -m localize.evaluate eval/results/latest
"""

from __future__ import annotations

import itertools
import json
import sys
from collections import defaultdict
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

import numpy as np

from detect import detectors as d
from detect.evaluate import _seasonal_z_signed
from eval import datasets as ds
from eval import stats
from faults import sim
from localize import rca

N_SVC, N_MET = len(rca.SVCS), len(sim.METRICS)


def features(inc: sim.Incident, thr: float) -> tuple[np.ndarray, list[tuple[int, int]], int]:
    today, hist = ds.stack(inc)
    z = _seasonal_z_signed(today, hist).reshape(N_SVC, N_MET, -1)
    absent = np.isnan(today).reshape(N_SVC, N_MET, -1).any(axis=1)
    A = rca.anomaly_matrix({s: z[i] for i, s in enumerate(rca.SVCS)}, {s: absent[i] for i, s in enumerate(rca.SVCS)})
    alarm = d.alarms(np.abs(z.reshape(N_SVC * N_MET, -1)), thr).any(axis=0) | d.alarms(absent.astype(float), 0.5).any(axis=0)
    cand = np.flatnonzero(alarm[max(0, inc.t0 - 10) :])
    t_det = int(cand[0]) + max(0, inc.t0 - 10) if cand.size else inc.t0
    return A, rca.build_graph(inc.trace_edges), t_det


def perturb(kind: str, inc: sim.Incident, A: np.ndarray, E: list[tuple[int, int]], t: int, rng: np.random.Generator) -> tuple[np.ndarray, list[tuple[int, int]]]:
    """Robustness perturbations, fixed before looking at their results.

    drop_edges: 30% of observed trace edges missing (sampling, uninstrumented hop).
    concurrent_anomaly: an unrelated service has a benign anomaly as large as
        50-100% of the root's peak, overlapping the incident window.
    downstream_confounder: same, but on a callee of the root (if it has one) -
        the case where "pick the most-downstream anomalous service" is fooled.
    """
    A = A.copy()
    E = list(E)
    r = rca.IDX[inc.root]
    if kind == "drop_edges":
        keep = rng.random(len(E)) >= 0.3
        E = [e for e, k in zip(E, keep) if k]
    elif kind in ("concurrent_anomaly", "downstream_confounder"):
        others = [i for i in range(N_SVC) if i != r]
        if kind == "downstream_confounder":
            callees = [v for (u, v) in E if u == r]
            others = callees or others
        o = int(rng.choice(others))
        peak = A[r, t : t + 20].max()
        start = int(np.clip(t + rng.integers(-5, 15), 0, A.shape[1] - 1))
        dur = int(rng.integers(6, 16))
        A[o, start : start + dur] = np.maximum(A[o, start : start + dur], rng.uniform(0.5, 1.0) * peak)
    return A, E


def rank_of(truth: str, ranking: list[str]) -> int:
    return ranking.index(truth) + 1


def evaluate_rankings(ranks: list[int]) -> dict[str, Any]:
    r = np.array(ranks, float)
    return {
        "top1": stats.bootstrap_ci(r <= 1).as_dict(),
        "top3": stats.bootstrap_ci(r <= 3).as_dict(),
        "mean_rank": stats.bootstrap_ci(r).as_dict(),
    }


def main(out_dir: Path) -> dict[str, Any]:
    det = json.loads((out_dir / "detection.json").read_text())
    thr = float(det["detectors"]["seasonal_robust_z"]["threshold"])
    dev = [(i, *features(i, thr)) for i in ds.incidents(ds.DEV_SEEDS)]
    test = [(i, *features(i, thr)) for i in ds.incidents(ds.TEST_SEEDS)]

    # ---- tune on DEV
    grid = []
    for alpha, rho, gamma in itertools.product([0.5, 0.7, 0.85, 0.95], [0.0, 0.1, 0.2, 0.5], [0.0, 0.5, 1.0, 2.0]):
        p = rca.Params(alpha=alpha, rho=rho, gamma=gamma)
        dev_ranks = [rank_of(inc.root, [s for s, _ in rca.rank(A, E, t, p)]) for inc, A, E, t in dev]
        grid.append(((float(np.mean(np.array(dev_ranks) <= 1)), float(np.mean(np.array(dev_ranks) <= 3)), -float(np.mean(dev_ranks))), p))
    grid.sort(key=lambda g: g[0], reverse=True)
    best = grid[0][1]
    print(f"best on DEV: {best} -> top1={grid[0][0][0]:.3f} top3={grid[0][0][1]:.3f}", file=sys.stderr)

    # ---- apply once to TEST
    rng = np.random.default_rng(12345)
    methods: dict[str, list[int]] = defaultdict(list)
    per_fault: dict[str, dict[str, list[int]]] = defaultdict(lambda: defaultdict(list))
    rankings_out = {}
    variants = {
        "ppr_full": best,
        "ablate_no_corr": replace(best, use_corr=False),
        "ablate_no_self_loop": replace(best, use_self=False),
        "ablate_no_personalisation": replace(best, personalise=False),
        "ablate_pure_pagerank_gamma0": replace(best, gamma=0.0),
    }
    for inc, A, E, t in test:
        cands = {
            "random": [str(x) for x in rng.permutation(rca.SVCS)],
            "most_alerting": rca.most_alerting(inc.alerts, t),
            "most_anomalous": rca.most_anomalous(A, t),
            "downstream_most_anomalous": rca.downstream_most(A, E, t),
        }
        for name, p in variants.items():
            ranked = rca.rank(A, E, t, p)
            cands[name] = [s for s, _ in ranked]
            if name == "ppr_full":
                rankings_out[inc.seed] = {"ranking": ranked, "t_det": t}
        for name, cand in cands.items():
            r = rank_of(inc.root, cand)
            methods[name].append(r)
            per_fault[name][inc.fault_type].append(r)

    # ---- robustness suite on TEST (no retuning)
    robustness: dict[str, dict[str, Any]] = {}
    for kind in ("drop_edges", "concurrent_anomaly", "downstream_confounder"):
        prng = np.random.default_rng(777)
        rk: dict[str, list[int]] = defaultdict(list)
        for inc, A0, E0, t in test:
            A, E = perturb(kind, inc, A0, E0, t, prng)
            rk["most_anomalous"].append(rank_of(inc.root, rca.most_anomalous(A, t)))
            rk["downstream_most_anomalous"].append(rank_of(inc.root, rca.downstream_most(A, E, t)))
            rk["ppr_full"].append(rank_of(inc.root, [s for s, _ in rca.rank(A, E, t, best)]))
            rk["ablate_no_corr"].append(rank_of(inc.root, [s for s, _ in rca.rank(A, E, t, replace(best, use_corr=False))]))
        robustness[kind] = {m: evaluate_rankings(v) for m, v in rk.items()}
        for k in (1, 3):
            c = stats.paired_compare(np.array(rk["downstream_most_anomalous"]) <= k, np.array(rk["ppr_full"]) <= k)
            robustness[kind][f"ppr_vs_downstream_top{k}"] = c.as_dict()

    results = {m: evaluate_rankings(r) for m, r in methods.items()}
    results["random"]["expected_top1"] = 1 / N_SVC
    results["random"]["expected_top3"] = 3 / N_SVC
    comps: dict[str, Any] = {}
    pvals = {}
    for base in ["most_alerting", "most_anomalous", "downstream_most_anomalous", "random"]:
        for k in (1, 3):
            c = stats.paired_compare(np.array(methods[base]) <= k, np.array(methods["ppr_full"]) <= k)
            key = f"ppr_full_vs_{base}_top{k}"
            comps[key] = c.as_dict()
            pvals[key] = c.p_mcnemar_exact
    for key, padj in stats.holm(pvals).items():
        comps[key]["p_holm"] = padj
    out = {
        "protocol": {"tuned_on": "DEV", "dev_incidents": len(dev), "test_incidents": len(test), "detector_threshold": thr},
        "chosen_params": asdict(best),
        "dev_grid_top5": [{"params": asdict(p), "dev_top1": s[0], "dev_top3": s[1]} for s, p in grid[:5]],
        "methods": results,
        "per_fault_top1": {m: {f: float(np.mean(np.array(v) <= 1)) for f, v in sorted(fs.items())} for m, fs in per_fault.items()},
        "paired": comps,
        "robustness": robustness,
        "ranks": {m: r for m, r in methods.items()},
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "localization.json").write_text(json.dumps(out, indent=1))
    (out_dir / "localizer_rankings.json").write_text(json.dumps(rankings_out))
    return out


if __name__ == "__main__":
    o = main(Path(sys.argv[1]) if len(sys.argv) > 1 else Path("eval/results/latest"))
    for kind, rr in o["robustness"].items():
        print(kind, {m: round(v["top1"]["estimate"], 3) for m, v in rr.items() if "top1" in v},
              "ppr-vs-downstream top1 diff=%.3f p=%.2g" % (rr["ppr_vs_downstream_top1"]["diff"], rr["ppr_vs_downstream_top1"]["p_mcnemar_exact"]))
    for m, r in o["methods"].items():
        print(f"{m:30s} top1={r['top1']['estimate']:.3f} [{r['top1']['ci95_lo']:.3f},{r['top1']['ci95_hi']:.3f}] "
              f"top3={r['top3']['estimate']:.3f} mean_rank={r['mean_rank']['estimate']:.2f}")
