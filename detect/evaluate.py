"""Detection evaluation: equal false-alarm budget, then compare recall and delay.

Protocol
1. Every detector's threshold is calibrated on the DEV fault-free week to the
   largest sensitivity whose fleet-wide false-alarm rate is <= BUDGET pages/day.
   The "as written" static rules are the exception: they are reported as
   deployed (threshold multiplier 1, real alert coverage).
2. False alarms/day are then measured on a different (TEST) week.
3. Recall within 10 / 30 min and detection delay are measured on TEST incidents.

A detection is the first alarm on *any* series at or after fault start. Missing
scrapes (target down) raise an alarm for every detector equally.

Run: python -m detect.evaluate  (writes eval/results/<date>/detection.json)
"""

from __future__ import annotations

import json
import sys
import time
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path
from typing import Any

import numpy as np

from detect import detectors as d
from eval import datasets as ds
from eval import stats
from faults import sim

BUDGET = 3.0  # false pages per day, fleet-wide (44 series)
WARM = 60  # steps excluded at the start of each incident window
STEP_MIN = sim.STEP_S / 60

STATIC_THR = np.array([sim.STATIC_RULES[r][1](s) for s, m in ds.SERIES for r in sim.STATIC_RULES if sim.STATIC_RULES[r][0] == m])
DEPLOYED = np.array(
    [any(sim.STATIC_RULES[r][0] == m and r in sim.COVERAGE[s] for r in sim.STATIC_RULES) for s, m in ds.SERIES]
)
METRIC_OF = [m for _, m in ds.SERIES]


def _transform(x: np.ndarray) -> np.ndarray:
    out = np.empty_like(x)
    for i, m in enumerate(METRIC_OF):
        out[i] = d.transform(m, x[i])
    return out


def _seasonal_z_signed(x: np.ndarray, hist: np.ndarray, tf: Callable[[np.ndarray], np.ndarray] | None = None) -> np.ndarray:
    tf = tf or _transform
    return d.seasonal_residual(tf(d.ffill(x)), np.stack([tf(h) for h in np.moveaxis(hist, 1, 0)], axis=1))


def _bocpd_magnitude(x: np.ndarray, hist: np.ndarray, tf: Callable[[np.ndarray], np.ndarray] | None = None) -> np.ndarray:
    """P(change in last 5 steps) x |mean residual over those steps|: probability times effect size.

    Plain BOCPD answers "did the distribution change?" and benign blips are real
    changes, so its score saturates at 1 and cannot be traded against a page
    budget. Weighting by the size of the shift restores a magnitude axis.
    """
    tf = tf or _transform
    th = np.stack([tf(h) for h in np.moveaxis(hist, 1, 0)], axis=1)
    z = d.seasonal_residual(tf(d.ffill(x)), th)
    p = d.bocpd(d.prewhiten(z, d.seasonal_residual_hist(th)))
    k = np.ones(5) / 5
    zm = np.stack([np.convolve(r, k, mode="full")[: r.size] for r in z])
    return p * np.abs(zm)


def _innovations(x: np.ndarray, hist: np.ndarray, tf: Callable[[np.ndarray], np.ndarray] | None = None) -> np.ndarray:
    tf = tf or _transform
    th = np.stack([tf(h) for h in np.moveaxis(hist, 1, 0)], axis=1)
    z = d.seasonal_residual(tf(d.ffill(x)), th)
    return d.prewhiten(z, d.seasonal_residual_hist(th))


# Each scorer: (today (S,n), history (S,H,n)) -> score (S,n).
Scorer = Callable[[np.ndarray, np.ndarray], np.ndarray]


def _static(x: np.ndarray, _h: np.ndarray) -> np.ndarray:
    return d.static_score(x, STATIC_THR)


SCORERS: dict[str, Scorer] = {
    "static_threshold": _static,
    "ewma_z": lambda x, h: d.ewma_z(_transform(d.ffill(x))),
    "rolling_robust_z": lambda x, h: d.rolling_robust_z(_transform(d.ffill(x))),
    "seasonal_robust_z": lambda x, h: np.abs(_seasonal_z_signed(x, h)),
    "seasonal_cusum_raw": lambda x, h: d.cusum(_seasonal_z_signed(x, h)),
    "seasonal_cusum": lambda x, h: d.cusum(_innovations(x, h)),
    "seasonal_bocpd": lambda x, h: d.bocpd(_innovations(x, h)),
    "seasonal_bocpd_magnitude": lambda x, h: _bocpd_magnitude(x, h),
}


# ---------------------------------------------------------------- week scores
def week_scores(seed: int) -> dict[str, np.ndarray]:
    """Scores on fault-free days H..H+6 (S, 7*DAY), state carried across days."""
    w = ds.week(seed)  # (S, D, DAY)
    H = sim.HISTORY_DAYS
    days = range(H, w.shape[1])
    contiguous = w.reshape(w.shape[0], -1)
    out: dict[str, np.ndarray] = {}
    out["static_threshold"] = d.static_score(contiguous, STATIC_THR)[:, H * sim.DAY :]
    tc = _transform(contiguous)
    out["ewma_z"] = d.ewma_z(tc)[:, H * sim.DAY :]
    rz = np.vstack([d.rolling_robust_z(tc[i : i + 1]) for i in range(tc.shape[0])])
    out["rolling_robust_z"] = rz[:, H * sim.DAY :]
    z = np.concatenate([_seasonal_z_signed(w[:, dd], w[:, dd - H : dd]) for dd in days], axis=1)
    e = np.concatenate([_innovations(w[:, dd], w[:, dd - H : dd]) for dd in days], axis=1)
    out["seasonal_robust_z"] = np.abs(z)
    out["seasonal_cusum_raw"] = d.cusum(z)
    out["seasonal_cusum"] = d.cusum(e)
    out["seasonal_bocpd"] = d.bocpd(e)
    out["seasonal_bocpd_magnitude"] = np.concatenate([_bocpd_magnitude(w[:, dd], w[:, dd - H : dd]) for dd in days], axis=1)
    return out


def fp_per_day(score: np.ndarray, thr: float) -> float:
    n_days = score.shape[1] / sim.DAY
    return float(d.episode_starts(d.alarms(score, thr)).sum() / n_days)


def calibrate(score: np.ndarray, budget: float) -> tuple[float, float]:
    """Smallest threshold with FP/day <= budget (bisection on a monotone-ish curve)."""
    lo, hi = float(np.percentile(score, 50)), float(score.max()) + 1e-9
    if fp_per_day(score, lo) <= budget:
        return lo, fp_per_day(score, lo)
    for _ in range(40):
        mid = (lo + hi) / 2
        if fp_per_day(score, mid) <= budget:
            hi = mid
        else:
            lo = mid
    return hi, fp_per_day(score, hi)


# ---------------------------------------------------------------- incidents
def incident_alarms(name: str, incs: list[sim.Incident], thr: float, cache: dict[str, np.ndarray]) -> np.ndarray:
    """(N, S, n) alarm masks for all incidents, plus absent-target alarms."""
    if name not in cache:
        xs, hs = zip(*(ds.stack(i) for i in incs))
        X, Hh = np.concatenate(xs), np.concatenate(hs)  # (N*S, n), (N*S, H, n)
        if name == "static_threshold":
            sc = np.vstack([_static(x, h) for x, h in zip(xs, hs)])
        else:
            # vectorise across incidents; the scorers are per-row independent
            S = len(ds.SERIES)
            parts = []
            for k in range(0, X.shape[0], S * 50):
                xk, hk = X[k : k + S * 50], Hh[k : k + S * 50]
                parts.append(_score_rows(name, xk, hk))
            sc = np.vstack(parts)
        cache[name] = sc.reshape(len(incs), len(ds.SERIES), -1)
    sc = cache[name]
    N, S, n = sc.shape
    a = d.alarms(sc.reshape(N * S, n), thr).reshape(N, S, n)
    absent = np.stack([np.isnan(ds.stack(i)[0]) for i in incs])
    a |= d.alarms(absent.reshape(N * S, n).astype(float), 0.5).reshape(N, S, n)
    return a


def _score_rows(name: str, x: np.ndarray, h: np.ndarray) -> np.ndarray:
    # METRIC_OF repeats every len(SERIES) rows; build a matching transform
    reps = x.shape[0] // len(ds.SERIES)
    metrics = METRIC_OF * reps

    def tf(a: np.ndarray) -> np.ndarray:
        out = np.empty_like(a)
        for i, m in enumerate(metrics):
            out[i] = d.transform(m, a[i])
        return out

    if name == "ewma_z":
        return d.ewma_z(tf(d.ffill(x)))
    if name == "rolling_robust_z":
        return d.rolling_robust_z(tf(d.ffill(x)))
    if name == "seasonal_robust_z":
        return np.abs(_seasonal_z_signed(x, h, tf))
    if name == "seasonal_cusum_raw":
        return d.cusum(_seasonal_z_signed(x, h, tf))
    if name == "seasonal_cusum":
        return d.cusum(_innovations(x, h, tf))
    if name == "seasonal_bocpd":
        return d.bocpd(_innovations(x, h, tf))
    if name == "seasonal_bocpd_magnitude":
        return _bocpd_magnitude(x, h, tf)
    raise KeyError(name)


def summarise(alarm: np.ndarray, incs: list[sim.Incident]) -> dict[str, Any]:
    delays: list[float] = []
    hit10, hit30, pre_fp, pre_hours = [], [], 0, 0.0
    root_hit: list[bool] = []
    per_ft: dict[str, list[bool]] = defaultdict(list)
    for a, inc in zip(alarm, incs):
        any_alarm = a.any(axis=0)
        post = np.flatnonzero(any_alarm[inc.t0 : inc.t0 + 60])
        delay = float(post[0]) * STEP_MIN if post.size else float("inf")
        delays.append(delay)
        hit10.append(delay <= 10)
        hit30.append(delay <= 30)
        per_ft[inc.fault_type].append(delay <= 10)
        root_rows = [k for k, (sv, _) in enumerate(ds.SERIES) if sv == inc.root]
        root_post = np.flatnonzero(a[root_rows].any(axis=0)[inc.t0 : inc.t0 + 20])
        root_hit.append(root_post.size > 0)
        starts = d.episode_starts(a)[:, WARM : inc.t0]
        pre_fp += int(starts.sum())
        pre_hours += (inc.t0 - WARM) * STEP_MIN / 60
    det = np.array([x for x in delays if np.isfinite(x)])
    return {
        "recall_10min": stats.bootstrap_ci(np.array(hit10, float)).as_dict(),
        "recall_30min": stats.bootstrap_ci(np.array(hit30, float)).as_dict(),
        "root_recall_10min": stats.bootstrap_ci(np.array(root_hit, float)).as_dict(),
        "delay_median_min": stats.bootstrap_ci(det, stats.median).as_dict() if det.size else None,
        "delay_p90_min": float(np.percentile(det, 90)) if det.size else None,
        "prefault_false_pages_per_hour": pre_fp / pre_hours,
        "recall_10min_by_fault": {k: float(np.mean(v)) for k, v in sorted(per_ft.items())},
        "hits_10min": [bool(x) for x in hit10],
        "root_hits_10min": [bool(x) for x in root_hit],
    }


def main(out_dir: Path) -> dict[str, Any]:
    t_start = time.time()
    test = ds.incidents(ds.TEST_SEEDS)
    dev_w, test_w = week_scores(ds.DEV_WEEK_SEED), week_scores(ds.TEST_WEEK_SEED)
    cache: dict[str, np.ndarray] = {}
    results: dict[str, Any] = {}
    for name in SCORERS:
        thr, dev_fp = calibrate(dev_w[name], BUDGET)
        r = summarise(incident_alarms(name, test, thr, cache), test)
        r.update({"threshold": thr, "fp_per_day_dev_week": dev_fp, "fp_per_day_test_week": fp_per_day(test_w[name], thr)})
        results[name] = r
        print(f"{name:20s} thr={thr:8.3f} fp/day dev={dev_fp:.2f} test={r['fp_per_day_test_week']:.2f} "
              f"recall@10m={r['recall_10min']['estimate']:.3f} root@10m={r['root_recall_10min']['estimate']:.3f} med_delay={r['delay_median_min'] and r['delay_median_min']['estimate']}",
              file=sys.stderr)
    # The deployed rules exactly as written (threshold x1, real coverage).
    asw = incident_alarms("static_threshold", test, 1.0, cache)
    asw &= DEPLOYED[None, :, None] | np.stack([np.isnan(ds.stack(i)[0]) for i in test])
    r = summarise(asw, test)
    sc_t = test_w["static_threshold"] * DEPLOYED[:, None]
    r.update({"threshold": 1.0, "fp_per_day_dev_week": fp_per_day(dev_w["static_threshold"] * DEPLOYED[:, None], 1.0),
              "fp_per_day_test_week": fp_per_day(sc_t, 1.0)})
    results["static_as_deployed"] = r
    # Recall vs false-alarm curve on TEST (for the README plot); thresholds swept.
    curves: dict[str, list[dict[str, float]]] = {}
    for name in SCORERS:
        pts = []
        for f in np.geomspace(0.6, 2.5, 12):
            thr = float(results[name]["threshold"] * f)
            a = incident_alarms(name, test, thr, cache)
            hits = np.mean([(a_.any(axis=0)[i.t0 : i.t0 + 20]).any() for a_, i in zip(a, test)])
            pts.append({"threshold": thr, "fp_per_day": fp_per_day(test_w[name], thr), "recall_10min": float(hits)})
        curves[name] = sorted(pts, key=lambda p: p["fp_per_day"])
    # Paired tests on recall@10min vs the calibrated static baseline.
    base = results["static_threshold"]["root_hits_10min"]
    comps = {n: stats.paired_compare(base, results[n]["root_hits_10min"]) for n in SCORERS if n != "static_threshold"}
    adj = stats.holm({n: c.p_mcnemar_exact for n, c in comps.items()})
    out = {
        "protocol": {"budget_pages_per_day": BUDGET, "series": len(ds.SERIES), "test_incidents": len(test),
                     "dev_week_seed": ds.DEV_WEEK_SEED, "test_week_seed": ds.TEST_WEEK_SEED,
                     "generator_version": sim.GENERATOR_VERSION},
        "detectors": results,
        "paired_root_recall_vs_static_calibrated": {n: {**c.as_dict(), "p_holm": adj[n]} for n, c in comps.items()},
        "curves_test": curves,
        "runtime_s": time.time() - t_start,
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "detection.json").write_text(json.dumps(out, indent=1))
    return out


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else Path("eval/results/latest"))
