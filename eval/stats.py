"""Statistics used by every evaluation: bootstrap CIs and paired tests.

Kept dependency-light (numpy + scipy.stats.binom) and tested in
tests/test_stats.py against known values.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass

import numpy as np
from numpy.typing import NDArray
from scipy.stats import binom

B_DEFAULT = 10_000


@dataclass(frozen=True)
class CI:
    estimate: float
    lo: float
    hi: float

    def fmt(self, pct: bool = True, digits: int = 1) -> str:
        if pct:
            return f"{100 * self.estimate:.{digits}f}% [{100 * self.lo:.{digits}f}, {100 * self.hi:.{digits}f}]"
        return f"{self.estimate:.{digits}f} [{self.lo:.{digits}f}, {self.hi:.{digits}f}]"

    def as_dict(self) -> dict[str, float]:
        return {"estimate": self.estimate, "ci95_lo": self.lo, "ci95_hi": self.hi}


def mean(a: NDArray[np.float64]) -> float:
    return float(np.mean(a))


def median(a: NDArray[np.float64]) -> float:
    return float(np.median(a))


def bootstrap_ci(
    x: Sequence[float] | NDArray[np.float64],
    stat: Callable[[NDArray[np.float64]], float] = mean,
    b: int = B_DEFAULT,
    seed: int = 0,
) -> CI:
    """Percentile bootstrap over units (incidents): resample with replacement."""
    a = np.asarray(x, dtype=float)
    if a.size == 0:
        return CI(float("nan"), float("nan"), float("nan"))
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, a.size, size=(b, a.size))
    samples = a[idx]
    if stat is mean:
        boots = samples.mean(axis=1)
    elif stat is median:
        boots = np.median(samples, axis=1)
    else:
        boots = np.array([stat(s) for s in samples])
    lo, hi = np.percentile(boots, [2.5, 97.5])
    return CI(float(stat(a)), float(lo), float(hi))


@dataclass(frozen=True)
class Paired:
    acc_a: float
    acc_b: float
    diff: CI  # acc_b - acc_a with paired-bootstrap CI
    b_only: int  # B correct, A wrong
    a_only: int  # A correct, B wrong
    p_mcnemar_exact: float
    odds_ratio: float  # b_only / a_only (discordant-pair odds ratio)

    def as_dict(self) -> dict[str, float]:
        return {
            "acc_a": self.acc_a,
            "acc_b": self.acc_b,
            "diff": self.diff.estimate,
            "diff_ci95_lo": self.diff.lo,
            "diff_ci95_hi": self.diff.hi,
            "b_only": self.b_only,
            "a_only": self.a_only,
            "p_mcnemar_exact": self.p_mcnemar_exact,
            "discordant_odds_ratio": self.odds_ratio,
        }


def mcnemar_exact(b_only: int, a_only: int) -> float:
    """Two-sided exact McNemar test: under H0 discordant pairs are Bin(n, 1/2)."""
    n = b_only + a_only
    if n == 0:
        return 1.0
    k = min(b_only, a_only)
    return float(min(1.0, 2 * binom.cdf(k, n, 0.5)))


def paired_compare(correct_a: Sequence[bool], correct_b: Sequence[bool], b: int = B_DEFAULT, seed: int = 0) -> Paired:
    """Is system B better than A on the *same* incidents?

    McNemar uses only discordant pairs, which is the right test for paired
    binary outcomes; the paired bootstrap on the per-incident difference gives an
    effect size (accuracy difference) with a CI.
    """
    ca = np.asarray(correct_a, dtype=float)
    cb = np.asarray(correct_b, dtype=float)
    assert ca.shape == cb.shape
    b_only = int(((cb == 1) & (ca == 0)).sum())
    a_only = int(((ca == 1) & (cb == 0)).sum())
    diff = bootstrap_ci(cb - ca, mean, b=b, seed=seed)
    orr = (b_only + 0.5) / (a_only + 0.5)  # Haldane correction
    return Paired(float(ca.mean()), float(cb.mean()), diff, b_only, a_only, mcnemar_exact(b_only, a_only), orr)


def holm(pvals: dict[str, float]) -> dict[str, float]:
    """Holm-Bonferroni adjusted p-values (we run several comparisons)."""
    items = sorted(pvals.items(), key=lambda kv: kv[1])
    m = len(items)
    out: dict[str, float] = {}
    running = 0.0
    for i, (k, p) in enumerate(items):
        running = max(running, min(1.0, (m - i) * p))
        out[k] = running
    return out
