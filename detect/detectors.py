"""Anomaly and change-point detectors, implemented from first principles.

All functions take arrays shaped (S, n): S independent series of n steps, and
return a non-negative score of the same shape. Larger = more anomalous. The
alarm rule (score >= threshold for MIN_RUN consecutive steps) is shared by all
detectors so that comparisons isolate the scoring method.

Plain-language notes on each method are in docs/DESIGN.md#detection.
"""

from __future__ import annotations

import numpy as np
from numpy.typing import NDArray

Arr = NDArray[np.float64]
MAD_TO_SIGMA = 1.4826  # MAD of a standard normal is 1/1.4826


def transform(metric: str, x: Arr) -> Arr:
    """Variance-stabilise: latency and error rate are multiplicative/skewed."""
    if metric == "latency_ms":
        return np.log(np.maximum(x, 1e-3))
    if metric == "error_rate":
        return np.log(x + 0.005)
    return x


def ffill(x: Arr) -> Arr:
    """Forward-fill NaNs (missing scrapes) along the last axis."""
    out = x.copy()
    mask = np.isnan(out)
    if not mask.any():
        return out
    idx = np.where(~mask, np.arange(out.shape[-1]), 0)
    np.maximum.accumulate(idx, axis=-1, out=idx)
    out = np.take_along_axis(out, idx, axis=-1)
    return np.nan_to_num(out, nan=0.0)


# ---------------------------------------------------------------- scorers
def static_score(x: Arr, thr: Arr) -> Arr:
    """Ratio to a fixed threshold (alarm when >= 1 * multiplier). One-sided."""
    return np.nan_to_num(x, nan=0.0) / thr[:, None]


def ewma_z(x: Arr, lam: float = 0.1, warm: int = 60, sigma_floor: float = 1e-3) -> Arr:
    """|x_t - m_{t-1}| / s_{t-1} with exponentially weighted mean and variance.

    Assumes local stationarity on the ~1/lam time scale. Fails on seasonality
    faster than that and adapts to slow drifts (e.g. memory leaks) - by design.
    """
    S, n = x.shape
    m = x[:, :warm].mean(axis=1)
    v = x[:, :warm].var(axis=1) + sigma_floor**2
    out = np.zeros_like(x)
    for t in range(warm, n):
        z = (x[:, t] - m) / np.sqrt(v)
        out[:, t] = np.abs(z)
        d = x[:, t] - m
        m = m + lam * d
        v = (1 - lam) * (v + lam * d * d)
        v = np.maximum(v, sigma_floor**2)
    return out


def rolling_robust_z(x: Arr, win: int = 60, sigma_floor: float = 1e-3) -> Arr:
    """|x_t - median(trailing win)| / (1.4826 * MAD(trailing win)).

    Median/MAD have a 50% breakdown point, so a few outliers in the trailing
    window do not move the baseline - unlike the mean/variance in EWMA.
    """
    S, n = x.shape
    out = np.zeros_like(x)
    if n <= win:
        return out
    from numpy.lib.stride_tricks import sliding_window_view

    w = sliding_window_view(x, win, axis=1)[:, :-1, :]  # windows ending at t-1
    med = np.median(w, axis=2)
    mad = np.median(np.abs(w - med[:, :, None]), axis=2) * MAD_TO_SIGMA
    out[:, win:] = np.abs(x[:, win:] - med) / np.maximum(mad, sigma_floor)
    return out


def seasonal_residual(x: Arr, hist: Arr, sigma_floor: float = 1e-3, smooth: int = 5) -> Arr:
    """Signed robust z of x against a same-time-of-day baseline.

    hist: (S, H, n) - the same window on H previous days. The baseline is the
    per-step median over days (smoothed over `smooth` steps); the scale is the
    MAD of all historical residuals in the window, so one bad day cannot
    dominate. This is a seasonal-naive baseline: STL would add a trend term,
    which we do not need over a 3-day horizon (see DESIGN.md).
    """
    base = np.median(hist, axis=1)
    if smooth > 1:
        k = np.ones(smooth) / smooth
        pad = smooth // 2
        bp = np.pad(base, ((0, 0), (pad, pad)), mode="edge")
        base = np.stack([np.convolve(b, k, mode="valid") for b in bp])
    resid_hist = hist - base[:, None, :]
    med_r = np.median(resid_hist.reshape(hist.shape[0], -1), axis=1)
    scale = np.median(np.abs(resid_hist.reshape(hist.shape[0], -1) - med_r[:, None]), axis=1) * MAD_TO_SIGMA
    return (x - base - med_r[:, None]) / np.maximum(scale, sigma_floor)[:, None]


def seasonal_z(x: Arr, hist: Arr) -> Arr:
    return np.abs(seasonal_residual(x, hist))


def prewhiten(z: Arr, z_hist: Arr, sigma_floor: float = 1e-3) -> Arr:
    """One-step-ahead AR(1) forecast errors of z, robustly standardised.

    CUSUM and BOCPD assume independent observations. Metric residuals are
    autocorrelated (a slow GC cycle, queueing), so evidence accumulates on
    fault-free data. Fit phi on history residuals (lag-1 autocorrelation),
    then e_t = z_t - phi * z_{t-1}. Cost: a sustained shift of size D shows up as
    D at onset and (1 - phi) * D afterwards, so slow ramps get harder to see.
    """
    a, b = z_hist[..., 1:], z_hist[..., :-1]
    a = a - a.mean(axis=-1, keepdims=True)
    b = b - b.mean(axis=-1, keepdims=True)
    phi = (a * b).sum(axis=(-2, -1)) / np.maximum((b * b).sum(axis=(-2, -1)), 1e-12)
    phi = np.clip(phi, 0.0, 0.98)
    e_hist = z_hist[..., 1:] - phi[:, None, None] * z_hist[..., :-1]
    flat = e_hist.reshape(e_hist.shape[0], -1)
    med = np.median(flat, axis=1)
    scale = np.median(np.abs(flat - med[:, None]), axis=1) * MAD_TO_SIGMA
    e = np.empty_like(z)
    e[:, 0] = z[:, 0]
    e[:, 1:] = z[:, 1:] - phi[:, None] * z[:, :-1]
    return (e - med[:, None]) / np.maximum(scale, sigma_floor)[:, None]


def seasonal_residual_hist(hist: Arr, sigma_floor: float = 1e-3) -> Arr:
    """Leave-one-day-out seasonal residuals of the history itself (S, H, n)."""
    H = hist.shape[1]
    out = np.empty_like(hist)
    for j in range(H):
        others = np.delete(hist, j, axis=1)
        out[:, j] = seasonal_residual(hist[:, j], others, sigma_floor)
    return out


def cusum(z: Arr, k: float = 0.5, clip: float = 8.0) -> Arr:
    """Two-sided tabular CUSUM on standardised residuals z.

    S+_t = max(0, S+_{t-1} + z_t - k),  S-_t = max(0, S-_{t-1} - z_t - k).
    k = half the shift (in sigmas) we want to detect fastest; with k = 0.5 it
    is tuned for 1-sigma shifts. Accumulating small evidence makes it much
    faster than a point threshold on sustained small shifts. z is clipped so a
    single wild point cannot trigger it alone (robustness to spikes).
    """
    zc = np.clip(z, -clip, clip)
    sp = np.zeros(z.shape[0])
    sn = np.zeros(z.shape[0])
    out = np.zeros_like(z)
    for t in range(z.shape[1]):
        sp = np.maximum(0.0, sp + zc[:, t] - k)
        sn = np.maximum(0.0, sn - zc[:, t] - k)
        out[:, t] = np.maximum(sp, sn)
    return out


def bocpd(z: Arr, hazard: float = 1 / 250, rmax: int = 300, recent: int = 5, clip: float = 8.0) -> Arr:
    """Bayesian online change-point detection (Adams & MacKay, 2007).

    Model: within a segment z ~ N(mu, sigma^2) with a Normal-Inverse-Gamma
    prior, so the predictive is Student-t. A constant hazard H gives a
    geometric prior on segment length (mean 1/H steps). We maintain the
    posterior over run length r_t and score P(r_t < recent | z_1..t): the
    probability that a change happened in the last `recent` steps.

    Run length is truncated at rmax (mass beyond it is folded into rmax), which
    keeps it O(n * rmax) per series.
    """
    from scipy.special import gammaln

    S, n = z.shape
    z = np.clip(z, -clip, clip)
    mu0, kappa0, alpha0, beta0 = 0.0, 1.0, 1.0, 1.0
    R = rmax + 1
    logp = np.full((S, R), -np.inf)
    logp[:, 0] = 0.0
    mu = np.full((S, R), mu0)
    kappa = np.full((S, R), kappa0)
    alpha = np.full((S, R), alpha0)
    beta = np.full((S, R), beta0)
    out = np.zeros_like(z)
    lh, l1h = np.log(hazard), np.log1p(-hazard)
    for t in range(n):
        x = z[:, t][:, None]
        # Student-t predictive for each run length
        nu = 2 * alpha
        scale2 = beta * (kappa + 1) / (alpha * kappa)
        lpred = gammaln((nu + 1) / 2) - gammaln(nu / 2) - 0.5 * np.log(np.pi * nu * scale2) - (nu + 1) / 2 * np.log1p((x - mu) ** 2 / (nu * scale2))
        a = logp + lpred
        grow = a + l1h
        cp = np.logaddexp.reduce(a + lh, axis=1)
        new = np.full_like(logp, -np.inf)
        new[:, 0] = cp
        new[:, 1:] = grow[:, :-1]
        new[:, -1] = np.logaddexp(new[:, -1], grow[:, -1])  # fold truncated mass
        new -= np.logaddexp.reduce(new, axis=1, keepdims=True)
        logp = new
        # posterior parameter updates (shift by one run length, reset r=0 to prior)
        mu_n = (kappa * mu + x) / (kappa + 1)
        kappa_n = kappa + 1
        alpha_n = alpha + 0.5
        beta_n = beta + kappa * (x - mu) ** 2 / (2 * (kappa + 1))
        mu = np.concatenate([np.full((S, 1), mu0), mu_n[:, :-1]], axis=1)
        kappa = np.concatenate([np.full((S, 1), kappa0), kappa_n[:, :-1]], axis=1)
        alpha = np.concatenate([np.full((S, 1), alpha0), alpha_n[:, :-1]], axis=1)
        beta = np.concatenate([np.full((S, 1), beta0), beta_n[:, :-1]], axis=1)
        out[:, t] = np.exp(logp[:, :recent]).sum(axis=1)
    return out


# ---------------------------------------------------------------- alarms
MIN_RUN = 2  # like Prometheus `for: 1m` at 30 s steps
MERGE_GAP = 10  # alarms within 5 min are one episode (one page)


def _rolling_sum(a: NDArray[np.int32], w: int) -> NDArray[np.int32]:
    """Sum of a[t-w+1..t] along the last axis (zero-padded at the start)."""
    c = np.cumsum(a, axis=-1, dtype=np.int32)
    out = c.copy()
    out[..., w:] = c[..., w:] - c[..., :-w]
    return out


def alarms(score: Arr, thr: float) -> NDArray[np.bool_]:
    """score >= thr for MIN_RUN consecutive steps."""
    above = (score >= thr).astype(np.int32)
    return _rolling_sum(above, MIN_RUN) >= MIN_RUN


def episode_starts(alarm: NDArray[np.bool_]) -> NDArray[np.bool_]:
    """True where an alarm begins with no other alarm in the previous MERGE_GAP steps."""
    a = alarm.astype(np.int32)
    prev = np.zeros_like(a)
    prev[..., 1:] = a[..., :-1]
    return alarm & (_rolling_sum(prev, MERGE_GAP) == 0)
