import numpy as np

from detect import detectors as d


def test_ffill_handles_leading_and_inner_nans():
    x = np.array([[np.nan, 1.0, np.nan, 3.0, np.nan]])
    assert d.ffill(x).tolist() == [[0.0, 1.0, 1.0, 3.0, 3.0]]


def test_robust_z_ignores_single_outlier_in_baseline():
    rng = np.random.default_rng(0)
    x = rng.normal(0, 1, (1, 200))
    y = x.copy()
    y[0, 100] = 1e6  # a wild point inside the trailing window
    zx, zy = d.rolling_robust_z(x, 60), d.rolling_robust_z(y, 60)
    # the scores after the outlier barely move (median/MAD breakdown point)
    assert np.max(np.abs(zx[0, 101:160] - zy[0, 101:160])) < 0.5


def test_ewma_is_not_robust_to_outlier():
    rng = np.random.default_rng(0)
    x = rng.normal(0, 1, (1, 200))
    y = x.copy()
    y[0, 100] = 1e3
    assert np.max(np.abs(d.ewma_z(x)[0, 101:] - d.ewma_z(y)[0, 101:])) > 0.5


def test_seasonal_residual_removes_daily_pattern():
    rng = np.random.default_rng(1)
    t = np.arange(240)
    pattern = 5 * np.sin(t / 20)
    hist = (pattern + rng.normal(0, 0.1, (3, 240)))[None]
    today = (pattern + rng.normal(0, 0.1, 240))[None]
    r = d.seasonal_residual(today, hist)
    assert np.median(np.abs(r)) < 2.0  # in sigma units, pattern gone
    assert np.std(today) > 3  # while the raw series varies a lot


def test_cusum_in_control_run_length_matches_theory():
    # Two-sided CUSUM, k=0.5, h=5: in-control ARL ~ 465 steps (one-sided ~930).
    rng = np.random.default_rng(2)
    z = rng.normal(0, 1, (400, 4000))
    s = d.cusum(z, k=0.5)
    first = np.array([np.argmax(r >= 5) if (r >= 5).any() else 4000 for r in s])
    arl = first.mean()
    assert 300 < arl < 650, arl


def test_cusum_beats_point_threshold_on_small_shift():
    rng = np.random.default_rng(3)
    z = rng.normal(0, 1, (500, 300))
    z[:, 150:] += 1.0  # a 1-sigma sustained shift
    first_cusum = np.argmax(d.cusum(z) >= 5, axis=1)
    point = np.abs(z) >= 3.5
    first_point = np.array([np.argmax(r[150:]) + 150 if r[150:].any() else 300 for r in point])
    assert np.median(first_cusum - 150) < np.median(first_point - 150)


def test_bocpd_localises_mean_shift():
    rng = np.random.default_rng(4)
    z = rng.normal(0, 1, (50, 200))
    z[:, 100:] += 3
    p = d.bocpd(z, recent=5)
    peak = np.argmax(p[:, 95:130], axis=1) + 95
    assert np.median(np.abs(peak - 100)) <= 4
    assert np.median(p[:, 20:95]) < 0.2


def test_alarm_requires_min_run_and_episodes_debounce():
    s = np.array([[0, 5, 0, 5, 5, 5, 0, 0, 5, 5, 0] + [0] * 20 + [5, 5]], dtype=float)
    a = d.alarms(s, 1.0)
    assert a[0].tolist()[:11] == [False, False, False, False, True, True, False, False, False, True, False]
    starts = np.flatnonzero(d.episode_starts(a)[0]).tolist()
    assert starts == [4, 32]
