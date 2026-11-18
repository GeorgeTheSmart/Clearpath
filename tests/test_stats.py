import numpy as np

from eval import stats


def test_mcnemar_exact_known_values():
    # n=10 discordant, split 9/1: p = 2*P(X<=1) = 2*(11/1024)
    assert abs(stats.mcnemar_exact(9, 1) - 22 / 1024) < 1e-12
    assert stats.mcnemar_exact(5, 5) == 1.0
    assert stats.mcnemar_exact(0, 0) == 1.0


def test_bootstrap_ci_covers_true_mean_about_95pct():
    rng = np.random.default_rng(0)
    hits = 0
    for s in range(200):
        x = rng.binomial(1, 0.3, 200).astype(float)
        ci = stats.bootstrap_ci(x, stats.mean, b=2000, seed=s)
        hits += ci.lo <= 0.3 <= ci.hi
    assert 0.90 <= hits / 200 <= 0.99


def test_paired_compare_detects_real_difference_only():
    rng = np.random.default_rng(1)
    a = rng.random(300) < 0.6
    b = a | (rng.random(300) < 0.3)  # b strictly dominates a
    r = stats.paired_compare(a, b, b=2000)
    assert r.a_only == 0 and r.b_only > 0 and r.p_mcnemar_exact < 1e-6 and r.diff.lo > 0
    same = stats.paired_compare(a, a, b=2000)
    assert same.p_mcnemar_exact == 1.0 and same.diff.estimate == 0


def test_holm_is_monotone_and_bounded():
    adj = stats.holm({"x": 0.01, "y": 0.04, "z": 0.03})
    assert adj["x"] == 0.03 and adj["z"] == 0.06 and adj["y"] == 0.06
