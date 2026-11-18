# Clearpath evaluation report

Generated 2026-11-18T08:56:20Z from `eval/results/latest`. Dataset: 300 held-out TEST incidents (seeded simulator (faults/sim.py), not a live cluster, generator v1). Brackets are 95% bootstrap CIs (10,000 resamples over incidents).

## 1. Detection (equal false-alarm budget: 3 pages/day fleet-wide)

| Detector | FP/day (test week) | Root service detected ≤10 min | Any alarm ≤10 min | Median delay (min) | p90 delay |
|---|---|---|---|---|---|
| static_threshold | 3.57 | 89.3% [85.7, 92.7] | 89.7% [86.0, 93.0] | 0.5 [0.5, 0.5] | 10.5 |
| ewma_z | 1.00 | 66.7% [61.3, 72.0] | 68.3% [63.0, 73.7] | 0.5 [0.5, 0.5] | 0.5 |
| rolling_robust_z | 3.57 | 99.7% [99.0, 100.0] | 99.7% [99.0, 100.0] | 0.5 [0.5, 0.5] | 2.0 |
| seasonal_robust_z | 2.71 | 100.0% [100.0, 100.0] | 100.0% [100.0, 100.0] | 0.5 [0.5, 0.5] | 2.5 |
| seasonal_cusum_raw | 2.00 | 8.3% [5.3, 11.7] | 14.0% [10.3, 18.0] | 15.5 [15.5, 15.5] | 16.0 |
| seasonal_cusum | 2.14 | 100.0% [100.0, 100.0] | 100.0% [100.0, 100.0] | 1.5 [1.5, 1.5] | 2.0 |
| seasonal_bocpd | 0.00 | 7.7% [4.7, 10.7] | 7.7% [4.7, 10.7] | 0.5 [0.5, 0.5] | 0.5 |
| seasonal_bocpd_magnitude | 2.71 | 88.0% [84.3, 91.7] | 88.7% [85.0, 92.0] | 0.5 [0.5, 0.5] | 10.25 |
| static_as_deployed | 1.86 | 55.3% [49.7, 61.0] | 81.3% [76.7, 85.7] | 0.5 [0.5, 0.5] | 12.650000000000006 |

Paired vs calibrated static thresholds (root detected ≤10 min, exact McNemar, Holm-adjusted):

| Detector | Δ (pp) [95% CI] | wins/losses | p (Holm) |
|---|---|---|---|
| ewma_z | -22.7 [-28.3, -17.0] | 10/78 | 1.7e-13 |
| rolling_robust_z | +10.3 [+7.0, +14.0] | 31/0 | 1.9e-09 |
| seasonal_robust_z | +10.7 [+7.3, +14.3] | 32/0 | 1.9e-09 |
| seasonal_cusum_raw | -81.0 [-85.3, -76.3] | 1/244 | 5.2e-71 |
| seasonal_cusum | +10.7 [+7.3, +14.3] | 32/0 | 1.9e-09 |
| seasonal_bocpd | -81.7 [-86.0, -77.0] | 0/245 | 2.5e-73 |
| seasonal_bocpd_magnitude | -1.3 [-3.0, +0.0] | 1/5 | 0.219 |

## 2. Root-cause localization

Parameters tuned on DEV only: `{'alpha': 0.7, 'rho': 0.0, 'gamma': 0.0, 'use_corr': True, 'use_self': True, 'personalise': True}`.

| Method | Top-1 | Top-3 | Mean rank |
|---|---|---|---|
| random | 6.0% [3.3, 8.7] | 26.3% [21.3, 31.3] | 6.26 [5.90, 6.61] |
| most_alerting | 55.0% [49.3, 60.7] | 74.0% [69.0, 79.0] | 3.04 [2.70, 3.41] |
| most_anomalous | 71.3% [66.0, 76.3] | 98.3% [96.7, 99.7] | 1.38 [1.31, 1.46] |
| downstream_most_anomalous | 98.3% [96.7, 99.7] | 100.0% [100.0, 100.0] | 1.02 [1.00, 1.03] |
| ppr_full | 99.3% [98.3, 100.0] | 100.0% [100.0, 100.0] | 1.01 [1.00, 1.02] |
| ablate_no_corr | 97.0% [95.0, 98.7] | 100.0% [100.0, 100.0] | 1.03 [1.01, 1.06] |
| ablate_no_self_loop | 98.0% [96.3, 99.3] | 100.0% [100.0, 100.0] | 1.02 [1.01, 1.04] |
| ablate_no_personalisation | 79.7% [75.0, 84.0] | 87.3% [83.3, 91.0] | 2.05 [1.78, 2.35] |
| ablate_pure_pagerank_gamma0 | 99.3% [98.3, 100.0] | 100.0% [100.0, 100.0] | 1.01 [1.00, 1.02] |

| Comparison (PPR minus baseline) | Δ (pp) [95% CI] | wins/losses | p (Holm) |
|---|---|---|---|
| ppr_full_vs_most_alerting_top1 | +44.3 [+38.7, +50.0] | 134/1 | 3.7e-38 |
| ppr_full_vs_most_alerting_top3 | +26.0 [+21.0, +31.0] | 78/0 | 2.6e-23 |
| ppr_full_vs_most_anomalous_top1 | +28.0 [+22.7, +33.3] | 85/1 | 1.1e-23 |
| ppr_full_vs_most_anomalous_top3 | +1.7 [+0.3, +3.3] | 5/0 | 0.188 |
| ppr_full_vs_downstream_most_anomalous_top1 | +1.0 [-0.3, +2.7] | 4/1 | 0.750 |
| ppr_full_vs_downstream_most_anomalous_top3 | +0.0 [+0.0, +0.0] | 0/0 | 1.000 |
| ppr_full_vs_random_top1 | +93.3 [+90.3, +96.0] | 281/1 | 5.8e-82 |
| ppr_full_vs_random_top3 | +73.7 [+68.7, +78.7] | 221/0 | 4.2e-66 |

Robustness (TEST, no retuning), top-1:

| Perturbation | most_anomalous | downstream_most_anomalous | ppr_full | ppr no corr | PPR − downstream (pp) |
|---|---|---|---|---|---|
| drop_edges | 71.3% [66.0, 76.3] | 91.7% [88.3, 94.7] | 93.0% [90.0, 95.7] | 95.0% [92.3, 97.3] | +1.3 [-1.0, +3.7], p=0.424 |
| concurrent_anomaly | 71.3% [66.0, 76.3] | 86.3% [82.3, 90.0] | 86.7% [82.7, 90.3] | 77.7% [72.7, 82.3] | +0.3 [-2.3, +3.0], p=1.000 |
| downstream_confounder | 71.3% [66.0, 76.3] | 64.7% [59.3, 70.0] | 67.7% [62.3, 73.0] | 62.7% [57.3, 68.0] | +3.0 [+0.7, +5.7], p=0.035 |

## 3. End-to-end systems

| System | Root top-1 | Fault-type acc. | Hallucination rate |
|---|---|---|---|
| a_static_most_alerting | 55.0% [49.3, 60.7] | 27.7% [22.7, 32.7] | n/a |
| b_localizer | 99.3% [98.3, 100.0] | 24.3% [19.7, 29.0] | n/a |
| b_plus_localizer_rag_no_llm | 99.3% [98.3, 100.0] | 92.7% [89.7, 95.3] | 0.0% [0.0, 0.0] |
| c_llm_no_rag | not run: no LLM configured in this environment (set CLEARPATH_LLM) | | |
| d_llm_rag | not run: no LLM configured in this environment (set CLEARPATH_LLM) | | |
| e_full | not run: no LLM configured in this environment (set CLEARPATH_LLM) | | |

| Paired comparison | Δ (pp) [95% CI] | wins/losses | p (exact McNemar) |
|---|---|---|---|
| fault_type_bplus_vs_a | +65.0 [+59.3, +70.7] | 198/3 | 8.4e-55 |
| fault_type_bplus_vs_b | +68.3 [+63.0, +73.7] | 206/1 | 2.0e-60 |
| root_top1_b_vs_a | +44.3 [+38.7, +50.0] | 134/1 | 6.2e-39 |

Runbook retrieval (query = sanitized context of the top suspect):

| Mode | Recall@1 | Recall@3 |
|---|---|---|
| bm25 | 92.0% [88.7, 95.0] | 99.0% [97.7, 100.0] |
| dense | 93.7% [91.0, 96.3] | 99.3% [98.3, 100.0] |
| hybrid | 92.7% [89.7, 95.3] | 99.3% [98.3, 100.0] |

## 4. Guardrails

* PII: 6580 planted values in TEST logs; leak rate after redaction **0.00%** (by kind: card 0.0%, phone 0.0%, email 0.0%); over-redaction on PII-free lines 0.05%.
* Simulator-injected adversarial log lines quarantined: 100.0% of 165; benign lines falsely quarantined: 0.001% of 86302.

| Red-team set | Attacks | Filter block rate | Hard negatives falsely blocked |
|---|---|---|---|
| payloads | 40 | 97.5% [92.5, 100.0] | 0.0% of 25 |
| payloads_heldout | 30 | 100.0% [100.0, 100.0] | 0.0% of 20 |

Action policy fuzz: 0 of 20,000 random action proposals outside the policy were accepted.
End-to-end attack success rate with/without guardrails needs an LLM: **not run** (no LLM configured).

## 5. Time to ticket and cost

* Scope: pipeline only: incident received -> ServiceNow incident created on the local mock over HTTP; no LLM; excludes detection delay and correlator window.
* Median 11.9 [11.6, 12.2] ms, p95 17.0 ms. Per-node medians (ms): ingest 0.73, gather_context 2.77, sanitize 2.36, retrieve 0.96, diagnose 0.10, open_ticket 5.15, await_approval 0.74.
* Cost per incident: no-LLM path 0 tokens; LLM: not run.

## 6. Correlator benchmark (go1.24.7, 2 CPUs, window 5m, lateness 30s)

| Scenario | Alerts | Throughput (alerts/s) | p50 / p99 / p99.9 (µs) | Peak heap (MB)* | Incidents | Largest incident share | Conserved |
|---|---|---|---|---|---|---|---|
| storm_10k_per_min_200svc | 1,000,000 | 1,313,544 | 0.50 / 2.40 / 20.1 | 115 | 667 | 0.022 | True |
| storm_1M_per_min_1000svc | 2,000,000 | 1,005,972 | 0.68 / 3.74 / 15.1 | 270 | 73 | 0.895 | True |
| noise_sweep_nu0_wc300s | 300,000 | 1,327,696 | 0.49 / 2.33 / 17.4 | 39 | 77 | 0.062 | True |
| noise_sweep_nu1_wc300s | 300,000 | 1,293,676 | 0.49 / 2.22 / 43.0 | 38 | 74 | 0.451 | True |
| noise_sweep_nu3_wc300s | 300,000 | 1,342,387 | 0.49 / 2.58 / 15.3 | 37 | 31 | 0.913 | True |
| noise_sweep_nu10_wc300s | 300,000 | 1,268,208 | 0.51 / 2.53 / 16.8 | 39 | 6 | 0.994 | True |
| noise_sweep_nu30_wc300s | 300,000 | 1,174,875 | 0.54 / 4.02 / 14.3 | 38 | 1 | 1.000 | True |
| noise_sweep_nu100_wc300s | 300,000 | 1,303,186 | 0.49 / 3.87 / 15.2 | 37 | 1 | 1.000 | True |
| noise_sweep_nu0_wc60s | 300,000 | 1,295,547 | 0.50 / 3.07 / 16.3 | 40 | 105 | 0.042 | True |
| noise_sweep_nu1_wc60s | 300,000 | 1,272,520 | 0.49 / 3.70 / 29.7 | 34 | 172 | 0.042 | True |
| noise_sweep_nu3_wc60s | 300,000 | 1,003,179 | 0.64 / 4.39 / 30.2 | 36 | 228 | 0.043 | True |
| noise_sweep_nu10_wc60s | 300,000 | 1,274,770 | 0.49 / 3.95 / 17.8 | 36 | 102 | 0.838 | True |
| noise_sweep_nu30_wc60s | 300,000 | 1,302,792 | 0.49 / 3.86 / 14.9 | 39 | 7 | 1.000 | True |
| noise_sweep_nu100_wc60s | 300,000 | 1,065,226 | 0.59 / 3.93 / 25.4 | 37 | 1 | 1.000 | True |

*Heap in use above the pre-loaded input, sampled every 20k alerts; includes not-yet-collected garbage, so it is an upper bound.
HTTP webhook path (batches of 100, localhost): 334,208 alerts/s.

Percolation: predicted critical background noise (alerts/service/hour) vs observed — see docs/DESIGN.md#percolation.

| Cross window | Predicted ν_c | ν where largest incident > 50% of alerts |
|---|---|---|
| 300 s | 1.8 | between 1 and 3 |
| 60 s | 8.8 | between 3 and 10 |
