# Evaluation methodology

Run everything with `make bench eval`. Results go to `eval/results/<date>/`: `detection.json`, `localization.json`, `metrics.json`, `report.md`, plus `bench_correlator.json`. The README table is generated from them by `eval/report.py`; nothing is typed in by hand.

## Dataset construction

* **Generator.** `faults/sim.py` (version 1) is a seeded, deterministic simulator of Online Boutique's 11 services and their call graph, at 30 s resolution (one Prometheus evaluation interval). Each incident is a 2-hour window plus the same window on the 3 previous days (for seasonal baselines). `Incident.digest()` hashes the content, so replay determinism is checkable.
* **Faults.** Nine types: CPU hog, memory leak → OOMKill, crash loop, latency injection, packet loss, bad config, bad deploy, DNS failure, dependency down. Each is injected into an eligible service with a random magnitude drawn from wide ranges (including subtle cases). The ground truth is the root service, the fault type and the runbook.
* **Propagation.** Effects travel callee → caller with random per-edge attenuation, retry amplification (×1–2 latency) and partial error propagation.
* **Realism added before any method existed:**
  * per-service noise levels and AR(1) autocorrelated noise;
  * a diurnal load cycle, with incidents placed at random times of day;
  * benign latency blips in history and in the incident window;
  * decoy deploys on unrelated services (30% of incidents);
  * uneven alert coverage per service (the edge has every rule, leaf teams only "is it up");
  * unobservable roots (no scrapes when a dependency is down);
  * unsampled low-volume trace edges;
  * synthetic PII in logs, and prompt-injection strings in 25% of incidents.
* **Splits** (`eval/datasets.py`, fixed constants):
  * DEV: incident seeds 0–199, fault-free week seed 500. Used for all tuning.
  * TEST: incident seeds 10000–10299 (300 incidents), fault-free week seed 501. Used once per reported number.
* **One disclosed adjustment.** The simulator was changed once, before any detector or localizer was written. The "most-alerting service" baseline was 82% top-1, which is unrealistically easy. Adding uneven alert coverage, retry amplification and subtler magnitudes brought it to 58.5% on a scratch sample (55.0% on TEST). The change is commit `d533b53`. It makes the baseline weaker, which is a bias in my methods' favour, so I'm stating it.
* **Public benchmarks.** None was used. RCAEval and LogHub-derived sets are the obvious candidates, but I could not download or check their licences from the build environment. Not inventing a dataset I cannot obtain was a hard rule.

## Systems compared (end to end)

| ID | System | What it uses |
|---|---|---|
| a | static alerts + most-alerting service | distinct firing rules per service; fault type from retrieving with alert names only |
| b | localizer only | PPR top-1; fault type from that service's alert names |
| b+ | localizer + RAG, no LLM | full sanitized context of the top suspect → runbook → fault type (the pipeline's degraded mode) |
| c | LLM, no RAG | implemented, **not run** (no network) |
| d | LLM + RAG | implemented, **not run** |
| e | full system | implemented, **not run** |

## Metrics and definitions

* **Detection.**
  * *Root recall@10min:* any alarm on the root service's series within 20 steps after fault start.
  * *FP/day:* number of alarm-episode starts per day over 44 series, on a fault-free week. Episodes are debounced at 5 min, and every detector requires 2 consecutive steps over threshold.
* **Localisation:** top-1 and top-3 accuracy, and the mean rank of the true root among 11 services. Random gives 1/11 and 3/11.
* **Hallucination rate:** evidence items whose `ref` is not an ID in the gathered context, or whose claim shares no content word or service with the referenced item (`agent/verify.py`), divided by total evidence items. For the deterministic system (b+) it is 0 by construction; the metric exists for the LLM rows.
* **PII leak rate:** planted PII values (cards with valid Luhn digits, emails, +91 phones) still present after `sanitize`, over every log line in the TEST fixtures, not just the gathered ones.
* **Injection:** the simulator's injected lines that get quarantined; benign lines falsely quarantined; the red-team block rate (dev set and sealed held-out set). End-to-end attack success needs an LLM (implemented in `eval/harness.llm_redteam`, not run).
* **Time to ticket:** wall time from incident received to ServiceNow incident created on the local mock over HTTP, no LLM. It excludes detection delay (reported separately) and the correlator window.

## Statistics

* **CIs:** 95% percentile bootstrap, 10,000 resamples, resampling incidents.
* **Paired tests:** "Is X better than Y on the same incidents?" uses the **exact McNemar** test, a binomial test on the discordant pairs. That is the correct test for paired binary outcomes; an unpaired two-proportion test would ignore the pairing and lose power. The effect size is the accuracy difference, with a paired-bootstrap CI, alongside the wins/losses counts.
* **Multiple comparisons:** Holm–Bonferroni within each family (detectors vs the static baseline; PPR vs the baselines).
* **Calibration tests:** `tests/test_stats.py` checks the exact McNemar p-values against hand-computed values, and checks that the bootstrap CI covers the true mean in 90–99% of 200 simulated datasets.

## Threats to validity

1. **Construct validity.** The propagation model, the log templates and the runbooks were all written by one person. Runbooks mention phrases that the simulator also emits ("no such host", "OOMKilled"), so retrieval accuracy is optimistic. Real logs are messier.
2. **Internal validity.** Hyper-parameters (α, ρ, γ; the detector thresholds) were tuned on DEV only, and the TEST seeds were fixed in code before any run. But the *method designs* (prewhitening, magnitude-weighted BOCPD) were revised after seeing TEST detection results. Those revisions are documented in commit history and in DESIGN.md. A fully clean protocol would have held out a third split.
3. **External validity.**
   * One topology with 11 services.
   * Faults are mostly abrupt, so top detectors saturate; memory leaks are the main differentiator.
   * No multi-root incidents.
   * No real Kubernetes behaviour (HPA, retries with jitter, partial rollouts).
   * The numbers say "on this fault model". They do not say "in production".
4. **Red-team sets.** Both were written by the filter's author. The held-out set was committed (with a SHA-256) before tuning and scored once, but it is not independent. Expect lower block rates on novel attacks; the safety argument does not rest on the filter.
5. **Benign blip density.** Incident windows carry more benign blips per hour than the fault-free weeks, so pre-fault false pages per hour on incident windows are higher than FP/day would suggest. Both numbers are reported.

## Negative and null results (kept on purpose)

* EWMA z-score: variance contamination by the step itself, 0% recall on crash loops.
* Raw CUSUM on autocorrelated residuals: 8% root recall at the page budget, until prewhitening.
* Plain BOCPD: cannot be calibrated to a page budget (7.7% recall).
* PPR vs the "downstream-most anomalous" heuristic: no significant difference on clean data.
* Hybrid retrieval vs dense alone: no significant difference on a 16-document corpus.
