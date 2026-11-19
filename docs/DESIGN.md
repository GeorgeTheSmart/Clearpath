# Design decisions and trade-offs

Each section states the decision, why I made it, what it costs, and where the code is. The numbers are quoted from `eval/results/latest/` and `eval/results/bench_correlator.json`.

## Go (not Rust) for the correlator

**Decision:** Go, standard library only.

* **Why:**
  * The Prometheus and Alertmanager ecosystem is Go. The webhook types, client libraries and the people who would maintain this all live there.
  * `testing/quick` gives property-based testing in the standard library.
  * The workload needs about 10k alerts/min ≈ 170 alerts/s. One goroutine sustains about 10⁶ alerts/s (bench), so there is roughly 4 orders of magnitude of headroom. Rust's advantages (no GC, tighter tail latency) do not matter at this operating point.
* **Cost:** GC pauses show up in the tail. Max per-alert latency was a few ms under multi-million-alert runs, against a p99.9 of about 15–30 µs. If the target were 10⁷ alerts/s with hard tail bounds, I would revisit Rust, or Go with arena-style pooling.

## Correlator grouping algorithm {#correlator}

**Specification:** two occurrences are linked if they are on the same service within `W`, or on adjacent services (trace call graph, undirected) within `Wc ≤ W`. An incident is a connected component. The spec says nothing about arrival order, so a correct implementation is order-independent as long as arrivals are at most `L` (lateness) out of order. The tests check exactly that, against an O(n²) brute-force reference, over 2,000 random scenarios per property.

**Data structure: interval-compressed union-find.**

* For each service, keep *segments*: maximal runs of that service's occurrences whose consecutive gaps are ≤ `Wc`.
* Every occurrence in a segment is linked to its neighbour, so the whole segment lies in one component.
* Because gaps are ≤ `Wc` ≤ `W`, the question "is any occurrence within X of t" (X = W or Wc) is exactly the interval test `t ∈ [tmin−X, tmax+X]`. Without the gap bound, the interval test would over-link.
* Components form a union-find (path halving, union by size, small-into-large map merges) over incident records. Each record holds its services, per-fingerprint aggregates (that is the dedupe) and counters.

**Eviction:**

* A segment can no longer gain links once `tmax + W + L < watermark`. Segments sit in a min-heap keyed by that deadline, with one entry per live segment.
* When a segment grows, its deadline only increases, so a popped stale entry is simply re-pushed (lazy rescheduling).
* An incident is emitted when its last live segment is evicted.

**Complexity:**

* Let `d` be the service degree and `k` the live segments per service. Segments of one service are separated by gaps > `Wc` and live for about `W + L`, so `k ≤ ⌈(W+L)/Wc⌉ + 1` (7 at the defaults).
* Per alert: `O((1+d)·k + log S + α(n))`, where `S` is the number of live segments. A storm of N alerts on one service stays **one** segment, so memory is O(live segments + distinct fingerprints per open incident), not O(alerts).
* The first version pushed one heap entry per alert, which made memory O(rate × window). The benchmark exposed it and I fixed it.

**Storm suppression without loss:**

* Each incident keeps at most `MaxFingerprints` distinct fingerprints. Further occurrences increment `Suppressed`.
* Property 3 checks that `Σ counts + suppressed = total` per incident, and `Σ total = alerts ingested`, even with fully shuffled (arbitrarily late) input.
* Late alerts are never dropped: they form an incident flagged `late`.

**Announce while open, not only on close.** An incident closes when no linked alert arrives for `Window + Lateness`. Alertmanager re-sends every firing alert (here every 30 s), so an alert that keeps firing keeps its incident open for as long as the outage lasts. With emit-on-close only, the agent would see a sustained outage only after it ended. This was found on the live cluster, where a long-lived burn-rate page held an incident open and nothing reached the agent. With `OpenAfter` (default 60 s, so related alerts gather first), the engine emits one `status: "open"` snapshot and fixes the incident's ID, and the final `closed` emission reuses it, so the agent diagnoses once and recognises the redelivery. If two announced incidents later merge, one ID is kept and the other is listed in `merged_ids`. The check runs on the server's ticker, not per alert, so ingest throughput is unchanged (the benchmark reproduces identical incident counts). Property test: across random scenarios every ID is announced at most once, every announcement is resolved by a close or a merge, and no occurrence is lost.

### Percolation: why there is a separate cross-service window {#percolation}

My first benchmark merged the whole 200-service fleet into one incident at just 1% background noise. Topology grouping on a connected graph is **site percolation**:

* If each service independently has an unrelated alert within ±`Wc` of a given time with probability `q = 1 − exp(−ν·2Wc)` (ν = noise alerts per service per unit time), a giant component appears once `q` exceeds the threshold `p_c = ⟨k⟩ / (⟨k²⟩ − ⟨k⟩)` (configuration-model result).
* Solving for ν gives the predicted critical noise level.

Measured (bench topology, ⟨k⟩ ≈ 4):

| Cross window Wc | Predicted ν_c (alerts/service/hour) | Observed: largest incident > 50% of all alerts |
|---|---|---|
| 300 s (= W) | 1.8 | between ν = 1 and 3 |
| 60 s | 8.8 | between ν = 3 and 10 |

The approximation predicts the transition. The trade-off is explicit: a tighter `Wc` tolerates about 5× more background noise but splits cascades whose hops are more than 60 s apart. Same-service grouping keeps the longer `W`. If noise exceeds ν_c anyway, the right fix is upstream (tune the noisy alerts); a grouping window cannot fix it.

### Scaling past one process {#scaling}

The engine state is in memory and single-threaded. To scale, I would shard by connected component of the *service graph* (not by alert), since links never cross components; within a component, shard by time with an overlap of `W + L`. State loss on restart produces a few duplicate or split incidents. That is acceptable because ServiceNow dedupes on `correlation_id`, and the incident ID is content-derived.

## Detection {#detection}

**Choice:** seasonal robust z-score as the pager signal, and prewhitened CUSUM where sustained small shifts matter.

* **Seasonal baseline.** For each step, take the median of the same time of day over the previous 3 days, then smooth it. The scale is the MAD of the historical residuals. This is "seasonal naive" rather than STL: over a 3-day horizon there is no trend to model, it has no fitting step that can fail, and the median gives a 50% breakdown point (one bad day cannot move the baseline).
* **Robust z instead of mean/σ.** One outlier inside the baseline window would inflate σ and hide the next anomaly (there is a unit test for this).
* **EWMA failed in an instructive way.** Its variance absorbs a step change at once, so the `for: 2 steps` rule never fires: 0% recall on crash loops. The fix would be censoring (don't update the baseline on flagged points). I kept EWMA as a reported baseline.
* **CUSUM.** It accumulates evidence: `S⁺ = max(0, S⁺ + z − k)`, with `k = 0.5σ` tuned for 1σ shifts. A unit test checks the in-control average run length against theory (≈465 steps, two-sided, h = 5).
* **Prewhitening.** Raw CUSUM on autocorrelated residuals needed h ≈ 234 to meet the page budget and detected 8% of root services. Running it on AR(1) one-step-ahead forecast errors (φ fitted on history) restored 100%. Cost: after the onset, a shift appears at only `(1−φ)` of its size, so slow ramps are harder to see.
* **BOCPD (Adams & MacKay).** Normal-Inverse-Gamma prior, Student-t predictive, run length truncated at 300. Its score `P(change in last 5 steps)` saturates at 1 for *any* real change, including benign blips, so it cannot be traded against a page budget (7.7% recall at 3 pages/day). Weighting it by effect size (`P × |mean residual|`) restores a magnitude axis (88%). Lesson: BOCPD is a change *localiser* (when did it change), not a pager.
* **Fair comparison.** Every detector is calibrated by bisection to the same 3 pages/day fleet-wide on a dev fault-free week, then measured on a different week and on held-out incidents. Comparing at default thresholds would compare thresholds, not methods.

## Root-cause localisation {#localizer}

Adapted from MicroRCA (Wu et al., NOMS 2020) and CloudRanger (Wang et al., CCGrid 2018). The service graph comes from **trace** edges (call counts), not from a static topology, so missing instrumentation shows up as missing edges; the robustness suite drops 30% of them.

* **Walk.** Transition probabilities go from caller to callee, weighted by |corr| between the two services' anomaly series around detection, times the callee's anomaly level. A weak backward edge `ρ` lets the walker escape a wrong branch. A self-loop weighted by the anomaly *not explained* by the most-correlated callee keeps the walker at a true root. Personalisation is proportional to the anomaly scores. Teleport α comes from a DEV grid.
* **Chosen on DEV:** α = 0.7, ρ = 0, γ = 0. The final score is the stationary probability alone: multiplying again by anomaly level did not help.
* **The honest result.** On clean data, PPR at 99.3% top-1 is statistically indistinguishable from the heuristic "anomalous services with no anomalous callee" (98.3%, p = 0.75). The graph does the work; PageRank adds robustness, and only modestly:
  * +3 pp with a downstream confounder;
  * correlation weighting is worth +9 pp under concurrent unrelated anomalies.
* **Removing personalisation hurts most** (−20 pp), because without it the walk is pure graph structure.

## Hybrid retrieval

* **BM25** catches exact tokens such as `OOMKilled` or `no such host`. **Dense** retrieval catches paraphrases. **RRF** (k = 60) fuses ranks without calibrating score scales, which matters because BM25 scores are unbounded and cosine scores are not.
* **The dense side is LSA** (TF-IDF → SVD), because a neural embedding model could not be downloaded offline. `Embedder` is the swap point.
* **Measured:** on a 16-runbook corpus, hybrid is not better than dense alone. With so few documents, fusion has little room to help. I report that and don't tune it away. A cross-encoder rerank hook exists, but it is not used (no model offline).

## Why human-in-the-loop, and why allow-listed remediation

The model drafts; a person decides. Three independent layers:

1. **Injection quarantine** on untrusted text.
2. **A prompt** that puts all gathered text in a delimited, declared-data block, with mandatory citations that are verified afterwards.
3. **The remediation boundary**, which bounds the blast radius regardless of layers 1–2:
   * three reversible verbs (rollout restart, scale 1–10, rollback), on known services, in one namespace;
   * an approval bound to the *hash of the exact actions*;
   * the agent's own identity cannot approve;
   * every decision goes into a hash-chained audit log.

Layer 3 is what makes the system safe even if layers 1–2 fail. The Kubernetes Role cannot delete, exec or read secrets, so even a bug in `validate()` cannot exceed that.

## Burn-rate alert design

Thresholds follow the Google SRE workbook multi-window, multi-burn-rate scheme:

* **Page** at 14.4× over 1 h AND 5 m (2% of the 30-day budget in an hour), and at 6× over 6 h AND 30 m (5% in 6 h).
* **Ticket** at 1× over 3 d AND 6 h.

The short window makes the alert stop soon after the burn stops. `tests/test_observability.py` checks the arithmetic, the presence of both windows, and that every alert carries `summary`, `severity`, `service` and a `runbook_url` that exists. ServiceNow urgency and impact map from the same burn rates, so ticket priority reflects budget burn, not alert volume.

### Where the SLIs come from {#sli-source}

Online Boutique exports no Prometheus request metrics, so the first version of these rules (written against `http_server_requests_total`) had **no data on a real cluster**: no burn alert could fire and the chaos suite could not measure anything. The SLIs now come from the **Linkerd proxy** beside every pod (`response_total` with Linkerd's success/failure `classification`, `response_latency_ms` histograms), scraped by `observability/linkerd-podmonitor.yaml`. A mesh measures every request with no application changes, which is also how you would instrument a fleet of services you do not own.

Three details that each broke the rules once, now pinned by `promtool` unit tests (`make rules-test`, `observability/tests/`):

* **rate() before sum().** Summing raw counters first turns every pod restart (a counter reset) into a fake error spike, exactly when a chaos test kills pods.
* **Zero errors is 0, not absent.** A healthy service has *no* failure series. Without `or vector(0)` on the numerator the ratio disappears, so burn alerts cannot evaluate and "recovered when ratio < x" can never become true.
* **`le="500.0"`.** Prometheus 3 renders histogram bucket labels as floats; `le="500"` silently matched nothing.

Symptom alerts derive `service` from the pod name for Kubernetes/cAdvisor series (which have no such label), because that is what the correlator groups on. Only rules labelled `clearpath="true"` are routed to the correlator; the chart's built-ins (Watchdog, etcd) would otherwise look like a permanent storm.

## Live path: from a cluster incident to a ticket {#live-path}

`agent/live.LiveSource` is the cluster counterpart of the replay fixture and feeds the **same** localizer, retrieval, guardrails and diagnosis code that the offline evaluation measures:

* **Metrics** from Prometheus on the simulator's 30 s grid, 30 min before the first alert to now: p99 latency and error rate per service from Linkerd, CPU and memory against the container's own limits.
* **Anomaly scores.** Offline, z-scores use a same-time-of-day baseline from previous days. A fresh cluster has no such history, so live scores are robust z (median/MAD) against the pre-incident window. That catches step changes but not "normal for 9 am, abnormal for 3 am"; the seasonal baseline needs days of retention.
* **Absence** counts only for a service that reported in the baseline and then stopped (killed, unschedulable), so a service with no HTTP traffic (redis-cart) is not "absent" forever.
* **Call graph** from the mesh: HTTP/gRPC edges with traffic in the window, plus open TCP connections. cartservice → redis-cart is a single long-lived connection whose open counter never increases, so `increase()` alone would drop the edge the localizer needs when redis is the root.
* **Logs and events** from the Kubernetes API (`pods/log`, `events`, read-only in one namespace), with levels parsed from Online Boutique's JSON or plain-text logs. Logs of a pod that was already deleted are gone; its absence is itself in the metric evidence.

Approved actions run through the Kubernetes API (`agent/kube.KubeExecutor`: the same patches as `kubectl rollout restart / scale / rollout undo`) with the namespaced Role, when `agent.execute=kube`; the default is `dry-run`.

## IRSA and OIDC instead of static keys

* **Pods:** the agent pod gets AWS credentials through IRSA. The role trusts only `system:serviceaccount:clearpath:clearpath-agent` on this cluster's OIDC issuer, and may only `s3:PutObject` under `audit/` plus read its own secret.
* **CI:** GitHub Actions assumes a role through GitHub's OIDC provider. The trust is limited to this repo's `main` branch and its `staging`/`production` environments.
* No long-lived keys exist anywhere to leak, and every credential is short-lived and scoped.
