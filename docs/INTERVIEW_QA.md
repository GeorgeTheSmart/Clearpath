# Interview Q&A (answers point at the code)

Numbers refer to `eval/results/latest/report.md` and `eval/results/bench_correlator.json`.

## A. System design (1–14)

1. **Walk me through Clearpath end to end.**
   Prometheus rules fire → Alertmanager webhook → Go correlator groups alerts into incidents → localizer ranks suspects using seasonal anomaly scores and the trace graph → the agent gathers context, sanitises it, retrieves runbooks, drafts a typed diagnosis with verified citations, opens a ServiceNow ticket with CMDB CIs, and waits for a human → allow-listed remediation → audit log. (README diagram; `agent/pipeline.py`)
2. **Why not just send all alerts to an LLM?**
   Cost, latency and correctness. The topology reasoning is done better and deterministically by the localizer (99% top-1 vs 55% for most-alerting); the LLM only explains and drafts. When the LLM is down, the system still files a ticket (`diagnose.fallback`).
3. **What is the critical path for time-to-ticket?**
   Detection delay (median 0.5 min, p90 2.5 min for the seasonal detector) + correlator window + pipeline (median 12–63 ms without an LLM depending on machine load, mostly the ServiceNow HTTP calls). With the local 7B LLM, add one call of about 10 s.
4. **How does it scale to 10k services?**
   Correlator: shard by connected component of the service graph, since links never cross components (DESIGN §scaling). Localizer: work on the anomalous subgraph only. Retrieval: an ANN index once the corpus is more than about 10⁴ chunks.
5. **What happens if the correlator restarts?**
   In-memory state is lost: open incidents split or duplicate. The content-derived incident ID plus ServiceNow `correlation_id` dedupes. Persisting segments to a WAL is the upgrade.
6. **Why a separate correlator service instead of Alertmanager grouping?**
   Alertmanager groups by label equality. It can't merge `frontend:HighLatency` with `cartservice:HighErrorRate` because they're adjacent in the call graph.
7. **How do you avoid paging on every blip?**
   Calibrated thresholds (3 pages/day budget), `for: 2 steps`, 5-minute episode debounce, and burn-rate alerts for paging; symptom alerts feed the correlator rather than people.
8. **Push or pull for context gathering?**
   Pull (PromQL/LogQL) around the detection time, so the agent sees pre-fault baselines. `LiveSource` is the interface, `FixtureSource` the replay.
9. **How is the system tested without a cluster?**
   A deterministic simulator with labelled ground truth; content digests prove replay determinism; the mock ServiceNow uses the same client as a real PDI.
10. **What would you build next?**
    LiveSource on the kind cluster, the LLM rows of the evaluation, a webhook HMAC, and recorded real incidents from `faults/inject.sh` as a second test set.
11. **Single biggest risk in production?**
    Distribution shift between simulator and reality, which is why the evaluation is labelled and why the safety bound doesn't depend on model accuracy.
12. **Why ServiceNow priority from burn rate?**
    Priority should reflect user impact (error-budget burn), not how many alerts fired (`servicenow.urgency_impact`).
13. **How do you handle multiple simultaneous incidents?**
    Separate components in the correlator; the percolation analysis tells you when unrelated noise would wrongly merge them.
14. **What's deliberately *not* automated?**
    Any irreversible action, and approval itself.

## B. Algorithms and data structures (15–30)

15. **Describe the correlator's data structure.**
    Per-service segments (runs with gaps ≤ Wc) plus union-find over incident records plus a min-heap of eviction deadlines (`correlator/engine/engine.go`).
16. **Why are segments exact?**
    Consecutive gaps ≤ Wc ≤ W, so the union of [tᵢ−X, tᵢ+X] over a segment is exactly [tmin−X, tmax+X] for X ∈ {Wc, W}.
17. **Complexity per alert?**
    O((1+d)·k + log S + α(n)), with k ≤ ⌈(W+L)/Wc⌉+1 live segments per service.
18. **Why union by size and path halving?**
    Near-constant amortised find (inverse Ackermann); small-into-large merging bounds the total map-merge cost at O(n log n).
19. **How do you prove order independence?**
    The output is a connected-components function of the occurrence set; the property test compares two random arrival orders with disorder ≤ L, and the engine against an O(n²) reference, over 2,000 scenarios each (`engine_test.go`).
20. **How did you check the tests catch bugs?**
    Mutation test: turning `<=` into `<` in the interval check makes both properties fail.
21. **What is lazy deletion in the heap?**
    One entry per live segment. When a segment grows, its deadline increases; a popped entry with a stale deadline is re-pushed rather than updated in place (no decrease-key needed).
22. **What did the benchmark reveal?**
    (1) A heap entry per alert gave O(rate×window) memory — fixed. (2) Topology grouping percolates: one giant incident at 1% noise — fixed with the cross window, and explained by theory.
23. **Explain the percolation threshold.**
    Configuration-model site percolation: p_c = ⟨k⟩/(⟨k²⟩−⟨k⟩). The occupation probability is q = 1−e^{−ν·2Wc}; solve q = p_c for the critical ν. Predicted 1.8 vs observed 1–3 /svc/h for Wc = 5 min; 8.8 vs 3–10 for Wc = 60 s.
24. **Personalised PageRank, in one sentence?**
    A random walk that follows weighted edges with probability α and teleports to a preference distribution (here, anomaly scores) with probability 1−α; rank by stationary probability (`localize/rca.py`).
25. **Why walk caller → callee?**
    Faults propagate upstream, so walking downstream from symptoms leads to causes.
26. **What does the self-loop do?**
    It keeps mass at a service whose anomaly isn't explained by its most-correlated callee — the signature of a root.
27. **How do you compute PageRank?**
    Power iteration until the L1 change is < 1e-12 (≤ 200 iterations); dangling rows teleport to the personalisation vector.
28. **Did PageRank beat simple heuristics?**
    Not significantly on clean data (99.3% vs 98.3%, p = 0.75). It wins modestly under a downstream confounder (+3 pp, CI 0.7–5.7). I'd say the graph matters more than the walk.
29. **Ablation results?**
    No personalisation −20 pp top-1; no correlation weights −2 pp clean, −9 pp under concurrent anomalies; no self-loop −1 pp.
30. **BM25 formula?**
    Σ idf(t)·f·(k1+1)/(f + k1·(1−b+b·|d|/avgdl)), with k1 = 1.5, b = 0.75, idf = ln(1+(N−n+0.5)/(n+0.5)) (`agent/retrieval.py`).

## C. Statistics (31–48)

31. **Why the median and MAD instead of the mean and SD?**
    50% breakdown point: one outlier in the baseline can't mask the next anomaly (`test_robust_z_ignores_single_outlier_in_baseline`).
32. **Why 1.4826?**
    MAD × 1.4826 estimates σ for Gaussian data (1/Φ⁻¹(0.75)).
33. **How does CUSUM work?**
    S⁺ₜ = max(0, S⁺ₜ₋₁ + zₜ − k); alarm when S > h. k is half the shift you want to detect fastest.
34. **What is ARL?**
    Average run length to an alarm. In-control ARL measures false alarms; out-of-control ARL measures detection delay. The test checks the in-control ARL ≈ 465 for two-sided k = 0.5, h = 5.
35. **Why did raw CUSUM fail?**
    The residuals were autocorrelated, so increments weren't independent and the sum drifted. h had to rise to 234 and recall fell to 8%.
36. **What is prewhitening?**
    Fit AR(1) on history, use one-step forecast errors eₜ = zₜ − φzₜ₋₁ (roughly independent). Cost: a sustained shift D shows up as D at onset, then (1−φ)D.
37. **Explain BOCPD.**
    Keep a posterior over the run length since the last change; each step either grows the run (1−H) or resets (H); the predictive under a Normal-Inverse-Gamma prior is Student-t. O(n·R) with truncation.
38. **Why couldn't BOCPD meet the page budget?**
    Its score is a probability of change, and any real change, including benign blips, drives it to 1, so there's no magnitude to threshold. Multiplying by the effect size fixed it (7.7% → 88%).
39. **Seasonality: why seasonal naive rather than STL?**
    Over 3 days there's no trend; the median of same-time-of-day values is robust and needs no fitting.
40. **Why calibrate every detector to the same FP budget?**
    Otherwise you compare thresholds, not methods. It's one operating point on the ROC; the curves are saved in `detection.json`.
41. **How do you compute the bootstrap CI?**
    Resample incidents with replacement 10,000 times, take the 2.5th/97.5th percentiles of the statistic (`eval/stats.py`).
42. **When is the percentile bootstrap bad?**
    Small n, skewed statistics, or estimates at a boundary (e.g. 100% accuracy gives a degenerate CI); BCa or a Wilson interval is better there.
43. **Why McNemar instead of a two-proportion z-test?**
    The systems are evaluated on the same incidents (paired). Only discordant pairs carry information about the difference; the exact version is a binomial(n, ½) test on them.
44. **Effect size?**
    The accuracy difference with a paired-bootstrap CI, plus the wins/losses counts; the discordant odds ratio is also reported.
45. **Multiple comparisons?**
    Holm–Bonferroni within each family: uniformly more powerful than Bonferroni, and it still controls FWER.
46. **Your CI for top-1 is [98.3, 100] — what does it mean?**
    Under resampling of incidents from this distribution, 95% of the bootstrap accuracies fall there. It says nothing about other distributions (external validity).
47. **How did you avoid overfitting to the test set?**
    Fixed DEV/TEST seeds, all hyper-parameters tuned on DEV, a sealed red-team held-out set. Caveat: method designs were revised after seeing TEST detection results (documented).
48. **What's a threat to validity you can't fix here?**
    The simulator and the runbooks share an author: construct validity.

## D. SRE and SLOs (49–60)

49. **SLI vs SLO vs SLA?**
    The measurement (non-5xx ratio), the internal target (99.9%/30 d), and the contractual promise with penalties.
50. **What is an error budget?**
    1 − SLO = 0.1% of requests per 30 days, which may fail without breaching the SLO.
51. **What is burn rate?**
    Observed error ratio ÷ budget ratio; 1× spends exactly the budget over the window.
52. **Why 14.4× over 1 h?**
    14.4 × 1 h / 720 h = 2% of the monthly budget in one hour: worth waking someone.
53. **Why two windows?**
    The long window gives significance; the short window makes the alert reset soon after recovery and avoids paging on already-resolved burns.
54. **Where are the SLOs defined?**
    `observability/prometheus/slo-rules.yaml`; tests check the arithmetic.
55. **What does every alert need?**
    `summary`, `severity`, `service`, and a `runbook_url` that exists (test-enforced).
56. **What did the chaos suite assert?**
    The expected alert fires, recovery happens within a bound, and error-budget spend stays under a limit (`chaos/expectations.yaml`). Written but not run here.
57. **Why does pod-kill need replicas ≥ 2?**
    With 1 replica, a kill is an outage until restart; the frontend experiment expects no page because of replicas.
58. **Symptom vs cause alerts?**
    Page on symptoms (SLO burn); cause alerts (CPU, memory) feed diagnosis and the correlator.
59. **What's toil here?**
    Manual triage of alert storms and copy-paste into ServiceNow; the system automates both and keeps the decision with a human.
60. **Postmortem inputs the system provides?**
    Timeline (audit log), evidence with IDs, budget spent, and the actions taken with the approver.

## E. Kubernetes (61–70)

61. **How does rollout restart work?**
    Patches a template annotation (`restartedAt`), which triggers a rolling update; it's reversible.
62. **Rollback?**
    `kubectl rollout undo` sets the template to the previous ReplicaSet's — needs `replicasets get/list`.
63. **Minimum RBAC for the agent?**
    Role in one namespace: deployments get/list/watch/patch, deployments/scale get/patch/update, replicasets get/list, pods/events read. No delete, exec, or secrets (`deploy/helm/.../rbac.yaml`).
64. **Why namespaced Role instead of ClusterRole?**
    Blast radius: a compromised agent can't touch kube-system or other tenants.
65. **Readiness vs liveness?**
    Readiness gates traffic; liveness restarts a stuck process. A wrong liveness probe causes crash loops.
66. **CrashLoopBackOff timing?**
    Exponential back-off between restarts, capped (5 min in kubelet); the simulator models doubling up to a cap.
67. **OOMKilled?**
    The container exceeded its memory limit; the kernel OOM killer sends SIGKILL (exit 137).
68. **CFS throttling?**
    CPU limits enforced per 100 ms period; throttled periods raise latency before CPU looks saturated.
69. **Why NetworkPolicy on the agent?**
    Only the correlator may call it, which limits who can inject incidents.
70. **Pod security choices?**
    runAsNonRoot, read-only root FS, drop ALL capabilities, seccomp RuntimeDefault, distroless image.

## F. Terraform and AWS (71–80)

71. **Module layout?**
    `modules/{vpc,eks,iam,s3,ecr}` composed by `envs/dev`; modules have inputs and outputs only, no providers.
72. **Remote state and locking?**
    S3 backend with encryption and a DynamoDB lock table (`scripts/tf_bootstrap.sh`).
73. **Why private subnets for nodes?**
    No public IPs; egress via NAT; load balancers in public subnets via subnet tags.
74. **IRSA, how?**
    The EKS OIDC issuer becomes an IAM OIDC provider; the role trust conditions on `sub = system:serviceaccount:ns:sa` and `aud = sts.amazonaws.com`; the pod's projected token is exchanged with STS.
75. **GitHub OIDC trust conditions?**
    `aud = sts.amazonaws.com`, `sub` restricted to this repo's main branch and named environments.
76. **Why a single NAT?**
    Cost for the demo; `nat_per_az = true` for AZ-independent egress.
77. **S3 hardening?**
    Public access block, BucketOwnerEnforced, SSE, versioning, TLS-only policy, Object Lock for audit.
78. **ECR settings?**
    Immutable tags, scan on push, KMS encryption, lifecycle (keep 20).
79. **What does checkov/tfsec catch?**
    Public buckets, unencrypted resources, wide CIDRs, missing logging — run in CI as a gate.
80. **Did you apply it?**
    No: written and to be validated in CI. The build environment had no terraform, and applying costs money (docs/COST.md, ask first).

## G. CI/CD and supply chain (81–88)

81. **PR pipeline?**
    ruff, mypy, pytest, go vet/test (-race), terraform fmt/validate/tflint/checkov, image build, Trivy (fail HIGH/CRITICAL), Syft SBOM, cosign on main.
82. **Why sign images?**
    So deploy can verify provenance (`cosign verify` with an identity regex) before Helm runs.
83. **Keyless signing?**
    Cosign gets a short-lived certificate from Fulcio using the workflow's OIDC token; the signature goes to the Rekor transparency log.
84. **Approval gate?**
    A GitHub Environment `production` with required reviewers; the job waits.
85. **What does the SBOM give you?**
    An inventory to answer "are we affected by CVE-X?" without rescanning.
86. **`ignore-unfixed` in Trivy?**
    Don't fail on CVEs with no available fix; still reported.
87. **Nightly job?**
    Runs bench + eval + the chaos suite on kind and commits results, so README numbers stay reproducible.
88. **Why `--atomic` in production Helm?**
    It rolls back automatically if the release fails to become ready.

## H. RAG and agents (89–98)

89. **Why hybrid retrieval?**
    BM25 for exact error strings, dense for paraphrase. On this tiny corpus, hybrid ≈ dense (no significant gain) — reported.
90. **What is RRF?**
    score = Σ 1/(k + rank); k = 60 damps top-rank dominance and needs no score normalisation.
91. **Why chunk by runbook section?**
    Citable IDs (`rb-x#symptoms`) and coherent units; the doc-level dedupe gives recall@k per runbook.
92. **How is hallucination measured?**
    Each evidence item cites a context ID; it's unverified if the ID doesn't exist or the claim shares nothing with the cited item (`agent/verify.py`).
93. **Structured output?**
    Pydantic `Diagnosis`; one repair retry with the validation error; then the deterministic fallback.
94. **Graceful degradation?**
    LLM errors or invalid output produce a ticket from the localizer + runbook, marked degraded (`test_llm_down_degrades_gracefully`).
95. **Caching?**
    SHA-256 of (provider, model, system, user, max_tokens) → disk; identical context costs nothing.
96. **Cost accounting?**
    Tokens and wall time per call; dollars only if the user sets current prices (never hard-coded).
97. **Why LangGraph?**
    Interrupts and checkpointers fit the human-approval step; the nodes are plain functions, so the graph is swappable (`agent/langgraph_app.py`).
98. **Deterministic replay?**
    Fixtures regenerate from seeds; the LLM cache makes the model part replayable too.

## I. Security (99–106)

99. **Prompt-injection defence in depth?**
    Filter (L1), delimited declared-data context (L2), approval plus allow-list plus RBAC (L3). Only L3 is a hard guarantee.
100. **How good is the filter?**
     It blocks most of the dev set, 100% on the sealed held-out set, with 0 hard-negative false blocks — but both sets are same-author, so expect less on novel attacks.
101. **How do you catch obfuscation?**
     NFKC, zero-width removal, letter-separator collapse, leetspeak map, base64 decode of the raw text (case-sensitive), pairwise line scoring.
102. **PII redaction validation?**
     Luhn for cards, octet range for IPv4; phone requires `+` or formatting to avoid redacting IDs (a bug found by tests).
103. **Why bind approval to an action hash?**
     Prevents approving A and executing B (TOCTOU).
104. **Why a hash-chained audit log?**
     Tamper-evident: editing record i breaks verification at i; pair it with Object Lock for tamper-resistance.
105. **What would an attacker with webhook access do?**
     Inject fake incidents → tickets and approval requests, but no action without a human. Gap: HMAC.
106. **Fuzzing the action policy?**
     20,000 random proposals across kinds, targets, replicas and extra fields; 0 out-of-policy accepted.

## J. ServiceNow / ITSM (107–112)

107. **Which tables?**
     `incident`, `cmdb_ci_service`, `cmdb_rel_ci` (Depends on::Used by), `task_ci` for affected CIs.
108. **Impact vs urgency vs priority?**
     Impact = breadth, urgency = time sensitivity, priority = a lookup matrix of both; set impact and urgency, and let ServiceNow compute priority.
109. **How are affected CIs found?**
     Root CI by name, then `cmdb_rel_ci` where parent or child = root (one hop up and down).
110. **Idempotency?**
     `correlation_id` = incident ID; query it before creating, in production.
111. **Auth to the PDI?**
     Basic auth in dev; OAuth client credentials in production; secrets from Secrets Manager via IRSA.
112. **Why a mock?**
     Offline tests and demos with identical endpoints and response envelope; the client code is unchanged against a real PDI.
