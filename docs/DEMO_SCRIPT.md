# 2-minute demo video script

| Time | Screen | Say |
|---|---|---|
| 0:00–0:15 | README results table | "Clearpath turns an alert storm into one ticket with a ranked root cause — and every number here comes from a script in the repo, with confidence intervals." |
| 0:15–0:35 | `make bench` output, percolation table | "The correlator is Go — about a million alerts a second on one core. The interesting part: topology grouping percolates. I predicted where from site-percolation theory, and the benchmark agreed." |
| 0:35–0:55 | `report.md` §1–2 | "Detection uses seasonal robust z-scores and prewhitened CUSUM, calibrated to the same page budget. Root cause is personalised PageRank over the trace graph: 99% top-1 versus 55% for 'most alerts'. And honestly, a simple downstream heuristic is almost as good — the graph does the work." |
| 0:55–1:30 | terminal: `make demo` | "Here's a held-out memory leak. The localizer ranks recommendationservice first; the diagnosis cites log IDs and a runbook chunk, all verified; a ServiceNow ticket opens with its CMDB CIs; the restart waits for me. I approve, it runs a dry-run kubectl, and the audit chain verifies." |
| 1:30–1:50 | `docs/SECURITY.md`, the fuzz line | "Logs are untrusted. Injection strings are quarantined, PII is redacted — but the real guarantee is structural: three reversible verbs, approval bound to the exact action hash, a one-namespace Role. 20,000 fuzzed proposals, zero out-of-policy accepted." |
| 1:50–2:00 | Limitations section | "The data is simulated, and the LLM rows are next. The limitations are listed right in the README." |

Screenshots of Grafana dashboards and a real PDI ticket need the cluster path (`make up-local`) and a ServiceNow PDI; they are not in this repo yet.
