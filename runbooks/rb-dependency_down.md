---
id: rb-dependency_down
fault_type: dependency_down
alerts: [TargetDown, HighErrorRate]
risk: high
---
# Downstream dependency down

## Symptoms
A dependency has no ready endpoints: Prometheus cannot scrape it (target down) and its callers fail with connection refused / unavailable errors. The dependency itself produces no logs.

## Diagnosis and fix
1. Check `up == 0` and endpoints: `kubectl get endpoints <svc>`.
2. Inspect pod status, node pressure and recent evictions for the dependency.
3. Mitigate: rollout restart or scale up the dependency; roll back if a release removed it.
4. Follow up: add PodDisruptionBudgets and readiness probes.
