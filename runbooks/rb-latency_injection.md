---
id: rb-latency_injection
fault_type: latency_injection
alerts: [HighLatencyP99]
risk: medium
---
# Network latency to a dependency

## Symptoms
Responses from one service are slow at the network level: latency rises at the service and its callers while CPU and error rate stay mostly normal, then timeouts appear upstream.

## Diagnosis and fix
1. Compare server-side latency with client-side latency at each caller to find the slow hop.
2. Check for network chaos, a noisy neighbour, or a degraded node (`kubectl describe node`).
3. Mitigate: move the pods (rollout restart onto other nodes) or fail over.
4. Follow up: set client timeouts below the upstream budget and add retries with jitter.
