---
id: rb-bad_config
fault_type: bad_config
alerts: [HighErrorRate]
risk: high
---
# Bad configuration or environment variable

## Symptoms
A ConfigMap or environment change gives the service an invalid or missing setting. Errors start right after the change, often with explicit configuration validation messages, while latency may even drop (fast failures).

## Diagnosis and fix
1. Correlate the error onset with ConfigMapUpdated / env change events.
2. Find the key named in 'invalid configuration', 'missing required key' or parse errors.
3. Mitigate: revert the ConfigMap and rollout restart, or roll back the deployment revision.
4. Follow up: validate config in CI and use a schema.
