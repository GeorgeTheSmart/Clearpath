---
id: rb-bad_deploy
fault_type: bad_deploy
alerts: [HighErrorRate, HighLatencyP99]
risk: high
---
# Bad deploy (regression in a new release)

## Symptoms
A new revision ships a bug: errors (5xx, unhandled exceptions) start at the rollout. Beware: an unrelated deploy can coincide with an incident, so confirm the error signature matches the new code path.

## Diagnosis and fix
1. Correlate onset with the deployment rollout event and revision number.
2. Check for new exception types (KeyError, TypeError, assertion failures) after the rollout.
3. Mitigate: roll back to the previous revision (`rollback` action).
4. Follow up: add a canary stage with automated analysis before full rollout.
