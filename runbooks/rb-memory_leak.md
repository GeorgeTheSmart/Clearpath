---
id: rb-memory_leak
fault_type: memory_leak
alerts: [HighMemory, PodCrashLooping]
risk: medium
---
# Memory leak leading to OOMKill

## Symptoms
Working-set memory grows steadily until the container hits its limit and is OOMKilled (exit code 137), restarts, and the cycle repeats. Latency degrades with GC pressure before each kill.

## Diagnosis and fix
1. Confirm a sawtooth in `container_memory_working_set_bytes` and `OOMKilled` in pod events.
2. Look for long GC pauses, heap growth messages and allocation failures in logs.
3. Mitigate: rollout restart buys time; roll back if the growth started with a release.
4. Follow up: capture a heap profile before the next kill; raise the limit only as a stopgap.
