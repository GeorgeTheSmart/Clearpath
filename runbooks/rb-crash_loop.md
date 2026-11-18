---
id: rb-crash_loop
fault_type: crash_loop
alerts: [PodCrashLooping, TargetDown]
risk: high
---
# Crash loop (CrashLoopBackOff)

## Symptoms
The process exits shortly after start (panic, failed initialisation), Kubernetes restarts it with exponential back-off, and the pod is unavailable most of the time.

## Diagnosis and fix
1. Read the previous container's logs: `kubectl logs --previous` for panics or fatal init errors.
2. Check pod events for BackOff and exit codes.
3. Mitigate: roll back to the previous revision if the crash started after a deploy.
4. Follow up: add a startup probe and fail fast with a clear error.
