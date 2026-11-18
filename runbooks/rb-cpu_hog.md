---
id: rb-cpu_hog
fault_type: cpu_hog
alerts: [HighCPU, HighLatencyP99]
risk: medium
---
# CPU saturation / CPU hog

## Symptoms
A container is using most of its CPU limit, so requests queue behind busy workers and latency rises before errors do. Kubernetes CFS throttling shows as `container_cpu_cfs_throttled_periods_total` increasing.

## Diagnosis and fix
1. Confirm saturation: `rate(container_cpu_usage_seconds_total[5m])` vs the CPU limit, and throttled periods.
2. Check for a hot loop or runaway job in recent logs (blocked event loop, worker pool saturated, handler deadline exceeded).
3. Mitigate: scale out the deployment (`scale` action) or roll back if a recent release introduced the hot path.
4. Follow up: profile (pprof / async-profiler) and set realistic CPU requests/limits.
