---
id: alert-HighLatencyP99
fault_type: none
alerts: [HighLatencyP99]
---
# Alert: HighLatencyP99

This alert is a symptom, not a cause. Check the dependency graph for the most-downstream anomalous service, then follow the matching runbook:

- [rb-latency_injection](rb-latency_injection.md)
- [rb-cpu_hog](rb-cpu_hog.md)
- [rb-packet_loss](rb-packet_loss.md)
