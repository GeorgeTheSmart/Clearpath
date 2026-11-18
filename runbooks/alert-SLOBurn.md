---
id: alert-SLOBurn
fault_type: none
alerts: [FrontendAvailabilityBudgetBurnFast, FrontendAvailabilityBudgetBurnSlow, FrontendLatencyBudgetBurnFast]
---
# Alert: SLO error budget burn

## Symptoms
Users are seeing errors or slow pages faster than the 30-day error budget allows. A fast burn (14.4x) spends 2% of the monthly budget per hour; a slow burn (6x) spends 5% in six hours.

## Diagnosis and fix
1. Open the Clearpath incident for this window: the localizer ranking names the most likely root-cause service.
2. Follow the runbook linked from that service's symptom alerts.
3. If a deploy is in flight anywhere on the request path, pause it.
4. Record budget spent in the ticket; a page-level burn needs a postmortem.
