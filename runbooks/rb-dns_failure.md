---
id: rb-dns_failure
fault_type: dns_failure
alerts: [HighErrorRate]
risk: medium
---
# DNS resolution failure

## Symptoms
A service cannot resolve the names of its dependencies (no such host, lookup failures), so all outbound calls from that service fail while the dependencies themselves are healthy.

## Diagnosis and fix
1. Find 'no such host' / 'name resolution failed' errors and which hostnames fail.
2. Check CoreDNS pods and the failing pod's /etc/resolv.conf and dnsPolicy.
3. Mitigate: rollout restart the affected service; restart CoreDNS if it is unhealthy.
4. Follow up: add DNS caching (NodeLocal DNSCache) and alert on CoreDNS errors.
