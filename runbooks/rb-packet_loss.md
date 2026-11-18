---
id: rb-packet_loss
fault_type: packet_loss
alerts: [HighErrorRate, HighLatencyP99]
risk: medium
---
# Packet loss / connection resets

## Symptoms
Packets to or from a service are dropped: TCP retransmissions raise latency and some requests fail with connection reset or transport closing errors.

## Diagnosis and fix
1. Look for connection reset by peer, retransmission and transport is closing in logs.
2. Check node network metrics (`node_netstat_Tcp_RetransSegs`) and CNI health.
3. Mitigate: reschedule the pods (rollout restart) away from the bad node.
4. Follow up: open a ticket with the network/platform team with the node name.
