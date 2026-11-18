#!/usr/bin/env bash
# Inject one catalogued fault into the real Online Boutique on kind, so live
# recordings can be added to the fixture set (same labels as faults/sim.py).
#   faults/inject.sh <fault_type> <service> [seed]
# Writes faults/live/<timestamp>-<fault>-<service>.json with the ground truth.
# NOT executed in the build environment (no cluster there).
set -euo pipefail
FT=${1:?fault type}; SVC=${2:?service}; SEED=${3:-0}; NS=boutique
TS=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p faults/live
case "$FT" in
  cpu_hog)
    kubectl -n $NS debug deploy/$SVC --image=busybox --target=server -- sh -c 'while :; do :; done' ;;
  memory_leak)
    kubectl -n $NS set env deploy/$SVC CLEARPATH_LEAK_MB_PER_MIN=40 ;;      # demo hook in apps/patches
  crash_loop)
    kubectl -n $NS set env deploy/$SVC CLEARPATH_CRASH_ON_START=1 ;;
  latency_injection)
    cat <<EOF | kubectl apply -f -
apiVersion: chaos-mesh.org/v1alpha1
kind: NetworkChaos
metadata: {name: lat-$SVC, namespace: $NS}
spec: {action: delay, mode: all, selector: {labelSelectors: {app: $SVC}}, delay: {latency: "400ms", jitter: "50ms"}, duration: "15m"}
EOF
    ;;
  packet_loss)
    cat <<EOF | kubectl apply -f -
apiVersion: chaos-mesh.org/v1alpha1
kind: NetworkChaos
metadata: {name: loss-$SVC, namespace: $NS}
spec: {action: loss, mode: all, selector: {labelSelectors: {app: $SVC}}, loss: {loss: "10", correlation: "25"}, duration: "15m"}
EOF
    ;;
  bad_config)
    kubectl -n $NS set env deploy/$SVC PORT=not-a-port ;;
  bad_deploy)
    kubectl -n $NS set image deploy/$SVC server=ghcr.io/georgethesmart/clearpath-buggy/$SVC:bug ;;
  dns_failure)
    kubectl -n $NS patch deploy/$SVC --type merge -p '{"spec":{"template":{"spec":{"dnsPolicy":"None","dnsConfig":{"nameservers":["203.0.113.53"]}}}}}' ;;
  dependency_down)
    kubectl -n $NS scale deploy/$SVC --replicas=0 ;;
  *) echo "unknown fault $FT" >&2; exit 2 ;;
esac
printf '{"ts":"%s","fault_type":"%s","root":"%s","seed":%s,"runbook":"rb-%s"}\n' "$TS" "$FT" "$SVC" "$SEED" "$FT" > "faults/live/$TS-$FT-$SVC.json"
echo "injected $FT into $SVC; ground truth faults/live/$TS-$FT-$SVC.json"
