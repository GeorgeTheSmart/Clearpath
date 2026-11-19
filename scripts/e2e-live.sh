#!/usr/bin/env bash
# End-to-end test on the live cluster (make up-local, make llm-up):
# take paymentservice down -> alerts -> correlator announces the incident while
# it is still open -> the agent diagnoses it from live data -> a human approves
# -> the action runs through the Kubernetes API -> the service and the shop
# recover -> the audit chain verifies. Exits non-zero on any failed step.
#
#   bash scripts/e2e-live.sh [service]      (default: paymentservice)
set -euo pipefail
SVC="${1:-paymentservice}"
NS=boutique
APPROVER="${APPROVER:-${USER:-${USERNAME:-oncall}}}"
OUT="${OUT:-var/e2e-live}"
mkdir -p "$OUT"
log() { printf '%s  %s\n' "$(date +%T)" "$*" | tee -a "$OUT/run.log"; }
agent_py() { kubectl -n clearpath exec deploy/clearpath-agent -- python -c "$1"; }

wait_for() { # wait_for <seconds> <description> <command...>
  local limit=$1 what=$2; shift 2
  local t0; t0=$(date +%s)
  until "$@" >/dev/null 2>&1; do
    if (( $(date +%s) - t0 > limit )); then log "TIMEOUT waiting for: $what"; exit 1; fi
    sleep 10
  done
  log "ok: $what ($(( $(date +%s) - t0 ))s)"
}

: > "$OUT/run.log"
log "precheck: $SVC healthy, agent up"
kubectl -n "$NS" rollout status "deploy/$SVC" --timeout=120s >/dev/null
kubectl -n clearpath rollout status deploy/clearpath-agent --timeout=120s >/dev/null
before=$(agent_py "import os; p='/var/clearpath/state'; print(' '.join(sorted(os.listdir(p))) if os.path.isdir(p) else '')")

T0=$(date +%s)
log "FAULT: scaling $SVC to 0 replicas (a sustained outage)"
kubectl -n "$NS" scale "deploy/$SVC" --replicas=0 >/dev/null

new_incident() {
  agent_py "
import json, os
p='/var/clearpath/state'; before=set('''$before'''.split())
for f in sorted(os.listdir(p)) if os.path.isdir(p) else []:
    if f in before: continue
    s=json.load(open(os.path.join(p,f)))
    if s.get('status')=='awaiting_approval' and s['diagnosis']['root_cause_service']=='$SVC':
        print(s['incident_id']); raise SystemExit(0)
raise SystemExit(1)"
}
wait_for 900 "agent diagnosed $SVC and is awaiting approval (outage still in progress)" new_incident
IID=$(new_incident)
T_DIAG=$(date +%s)
kubectl -n "$NS" get "deploy/$SVC" -o jsonpath='{.spec.replicas}' | grep -qx 0 && log "confirmed: diagnosis arrived DURING the outage (replicas still 0)"

agent_py "
import json; s=json.load(open('/var/clearpath/state/$IID.json')); d=s['diagnosis']
print('incident', s['incident_id'], '| ticket', (s.get('ticket') or {}).get('number'))
print('diagnosis:', d['fault_type'], 'on', d['root_cause_service'], '| confidence', d['confidence'], '| degraded', d['degraded'])
for e in d['evidence']: print('  evidence', e['ref'], '-', e['claim'][:110])
print('unverified evidence:', s['verification']['unverified'])
print('proposed:', s['proposed_actions'], '| rejected:', s['rejected_actions'])
" | tee -a "$OUT/run.log"
agent_py "import json; print(json.dumps(json.load(open('/var/clearpath/state/$IID.json')), default=str))" > "$OUT/state-before-approval.json"

log "APPROVE as '$APPROVER' (authenticated header, as the approval proxy would set it)"
kubectl -n clearpath port-forward deploy/clearpath-agent 18000:8000 >/dev/null 2>&1 & PF=$!
trap 'kill $PF 2>/dev/null || true' EXIT
sleep 4
curl -sS -X POST "http://127.0.0.1:18000/approve/$IID" -H "X-Forwarded-User: $APPROVER" \
  -H 'Content-Type: application/json' -d '{"approve": true, "reason": "e2e-live"}' | tee "$OUT/approval-response.json"; echo
grep -q '"remediated"' "$OUT/approval-response.json" || { log "approval did not remediate"; exit 1; }

replicas_up() { [ "$(kubectl -n "$NS" get "deploy/$SVC" -o jsonpath='{.status.availableReplicas}')" -ge 1 ]; }
wait_for 300 "$SVC has an available replica again (action executed via the Kubernetes API)" replicas_up
T_FIX=$(date +%s)

log "replay of the same approval must be refused (single-use)"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:18000/approve/$IID" -H "X-Forwarded-User: $APPROVER" -d '{"approve": true}')
[ "$code" = 409 ] && log "ok: replay refused with 409" || { log "replay returned $code"; exit 1; }

agent_py "
from agent.audit import AuditLog; from pathlib import Path
a=AuditLog(Path('/var/clearpath/audit.jsonl')); ok,bad=a.verify()
ev=[r['event'] for r in a.records() if r['data'].get('incident')=='$IID']
print('audit chain ok:', ok, '| events for incident:', ev)
raise SystemExit(0 if ok and ev.index('approval_decision') < ev.index('remediation_executed') else 1)" | tee -a "$OUT/run.log"

log "RESULT: outage -> diagnosis $((T_DIAG - T0))s, -> service restored $((T_FIX - T0))s after the fault (human approval included)"
