#!/usr/bin/env bash
# Process completion is not a delivery acknowledgement. GCS is the test oracle.
set -euo pipefail
source /run/issue195/context.env
unit=cicd-sensor-agent.service
probe() { /usr/local/bin/issue195-shutdown-probe "$1"; }
probe "hook_enter_provider_rc_${1:-unknown}"
actual=$(systemctl show "$unit" --property=InvocationID --value)
if [[ "$actual" != "$EXPECTED_INVOCATION_ID" ]] || ! systemctl is-active --quiet "$unit"; then
  probe hook_agent_missing_or_changed
  exit 1
fi
probe before_sigterm
systemctl kill --kill-who=main --signal=SIGTERM "$unit"
deadline=$((SECONDS + 30))
while [[ $SECONDS -lt $deadline ]]; do
  state=$(systemctl show "$unit" --property=ActiveState --value 2>/dev/null || true)
  if [[ "$state" == inactive || "$state" == failed || -z "$state" ]]; then
    probe "agent_exit_state_${state:-collected}"
    # Report only lifecycle/error messages, never runtime event payloads.
    journalctl --no-pager -u "$unit" -o cat | python3 -c '
import sys,json
allowed={"summary_emit_failed","job_project_scope_finalize_failed","agent_ingest_send_failed","job_finalized","jobs_finalized","agent_stopped"}
for line in sys.stdin:
 try: d=json.loads(line)
 except ValueError: continue
 if d.get("msg") in allowed: print(json.dumps({k:d[k] for k in ("time","level","msg","reason","count","finalized_jobs") if k in d}))
'
    if [[ "$state" == failed ]]; then exit 1; fi
    exit 0
  fi
  sleep 0.2
done
probe agent_exit_timeout
exit 1
