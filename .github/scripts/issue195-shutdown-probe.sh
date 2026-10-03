#!/usr/bin/env bash
# Independent observation only. Does not stop the sensor or modify vendor hooks.
set -u

send_probe() {
  curl --silent --show-error --max-time 2 --output /dev/null --get \
    --data-urlencode "issue=195" \
    --data-urlencode "run_id=${GITHUB_RUN_ID}" \
    --data-urlencode "run_attempt=${GITHUB_RUN_ATTEMPT}" \
    --data-urlencode "job=${GITHUB_JOB}" \
    --data-urlencode "runner=${PROBE_RUNNER}" \
    --data-urlencode "rep=${PROBE_REP}" \
    --data-urlencode "order=${PROBE_ORDER}" \
    --data-urlencode "tracking_id=${PROBE_TRACKING_ID}" \
    --data-urlencode "phase=$1" \
    --data-urlencode "probe_epoch_ms=$(date +%s%3N)" \
    --data-urlencode "service_result=${SERVICE_RESULT:-unset}" \
    --data-urlencode "exit_code=${EXIT_CODE:-unset}" \
    --data-urlencode "exit_status=${EXIT_STATUS:-unset}" \
    "${PROBE_ENDPOINT}" || true
}

if [[ $# -gt 0 ]]; then
  send_probe "$1"
  exit 0
fi

on_term() {
  trap - TERM INT
  send_probe term
  sleep 2
  send_probe clean_exit
  exit 0
}

trap on_term TERM INT
send_probe started
while true; do
  sleep 5
  send_probe heartbeat
done
