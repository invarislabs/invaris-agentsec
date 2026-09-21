#!/usr/bin/env bash
# Start the agent under test in the background and wait until it answers HTTP.
# Environment: START_COMMAND (optional), WAIT_URL (optional), WAIT_TIMEOUT (default 60), RUNNER_TEMP.
set -euo pipefail

if [ -z "${START_COMMAND:-}" ]; then
  echo "No start-command given; assuming the agent is already running."
  exit 0
fi

tmp="${RUNNER_TEMP:-/tmp}"
log="$tmp/agentsec-agent.log"
pidfile="$tmp/agentsec-agent.pid"
rm -f "$pidfile"

# A new session lets stop-agent.sh kill the whole process tree, not only the shell.
if command -v setsid >/dev/null 2>&1; then
  setsid nohup bash -c "$START_COMMAND" >"$log" 2>&1 &
else
  nohup bash -c "$START_COMMAND" >"$log" 2>&1 &
fi
pid=$!
echo "$pid" > "$pidfile"
echo "Started the agent (pid $pid). Its log: $log"

if [ -z "${WAIT_URL:-}" ]; then
  exit 0
fi

timeout="${WAIT_TIMEOUT:-60}"
deadline=$(( $(date +%s) + timeout ))
# Any HTTP response counts as reachable (even 404 or 501); a refused connection does not.
until curl -s -o /dev/null --max-time 2 "$WAIT_URL"; do
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "::error::The agent process exited before $WAIT_URL became reachable"
    tail -n 50 "$log" || true
    exit 1
  fi
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "::error::Timed out after ${timeout}s waiting for $WAIT_URL"
    tail -n 50 "$log" || true
    exit 1
  fi
  sleep 1
done
echo "The agent is reachable at $WAIT_URL"
