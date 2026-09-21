#!/usr/bin/env bash
# Stop the agent that start-agent.sh started. Safe to run when nothing was started.
set -uo pipefail

pidfile="${RUNNER_TEMP:-/tmp}/agentsec-agent.pid"
[ -f "$pidfile" ] || exit 0
pid="$(cat "$pidfile")"
# Kill the whole process group (start-agent.sh used setsid), falling back to the single process.
kill -- "-$pid" 2>/dev/null || kill "$pid" 2>/dev/null || true
rm -f "$pidfile"
echo "Stopped the agent (pid $pid)."
