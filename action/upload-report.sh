#!/usr/bin/env bash
# Send the report to a hosted AgentSec dashboard. A failed upload is a warning, never a failed job:
# the security result is the suite's, not the dashboard's.
# Environment: AGENTSEC_SERVER, AGENTSEC_TOKEN, REPORT_PATH, NO_TRACES, AGENTSEC_BIN.
set -uo pipefail

read -r -a bin <<< "${AGENTSEC_BIN:-agentsec}"
if [ ! -f "${REPORT_PATH:-}" ]; then
  echo "No report at ${REPORT_PATH:-<unset>}; nothing to upload."
  exit 0
fi
if [ -z "${AGENTSEC_TOKEN:-}" ]; then
  echo "::warning::dashboard-url is set but dashboard-token is empty; the report was not uploaded."
  exit 0
fi
args=(upload "$REPORT_PATH")
if [ "${NO_TRACES:-false}" = "true" ]; then
  args+=(--no-traces)
fi
if ! "${bin[@]}" "${args[@]}"; then
  echo "::warning::Upload to the AgentSec dashboard failed; the job result is unaffected."
fi
exit 0
