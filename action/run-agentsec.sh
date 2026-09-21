#!/usr/bin/env bash
# Run `agentsec test` and record its exit code as a step output WITHOUT failing the step,
# so that reports can be uploaded before the job is failed by the final gate.
# Environment: POLICY, FAIL_ON, SEED, FORMATS, OUT, JUDGE, EXTRA_ARGS, AGENTSEC_BIN, GITHUB_OUTPUT.
set -uo pipefail

read -r -a bin <<< "${AGENTSEC_BIN:-agentsec}"
args=(test --policy "${POLICY:-agentsec.yaml}" --out "${OUT:-.agentsec}"
      --format "${FORMATS:-json,html,markdown}" --fail-on "${FAIL_ON:-low}" --seed "${SEED:-0}")
if [ "${JUDGE:-false}" = "true" ]; then
  args+=(--judge)
fi
if [ -n "${EXTRA_ARGS:-}" ]; then
  read -r -a extra <<< "$EXTRA_ARGS"
  args+=("${extra[@]}")
fi

"${bin[@]}" "${args[@]}"
code=$?

report="${OUT:-.agentsec}/report.json"
findings=""
scenarios=""
if [ -f "$report" ]; then
  read -r findings scenarios < <(python3 -c \
    'import json,sys; s=json.load(open(sys.argv[1]))["summary"]; print(s["findings"], s["scenarios"])' "$report" \
    2>/dev/null || true)
fi

{
  echo "exit-code=$code"
  echo "report-dir=${OUT:-.agentsec}"
  echo "findings=${findings:-}"
  echo "scenarios=${scenarios:-}"
} >> "${GITHUB_OUTPUT:-/dev/null}"

case "$code" in
  0) echo "AgentSec finished: no findings at or above '${FAIL_ON:-low}'." ;;
  1) echo "AgentSec found issues at or above '${FAIL_ON:-low}'." ;;
  *) echo "AgentSec could not complete (exit code $code): check the policy and that the agent is reachable." ;;
esac
exit 0
