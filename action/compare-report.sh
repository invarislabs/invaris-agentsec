#!/usr/bin/env bash
# Compare the report just produced against an earlier one (BASELINE_REPORT), for pull-request and
# scheduled regression testing. Never fails the step itself: the result goes to GITHUB_OUTPUT and
# GITHUB_STEP_SUMMARY, and the final gate step decides whether the job fails.
# Environment: BASELINE_REPORT, CURRENT_REPORT, COMPARE_FAIL_ON, GITHUB_OUTPUT, GITHUB_STEP_SUMMARY.
set -uo pipefail

if [ -z "${BASELINE_REPORT:-}" ]; then
  echo "No baseline-report given; skipping the regression comparison."
  { echo "compare-exit-code="; echo "compare-summary-path="; } >> "${GITHUB_OUTPUT:-/dev/null}"
  exit 0
fi

current="${CURRENT_REPORT:-.agentsec/report.json}"
if [ ! -f "$BASELINE_REPORT" ]; then
  echo "::warning title=AgentSec compare::baseline-report '$BASELINE_REPORT' does not exist; skipping the comparison"
  { echo "compare-exit-code=2"; echo "compare-summary-path="; } >> "${GITHUB_OUTPUT:-/dev/null}"
  exit 0
fi
if [ ! -f "$current" ]; then
  echo "::warning title=AgentSec compare::current report '$current' does not exist (did the run step fail before writing it?); skipping the comparison"
  { echo "compare-exit-code=2"; echo "compare-summary-path="; } >> "${GITHUB_OUTPUT:-/dev/null}"
  exit 0
fi

summary_file="$(mktemp)"
code=0
python3 - "$BASELINE_REPORT" "$current" "${COMPARE_FAIL_ON:-low}" "$summary_file" <<'PY' || code=$?
import sys

from agentsec.compare import CompareError, compare, load, render_markdown

baseline_path, current_path, fail_on, out_path = sys.argv[1:5]
try:
    c = compare(load(baseline_path), load(current_path))
except CompareError as exc:
    print("error: %s" % exc, file=sys.stderr)
    sys.exit(2)
with open(out_path, "w", encoding="utf-8") as fh:
    fh.write(render_markdown(c, baseline_path, current_path))
if fail_on != "none" and c.regressions(fail_on):
    sys.exit(1)
PY
code=${code:-0}

if [ -n "${GITHUB_STEP_SUMMARY:-}" ] && [ -s "$summary_file" ]; then
  { echo; echo "## AgentSec regression comparison"; echo; cat "$summary_file"; } >> "$GITHUB_STEP_SUMMARY"
fi

{
  echo "compare-exit-code=$code"
  echo "compare-summary-path=$summary_file"
} >> "${GITHUB_OUTPUT:-/dev/null}"

case "$code" in
  0) echo "agentsec compare: no new or worsened findings at or above '${COMPARE_FAIL_ON:-low}'." ;;
  1) echo "agentsec compare: new or worsened findings at or above '${COMPARE_FAIL_ON:-low}'." ;;
  *) echo "agentsec compare: could not compare the reports (exit code $code)." ;;
esac
exit 0
