#!/usr/bin/env bash
# Post or update a pull-request comment with the regression comparison from compare-report.sh.
# Never fails the step itself; problems are reported as workflow warnings.
# Environment: SUMMARY_PATH, GITHUB_EVENT_NAME, GITHUB_EVENT_PATH, GITHUB_REPOSITORY, GITHUB_TOKEN,
#              COMMENT_MARKER_KEY.
set -uo pipefail

if [ -z "${SUMMARY_PATH:-}" ] || [ ! -s "${SUMMARY_PATH:-}" ]; then
  echo "No comparison summary to post; skipping the pull-request comment."
  exit 0
fi
if [ "${GITHUB_EVENT_NAME:-}" != "pull_request" ] && [ "${GITHUB_EVENT_NAME:-}" != "pull_request_target" ]; then
  echo "Not a pull_request event; skipping the pull-request comment."
  exit 0
fi
if ! command -v gh >/dev/null 2>&1; then
  echo "::warning title=AgentSec compare::the gh CLI is not available; skipping the pull-request comment"
  exit 0
fi
if [ -z "${GITHUB_TOKEN:-}" ]; then
  echo "::warning title=AgentSec compare::no github-token available; skipping the pull-request comment"
  exit 0
fi

pr_number="$(python3 -c '
import json, os, sys
try:
    with open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8") as fh:
        print(json.load(fh)["pull_request"]["number"])
except Exception:
    sys.exit(1)
' 2>/dev/null || true)"
if [ -z "$pr_number" ]; then
  echo "::warning title=AgentSec compare::could not determine the pull request number; skipping the pull-request comment"
  exit 0
fi

marker="<!-- agentsec-compare:${COMMENT_MARKER_KEY:-default} -->"
body_file="$(mktemp)"
{ echo "$marker"; echo; echo "### AgentSec regression comparison"; echo; cat "$SUMMARY_PATH"; } > "$body_file"

export GH_TOKEN="$GITHUB_TOKEN"
existing="$(gh api "repos/${GITHUB_REPOSITORY}/issues/${pr_number}/comments" --paginate \
  --jq ".[] | select(.body | startswith(\"$marker\")) | .id" 2>/dev/null | head -n1 || true)"

if [ -n "$existing" ]; then
  if gh api --method PATCH "repos/${GITHUB_REPOSITORY}/issues/comments/${existing}" -f body=@"$body_file" >/dev/null 2>&1; then
    echo "Updated the existing AgentSec comparison comment (id $existing)."
  else
    echo "::warning title=AgentSec compare::failed to update pull-request comment $existing"
  fi
else
  if gh api --method POST "repos/${GITHUB_REPOSITORY}/issues/${pr_number}/comments" -f body=@"$body_file" >/dev/null 2>&1; then
    echo "Posted a new AgentSec comparison comment."
  else
    echo "::warning title=AgentSec compare::failed to post a pull-request comment"
  fi
fi
exit 0
