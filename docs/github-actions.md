# GitHub Actions

AgentSec ships a composite GitHub Action (`action.yml` at the repo root) that installs AgentSec,
optionally starts your agent, runs the suite, uploads the reports and fails the job if findings meet
your threshold.

## Usage

```yaml
name: agent-security
on: [pull_request]
permissions:
  contents: read
jobs:
  agentsec:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: invarislabs/invaris-agentsec@main   # adjust to where you host this repo
        with:
          policy: agentsec.yaml
          fail-on: high
          start-command: python my_agent/server.py --port 8000
          wait-for-url: http://127.0.0.1:8000/
```

If your agent is already running (a staging URL in the policy), omit `start-command`.

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `policy` | `agentsec.yaml` | Policy file |
| `fail-on` | `low` | Severity threshold (`low`, `medium`, `high`, `critical`, `none`) |
| `seed` | `0` | Scenario seed |
| `formats` | `json,html,markdown` | Report formats, comma-separated: `json`, `html`, `markdown`, `sarif`. Add `sarif` for [GitHub Code Scanning](#github-code-scanning-sarif) |
| `judge` | empty | Set to enable the model-assisted judge |
| `start-command` | empty | Command that starts the agent in the background |
| `wait-for-url` | empty | URL polled until the agent answers (any HTTP response counts) |
| `wait-timeout` | `60` | Seconds to wait for the agent |
| `working-directory` | `.` | Where to run |
| `out` | `.agentsec` | Report directory |
| `python-version` | `3.11` | Python to set up (empty to skip) |
| `package` | action checkout | What to `pip install` |
| `extra-args` | empty | Extra `agentsec test` arguments, e.g. `-s prompt_injection/ignore_previous` |
| `upload-artifact` | `true` | Upload the report directory |
| `artifact-name` | `agentsec-reports` | Artifact name |
| `baseline-report` | empty | Path to an earlier `report.json` to compare this run against. See [Pull-request and scheduled regression testing](#pull-request-and-scheduled-regression-testing) |
| `compare-fail-on` | `low` | Fail the job if a new or worsened finding at or above this severity exists. Only used with `baseline-report` |
| `pr-comment` | `true` | On a `pull_request` event, post or update a comment with the comparison. Only used with `baseline-report` |
| `github-token` | the job's own token | Token used to post the comment |
| `comment-marker` | `default` | Distinguishes this action's comment from others in the same workflow, e.g. across a matrix |

## Outputs

`exit-code` (0 clean, 1 findings at or above threshold, 2 config/connection error), `findings`,
`scenarios`, `report-dir`, `compare-exit-code` (0 clean, 1 regressions, 2 error, empty if no `baseline-report` was given).

## Pull-request and scheduled regression testing

Set `baseline-report` to an earlier `report.json` and the action runs `agentsec compare` against it after
the suite, in addition to the usual absolute `fail-on` threshold. This is for catching regressions rather
than every existing finding: a policy that already tolerates some medium-severity findings can still fail
a pull request that makes something new or worse.

```yaml
name: agent-security
on:
  pull_request:
  schedule:
    - cron: "0 6 * * *"   # also run nightly against main, catching drift with no pull request involved
permissions:
  contents: read
  pull-requests: write   # only needed for the pull-request comment
jobs:
  baseline:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: {ref: main}
      - uses: invarislabs/invaris-agentsec@main
        with:
          start-command: python my_agent/server.py --port 8000
          wait-for-url: http://127.0.0.1:8000/
          out: .agentsec/baseline
          fail-on: none          # this run is only to produce a baseline report, not to gate anything
          artifact-name: agentsec-baseline
  agentsec:
    needs: baseline
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4    # the pull request's own ref
      - uses: invarislabs/invaris-agentsec@main
        with:
          start-command: python my_agent/server.py --port 8000
          wait-for-url: http://127.0.0.1:8000/
          baseline-report: .agentsec/baseline/report.json   # from an artifact download, or a prior job/step
          compare-fail-on: high
```

The example above builds the baseline by checking out `main` in one job and the pull request in another;
a workflow that keeps its baseline report elsewhere (an artifact from the last `main` build, a file checked
into the repo, cloud storage) can skip the `baseline` job and pass that path directly. `needs:`/artifact
download between jobs, or a `git show main:...` step, are ordinary workflow plumbing, not part of this action.

On a `pull_request` event, a comment is posted with the new, fixed and changed findings, and updated in
place on later pushes (matched by an HTML marker, `comment-marker` if you need more than one per PR). It
uses the `gh` CLI (preinstalled on GitHub-hosted runners) and the job's own token by default; set
`github-token` for a token with different permissions, and the job needs `pull-requests: write`. A forked
pull request's default token often can't comment; the step warns and continues rather than failing the
job for that reason alone. Set `pr-comment: false` to only gate the job and skip the comment, which is
what `.github/workflows/ci.yml`'s own comparison job does, since it must not post on this project's real
pull requests.

## GitHub Code Scanning (SARIF)

Add `sarif` to `formats` and AgentSec writes `results.sarif` alongside the other reports (SARIF 2.1.0:
one rule per finding type, one result per finding, `critical`/`high` mapped to `error`, `medium` to
`warning`, `low` to `note`). Upload it with `github/codeql-action/upload-sarif` to see findings in the
repository's **Security > Code scanning** tab, with each one linked back to its scenario and OWASP
Agentic Security Initiative category:

```yaml
permissions:
  contents: read
  security-events: write   # required to upload SARIF
jobs:
  agentsec:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: invarislabs/invaris-agentsec@main
        id: agentsec
        with:
          formats: json,html,markdown,sarif
          fail-on: none          # let Code Scanning surface findings; don't also fail the step here
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: ${{ steps.agentsec.outputs.report-dir }}/results.sarif
```

Set `fail-on: none` (or a threshold looser than what you want Code Scanning to police) when you'd rather
findings surface as code-scanning alerts than fail the step directly; keep the usual `fail-on` if you want
both. `security-events: write` is required for the upload step and is not implied by `contents: read`.
SARIF is additive: it changes nothing about the other formats, `compare-report.sh`, or the PR comment.

This repo runs exactly this setup on itself: see `.github/workflows/self-scan.yml` for a complete, working example, and its [findings](https://github.com/invarislabs/invaris-agentsec/security/code-scanning) for what the result looks like.

## How it works

Logic lives in scripts under `action/` (`start-agent.sh`, `run-agentsec.sh`, `stop-agent.sh`,
`compare-report.sh`, `pr-comment.sh`) so it can be tested locally. Inputs reach scripts through `env:` and
are never interpolated into `run:` text, which prevents script injection through input values. Steps never
fail by themselves: reports are uploaded first, and a final gate step fails the job from the recorded exit
codes. The agent is always stopped (`if: always()`).

## Verification status

The scripts are exercised by `tests/test_action_scripts.py` against the real reference agents (and, for
`pr-comment.sh`, against a fake `gh` binary, since no real GitHub API call is made in tests), and the YAML
wiring is checked structurally, and `tests/test_sarif_report.py` checks the SARIF output's shape and
validity in isolation.

`.github/workflows/self-scan.yml`, in this repo, is the real-world check for the rest: it calls the Action
the way an outside project actually would (`uses: invarislabs/invaris-agentsec@main`, not the `uses: ./`
that `ci.yml` uses to test the Action's own code from inside this repo), against the bundled vulnerable
reference agent, and uploads the SARIF output to this repo's own **Security > Code Scanning** tab. Its
latest run is under the [Actions tab](https://github.com/invarislabs/invaris-agentsec/actions/workflows/self-scan.yml),
and the findings it reports are visible under [Security > Code scanning](https://github.com/invarislabs/invaris-agentsec/security/code-scanning) --
both are the live proof that the packaged Action and the SARIF/Code Scanning path work end to end for a
real, external consumer of the Action, not just inside this repo's own test suite. A real posted or updated
pull-request comment from `baseline-report` is the one piece still unverified on real GitHub Actions.
