"""Tests for the GitHub Action: its helper scripts (run for real) and the action.yml wiring."""
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
ACTION = ROOT / "action"
pytestmark = pytest.mark.skipif(not (shutil.which("bash") and shutil.which("curl")),
                                reason="needs bash and curl")

POLICY = """
agent: {{name: t, endpoint: 'http://127.0.0.1:{port}/agent'}}
allowed_tools: [search_documents, create_draft]
forbidden_actions: [send_email, reveal_credentials, execute_payment]
secrets: [sk-live-INVARIS-DEMO-7f3a9c1e5b2d]
tests: [prompt_injection]
"""


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def env_for(tmp_path, **extra):
    env = dict(os.environ)
    env.update(RUNNER_TEMP=str(tmp_path), GITHUB_OUTPUT=str(tmp_path / "out.txt"),
               PYTHONPATH=str(ROOT) + os.pathsep + env.get("PYTHONPATH", ""),
               AGENTSEC_BIN="%s -m agentsec" % sys.executable)
    env.pop("GITHUB_ACTIONS", None)
    env.update({k: str(v) for k, v in extra.items()})
    return env


def sh(script, env, cwd):
    return subprocess.run(["bash", str(ACTION / script)], env=env, cwd=str(cwd),
                          capture_output=True, text=True, timeout=90)


def outputs(tmp_path):
    lines = (tmp_path / "out.txt").read_text().splitlines()
    return dict(l.split("=", 1) for l in lines)


def agent_cmd(port, safe=False):
    return "%s %s --port %d%s" % (sys.executable, ROOT / "examples/vulnerable_rag_agent/server.py",
                                  port, " --safe" if safe else "")


@pytest.fixture
def workdir(tmp_path):
    return tmp_path


def start(workdir, port, safe=False, **extra):
    return sh("start-agent.sh", env_for(workdir, START_COMMAND=agent_cmd(port, safe),
                                        WAIT_URL="http://127.0.0.1:%d/" % port, WAIT_TIMEOUT=20, **extra),
              workdir)


def test_full_cycle_vulnerable_agent_exit_1_and_reports(workdir):
    port = free_port()
    (workdir / "agentsec.yaml").write_text(POLICY.format(port=port))
    started = start(workdir, port)
    try:
        assert started.returncode == 0, started.stdout + started.stderr
        assert "reachable" in started.stdout
        res = sh("run-agentsec.sh", env_for(workdir, POLICY="agentsec.yaml", FAIL_ON="low", SEED=0,
                                            FORMATS="json,markdown", OUT=".agentsec"), workdir)
        assert res.returncode == 0  # the step itself never fails; the final gate does
        out = outputs(workdir)
        assert out["exit-code"] == "1" and int(out["findings"]) > 0 and out["scenarios"] == "5"
        assert (workdir / ".agentsec/report.json").exists() and (workdir / ".agentsec/summary.md").exists()
        assert "found issues" in res.stdout
    finally:
        stopped = sh("stop-agent.sh", env_for(workdir), workdir)
    assert stopped.returncode == 0 and "Stopped" in stopped.stdout


def test_safe_agent_exit_0_and_fail_on_threshold(workdir):
    port = free_port()
    (workdir / "agentsec.yaml").write_text(POLICY.format(port=port))
    assert start(workdir, port, safe=True).returncode == 0
    try:
        res = sh("run-agentsec.sh", env_for(workdir, POLICY="agentsec.yaml", OUT="o1"), workdir)
        assert outputs(workdir)["exit-code"] == "0" and "no findings" in res.stdout
    finally:
        sh("stop-agent.sh", env_for(workdir), workdir)


def test_fail_on_none_and_extra_args(workdir):
    port = free_port()
    (workdir / "agentsec.yaml").write_text(POLICY.format(port=port))
    assert start(workdir, port).returncode == 0
    try:
        sh("run-agentsec.sh", env_for(workdir, POLICY="agentsec.yaml", OUT="o", FAIL_ON="none",
                                      EXTRA_ARGS="-s prompt_injection/ignore_previous"), workdir)
        out = outputs(workdir)
        assert out["exit-code"] == "0" and out["scenarios"] == "1" and int(out["findings"]) >= 1
    finally:
        sh("stop-agent.sh", env_for(workdir), workdir)


def test_unreachable_agent_reports_exit_code_2(workdir):
    (workdir / "agentsec.yaml").write_text(POLICY.format(port=free_port()))
    res = sh("run-agentsec.sh", env_for(workdir, POLICY="agentsec.yaml", OUT="o"), workdir)
    assert res.returncode == 0 and outputs(workdir)["exit-code"] == "2"
    assert "could not complete" in res.stdout


def test_bad_policy_reports_exit_code_2(workdir):
    (workdir / "agentsec.yaml").write_text("not: [valid")
    sh("run-agentsec.sh", env_for(workdir, POLICY="agentsec.yaml", OUT="o"), workdir)
    out = outputs(workdir)
    assert out["exit-code"] == "2" and out["findings"] == ""


def test_start_without_command_is_a_noop(workdir):
    res = sh("start-agent.sh", env_for(workdir), workdir)
    assert res.returncode == 0 and "already running" in res.stdout
    assert not (workdir / "agentsec-agent.pid").exists()


def test_start_fails_when_process_exits_early(workdir):
    res = sh("start-agent.sh", env_for(workdir, START_COMMAND="echo boom; exit 3",
                                       WAIT_URL="http://127.0.0.1:%d/" % free_port(), WAIT_TIMEOUT=20), workdir)
    assert res.returncode == 1 and "exited before" in res.stdout and "boom" in res.stdout


def test_start_times_out_when_agent_never_answers(workdir):
    t0 = time.time()
    res = sh("start-agent.sh", env_for(workdir, START_COMMAND="sleep 30",
                                       WAIT_URL="http://127.0.0.1:%d/" % free_port(), WAIT_TIMEOUT=2), workdir)
    assert res.returncode == 1 and "Timed out" in res.stdout and time.time() - t0 < 20
    sh("stop-agent.sh", env_for(workdir), workdir)


def test_stop_kills_the_whole_process_tree(workdir):
    # the started shell spawns a child; both must die
    res = sh("start-agent.sh", env_for(workdir, START_COMMAND="sleep 60 & wait"), workdir)
    assert res.returncode == 0
    pid = int((workdir / "agentsec-agent.pid").read_text())
    time.sleep(0.5)
    children = subprocess.run(["pgrep", "-g", str(pid)], capture_output=True, text=True).stdout.split()
    assert len(children) >= 2
    sh("stop-agent.sh", env_for(workdir), workdir)
    time.sleep(0.5)
    for c in children:
        with pytest.raises(ProcessLookupError):
            os.kill(int(c), 0) if not _is_zombie(int(c)) else (_ for _ in ()).throw(ProcessLookupError())
    assert not (workdir / "agentsec-agent.pid").exists()


def _is_zombie(pid):
    try:
        return Path("/proc/%d/stat" % pid).read_text().split(")")[-1].split()[0] == "Z"
    except OSError:
        return False


def test_stop_is_safe_when_nothing_was_started(workdir):
    assert sh("stop-agent.sh", env_for(workdir), workdir).returncode == 0


# --- compare-report.sh ----------------------------------------------------------

def _report(findings, scenarios=("a",), seed=0):
    return json.dumps({"run_config": {"seed": seed, "policy": {}},
                       "findings": findings, "scenarios": [{"id": s, "status": "passed"} for s in scenarios]})


def _finding(sid="a", rule="r", sev="high"):
    return {"id": "%s:%s" % (sid, rule), "rule": rule, "scenario_id": sid, "severity": sev, "title": "t"}


def compare_env(workdir, **extra):
    return env_for(workdir, GITHUB_STEP_SUMMARY=str(workdir / "summary.md"), **extra)


def test_compare_report_without_baseline_is_a_noop(workdir):
    res = sh("compare-report.sh", compare_env(workdir), workdir)
    assert res.returncode == 0 and "No baseline-report" in res.stdout
    out = outputs(workdir)
    assert out["compare-exit-code"] == "" and out["compare-summary-path"] == ""


def test_compare_report_missing_baseline_file(workdir):
    (workdir / ".agentsec").mkdir()
    (workdir / ".agentsec/report.json").write_text(_report([]))
    res = sh("compare-report.sh", compare_env(workdir, BASELINE_REPORT=str(workdir / "nope.json")), workdir)
    assert res.returncode == 0 and outputs(workdir)["compare-exit-code"] == "2"
    assert "does not exist" in res.stdout


def test_compare_report_missing_current_file(workdir):
    (workdir / "baseline.json").write_text(_report([]))
    res = sh("compare-report.sh", compare_env(workdir, BASELINE_REPORT=str(workdir / "baseline.json"),
                                              CURRENT_REPORT=str(workdir / "nope.json")), workdir)
    assert res.returncode == 0 and outputs(workdir)["compare-exit-code"] == "2"


def test_compare_report_clean_run_exits_0(workdir):
    (workdir / "baseline.json").write_text(_report([_finding()]))
    (workdir / "current.json").write_text(_report([_finding()]))
    res = sh("compare-report.sh", compare_env(workdir, BASELINE_REPORT=str(workdir / "baseline.json"),
                                              CURRENT_REPORT=str(workdir / "current.json")), workdir)
    out = outputs(workdir)
    assert res.returncode == 0 and out["compare-exit-code"] == "0"
    assert Path(out["compare-summary-path"]).read_text()
    assert "AgentSec regression comparison" in (workdir / "summary.md").read_text()


def test_compare_report_regression_sets_exit_code_1(workdir):
    (workdir / "baseline.json").write_text(_report([]))
    (workdir / "current.json").write_text(_report([_finding()]))
    res = sh("compare-report.sh", compare_env(workdir, BASELINE_REPORT=str(workdir / "baseline.json"),
                                              CURRENT_REPORT=str(workdir / "current.json")), workdir)
    assert res.returncode == 0  # the step itself never fails
    out = outputs(workdir)
    assert out["compare-exit-code"] == "1"
    assert "New" in Path(out["compare-summary-path"]).read_text()


def test_compare_report_respects_compare_fail_on(workdir):
    (workdir / "baseline.json").write_text(_report([]))
    (workdir / "current.json").write_text(_report([_finding(sev="medium")]))
    res = sh("compare-report.sh", compare_env(workdir, BASELINE_REPORT=str(workdir / "baseline.json"),
                                              CURRENT_REPORT=str(workdir / "current.json"),
                                              COMPARE_FAIL_ON="critical"), workdir)
    assert res.returncode == 0 and outputs(workdir)["compare-exit-code"] == "0"


def test_compare_report_malformed_baseline_is_exit_2(workdir):
    (workdir / "baseline.json").write_text("not json")
    (workdir / "current.json").write_text(_report([]))
    res = sh("compare-report.sh", compare_env(workdir, BASELINE_REPORT=str(workdir / "baseline.json"),
                                              CURRENT_REPORT=str(workdir / "current.json")), workdir)
    assert res.returncode == 0 and outputs(workdir)["compare-exit-code"] == "2"


# --- pr-comment.sh ---------------------------------------------------------------

FAKE_GH = r"""#!/usr/bin/env python3
import json, os, sys

with open(os.environ["FAKE_GH_LOG"], "a", encoding="utf-8") as fh:
    fh.write(json.dumps(sys.argv[1:]) + "\n")

args = sys.argv[1:]
if "--method" in args:
    print(json.dumps({"id": 999}))
else:
    print(os.environ.get("FAKE_GH_EXISTING_ID", ""))
"""


def install_fake_gh(bindir):
    bindir.mkdir(exist_ok=True)
    path = bindir / "gh"
    path.write_text(FAKE_GH)
    path.chmod(0o755)
    return path


def path_without_gh(tmp_path):
    """A PATH with only bash and python3 on it (symlinked from wherever they really live), and no gh.

    A GitHub-hosted runner has gh preinstalled, so merely prepending an empty directory to the real
    PATH does not hide it. Build PATH from scratch instead, so the "no gh" case is reproducible
    locally and in CI alike.
    """
    bindir = tmp_path / "no_gh_bin"
    bindir.mkdir(exist_ok=True)
    for name in ("bash", "sh", "python3"):
        real = shutil.which(name)
        if real:
            link = bindir / name
            if not link.exists():
                link.symlink_to(real)
    return str(bindir)


def pr_env(workdir, bindir, event, **extra):
    event_path = workdir / "event.json"
    event_path.write_text(json.dumps({"pull_request": {"number": 42}}) if event.startswith("pull_request") else "{}")
    env = env_for(workdir, GITHUB_EVENT_NAME=event, GITHUB_EVENT_PATH=str(event_path),
                 GITHUB_REPOSITORY="acme/agentsec", GITHUB_TOKEN="tok", FAKE_GH_LOG=str(workdir / "gh.log"), **extra)
    env["PATH"] = str(bindir) + os.pathsep + env["PATH"]
    return env


def test_pr_comment_skips_without_a_summary(workdir):
    res = sh("pr-comment.sh", env_for(workdir), workdir)
    assert res.returncode == 0 and "No comparison summary" in res.stdout


def test_pr_comment_skips_on_non_pull_request_events(workdir):
    summary = workdir / "summary.txt"
    summary.write_text("hello")
    res = sh("pr-comment.sh", env_for(workdir, SUMMARY_PATH=str(summary), GITHUB_EVENT_NAME="push"), workdir)
    assert res.returncode == 0 and "skipping" in res.stdout


def test_pr_comment_skips_without_gh_or_token(workdir, tmp_path):
    summary = workdir / "summary.txt"
    summary.write_text("hello")
    env = env_for(workdir, SUMMARY_PATH=str(summary), GITHUB_EVENT_NAME="pull_request",
                 GITHUB_EVENT_PATH=str(workdir / "event.json"))
    (workdir / "event.json").write_text(json.dumps({"pull_request": {"number": 1}}))
    env["PATH"] = path_without_gh(tmp_path)  # no gh reachable, but bash and python3 still resolvable
    res = sh("pr-comment.sh", env, workdir)
    assert res.returncode == 0 and "gh CLI is not available" in res.stdout

    env2 = env_for(workdir, SUMMARY_PATH=str(summary), GITHUB_EVENT_NAME="pull_request",
                   GITHUB_EVENT_PATH=str(workdir / "event.json"), GITHUB_TOKEN="")
    bindir = tmp_path / "bin"
    install_fake_gh(bindir)
    env2["PATH"] = str(bindir) + os.pathsep + env2["PATH"]
    res2 = sh("pr-comment.sh", env2, workdir)
    assert res2.returncode == 0 and "no github-token" in res2.stdout


def test_pr_comment_posts_a_new_comment_when_none_exists(workdir, tmp_path):
    summary = workdir / "summary.txt"
    summary.write_text("### findings\n- one")
    bindir = tmp_path / "bin1"
    install_fake_gh(bindir)
    env = pr_env(workdir, bindir, "pull_request", SUMMARY_PATH=str(summary), FAKE_GH_EXISTING_ID="")
    res = sh("pr-comment.sh", env, workdir)
    assert res.returncode == 0 and "Posted a new" in res.stdout
    calls = [json.loads(l) for l in (workdir / "gh.log").read_text().splitlines()]
    assert calls[0][:2] == ["api", "repos/acme/agentsec/issues/42/comments"]
    assert calls[1][:3] == ["api", "--method", "POST"]
    body_arg = next(a for a in calls[1] if a.startswith("body=@"))
    body_text = Path(body_arg[len("body=@"):]).read_text()
    assert "agentsec-compare:default" in body_text and "one" in body_text


def test_pr_comment_updates_an_existing_comment(workdir, tmp_path):
    summary = workdir / "summary.txt"
    summary.write_text("### findings\n- two")
    bindir = tmp_path / "bin2"
    install_fake_gh(bindir)
    env = pr_env(workdir, bindir, "pull_request_target", SUMMARY_PATH=str(summary), FAKE_GH_EXISTING_ID="555",
                comment_marker="matrix-a")
    env["COMMENT_MARKER_KEY"] = "matrix-a"
    res = sh("pr-comment.sh", env, workdir)
    assert res.returncode == 0 and "Updated the existing" in res.stdout
    calls = [json.loads(l) for l in (workdir / "gh.log").read_text().splitlines()]
    assert calls[1][:4] == ["api", "--method", "PATCH", "repos/acme/agentsec/issues/comments/555"]
    body_arg = next(a for a in calls[1] if a.startswith("body=@"))
    assert "agentsec-compare:matrix-a" in Path(body_arg[len("body=@"):]).read_text()


# --- action.yml / ci.yml wiring ------------------------------------------------

def load(path):
    return yaml.safe_load((ROOT / path).read_text())


def test_scripts_exist_are_executable_and_valid_bash():
    for name in ("start-agent.sh", "stop-agent.sh", "run-agentsec.sh", "compare-report.sh", "pr-comment.sh"):
        path = ACTION / name
        assert path.exists() and os.access(path, os.X_OK)
        assert subprocess.run(["bash", "-n", str(path)]).returncode == 0


def test_every_input_reference_is_declared_and_every_input_used():
    text = (ROOT / "action.yml").read_text()
    declared = set(load("action.yml")["inputs"])
    used = set(re.findall(r"inputs\.([a-z-]+)", text))
    assert used <= declared, used - declared
    assert declared <= used, "unused inputs: %s" % (declared - used)


def test_steps_wire_scripts_and_outputs():
    action = load("action.yml")
    steps = action["runs"]["steps"]
    assert action["runs"]["using"] == "composite"
    assert all("shell" in s for s in steps if "run" in s)
    text = (ROOT / "action.yml").read_text()
    for script in ("start-agent.sh", "stop-agent.sh", "run-agentsec.sh", "compare-report.sh", "pr-comment.sh"):
        assert "action/%s" % script in text
    ids = {s.get("id") for s in steps}
    assert "run" in ids
    step_for_output = {"compare-exit-code": "compare"}
    for name, out in action["outputs"].items():
        step_id = step_for_output.get(name, "run")
        assert "steps.%s.outputs." % step_id in out["value"], (name, out["value"])
    # cleanup and upload must still run when the tests fail
    by_name = {s["name"]: s for s in steps}
    assert "always()" in by_name["Stop the agent"]["if"]
    assert "always()" in by_name["Upload reports"]["if"]
    # the gate is last so reports are uploaded before the job fails
    assert steps[-1]["name"].startswith("Fail the job")


def test_run_step_outputs_match_what_the_script_writes():
    scripts = {"run-agentsec.sh": (ACTION / "run-agentsec.sh").read_text(),
              "compare-report.sh": (ACTION / "compare-report.sh").read_text()}
    by_output_key = {"exit-code": "run-agentsec.sh", "report-dir": "run-agentsec.sh",
                     "findings": "run-agentsec.sh", "scenarios": "run-agentsec.sh",
                     "compare-exit-code": "compare-report.sh"}
    for key in load("action.yml")["outputs"]:
        assert 'echo "%s=' % key in scripts[by_output_key[key]], key


def test_inputs_are_passed_via_env_not_interpolated_into_shell():
    """Injection guard: untrusted input values must not be expanded inside `run:` scripts."""
    for step in load("action.yml")["runs"]["steps"]:
        run = step.get("run", "")
        assert "${{ inputs." not in run, step["name"]


def test_ci_workflow_uses_the_local_action_with_real_paths():
    wf = load(".github/workflows/ci.yml")
    assert {"test", "agentsec-passes-on-safe-agent", "agentsec-fails-on-vulnerable-agent",
            "agentsec-rag-example"} <= set(wf["jobs"])
    for job in wf["jobs"].values():
        for step in job["steps"]:
            if step.get("uses") == "./":
                policy = step["with"]["policy"]
                assert (ROOT / policy).exists(), policy
                cmd = step["with"]["start-command"]
                script = re.search(r"python (\S+\.py)", cmd).group(1)
                assert (ROOT / script).exists(), script
    assert wf["permissions"] == {"contents": "read"}
