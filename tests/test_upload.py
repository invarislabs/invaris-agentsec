"""`agentsec upload` and the Action's upload step, against a small local receiving server."""
import gzip
import json
import os
import shutil
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from agentsec.cli.main import main
from agentsec.upload import UploadError, ci_metadata, endpoint, strip_traces, upload

ROOT = Path(__file__).resolve().parent.parent
TOKEN = "asp_testtoken_0123456789"


class Receiver(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        if self.path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.2:9/steal")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        raw = self.rfile.read(int(self.headers["Content-Length"]))
        self.server.received.append({"path": self.path, "headers": dict(self.headers),
                                     "body": json.loads(gzip.decompress(raw))})
        if self.headers.get("Authorization") != "Bearer " + TOKEN:
            self._send(401, {"detail": "invalid token"})
        elif self.server.fail:
            self._send(413, {"detail": "report too large for this plan"})
        else:
            self._send(201, {"id": "r1", "url": "http://dash.test/p/demo/r/r1"})

    def _send(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def receiver():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
    srv.received, srv.fail = [], False
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    srv.url = "http://127.0.0.1:%d" % srv.server_address[1]
    yield srv
    srv.shutdown()


@pytest.fixture
def report_file(tmp_path):
    report = {"report_schema_version": "1", "tool": {"name": "invaris-agentsec", "version": "0.7.0"},
              "run_config": {"seed": 0, "policy": {"agent": {"name": "a", "endpoint": "http://x"}}},
              "summary": {"scenarios": 1, "findings": 0, "by_severity": {}},
              "findings": [],
              "scenarios": [{"id": "s/1", "category": "s", "title": "t", "vector": "direct", "status": "passed",
                             "finding_ids": [], "trace": {"outcome": "completed", "usage": {},
                                                          "events": [{"seq": 0, "type": "user_message", "content": "hi"}]}}]}
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report))
    return path


def test_upload_sends_gzip_json_with_bearer_token_and_metadata(receiver, report_file):
    result = upload(str(report_file), receiver.url, TOKEN, {"branch": "main", "label": "v3"})
    assert result["url"].endswith("/r/r1")
    got = receiver.received[0]
    assert got["path"] == "/api/v1/reports"
    assert got["headers"]["Content-Encoding"] == "gzip"
    assert got["body"]["metadata"] == {"branch": "main", "label": "v3"}
    assert got["body"]["report"]["scenarios"][0]["trace"]["events"][0]["content"] == "hi"


def test_no_traces_strips_transcripts_but_keeps_the_rest(receiver, report_file):
    upload(str(report_file), receiver.url, TOKEN, no_traces=True)
    trace = receiver.received[0]["body"]["report"]["scenarios"][0]["trace"]
    assert trace["events"] == [] and trace["events_stripped"] and trace["outcome"] == "completed"
    original = json.loads(report_file.read_text())
    assert strip_traces(original)["summary"] == original["summary"]


def test_bad_token_and_server_errors_are_explained(receiver, report_file):
    with pytest.raises(UploadError, match="rejected the token"):
        upload(str(report_file), receiver.url, "wrong", {})
    receiver.fail = True
    with pytest.raises(UploadError, match="HTTP 413: report too large"):
        upload(str(report_file), receiver.url, TOKEN, {})


def test_redirects_are_not_followed_with_the_token(receiver, report_file):
    with pytest.raises(UploadError, match="redirect"):
        upload(str(report_file), receiver.url + "/redirect", TOKEN, {})


def test_token_is_never_sent_over_plain_http_to_another_host():
    with pytest.raises(UploadError, match="plain HTTP"):
        endpoint("http://dashboard.example.com")
    assert endpoint("https://dashboard.example.com/") == "https://dashboard.example.com/api/v1/reports"
    assert endpoint("http://127.0.0.1:8000").startswith("http://127.0.0.1:8000/")
    with pytest.raises(UploadError):
        endpoint("ftp://x")


def test_missing_token_and_non_reports(tmp_path, report_file):
    with pytest.raises(UploadError, match="no token"):
        upload(str(report_file), "https://d.example", "", {})
    junk = tmp_path / "x.json"
    junk.write_text("[]")
    with pytest.raises(UploadError, match="not an AgentSec report"):
        upload(str(junk), "https://d.example", TOKEN, {})


def test_github_actions_metadata():
    env = {"GITHUB_ACTIONS": "true", "GITHUB_REF_NAME": "12/merge", "GITHUB_HEAD_REF": "fix-leak",
           "GITHUB_SHA": "abc123", "GITHUB_SERVER_URL": "https://github.com", "GITHUB_REPOSITORY": "o/r",
           "GITHUB_RUN_ID": "99", "GITHUB_EVENT_NAME": "pull_request"}
    assert ci_metadata(env) == {"branch": "fix-leak", "commit": "abc123", "ci_url": "https://github.com/o/r/actions/runs/99",
                                "repository": "o/r", "event": "pull_request"}
    assert ci_metadata({}) == {}


def test_cli_upload(receiver, report_file, monkeypatch, capsys):
    monkeypatch.setenv("AGENTSEC_TOKEN", TOKEN)
    assert main(["upload", str(report_file), "--server", receiver.url, "--label", "nightly"]) == 0
    assert "Uploaded" in capsys.readouterr().out
    assert receiver.received[0]["body"]["metadata"]["label"] == "nightly"
    monkeypatch.delenv("AGENTSEC_TOKEN")
    assert main(["upload", str(report_file), "--server", receiver.url]) == 2
    monkeypatch.delenv("AGENTSEC_SERVER", raising=False)
    assert main(["upload", str(report_file)]) == 2
    assert "AGENTSEC_SERVER" in capsys.readouterr().err


@pytest.mark.skipif(not shutil.which("bash"), reason="needs bash")
def test_action_upload_step_never_fails_the_job(receiver, report_file, tmp_path):
    def run(**env):
        e = dict(os.environ, PYTHONPATH=str(ROOT), AGENTSEC_BIN="%s -m agentsec" % sys.executable,
                 REPORT_PATH=str(report_file), AGENTSEC_SERVER=receiver.url)
        e.pop("AGENTSEC_TOKEN", None)
        e.update(env)
        return subprocess.run(["bash", str(ROOT / "action" / "upload-report.sh")], env=e, capture_output=True,
                              text=True, timeout=60)
    ok = run(AGENTSEC_TOKEN=TOKEN, NO_TRACES="true")
    assert ok.returncode == 0 and "Uploaded" in ok.stdout
    assert receiver.received[-1]["body"]["report"]["scenarios"][0]["trace"]["events"] == []
    bad = run(AGENTSEC_TOKEN="wrong")
    assert bad.returncode == 0 and "::warning::Upload" in bad.stdout
    none = run()
    assert none.returncode == 0 and "dashboard-token is empty" in none.stdout
    missing = run(AGENTSEC_TOKEN=TOKEN, REPORT_PATH=str(tmp_path / "nope.json"))
    assert missing.returncode == 0 and "nothing to upload" in missing.stdout
