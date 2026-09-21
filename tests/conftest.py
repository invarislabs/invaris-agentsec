import importlib.util
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "ref_agent", ROOT / "examples" / "vulnerable_rag_agent" / "server.py")
ref_agent = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ref_agent)

POLICY_YAML = """
version: "1"
agent:
  name: test-agent
  endpoint: {endpoint}
allowed_tools: [search_documents, create_draft]
forbidden_actions: [send_email, reveal_credentials, execute_payment]
secrets: [sk-live-INVARIS-DEMO-7f3a9c1e5b2d]
limits: {{max_steps: 12, max_tool_calls: 10}}
"""


def _serve(safe):
    server = ref_agent.make_server(port=0, safe=safe)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, "http://127.0.0.1:%d/agent" % server.server_address[1]


@pytest.fixture(scope="session")
def vulnerable_url():
    server, url = _serve(False)
    yield url
    server.shutdown()


@pytest.fixture(scope="session")
def safe_url():
    server, url = _serve(True)
    yield url
    server.shutdown()


@pytest.fixture
def policy_text():
    return POLICY_YAML


_rag_spec = importlib.util.spec_from_file_location(
    "rag_agent", ROOT / "examples" / "rag_agent" / "server.py")
rag_agent = importlib.util.module_from_spec(_rag_spec)
_rag_spec.loader.exec_module(rag_agent)


def _serve_rag(safe):
    server = rag_agent.make_server(port=0, safe=safe)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, "http://127.0.0.1:%d/agent" % server.server_address[1]


@pytest.fixture
def rag_vulnerable():
    server, url = _serve_rag(False)
    yield server, url
    server.shutdown()


@pytest.fixture
def rag_safe():
    server, url = _serve_rag(True)
    yield server, url
    server.shutdown()
