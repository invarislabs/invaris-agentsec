"""Run AgentSec's memory scenarios against an agent whose memory is a real memory library.

    <venv>/bin/python benchmarks/memory-systems/run.py <dict|mem0|langgraph>

For each agent configuration (memory_agent.CONFIGS) a fresh backend is created and the scenarios run.
Writes results/<backend>.json.
"""
import json
import os
import sys
import time
from importlib.metadata import PackageNotFoundError, version

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from agentsec.adapters import CallableAdapter  # noqa: E402
from agentsec.policies import load_policy  # noqa: E402
from agentsec.runners import run_suite  # noqa: E402

import backends  # noqa: E402
import memory_agent  # noqa: E402

SCENARIOS = ["memory_poisoning", "identity_and_session_confusion/credential_from_other_session"]
PACKAGES = {"mem0": ["mem0ai", "qdrant-client"], "langgraph": ["langgraph"], "dict": []}


def main(backend_name: str):
    policy = load_policy(os.path.join(HERE, "policy.yaml"))
    vers = {}
    for p in PACKAGES[backend_name]:
        try:
            vers[p] = version(p)
        except PackageNotFoundError:
            pass
    out = {"backend": backend_name, "versions": vers, "configs": {}}
    for cfg_name, cfg in memory_agent.CONFIGS.items():
        backend = backends.BACKENDS[backend_name]()
        start = time.time()
        suite = run_suite(policy, CallableAdapter(memory_agent.make_agent(backend, cfg)), seed=0,
                          categories=["memory_poisoning", "identity_and_session_confusion"], only=SCENARIOS)
        out["backend_label"] = backend.name
        out["configs"][cfg_name] = {"config": cfg, "seconds": round(time.time() - start, 2), "scenarios": {
            r.scenario.id: {"status": r.status, "rules": sorted({f.rule for f in r.findings})} for r in suite.results}}
    os.makedirs(os.path.join(HERE, "results"), exist_ok=True)
    with open(os.path.join(HERE, "results", backend_name + ".json"), "w") as fh:
        json.dump(out, fh, indent=1, sort_keys=True)
        fh.write("\n")
    for cfg_name, r in out["configs"].items():
        print("%-10s %-17s" % (backend_name, cfg_name),
              {k.split("/")[1]: (v["rules"] or v["status"]) for k, v in r["scenarios"].items()})


if __name__ == "__main__":
    main(sys.argv[1])
