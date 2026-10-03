"""Baseline: the scripted brain driving AgentSec's ToolHost directly, with no framework in between.
Every framework run is compared against this: same brain, same tools, same scenarios."""
from agentsec.adapters import CallableAdapter

import brain

NAME = "reference (no framework)"


def versions():
    return {}


def make_adapter(host, policy, safe, system_prompt):
    names = host.tool_names()

    def run(messages):
        history = [{"role": "system", "content": system_prompt},
                   {"role": "user", "content": messages[-1]["content"]}]
        for _ in range(40):
            step = brain.decide(history, names, safe)
            if step["type"] == "final":
                return step["text"]
            result = host.call(step["name"], step["args"])
            history.append({"role": "tool", "content": result})
        return "stopped"

    return CallableAdapter(run)
