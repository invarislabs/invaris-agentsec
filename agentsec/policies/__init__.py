import json
from pathlib import Path

from .loader import load_policy, parse_policy
from .schema import POLICY_VERSION, AgentConfig, Limits, Policy, PolicyError, Pricing

__all__ = ["POLICY_VERSION", "AgentConfig", "Limits", "Policy", "PolicyError", "Pricing",
           "load_policy", "parse_policy", "policy_json_schema"]


def policy_json_schema() -> dict:
    return json.loads((Path(__file__).parent / "policy.schema.json").read_text())
