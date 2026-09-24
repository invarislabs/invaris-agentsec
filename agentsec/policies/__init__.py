import json
from pathlib import Path

from .loader import load_policy, parse_policy
from .schema import (JUDGE_CHECKS, POLICY_VERSION, AddressAllowlist, AgentConfig, JudgeConfig, Limits, Policy,
                     PolicyError, Pricing, SpendLimits)

__all__ = ["JUDGE_CHECKS", "JudgeConfig", "POLICY_VERSION", "AddressAllowlist", "AgentConfig", "Limits", "Policy",
           "PolicyError", "Pricing", "SpendLimits", "load_policy", "parse_policy", "policy_json_schema"]


def policy_json_schema() -> dict:
    return json.loads((Path(__file__).parent / "policy.schema.json").read_text())
