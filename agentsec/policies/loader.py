from __future__ import annotations

from typing import Any, Dict, List, Optional

import yaml

from .schema import POLICY_VERSION, AgentConfig, Limits, Policy, PolicyError, Pricing, _sha

_TOP = {"version", "agent", "allowed_tools", "forbidden_actions", "secrets", "limits", "tests"}
_AGENT = {"name", "endpoint", "model", "api_key_env", "headers", "timeout_s",
          "declare_tools", "retrieval_tools", "pricing"}
_LIMITS = {"max_steps", "max_tool_calls", "max_repeated_calls", "max_tokens",
           "max_seconds", "max_cost_usd"}
_PRICING = {"input_per_1k", "output_per_1k"}


def _check_keys(section: str, data: Dict[str, Any], allowed: set) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise PolicyError("unknown key(s) in %s: %s (allowed: %s)"
                          % (section, ", ".join(unknown), ", ".join(sorted(allowed))))


def _mapping(section: str, value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise PolicyError("%s must be a mapping" % section)
    return value


def _str_list(section: str, value: Any) -> List[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise PolicyError("%s must be a list of non-empty strings" % section)
    return list(value)


def _number(section: str, value: Any, *, integer: bool = False, minimum: float = 0) -> Any:
    ok = isinstance(value, (int, float)) and not isinstance(value, bool)
    if integer:
        ok = ok and isinstance(value, int)
    if not ok or value < minimum:
        raise PolicyError("%s must be a %snumber >= %s" % (section, "whole " if integer else "", minimum))
    return value


def parse_policy(text: str) -> Policy:
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyError("policy is not valid YAML: %s" % exc)
    raw = _mapping("policy", raw if raw is not None else {})
    _check_keys("policy", raw, _TOP)

    version = str(raw.get("version", POLICY_VERSION))
    if version != POLICY_VERSION:
        raise PolicyError("unsupported policy version %r (this AgentSec understands %r)"
                          % (version, POLICY_VERSION))

    if "agent" not in raw:
        raise PolicyError("`agent` section is required")
    a = _mapping("agent", raw["agent"])
    _check_keys("agent", a, _AGENT)
    for req in ("name", "endpoint"):
        if not isinstance(a.get(req), str) or not a[req]:
            raise PolicyError("agent.%s is required and must be a string" % req)
    if not a["endpoint"].startswith(("http://", "https://")):
        raise PolicyError("agent.endpoint must start with http:// or https://")

    pricing: Optional[Pricing] = None
    if "pricing" in a:
        p = _mapping("agent.pricing", a["pricing"])
        _check_keys("agent.pricing", p, _PRICING)
        pricing = Pricing(
            input_per_1k=float(_number("agent.pricing.input_per_1k", p.get("input_per_1k", 0))),
            output_per_1k=float(_number("agent.pricing.output_per_1k", p.get("output_per_1k", 0))),
        )
    headers = a.get("headers", {})
    if not isinstance(headers, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in headers.items()):
        raise PolicyError("agent.headers must be a mapping of strings")

    agent = AgentConfig(
        name=a["name"], endpoint=a["endpoint"],
        model=str(a.get("model", "agentsec-target")),
        api_key_env=a.get("api_key_env"), headers=dict(headers),
        timeout_s=float(_number("agent.timeout_s", a.get("timeout_s", 30), minimum=0.1)),
        declare_tools=bool(a.get("declare_tools", True)),
        retrieval_tools=_str_list("agent.retrieval_tools", a.get("retrieval_tools", [])),
        pricing=pricing,
    )

    lim = _mapping("limits", raw.get("limits", {}))
    _check_keys("limits", lim, _LIMITS)
    limits = Limits()
    for key in ("max_steps", "max_tool_calls", "max_repeated_calls", "max_tokens"):
        if key in lim:
            setattr(limits, key, _number("limits.%s" % key, lim[key], integer=True, minimum=1))
    for key in ("max_seconds", "max_cost_usd"):
        if key in lim:
            setattr(limits, key, float(_number("limits.%s" % key, lim[key], minimum=0)))

    allowed = raw.get("allowed_tools")
    return Policy(
        agent=agent,
        allowed_tools=_str_list("allowed_tools", allowed) if allowed is not None else None,
        forbidden_actions=_str_list("forbidden_actions", raw.get("forbidden_actions", [])),
        secrets=_str_list("secrets", raw.get("secrets", [])),
        limits=limits,
        tests=_str_list("tests", raw.get("tests", [])),
        version=version,
        source_sha256=_sha(text),
    )


def load_policy(path: str) -> Policy:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise PolicyError("cannot read policy file %s: %s" % (path, exc))
    return parse_policy(text)
