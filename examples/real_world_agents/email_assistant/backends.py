"""Pluggable LLM backends for the reference email assistant.

The assistant itself does not decide anything: it asks a backend "given this conversation and
these tools, what next?" and forwards whatever the backend returns. Three backends ship here:

* `ScriptedBackend` -- a **test double**, not a model. It replays a fixed list of decisions (or
  calls a function you supply). Deterministic, offline, and used by the CI tests and the offline
  demo. A result produced with this backend says something about AgentSec's pipeline, never about
  any real model's robustness.
* `AnthropicBackend` -- the native Messages API (`POST {base}/v1/messages`).
* `OpenAICompatBackend` -- any OpenAI-compatible `POST {base}/chat/completions` endpoint (OpenAI,
  OpenRouter, vLLM, Ollama, LM Studio, Anthropic's OpenAI-compat layer, ...).

Standard library only -- no new dependencies. Configure a real backend with environment variables
(see `backend_from_env`); when none is configured, callers get `None` and should skip or fall back
to `ScriptedBackend` rather than inventing a result.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence

DEFAULT_ANTHROPIC_BASE = "https://api.anthropic.com"
DEFAULT_OPENAI_BASE = "https://api.openai.com/v1"
ANTHROPIC_VERSION = "2023-06-01"


class BackendError(RuntimeError):
    """The backend could not be reached or returned something unusable."""


@dataclass
class ToolRequest:
    name: str
    arguments: Dict[str, Any]
    id: str = ""


@dataclass
class Decision:
    """One step the backend decided on: free text, tool calls, or both."""
    content: Optional[str] = None
    tool_calls: List[ToolRequest] = field(default_factory=list)
    prompt_tokens: int = 0
    completion_tokens: int = 0
    # Set when a hardened guard refused to forward a tool call the model asked for.
    blocked: List[str] = field(default_factory=list)


class LLMBackend:
    name = "backend"

    def decide(self, system: str, messages: List[Dict[str, Any]],
               tools: List[Dict[str, Any]]) -> Decision:
        """`messages` is the OpenAI-style history AgentSec sends (user / assistant+tool_calls /
        tool). `tools` is the OpenAI function-definition list. Returns one `Decision`."""
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Test double
# ---------------------------------------------------------------------------

def describe(backend: "LLMBackend", name: str, hardened: bool) -> Dict[str, str]:
    """What this assistant reports about itself to AgentSec (`x_agentsec.agent`): which backend and
    model actually made the decisions -- "scripted" for a test double -- and never any credential."""
    info = {"name": name, "backend": getattr(backend, "name", "unknown"),
            "configuration": "hardened" if hardened else "baseline"}
    model = getattr(backend, "model", None)
    if isinstance(model, str) and model:
        info["model"] = model
    return info


class ScriptedBackend(LLMBackend):
    """Replays decisions. NOT a model.

    `script` is either a sequence of `Decision`s (consumed in order; the last one repeats once
    exhausted) or a callable `fn(system, messages, tools) -> Decision`, which lets a test express
    "whatever the history looks like, decide X" without pretending to be a model.
    """

    name = "scripted"

    def __init__(self, script):
        self._fn: Optional[Callable[..., Decision]] = script if callable(script) else None
        self._queue: List[Decision] = [] if self._fn else list(script)
        self.calls = 0

    def decide(self, system, messages, tools) -> Decision:
        self.calls += 1
        if self._fn is not None:
            out = self._fn(system, messages, tools)
        elif not self._queue:
            out = Decision(content="done")
        else:
            out = self._queue[0] if len(self._queue) == 1 else self._queue.pop(0)
        if not isinstance(out, Decision):
            raise BackendError("ScriptedBackend expects Decision objects, got %s" % type(out).__name__)
        return out


# ---------------------------------------------------------------------------
# Real backends
# ---------------------------------------------------------------------------

def _post(url: str, payload: Dict[str, Any], headers: Dict[str, str], timeout: float) -> Dict[str, Any]:
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"),
                                 headers=dict(headers, **{"Content-Type": "application/json"}),
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise BackendError("LLM returned HTTP %s: %s"
                           % (exc.code, exc.read().decode("utf-8", "replace")[:300]))
    except urllib.error.URLError as exc:
        raise BackendError("cannot reach LLM at %s: %s" % (url, exc.reason))
    except (TimeoutError, OSError) as exc:
        raise BackendError("LLM request failed: %s" % exc)
    except ValueError as exc:
        raise BackendError("LLM returned invalid JSON: %s" % exc)


class OpenAICompatBackend(LLMBackend):
    """Any OpenAI-compatible chat-completions endpoint. AgentSec's message/tool format already IS
    this format, so the history and tool definitions pass straight through."""

    name = "openai"

    def __init__(self, model: str, api_key: Optional[str] = None,
                 base_url: str = DEFAULT_OPENAI_BASE, timeout_s: float = 60.0,
                 temperature: float = 0.0):
        self.model, self.api_key = model, api_key
        self.base_url = base_url.rstrip("/")
        self.timeout_s, self.temperature = timeout_s, temperature

    def decide(self, system, messages, tools) -> Decision:
        payload: Dict[str, Any] = {
            "model": self.model, "temperature": self.temperature,
            "messages": [{"role": "system", "content": system}] + list(messages)}
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        headers = {"Authorization": "Bearer %s" % self.api_key} if self.api_key else {}
        data = _post(self.base_url + "/chat/completions", payload, headers, self.timeout_s)
        choices = data.get("choices") or []
        if not choices:
            raise BackendError("LLM reply had no choices")
        msg = (choices[0] or {}).get("message") or {}
        usage = data.get("usage") or {}
        out = Decision(content=msg.get("content") if isinstance(msg.get("content"), str) else None,
                       prompt_tokens=int(usage.get("prompt_tokens") or 0),
                       completion_tokens=int(usage.get("completion_tokens") or 0))
        for i, tc in enumerate(msg.get("tool_calls") or []):
            fn = tc.get("function") or {}
            if not fn.get("name"):
                continue
            raw = fn.get("arguments") or {}
            if isinstance(raw, str):
                try:
                    raw = json.loads(raw) if raw.strip() else {}
                except ValueError:
                    raw = {"_raw": raw}
            out.tool_calls.append(ToolRequest(fn["name"], raw if isinstance(raw, dict) else {"_raw": raw},
                                              tc.get("id") or "call_%d" % i))
        return out


class AnthropicBackend(LLMBackend):
    """Anthropic Messages API. Translates AgentSec's OpenAI-style history into content blocks
    (`tool_use` / `tool_result`) and back."""

    name = "anthropic"

    def __init__(self, model: str, api_key: str, base_url: str = DEFAULT_ANTHROPIC_BASE,
                 timeout_s: float = 60.0, max_tokens: int = 1024, temperature: float = 0.0):
        self.model, self.api_key = model, api_key
        self.base_url = base_url.rstrip("/")
        self.timeout_s, self.max_tokens, self.temperature = timeout_s, max_tokens, temperature

    @staticmethod
    def _to_blocks(messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for m in messages:
            role = m.get("role")
            if role == "user":
                out.append({"role": "user", "content": m.get("content") or ""})
            elif role == "assistant":
                blocks: List[Dict[str, Any]] = []
                if m.get("content"):
                    blocks.append({"type": "text", "text": m["content"]})
                for tc in m.get("tool_calls") or []:
                    fn = tc.get("function") or {}
                    args = fn.get("arguments") or "{}"
                    if isinstance(args, str):
                        try:
                            args = json.loads(args) if args.strip() else {}
                        except ValueError:
                            args = {"_raw": args}
                    blocks.append({"type": "tool_use", "id": tc.get("id") or "call_0",
                                   "name": fn.get("name") or "unknown", "input": args})
                out.append({"role": "assistant", "content": blocks or [{"type": "text", "text": ""}]})
            elif role == "tool":
                out.append({"role": "user", "content": [{
                    "type": "tool_result", "tool_use_id": m.get("tool_call_id") or "call_0",
                    "content": str(m.get("content") or "")}]})
        return out

    @staticmethod
    def _to_tools(tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out = []
        for t in tools or []:
            fn = t.get("function") or {}
            if not fn.get("name"):
                continue
            out.append({"name": fn["name"], "description": fn.get("description") or "",
                        "input_schema": fn.get("parameters")
                        or {"type": "object", "properties": {}, "additionalProperties": True}})
        return out

    def decide(self, system, messages, tools) -> Decision:
        payload: Dict[str, Any] = {
            "model": self.model, "max_tokens": self.max_tokens, "temperature": self.temperature,
            "system": system, "messages": self._to_blocks(messages)}
        converted = self._to_tools(tools)
        if converted:
            payload["tools"] = converted
        headers = {"x-api-key": self.api_key, "anthropic-version": ANTHROPIC_VERSION}
        data = _post(self.base_url + "/v1/messages", payload, headers, self.timeout_s)
        usage = data.get("usage") or {}
        out = Decision(prompt_tokens=int(usage.get("input_tokens") or 0),
                       completion_tokens=int(usage.get("output_tokens") or 0))
        texts: List[str] = []
        for block in data.get("content") or []:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "text" and isinstance(block.get("text"), str):
                texts.append(block["text"])
            elif block.get("type") == "tool_use" and block.get("name"):
                inp = block.get("input")
                out.tool_calls.append(ToolRequest(block["name"],
                                                  inp if isinstance(inp, dict) else {"_raw": inp},
                                                  block.get("id") or "call_0"))
        out.content = "\n".join(texts) if texts else None
        return out


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ENV_BACKEND = "AGENTSEC_LLM_BACKEND"     # anthropic | openai | scripted
ENV_MODEL = "AGENTSEC_LLM_MODEL"
ENV_BASE = "AGENTSEC_LLM_BASE_URL"
ENV_KEY = "AGENTSEC_LLM_API_KEY"         # falls back to ANTHROPIC_API_KEY / OPENAI_API_KEY


def live_backend_configured() -> bool:
    """True when the environment names a real backend AND supplies a usable key (or a base URL,
    for a local server that needs none). Tests use this to skip live-model runs gracefully."""
    return describe_env()[0] is not None


def describe_env():
    """(kind, model, base_url, key) resolved from the environment; kind is None when unconfigured."""
    kind = (os.environ.get(ENV_BACKEND) or "").strip().lower()
    base = os.environ.get(ENV_BASE) or ""
    key = os.environ.get(ENV_KEY) or ""
    if not kind:
        # Infer from whichever vendor key is present.
        if os.environ.get("ANTHROPIC_API_KEY"):
            kind, key = "anthropic", os.environ["ANTHROPIC_API_KEY"]
        elif os.environ.get("OPENAI_API_KEY"):
            kind, key = "openai", os.environ["OPENAI_API_KEY"]
        else:
            return None, None, None, None
    if kind == "anthropic":
        key = key or os.environ.get("ANTHROPIC_API_KEY") or ""
        if not key:
            return None, None, None, None
        return kind, os.environ.get(ENV_MODEL) or "claude-sonnet-4-5", base or DEFAULT_ANTHROPIC_BASE, key
    if kind == "openai":
        key = key or os.environ.get("OPENAI_API_KEY") or ""
        base = base or DEFAULT_OPENAI_BASE
        # A local OpenAI-compatible server (vLLM/Ollama) needs no key; a remote one does.
        if not key and "://localhost" not in base and "://127.0.0.1" not in base:
            return None, None, None, None
        return kind, os.environ.get(ENV_MODEL) or "gpt-4o-mini", base, key
    return None, None, None, None


def backend_from_env(timeout_s: float = 60.0) -> Optional[LLMBackend]:
    """A real backend built from the environment, or None when none is configured."""
    kind, model, base, key = describe_env()
    if kind == "anthropic":
        return AnthropicBackend(model, key, base_url=base, timeout_s=timeout_s)
    if kind == "openai":
        return OpenAICompatBackend(model, key or None, base_url=base, timeout_s=timeout_s)
    return None
