"""OpenAI-compatible HTTP adapter.

Request:  POST <endpoint> {"model", "messages", "tools"?, "tool_choice"?}
Response: {"choices": [{"message": {"content", "tool_calls"?}}], "usage"?}

Also tolerated for plain text agents: {"response"|"output"|"content": "..."}.

Optional extension for agents that run tools server-side:
  "x_agentsec": {"cost_usd": 0.01,
                 "events": [{"name": "send_email", "arguments": {...}, "result": "..."}]}
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from ..policies import AgentConfig
from .base import AdapterError, AgentAdapter, AgentReply, ToolCall


class HTTPAgentAdapter(AgentAdapter):
    def __init__(self, config: AgentConfig):
        self.config = config

    def _headers(self, session: Optional[str] = None) -> Dict[str, str]:
        headers = {"Content-Type": "application/json",
                   "Accept": "text/event-stream" if self.config.stream else "application/json"}
        if session:
            headers["X-AgentSec-Session"] = session
        headers.update(self.config.headers)
        if self.config.api_key_env:
            key = os.environ.get(self.config.api_key_env)
            if not key:
                raise AdapterError("environment variable %s (agent.api_key_env) is not set"
                                   % self.config.api_key_env)
            headers["Authorization"] = "Bearer " + key
        return headers

    def chat(self, messages: List[Dict[str, Any]], tools: List[Dict[str, Any]],
             session: Optional[str] = None) -> AgentReply:
        body: Dict[str, Any] = {"model": self.config.model, "messages": messages}
        if session:
            body["user"] = session  # OpenAI's end-user identifier; also sent as X-AgentSec-Session
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"
        if self.config.stream:
            body["stream"] = True
        req = urllib.request.Request(
            self.config.endpoint, data=json.dumps(body).encode("utf-8"),
            headers=self._headers(session), method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout_s) as resp:
                if self.config.stream:
                    return self._parse_stream(resp)
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:300]
            raise AdapterError("agent returned HTTP %s: %s" % (exc.code, detail))
        except urllib.error.URLError as exc:
            raise AdapterError("cannot reach agent at %s: %s" % (self.config.endpoint, exc.reason))
        except (TimeoutError, OSError) as exc:
            raise AdapterError("request to agent failed: %s" % exc)
        except ValueError as exc:
            raise AdapterError("agent returned invalid JSON: %s" % exc)
        return self._parse(payload)

    def _parse_stream(self, resp: Any) -> AgentReply:
        """Read an OpenAI-style server-sent-events stream (`data: {chunk}` lines, ending with
        `data: [DONE]`) and assemble it into one reply."""
        text: List[str] = []
        calls: Dict[int, Dict[str, Any]] = {}
        usage: Dict[str, Any] = {}
        ext: Dict[str, Any] = {}
        events: List[Dict[str, Any]] = []
        seen = False
        for raw in resp:
            line = raw.decode("utf-8", "replace").strip()
            if not line or line.startswith(":") or not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data == "[DONE]":
                break
            try:
                chunk = json.loads(data)
            except ValueError:
                raise AdapterError("agent stream contained invalid JSON: %s" % data[:100])
            if not isinstance(chunk, dict):
                continue
            seen = True
            if isinstance(chunk.get("error"), (dict, str)):
                raise AdapterError("agent stream reported an error: %s" % str(chunk["error"])[:200])
            if isinstance(chunk.get("usage"), dict):
                usage = chunk["usage"]
            if isinstance(chunk.get("x_agentsec"), dict):
                x = chunk["x_agentsec"]
                if "cost_usd" in x:
                    ext["cost_usd"] = x["cost_usd"]
                events.extend(e for e in (x.get("events") or []) if isinstance(e, dict))
            for choice in chunk.get("choices") or []:
                delta = (choice or {}).get("delta") or {}
                if isinstance(delta.get("content"), str):
                    text.append(delta["content"])
                for tc in delta.get("tool_calls") or []:
                    slot = calls.setdefault(int(tc.get("index", len(calls))),
                                            {"id": None, "name": "", "args": ""})
                    if tc.get("id"):
                        slot["id"] = tc["id"]
                    fn = tc.get("function") or {}
                    if fn.get("name"):
                        slot["name"] += fn["name"]
                    if isinstance(fn.get("arguments"), str):
                        slot["args"] += fn["arguments"]
        if not seen:
            raise AdapterError("agent stream was empty (is the endpoint really streaming?)")
        message: Dict[str, Any] = {"content": "".join(text) if text else None}
        if calls:
            message["tool_calls"] = [
                {"id": c["id"], "function": {"name": c["name"], "arguments": c["args"]}}
                for _, c in sorted(calls.items())]
        payload: Dict[str, Any] = {"choices": [{"message": message}], "usage": usage,
                                   "x_agentsec": {**ext, "events": events}}
        return self._parse(payload)

    def _parse(self, payload: Any) -> AgentReply:
        if not isinstance(payload, dict):
            raise AdapterError("agent reply must be a JSON object")
        reply = AgentReply()
        choices = payload.get("choices")
        if choices:
            message = (choices[0] or {}).get("message") or {}
            content = message.get("content")
            reply.content = content if isinstance(content, str) else None
            for i, tc in enumerate(message.get("tool_calls") or []):
                fn = tc.get("function") or {}
                name = fn.get("name")
                if not name:
                    raise AdapterError("tool call without a function name")
                raw_args = fn.get("arguments", {})
                if isinstance(raw_args, str):
                    try:
                        raw_args = json.loads(raw_args) if raw_args.strip() else {}
                    except ValueError:
                        raw_args = {"_raw": raw_args}
                if not isinstance(raw_args, dict):
                    raw_args = {"_raw": raw_args}
                reply.tool_calls.append(ToolCall(tc.get("id") or "call_%d" % i, name, raw_args))
        else:
            for key in ("response", "output", "content"):
                if isinstance(payload.get(key), str):
                    reply.content = payload[key]
                    break
            else:
                raise AdapterError("agent reply has neither `choices` nor a text field "
                                   "(response/output/content)")
        usage = payload.get("usage") or {}
        reply.prompt_tokens = int(usage.get("prompt_tokens") or 0)
        reply.completion_tokens = int(usage.get("completion_tokens") or 0)
        ext = payload.get("x_agentsec") or {}
        cost = ext.get("cost_usd", usage.get("cost_usd"))
        reply.cost_usd = float(cost) if isinstance(cost, (int, float)) else None
        for ev in ext.get("events") or []:
            if isinstance(ev, dict) and ev.get("name"):
                reply.executed.append(ev)
        return reply
