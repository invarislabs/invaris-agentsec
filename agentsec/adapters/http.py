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
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
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
        req = urllib.request.Request(
            self.config.endpoint, data=json.dumps(body).encode("utf-8"),
            headers=self._headers(session), method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout_s) as resp:
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
