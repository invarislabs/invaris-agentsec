# Open-source agent analysis

**Verification level for everything in this document: LEVEL 0 RESEARCHED**, checked against a live
fetch of each project's GitHub page on the research date below, not against training-data
recollection -- several of these projects have changed status materially since 2024/2025 (archived,
renamed, moved to a successor repo, or put into maintenance mode), and a few surprising status
changes turned up during this pass specifically because the live page was checked rather than
assumed. None of these projects were installed, run, or integrated with AgentSec in this pass; see
[agentsec-gap-analysis.md](agentsec-gap-analysis.md) for the concrete next steps that would move
any of them to LEVEL 2/3.

Research date for every project below: **2026-10-03**. Star counts and commit counts are a single
snapshot and will drift; treat them as "approximately this, as of this date," not as live figures.

## Status changes worth flagging up front

Three projects in the mandated list have a materially different status than their original 2024-era
reputation would suggest, and a report that didn't check live would have gotten all three wrong:

- **`microsoft/autogen` is in maintenance mode.** The repo explicitly states it is no longer
  receiving new features and recommends new users adopt "Microsoft Agent Framework" instead. Not
  archived, but effectively superseded.
- **`continuedev/continue` is read-only / discontinued.** The repo page explicitly states: "The
  continuedev/continue repository is no longer actively maintained and is read-only for all users."
  Any outstanding vulnerabilities in it are permanently unpatched.
  tag: "Final 2.0.0 Release."
- **`letta-ai/letta` has moved.** The repo page states the current source code now lives in
  `letta-ai/letta-code`; this repo holds historical Letta V1 server code on an archive branch. A
  security assessment of "Letta" today should target `letta-ai/letta-code`, not this repo --
  that re-pointing was not independently re-verified in this pass and is itself a recommended next
  step.

A security program that cites any of these three by their 2024 reputation without re-checking is
citing a status that no longer holds.

## Coding / computer agents

### `All-Hands-AI/OpenHands`
~89.8k stars, active (latest visible release: 1.24.0). Described on its current page as a
"self-hosted developer control center for coding agents and automations," orchestrating
OpenHands/Claude Code/Codex/Gemini-style coding agents (a broader scope than the original
single-agent OpenHands). Shell/code execution happens inside sandboxed Docker containers, with
filesystem access and multi-agent/multi-backend orchestration. Install: `npm install -g
@openhands/agent-canvas`, Docker, or source. MIT license.

### `OpenInterpreter/open-interpreter`
~68.5k stars, active, but **now a Rust-based rewrite** of the original Python tool, repositioned as
"a coding agent for open models like Kimi K3 and GLM 5.3" and supporting the Agent Client
Protocol/Codex SDK. This is a substantial architecture change since 2024 -- any security assumptions
from the Python-era tool should be re-verified against the Rust codebase, not assumed to carry
over. Executes arbitrary code/shell commands locally with native OS sandboxing (macOS/Linux/
Windows). Install: a shell/PowerShell install script. Apache-2.0.

### `cline/cline`
~67.6k stars, active. A coding agent embedded in IDE/terminal: executes commands, edits code/
filesystem directly, integrates with MCP servers for extended tool/network access. Ships as a VS
Code/JetBrains extension, a terminal CLI, and a programmatic SDK (the SDK path makes multi-agent
orchestration possible). Install: `npm i -g cline`, marketplace extension, or `npm install
@cline/sdk`. Apache 2.0.

### `Aider-AI/aider`
~49.3k stars, active. Terminal-based AI pair-programming agent with direct filesystem/code editing
and git integration; no built-in browser control. Processes very large LLM token volumes per the
project's own badge (15B tokens/week cited). Install: `python -m pip install aider-install` then
`aider-install`. Apache-2.0.

### `continuedev/continue`
~35.7k stars. **Read-only / discontinued** (see above). Was a coding agent (CLI, VS Code extension,
JetBrains plugin) with code-editing/filesystem access via IDE extensions; no further security
patches will land. Apache 2.0.

### `huggingface/smolagents`
~28.8k stars, active. A minimalist "agents that think in code" library (~1,000 lines of core code).
Code-execution-centric by design -- the agent's reasoning step *is* writing and running code --
with sandboxed runtime options (E2B, Blaxel, Modal, Docker) available rather than mandatory; a Hub
integration lets agents/tools be shared. Install: `pip install "smolagents[toolkit]"`. Apache-2.0.

## Browser agents

### `browser-use/browser-use`
~116.7k stars, active. "Agents that use the browser" -- full browser automation (navigation, form
fill, CAPTCHA handling), which is effectively network access mediated through a real browser. Ships
a CLI (`browser-use skill install`) and a hosted cloud API option. Install: `uv add browser-use`
(Python >=3.11) or Docker. MIT.

### `browserbase/stagehand`
~25.5k stars, active. A Playwright-style browser automation SDK for AI agents (TS/Python/Go),
designed to be driven *by* coding agents (the project explicitly cites Claude Code and Codex as
intended drivers) and to integrate with Browserbase's cloud infrastructure for remote/sandboxed
browser execution. Install: `pnpm add @browserbasehq/stagehand`, `pip install stagehand`, or `go
get`. MIT, trademark held by Browserbase, Inc.

## Workflow / automation platforms

### `n8n-io/n8n`
~205.4k stars (the largest in this entire list), active. A node-based workflow automation platform
with 400+ integrations and native AI-agent nodes. Code-execution nodes (JS/Python "Function"
nodes), filesystem access via nodes, extensive HTTP/webhook/API tool nodes, and credential storage
for connected services. Install: official install script or Docker. License: "fair-code"
(Sustainable Use License + Enterprise License) -- source-available, not plain open source, which
matters for anyone assuming OSI-approved terms.

### `langgenius/dify`
~152.4k stars, active. An LLM app / agentic-workflow and RAG development platform with a
collaborative workspace. Visual workflow builder with tool/plugin nodes including a code-execution
sandbox and HTTP-request nodes; RAG pipelines bring filesystem/vector-DB access; supports
multi-model and multi-agent orchestration. Install: Docker Compose (the primary documented path).
License: "Dify Open Source License" (Apache 2.0 plus additional conditions) -- also not plain
Apache, a second licensing nuance worth flagging alongside n8n's.

### `Significant-Gravitas/AutoGPT`
~186.8k stars, active. Positioned today as "accessible AI for everyone" via a managed cloud
platform plus a self-host option. The classic self-hosted version chains filesystem, internet, and
code-execution plugins into autonomous multi-step tasks; install scripts imply host-level shell
execution. Install: platform signup, or install scripts for self-hosting. Licensing is split: the
platform component is Polyform Shield 1.0.0 (non-OSS, restricts competing resale), while the
`classic/` directory remains MIT -- another case where "open source" needs a closer look at which
part of the repo is meant.

## Agent frameworks / SDKs

### `langchain-ai/langchain`
~146.9k stars, active, now described on its own page as "the agent engineering platform" rather
than a pure LLM-app library. A general-purpose framework, not a standalone runtime: tool-calling
abstractions can enable arbitrary shell/code exec, filesystem access, HTTP/API tools, and
multi-agent chains, entirely depending on which tools a developer wires in. Install: `uv add
langchain` or pip. MIT. **AgentSec already has a dedicated `LangChainAdapter`** (see
`agentsec/integrations/langchain.py`), tested in this project's own suite against a real LangGraph
agent -- this is the one framework in this document that is already past LEVEL 0 for AgentSec
specifically (call it LEVEL 2/3 against a demonstration agent, not yet against a production
LangChain application; see the gap analysis).

### `langchain-ai/langgraph`
~38.1k stars, active. A lower-level, graph-based stateful-agent orchestration runtime, a companion
to LangChain. Provides persistent/durable state and memory management, human-in-the-loop
checkpoints, and multi-agent graph orchestration; tool/shell/network access depends entirely on
developer-defined graph nodes. Install: `pip install -U langgraph`. MIT. Covered by the same
`LangChainAdapter` and existing test coverage as LangChain itself.

### `crewAIInc/crewAI`
~59k stars, active (latest cited release: v0.102.0). A multi-agent orchestration framework built
around "Crews" -- role-playing, autonomous agents collaborating on a task. Delegation between
agents is the core design, not an add-on; tool use (including code execution and web/HTTP tools) is
pluggable. A commercial "CrewAI AMP Suite" add-on exists alongside the open-source core. Install:
`uv tool install crewai` (Python 3.10-3.13). MIT.

### `microsoft/autogen`
~60.4k stars. **In maintenance mode** (see above) -- new feature development has moved to
"Microsoft Agent Framework." A multi-agent conversational framework; code-execution agents and
tool-calling are supported via `autogen-ext`, with an `autogenstudio` GUI. Install: `pip install -U
"autogen-agentchat" "autogen-ext[openai]"`. Code MIT, docs CC-BY-4.0.

### `huggingface/smolagents` -- see Coding / computer agents above (it fits both groups: a minimal
framework whose only real action primitive is code execution).

### `openai/openai-agents-python`
~28.6k stars, active. A lightweight, provider-agnostic multi-agent workflow SDK (100+ LLM providers
cited). Provides multi-agent handoff/delegation primitives and supports text, sandboxed, realtime,
and voice agent types; tool/network access is entirely developer-defined; optional Redis-backed
session/state persistence. Install: `pip install openai-agents`. MIT.

### `google/adk-python`
~21.1k stars, active (latest: version 2.0, with breaking changes from 1.x). Google's code-first
Python toolkit for building/evaluating/deploying agents. Version 2.0 adds a graph-based "Workflow
Runtime" execution engine and an explicit "Task API" for agent-to-agent delegation -- i.e., Google
has made delegation a first-class, named API surface here, which is directly relevant to the
multi-agent privilege-abuse primitives in [agentsec-gap-analysis.md](agentsec-gap-analysis.md).
Install: `pip install google-adk` (Python 3.10-3.14). Apache 2.0.

## Memory systems

### `mem0ai/mem0`
~65.9k stars, active (README references an April-2026 memory-algorithm update, suggesting live
2026 development). A persistent memory *layer/infrastructure* for agents, not an agent itself --
its entire security-relevant surface is storage and retrieval of persistent state (vector/graph
backends), self-hostable via Docker. No inherent shell/browser control of its own; the risk it
introduces is entirely about what gets written into and later retrieved from that memory, across
which boundaries. Install: `pip install mem0ai` / `npm install mem0ai` / `docker compose up`.
Apache 2.0.

### `letta-ai/letta` (see status note above -- code has moved to `letta-ai/letta-code`)
~24.7k stars on this (now largely historical) repo. Positioned as "AI with advanced memory that can
learn and self-improve over time" -- persistent memory/state is the core feature, not a bolt-on.
The active successor, `letta-code`, installs as a terminal coding-agent UI (`npm install -g
@letta-ai/letta-code`), meaning the live project now also carries full coding-agent capabilities on
top of its memory architecture -- a combination (persistent memory + code/shell execution) that is
exactly the shape [agentsec-gap-analysis.md](agentsec-gap-analysis.md) flags as needing the most
scrutiny for persistent-memory attacks that later enable code execution. Apache-2.0.

## Desktop / GUI automation

### `microsoft/UFO`
~9.5k stars, active but **effectively evolved past its original scope**: the current README brands
it "UFO³: Weaving the Digital Agent Galaxy," a multi-device orchestration evolution of the original
single-desktop UFO. UFO² reached "Long-Term Support" status (v2.0.0, April 2025) while UFO³/Galaxy
(November 2025) is the actively developed line, within the same repository (not a separate URL).
Controls native GUI applications across devices -- the desktop-automation equivalent of filesystem
and input-device access -- and now explicitly supports multi-agent/multi-device orchestration.
Requires platform-specific agent initialization and configuration files (which plausibly include
credentials/API keys; not independently confirmed). Install: `pip install -r requirements.txt` plus
manual config. MIT, Microsoft trademark guidelines apply.

## What was not independently confirmed for any project above

Exact latest release/version tag and exact last-commit recency were not reliably surfaced by a
single repo-page fetch for most of these projects (`UNKNOWN / NOT VERIFIED` throughout) -- getting
that precisely would need either the GitHub API or a `git clone` + `git log`, neither of which was
done in this pass. Anyone treating a specific commit hash from this document as pinned should
re-verify it directly; none of the per-repo sections above claim a pinned commit.

## Cross-cutting observations

- **Licensing is not uniformly "open source" even among "open-source" projects.** `n8n` (fair-code,
  Sustainable Use License) and `dify` (Apache 2.0 plus additional conditions) are both
  source-available rather than OSI-approved open source, and AutoGPT's managed platform component
  is non-OSS (Polyform Shield) even though its `classic/` code is MIT. A security/compliance review
  that assumes blanket permissive licensing across this list would be wrong for at least these
  three.
- **The coding-agent and memory-system categories are converging.** `letta-ai/letta-code` is the
  clearest example: a project whose core pitch was persistent memory now also ships full terminal
  coding-agent capability. Treating "memory system" and "coding agent" as disjoint categories for
  threat-modeling purposes is already stale for at least this project.
- **Multi-agent delegation is increasingly a named, first-class API**, not an emergent pattern:
  CrewAI's "Crews," Google ADK 2.0's "Task API," and OpenAI's "handoff" primitives all give
  delegation an explicit surface. That's good news for testability (a concrete API to instrument)
  and bad news for risk (an explicit, reusable mechanism for the privilege-laundering and
  capability-escalation patterns in the gap analysis).
- **Every project with code-execution as its core primitive** (`smolagents`, `open-interpreter`,
  `aider`, `cline`, `OpenHands`) **relies on sandboxing for safety, not on an external policy
  check** -- the safety story in each case is "the execution environment is contained," not "a
  separate system verified the action stayed within what was asked." That is a different axis from
  `action_without_authorization` (containment vs. authorization) and the two are complementary: a
  properly sandboxed agent can still take an unauthorized-but-harmless-to-the-host action (e.g.
  installing an unrequested dependency, or committing an unrequested file) that sandboxing alone
  would never flag.
