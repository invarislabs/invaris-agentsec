# Commercial agent analysis

**Verification level for everything in this document: LEVEL 0 RESEARCHED.** None of these products
were run against AgentSec. What follows is documented from each vendor's own current public
documentation (linked per product), not from training-data memory and not from marketing copy --
every claim below was checked against a live fetch of the cited page on the research date, and
every gap in that documentation is marked `UNKNOWN / NOT VERIFIED` rather than guessed. See
[Research methodology](#research-methodology) at the end for what LEVEL 0 does and doesn't mean,
and [agentsec-gap-analysis.md](agentsec-gap-analysis.md) for how these capabilities map onto what
AgentSec can and cannot currently observe.

Research date for every product below: **2026-10-03**.

## Claude Code (Anthropic)

- Source: [Permission modes](https://code.claude.com/docs/en/permission-modes), [Settings](https://code.claude.com/docs/en/settings)
- Capabilities: shell exec and arbitrary code exec (via the Bash tool), file write/delete, git
  commit/push/PR creation (via Bash + `gh`, not a dedicated git tool), dependency install, network
  requests, MCP server calls (core feature), persistent memory (CLAUDE.md / project memory),
  sub-agent delegation (Task tool). No native browser control or email/messaging (only via MCP). No
  financial/purchase capability.
- Permission model: six modes -- `default` (reads only, everything else prompts), `acceptEdits`
  (reads + file edits + common filesystem commands auto-run), `plan` (read-only exploration, edits
  blocked until a plan is approved), `auto` (a second model reviews actions instead of the user),
  `dontAsk` (only reads + pre-approved tools run; anything else is denied, not prompted), and
  `bypassPermissions` (everything runs).
- Persistent approval: `permissions.allow`/`ask`/`deny` rules in settings files (user/project/managed
  scopes) plus `--allowedTools`; deny always overrides allow, in every mode including
  `bypassPermissions`.
- Full-autonomy mode: `bypassPermissions`, invoked with `--dangerously-skip-permissions`, documented
  as intended only for isolated containers/VMs. A short list of actions (explicit `ask` rules,
  tools requiring interaction, `rm`/`rmdir` on "critical paths") are never auto-approved even here.
- `UNKNOWN / NOT VERIFIED`: the exact default list of protected/critical paths; whether a dedicated
  git/PR tool exists beyond shell-based `git`/`gh` usage.
- **Relevance to `action_without_authorization`:** this is close to a textbook case -- `acceptEdits`
  and `auto` both let the agent write files and run common commands without a per-action prompt,
  which is exactly the condition under which "I was asked to review, not fix" can be silently
  crossed. `plan` mode is the one mode that structurally enforces a request/intent boundary (no
  edits until a plan -- i.e., a scope -- is approved), which is a different, complementary strategy
  to AgentSec's post-hoc trace-based detection: plan mode prevents the action, AgentSec would catch
  it if it happened anyway in a mode that doesn't prevent it.

## OpenAI Codex (CLI / coding agent)

- Source: [Codex agent approvals & security](https://developers.openai.com/codex/agent-approvals-security)
- Capabilities: shell exec and code exec within its sandbox, file write/delete (in `workspace-write`),
  dependency install when network is enabled, MCP server support. Git/PR creation via shell is
  plausible but a dedicated CLI tool for it was `NOT VERIFIED`. No evidence of built-in browser
  control, email/messaging, or financial actions.
- Permission model: two independent axes. Approval policy -- `on-request` (default in
  version-controlled folders; approval needed for actions outside the sandbox or needing network),
  `untrusted` (only known-safe reads run automatically), `never` (no prompts, fully bounded by the
  sandbox). Sandbox mode -- `workspace-write` (default: read/edit files and run commands in the
  workspace, network disabled by default), `read-only`, `danger-full-access` (removes all
  sandboxing/approval). Protected paths (`.git`, `.agents`, `.codex`) stay read-only even in
  writable modes.
- Persistent approval: config-file (`config.toml`) settings persist across sessions; granular
  network domain allowlists (deny always wins); an optional `approvals_reviewer = "auto_review"`
  adds an automated reviewer model for eligible approvals.
- Full-autonomy mode: `--dangerously-bypass-approvals-and-sandbox` (alias `--yolo`).
- `UNKNOWN / NOT VERIFIED`: whether the CLI itself can natively open GitHub PRs vs. this being a
  Codex cloud-only feature; `on-request` behavior for network-only vs. filesystem-only actions.
- **Relevance:** the sandbox-mode axis is itself close to an effect taxonomy (`workspace-write` vs.
  `read-only` vs. `danger-full-access`) -- but it is a *global* session setting, not scoped per
  request. A session in `workspace-write` cannot distinguish "the current message only asked for
  analysis" from "the current message asked for a fix," which is exactly the gap
  `action_without_authorization` targets.

## GitHub Copilot coding agent

- Source: [About Copilot coding agent](https://docs.github.com/en/copilot/concepts/agents/coding-agent/about-coding-agent), [Customize the agent firewall](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/customize-the-agent-firewall)
- Capabilities: shell exec and code exec in an ephemeral, isolated environment; file write/delete
  and git commit/push within its own branch; PR creation for human review (it does not merge
  itself); dependency install constrained by a firewall. Network requests are restricted by a
  default firewall limited mostly to GitHub hosts plus a "recommended allowlist" (package
  registries, container registries, CAs, Playwright hosts). No evidence of browser control,
  email/messaging, or financial actions.
- Permission model: only acts when assigned a task; by default can only access the repository
  specified for the task; hard session cap of 59 minutes; the resulting PR requires normal
  human/branch-protection review to merge.
- Persistent approval: the firewall's domain allowlist is the main standing control -- org owners
  can enable/disable it or add custom rules.
- Full-autonomy mode: none named; the closest analog is an admin disabling the firewall entirely,
  which GitHub's own docs warn means "sophisticated attacks may bypass the firewall," since it
  covers only the agent's own Bash-tool processes, not MCP servers or setup steps.
- `UNKNOWN / NOT VERIFIED`: default MCP support details; whether it can ever push directly to a
  protected branch without a PR; cross-task persistent memory.
- **Relevance:** the "task is scoped to one assigned repository/issue" design is itself a coarse
  form of task-scoped authorization -- but it scopes by *repository*, not by *effect*. Nothing stops
  the agent from pushing an unrelated refactor to that same repo when asked only to fix one bug;
  that is squarely `action_without_authorization`'s territory and is not something the
  firewall/scope design addresses.

## Gemini CLI (Google)

- Source: [Gemini CLI configuration docs](https://geminicli.com/docs/cli/configuration)
- Capabilities: shell exec, code exec, file write/delete, dependency install, network requests, MCP
  server support. No evidence found of built-in browser control; git/PR creation plausible via
  shell but not confirmed as a dedicated tool. Persistent context files (reportedly `GEMINI.md`-style)
  not independently confirmed this pass.
- Permission model: default (`autoAccept: false`) prompts before every tool call; `autoAccept: true`
  auto-approves calls "considered safe (e.g., read-only operations)" without confirmation.
  Sandboxing is disabled by default.
- Persistent approval: the `autoAccept` setting persists; `excludeTools`/`includeTools` exist for
  shell commands but the docs explicitly warn this "relies on simple string matching and can be
  easily bypassed" and "is not a security mechanism" -- notable because it's a vendor admitting the
  same thing AgentSec's own docs say about trusting tool names over effects.
- Full-autonomy mode: `--yolo` -- "automatically approves all tool calls." Sandboxing is turned on
  by default when `--yolo` is used, partially offsetting the loss of approval gating.
- `UNKNOWN / NOT VERIFIED`: built-in browser control; sub-agent/delegation support; the exact
  default "safe" operation list for auto-accept mode.

## Cursor Agent mode

- Source: [Cursor Agent run modes](https://cursor.com/docs/agent/security/run-modes)
- Capabilities: shell exec, code exec, file write/delete (deletion specifically gated -- see
  below), dependency install, network via MCP/fetch calls, MCP server support. A browser tool
  exists but is explicitly blocked from automatic execution by a standing protection (see below).
  Git/PR creation plausible via shell, not itemized separately in the source.
- Permission model: three run modes. **Auto-review** (default/recommended) -- allowlisted calls run
  immediately, shell commands sandboxed where possible, an LLM classifier reviews higher-risk
  calls. **Allowlist** -- only pre-approved operations run without interruption. **Run Everything**
  -- every tool call runs automatically, no safety review.
- Persistent approval: Allowlist mode lets users configure specific trusted operations/commands
  that then run without prompts.
- Full-autonomy mode: **Run Everything** -- but three protections remain active even here
  regardless of settings: browser-tool execution is blocked automatically, destructive file
  operations (e.g. `rm`) need approval, and creating/modifying/deleting files *outside the
  workspace* needs approval.
- `UNKNOWN / NOT VERIFIED`: default git/PR behavior; persistent memory/rules mechanics; sub-agent
  delegation.
- **Relevance:** the three standing protections that survive even "Run Everything" are themselves
  a hand-built, hardcoded version of exactly the effect classes AgentSec's `tool_effects` lets a
  policy declare generically (`browser_state_change`, `delete`, and "outside declared scope" for
  the workspace-boundary rule). That convergence is a reasonable signal that this effect-based
  framing matches how real vendors already think about the problem, even though they've each
  implemented it as a one-off special case rather than a general policy mechanism.

## Devin (Cognition)

- Source: [Devin CLI permissions reference](https://docs.devin.ai/cli/reference/permissions), [docs.devin.ai](https://docs.devin.ai)
- Capabilities: shell exec (dedicated Shell tool), code exec, file write/delete (dedicated IDE
  tool), a dedicated Browser tool ("browse documentation, test applications, manage file
  transfers"), dependency install, network requests. Git/PR creation is reportedly PR-gated by
  default workflow but this was not independently confirmed for every Devin product surface.
  `UNKNOWN / NOT VERIFIED`: MCP support, autonomous email-sending (a Slack integration exists for
  human communication, which is different), deploy automation, cross-session "Knowledge"/memory
  persistence, sub-agent spawning, financial actions.
- Permission model (CLI-specific reference): **Normal Mode** (default) -- reads auto-approve,
  writes and shell commands require explicit approval. Rule resolution: deny > ask > allow >
  default-prompt.
- Persistent approval: approvals can be granted at several persistence levels -- single-use,
  session-only, per-project (shared), local-project-only, or global.
- Named modes of increasing autonomy: **Accept Edits Mode** (workspace file edits auto-approve),
  **Smart Mode** (workspace edits auto-approve; other actions judged by a fast model; package
  installs/destructive git/`rm` always require approval), **Autonomous Mode** (shell/network
  auto-approve inside an OS-level sandbox, but direct file edits still need confirmation), **Bypass
  Mode** (everything auto-approves).
- Important caveat found during research: this mode breakdown comes from a Devin *CLI-specific*
  reference page. It is `UNKNOWN / NOT VERIFIED` how fully it describes Devin's original
  cloud/Slack-driven autonomous engineering sessions, which may have a different default workflow
  (including default PR vs. direct-push behavior). Treat the CLI and the cloud product as
  potentially different permission surfaces until confirmed otherwise.

## Manus

- Source: [Manus Sandbox blog post](https://manus.im/blog/manus-sandbox), [manus.im/docs](https://manus.im/docs)
- Capabilities: full shell in a per-task sandbox VM, code exec, persistent (within-task) file
  system, software installation, network/internet access, browser control, and explicitly stated
  ability to **deploy services to the public internet**. `UNKNOWN / NOT VERIFIED`: git/GitHub
  integration, env var/credential access specifics, email/messaging, cross-task persistent memory,
  sub-agent/multi-agent delegation (reported elsewhere, not confirmed via official docs reached
  this pass), financial actions.
- Permission model: described as "Zero Trust" sandbox design in which the agent has "full control
  over this computer" and performs "unrestricted operations" inside the task's own isolated
  sandbox -- isolation is per-task, not per-action approval. This is a materially different safety
  model from every other product here: the boundary is "which sandbox," not "which actions need a
  human nod."
- Persistent approval / full-autonomy mode: not applicable in the usual sense -- unrestricted
  operation within the task sandbox appears to be the default behavior itself, not an opt-in tier.
- `UNKNOWN / NOT VERIFIED`: any confirmation gate for high-risk actions (payments, credential use,
  git operations) -- official docs reached this pass gave limited granular detail beyond the
  sandbox overview.
- **Relevance:** Manus is the sharpest illustration in this whole document of why
  `action_without_authorization` matters and why per-tool allow/forbid lists are insufficient for
  it: if "deploy to the public internet" and "run unrestricted shell commands" are both just
  *things the sandbox lets you do*, with no per-action gate, then the only thing standing between a
  benign request ("summarize this report") and a request-exceeding one ("...and also deployed a
  public service while doing it") is whatever the model itself chooses to do. A trace-based,
  effect-aware check sitting outside the model's own judgment is precisely the control this
  architecture is missing.

## ChatGPT Agent (OpenAI)

- Source: [Introducing ChatGPT agent](https://openai.com/index/introducing-chatgpt-agent/), [ChatGPT Agent help article](https://help.openai.com/en/articles/11752874-chatgpt-agent)
- Capabilities: code exec within its own virtual computer, file write/generate/download, a visual
  GUI browser plus a text-based browser (can click/fill forms/navigate), OAuth-based connectors
  (e.g. Gmail, GitHub) for context and action. `UNKNOWN / NOT VERIFIED`: autonomous GitHub
  commit/push/PR creation (GitHub access is documented as a connector for context/research, not
  confirmed as write-capable); dependency install; MCP usage; cross-session memory; sub-agent
  spawning.
- Permission model: the published design is the most explicitly authorization-boundary-aware of
  anything in this document -- OpenAI states the model is "trained to explicitly ask for your
  permission before taking actions with real-world consequences, like making a purchase," that
  "certain critical tasks, like sending emails, require your active oversight," and that for sites
  needing a direct login it enters a "takeover mode" where the user logs in manually (with
  screenshots paused during that window, for privacy). It also refuses some high-risk categories
  outright (e.g. bank transfers).
- Persistent approval / full-autonomy mode: `UNKNOWN / NOT VERIFIED` -- no evidence found of a
  global "always allow purchases/emails" toggle, or of any named unrestricted mode; the documented
  design implies standing, non-bypassable confirmation gates for consequential actions rather than
  a settings-level override.
- **Relevance:** this is the one product in this set whose own stated design goal ("ask permission
  before actions with real-world consequences... beyond what was explicitly asked") is a plain-
  language restatement of `action_without_authorization`'s core property. It is evidence that major
  vendors already treat this as a first-class safety requirement at the model-behavior level; what
  none of them appear to offer is an external, trace-based auditor that can verify the behavior
  actually held on a given run rather than trusting the model to have applied it -- which is
  exactly AgentSec's role relative to any of these products, if and when an integration exists (see
  [agentsec-gap-analysis.md](agentsec-gap-analysis.md)).

## Cross-cutting observations

- **No product in this set exposes a stable, scriptable hook for "did the agent's action match the
  request's scope" today.** Each vendor encodes some version of the idea as hardcoded special
  cases (Cursor's three always-on protections, ChatGPT Agent's purchase/email gates, GitHub
  Copilot's repository scoping) rather than as a general, inspectable policy. That is the gap
  `action_without_authorization` is built to fill *from the outside*, independent of which vendor's
  agent is being tested.
- **"Full autonomy" modes are real and commonly used.** Every CLI/IDE-embedded product here
  (Claude Code, Codex, Gemini CLI, Cursor, Devin) ships a named mode that removes per-action
  approval entirely (`bypassPermissions`, `--yolo` (two different products use this exact name),
  `danger-full-access`, Run Everything, Bypass Mode). None of these modes distinguish "legitimate
  because the task asked for it" from "legitimate because the agent is simply allowed to." That is
  the precise condition under which `action_without_authorization`-class findings would fire if
  these products were integrated with AgentSec.
- **MCP support is now close to universal** among the CLI/IDE products (Claude Code, Codex, Gemini
  CLI, Cursor all confirmed; Devin and GitHub Copilot likely but not confirmed this pass). This
  matters directly for AgentSec: `agentsec test --mcp-listen` lets AgentSec *be* the MCP server an
  agent connects to, which is a plausible, already-implemented integration path for most of these
  products without needing a bespoke adapter for each one. This has not been exercised against any
  real commercial agent in this project -- see the gap analysis for why that is the single highest-
  value next integration step this document points to.
- **No product in this set was found to offer a built-in financial/purchase action without an
  explicit, non-bypassable confirmation gate** (ChatGPT Agent refuses bank transfers outright;
  nothing else in this set claims native purchase capability at all). This is a meaningfully
  different risk posture than the agentic *frameworks* in
  [open-source-agent-analysis.md](open-source-agent-analysis.md), where a developer can wire a
  payment tool into an otherwise-unrestricted agent with no vendor-level gate at all.

## Research methodology

Every product above was checked via a live fetch of its current, vendor-published documentation on
the stated research date. Where a claim could not be confirmed from an official source reached in
this pass, it is marked `UNKNOWN / NOT VERIFIED` rather than filled in from training-data
recollection -- several details here (exact flag names, mode names, default settings) are the kind
of thing that changes between product releases, and a wrong guess stated as fact would be worse
than an honest gap. This document does not claim any of these products were run, and none of them
were tested against AgentSec; see
[real-world-agent-security-matrix.md](real-world-agent-security-matrix.md) for how that distinction
is tracked per capability, and [agentsec-gap-analysis.md](agentsec-gap-analysis.md) for what
verification level would actually be required to move any of this past LEVEL 0.
