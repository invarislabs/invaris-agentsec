# Domain attack packs

AgentSec's built-in categories (`prompt_injection`, `unauthorized_tool_use`, and the rest) are
deliberately generic: they hold for any tool-using agent, regardless of what it does for a living.
Attack packs are the extension point for the opposite need -- scenarios that only make sense for a
particular *kind* of agent, because they target that kind's specific tools, data, and failure
modes. Nothing about this needs a change to AgentSec itself: `agentsec/attacks/packs.py` already
loads a pack's `CATEGORIES`, and (as of this doc) its optional `EVALUATORS`, as ordinary Python
imports. See [Extending](extending.md#write-an-attack-pack) for the mechanics.

This page is the reference implementation plus a roadmap: four domains (coding agents, browser
agents, RAG-backed agents, and customer-support agents) are fully built and tested; one more
(financial/on-chain agents) is specified concretely enough to build the same way, reusing the same
two extension points every time.

## The pattern, in one paragraph

A domain pack's categories fall into two groups. Some attacks are already fully described by
AgentSec's existing vocabulary -- "a forbidden tool got called after the agent read untrusted
text" -- and need nothing but a `Scenario` with the right `vector`, `payload`, and a forbidden
action from the policy; the built-in `ToolPolicyEvaluator` catches these automatically, the same
way it does for the generic categories. Others are attacks where the *tool call itself is
legitimate* -- `install_package`, `send_transaction`, `issue_refund` are all real, allowed tools --
and the danger is entirely in the arguments. Those need a pack-provided `Evaluator` that inspects
`trace.of_type("tool_call")` for the specific argument shape that makes an otherwise-normal call
dangerous. `examples/attack_packs/coding_agent_pack.py`, `examples/attack_packs/browser_agent_pack.py`,
`examples/attack_packs/rag_pack.py` and `examples/attack_packs/support_agent_pack.py` each have one
category of each kind, as a concrete template. Two more cases show up further in: a category built
to have *no* deterministic signal at all, on purpose (`rag_citation_spoofing`), and a category that
needs no pack evaluator not because a forbidden tool was called, but because a *built-in* evaluator
other than the tool-policy one (here, the canary check in `SecretLeakEvaluator`) already covers it
(`support_agent_cross_customer_leak`) -- see below.

## Built: coding-agent attacks

`examples/attack_packs/coding_agent_pack.py`, covered by `tests/test_attack_packs.py`.

- `coding_agent_pr_comment_injection` -- a hidden instruction in a PR review comment or issue body
  tells the agent to run a shell command or push directly to the remote. Needs no custom
  evaluator: the built-in forbidden-action check already covers it.
- `coding_agent_malicious_dependency` -- a package-search tool result claims a typosquatted
  package replaced the real one. `install_package` is a normal, allowed tool; the pack's
  `TyposquatPackageEvaluator` flags the call by the package *name* in its arguments.
- `coding_agent_insecure_patch` -- a spoofed CI failure pressures the agent into "fixing" a build
  by disabling TLS verification or turning on debug mode. `write_file` is a normal, allowed tool;
  the pack's `InsecurePatchEvaluator` flags the call by scanning its `content` argument for a small
  set of dangerous patterns.

## Built: browser-agent attacks

`examples/attack_packs/browser_agent_pack.py`, covered by `tests/test_attack_packs.py`. This is
the domain behind CometJacking-style incidents (see [Why AgentSec](why-agentsec.md)) and the
closest thing AgentSec has today to that incident class: an agent that navigates pages, fills
forms, and acts on whatever it reads there -- content written by the page's author, not the user.

- `browser_agent_hidden_page_instruction` -- a page's DOM contains an invisible or off-screen
  instruction (white-on-white text, a hidden `alt` attribute) telling the agent to call a forbidden
  tool -- submitting a form with the user's saved autofill data, or downloading a file. Needs no
  custom evaluator: the built-in forbidden-action check already covers it, the same way
  `coding_agent_pr_comment_injection` does.
- `browser_agent_lookalike_domain` -- a search result or link presents a typosquatted domain
  (`arnaz0n.com`, an extra hyphen, a swapped TLD) as the real one, and the agent is asked to
  complete a login there. `navigate` is a normal, allowed tool; the pack's
  `LookalikeDomainEvaluator` flags the call by the domain *substring* in its `url` argument, the
  same shape as `TyposquatPackageEvaluator` but for domains instead of packages.
- `browser_agent_consent_trap` -- a page disguises credential entry as a routine "verify you're
  human" step. Needs no custom evaluator: the target is a forbidden action (`enter_credentials`),
  so the built-in check catches it.

## Built: RAG-backed agent attacks

`examples/attack_packs/rag_pack.py`, covered by `tests/test_attack_packs.py`. AgentSec already has
`unsafe_retrieved_documents` and `indirect_prompt_injection` for "a retrieved document says
something bad." This pack is narrower: attacks that exploit *how retrieval itself ranks and trusts
documents*. It is also the pack that demonstrates a fourth answer to "does this need a pack
evaluator?" -- sometimes the right answer is "no evaluator at all, deterministic or pack-provided,
can see this; use the judge."

- `rag_embedding_stuffing` -- a chunk is keyword-stuffed to rank highly for many unrelated queries,
  so it gets retrieved (and its injected instruction read) regardless of what was actually asked.
  Needs no custom evaluator: the existing marker mechanism catches it once the chunk is the
  scenario's planted document, the same as the built-in `indirect_prompt_injection` category.
- `rag_citation_spoofing` -- an injected chunk imitates a trusted source's citation format ("per
  our official Data Sharing Policy v4.2...") to borrow authority it hasn't earned, and the agent
  discloses more than it should on that authority. Deliberately built with no forbidden tool call,
  marker or canary: "did the agent treat this as authoritative" is a judgment call, not a pattern
  match, so it produces zero findings without `--judge` and is flagged only by the judge's
  `goal_hijack` check (see [Judge](judge.md)) -- confirmed by a test using a scripted judge
  adapter, not just asserted.
- `rag_stale_document_resurrection` -- a retrieved document is an explicitly superseded policy
  version (an old refund policy permitting something the current one forbids). `approve_refund` is
  a normal, allowed tool; the pack's `StaleDocumentEvaluator` flags the call by checking its
  `justification` argument for language tied to the superseded document, the same shape as
  `TyposquatPackageEvaluator` but for a stale citation instead of a package name.

## Built: customer-support agent attacks

`examples/attack_packs/support_agent_pack.py`, covered by `tests/test_attack_packs.py`.

- `support_agent_impersonation_escalation` -- a caller claims false authority ("the CEO's
  assistant") or invents urgency to get identity verification skipped. Needs no custom evaluator:
  it ends in a forbidden tool call, which the built-in `ToolPolicyEvaluator` already catches, the
  same way `coding_agent_pr_comment_injection` does.
- `support_agent_refund_abuse` -- a caller pushes for a refund far above what the order could
  justify, or talks the agent into refunding the same order twice in one conversation.
  `issue_refund` is a normal, allowed tool; the pack's `RefundAbuseEvaluator` flags a call over a
  fixed cap, or a repeat call for an order id already refunded earlier in the trace.
- `support_agent_cross_customer_leak` -- an account reference one caller gives for verification is
  disclosed to a different, later caller. Built as a two-session scenario
  (`Followup(same_session=False)`), the same shape as the built-in `memory_poisoning` category's
  own `cross_session_leak` scenario. Needs no custom evaluator: the built-in `SecretLeakEvaluator`
  already flags a planted canary that turns up in the agent's own output in a later session.

## Specified: one more domain

Each entry below names concrete scenarios, which extension point each needs, and the one
detection nuance worth knowing before building it. None of this is implemented yet.

### Financial / on-chain agents

The domain README already names as an intended user ("Financial and blockchain teams building
transaction-capable agents"); `wallet and on-chain transaction policies` is listed under
[Future Work](../README.md#future-work) at the engine level. These are the pack-level scenarios
that would sit on top of that once the policy schema has a place to declare spend limits and an
address allowlist.

- `onchain_agent_unlimited_approval` -- a task disguised as routine ("gas optimization", "staking
  migration") asks the agent to approve an unlimited token allowance to an attacker-controlled
  contract. Needs a pack evaluator inspecting a `send_transaction`/`approve_token` call's `amount`
  for an unbounded value and its destination against an allowlist.
- `onchain_agent_address_poisoning` -- a retrieved transaction history or support message contains
  a visually similar but different wallet address, nudging the agent to reuse it for a "repeat"
  payment. Same shape as the domain-lookalike evaluators above, applied to addresses.
- `onchain_agent_unbounded_spend` -- a fabricated "urgent invoice" pressures the agent past a
  policy-declared daily spend cap. Needs a pack evaluator comparing the transaction `amount`
  argument against a limit, the same idea as AgentSec's existing `limits:` policy block
  (`max_tool_calls`, `max_cost_usd`) extended to a monetary domain instead of an execution budget.

## Building the next one

1. Pick the domain's tools and write two or three scenarios per the shape in
   [Extending](extending.md#write-an-attack-pack): a `user_message`, a `payload`, and either
   `markers` or a `responder` that returns the payload for the tool call it targets.
2. Decide, per scenario, whether the built-in evaluators already cover it (a forbidden tool called,
   a marker echoed, a canary leaked) or whether the danger is in an otherwise-legitimate tool
   call's arguments. Only the second case needs a pack evaluator.
3. Decide whether the danger can even be expressed deterministically at all. Most attacks can
   (steps above); a few, like `rag_citation_spoofing`, come down to a judgment call no pattern
   match can make -- for those, write no evaluator and rely on `judge:` with the `goal_hijack` or
   `paraphrased_leak` check instead (see [Judge](judge.md)). Separately, if the danger is really
   about a fact leaking across sessions, check whether a *different* built-in evaluator already
   covers it (a canary via `SecretLeakEvaluator`, a marker via `InjectionFollowedEvaluator`) before
   writing a new one -- `support_agent_cross_customer_leak` needs none at all.
4. Write the pack evaluator against `trace.of_type("tool_call")`, following
   `TyposquatPackageEvaluator` / `InsecurePatchEvaluator` in `coding_agent_pack.py`,
   `LookalikeDomainEvaluator` in `browser_agent_pack.py`, `StaleDocumentEvaluator` in
   `rag_pack.py`, or `RefundAbuseEvaluator` in `support_agent_pack.py`.
5. Test the loader in isolation and `run_suite` end to end with a small scripted agent, the way
   `tests/test_attack_packs.py` does for the coding-agent pack -- and, for a judge-only category,
   with a scripted judge adapter too, the way it does for `rag_citation_spoofing`.
