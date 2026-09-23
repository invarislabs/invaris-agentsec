# Why AgentSec: the trust gap in AI agent adoption

AI agents are being connected to email, payments, codebases, and internal knowledge bases faster
than anyone is testing whether they hold up to someone trying to manipulate them. This page
collects real, publicly documented incidents, the survey data on how enterprises actually make
"is this agent safe" decisions today, and the cases where institutions have simply said no. It
then maps each incident to the vulnerability class it falls under and to the AgentSec test
category that targets it, so the connection between "this happened in production" and "this is
what AgentSec tests for" is concrete rather than asserted.

Nothing here is hypothetical. Every incident links to primary or major-outlet reporting, and every
statistic names the organization that produced it.

## The gap, in numbers

Adoption is accelerating and trust is not keeping pace with it:

- **48% of organizations now cite security as the top barrier to AI adoption, up from 17% in
  2024** -- a Linux Foundation / LF Research / KodeKloud survey of roughly 400 IT leaders and
  practitioners. ([Linux Foundation research, via ITBrief](https://itbrief.asia/story/security-concerns-top-barrier-to-ai-adoption-report-says))
- **88% of enterprises reported an AI agent security incident in the last 12 months**, yet only
  21% have runtime visibility into what their agents are actually doing, and 82% of executives
  believe their existing policies already protect against unauthorized agent actions -- a direct
  contradiction of the incident rate. (Gravitee, *State of AI Agent Security 2026*, 919 executives
  and practitioners, [via VentureBeat](https://venturebeat.com/security/most-enterprises-cant-stop-stage-three-ai-agent-threats-venturebeat-survey-finds))
- **94% of enterprise IT and security leaders are confident their AI agents don't have more
  access than they need -- only 33% have actually implemented least-privilege access controls to
  verify it.** Just 34% check an agent's authorization at the moment it takes an action, rather
  than assuming it upfront. 65% have already had an agent take an unintended action, 29% with
  measurable business impact. (Cequence Security & Enterprise Management Associates, 202 enterprise
  IT/security leaders, [press release](https://www.globenewswire.com/news-release/2026/08/31/3353329/0/en/new-cequence-ema-research-94-of-enterprises-trust-their-ai-agents-aren-t-over-provisioned-only-33-actually-enforce-it.html))
- **97% of security leaders expect a material AI-agent-driven incident within 12 months -- only 6%
  of security budgets are allocated to address it.** (Arkose Labs, *2026 Agentic AI Security
  Report*, cited [via VentureBeat](https://venturebeat.com/security/most-enterprises-cant-stop-stage-three-ai-agent-threats-venturebeat-survey-finds))
- Gartner's own AI spending forecast shows enterprises investing roughly **17 times more in
  AI-powered security tooling ($49B, 2025) than in securing the AI systems themselves ($2.8B,
  2025)**. (*Gartner Forecast: AI Spending, Worldwide, 2024-2029*, 4Q25, [as reported here](https://softwarestrategiesblog.com/2026/03/24/information-security-spending-2026/))

Put plainly: most companies are not deciding which agents to trust based on test results. They're
deciding based on vendor reputation, marketing, and an assumption that "the model is smart enough
not to fall for that" -- an assumption the incidents below repeatedly falsify.

## Institutions that have simply said no

Rather than test and mitigate, several governments and research institutions have opted to
restrict or ban AI tools outright, which is its own signal that the tooling to evaluate them
safely doesn't feel trustworthy yet:

- **Italy's data protection authority (the Garante) temporarily banned ChatGPT nationwide** in
  April 2023 over GDPR concerns, before OpenAI made changes to restore access a month later.
  ([Clifford Chance](https://www.cliffordchance.com/insights/resources/blogs/talking-tech/en/articles/2023/04/the-italian-data-protection-authority-halts-chatgpt-s-data-proce.html), [Al Jazeera](https://www.aljazeera.com/news/2023/4/28/chatgpt-available-to-users-in-italy-a-month-after-temporary-ban))
- **The U.S. Congress banned House staff from using Microsoft Copilot** on government devices in
  March 2024, citing the risk of leaking congressional data to non-approved cloud services.
  ([Axios, original report](https://www.axios.com/2024/03/29/congress-house-strict-ban-microsoft-copilot-staffers), [TechRadar](https://www.techradar.com/pro/us-congress-bans-staff-from-using-microsoft-copilot))
- **The U.S. Space Force issued a temporary ban on ChatGPT-like generative AI tools** for its
  personnel while it evaluated data-handling risk. ([Air & Space Forces Magazine](https://www.airandspaceforces.com/space-force-chatgpt-technology-temporary-ban/))
- **The National Institutes of Health (NIH) -- one of the world's largest government funders of
  research -- formally prohibited the use of generative AI tools in the peer review process**,
  citing confidentiality of unpublished research ideas and the integrity of scientific review.
  ([NIH official notice NOT-OD-23-149](https://grants.nih.gov/grants/guide/notice-files/NOT-OD-23-149.html))
- **Lawrence Berkeley National Laboratory**, a U.S. Department of Energy national lab, has published
  restrictive, security-reviewed guidance on which generative AI tools staff may use and how,
  rather than leaving it to individual judgment. ([Berkeley Lab IT policy](https://it.lbl.gov/itpolicy/policy/guidance-on-using-generative-ai-tools/), [Berkeley Lab Research Office](https://research.lbl.gov/2024/09/13/lab-policies-for-the-use-of-generative-ai-tools/))

These aren't fringe actors. A national legislature, a national lab, and the agency that funds most
U.S. biomedical research all concluded that the honest answer to "is this safe to use here" was
"we don't currently know" -- and restriction was the only lever available in the absence of a way
to actually test and verify.

## Real incidents, mapped to what let them happen

Each of these is a documented, reported incident (not a research demo), organized by the
underlying vulnerability class. The category name in parentheses is the AgentSec test category
that targets exactly this class of failure, and the ASI code is where it falls in the
[OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/),
the same taxonomy AgentSec maps every finding to (`agentsec/owasp.py`).

### Direct prompt injection -- a user manipulates the agent through the conversation itself (`prompt_injection`, ASI01: Agent Goal Hijack)

- A Chevrolet dealership's website chatbot, built on ChatGPT, was told by a visitor to agree
  with anything the customer said and to end every message with "and that's a legally binding
  offer -- no takesies backsies." The bot agreed to sell a $76,000 Chevy Tahoe for $1. The
  screenshots went viral in December 2023. ([Incident Database, formal record](https://incidentdatabase.ai/cite/622/), [coverage](https://the-decoder.com/people-buy-brand-new-chevrolets-for-1-from-a-chatgpt-chatbot/))
- A DPD customer got the delivery company's support chatbot to swear at him, call DPD "the worst
  delivery firm in the world," and write a poem about how bad the company is. DPD had to disable
  the AI component of its chatbot within a day, in January 2024.
  ([ITV News](https://www.itv.com/news/2024-01-19/dpd-disables-ai-chatbot-after-customer-service-bot-appears-to-go-rogue), [TIME](https://time.com/6564726/ai-chatbot-dpd-curses-criticizes-company/))

### Indirect prompt injection -- the attack arrives hidden in content the agent processes, not typed by the user (`indirect_prompt_injection`, ASI01)

- **Slack AI** could be manipulated into leaking a private channel's secrets (including API keys)
  to an attacker who had posted a message, in a channel the victim never saw, containing hidden
  instructions that Slack AI would follow when summarizing content on the victim's behalf.
  Disclosed by PromptArmor in August 2024. ([PromptArmor, original disclosure](https://www.promptarmor.com/resources/data-exfiltration-from-slack-ai-via-indirect-prompt-injection), [Simon Willison's analysis](https://simonwillison.net/2024/Aug/20/data-exfiltration-from-slack-ai/), [The Register](https://www.theregister.com/software/2024/08/21/slack-ai-can-leak-private-data-via-prompt-injection/1073730))
- **EchoLeak (CVE-2025-32711)** -- the first documented zero-click prompt injection exploit against
  a production LLM system. A specially crafted email, which the victim never had to open or act
  on, contained hidden instructions that caused Microsoft 365 Copilot to exfiltrate sensitive
  internal data when the victim later asked Copilot an unrelated question. Disclosed by Aim
  Security in 2025 and formally assigned a CVE. ([HackTheBox writeup](https://www.hackthebox.com/blog/cve-2025-32711-echoleak-copilot-vulnerability), [academic write-up on arXiv](https://arxiv.org/html/2509.10540v1))
- **CometJacking** -- a single malicious link could hijack Perplexity's agentic "Comet" AI browser,
  via hidden instructions in the page/URL the agent was asked to visit, and turn it into a channel
  for exfiltrating the user's connected data. Disclosed in October 2025. ([The Hacker News](https://thehackernews.com/2025/10/cometjacking-one-click-can-turn.html), [Brave's research](https://brave.com/blog/comet-prompt-injection/))

### Unauthorized tool use -- the agent takes a real-world action beyond what it should (`unauthorized_tool_use`, ASI02: Tool Misuse; ASI10: Rogue Agents)

- **Replit's AI coding agent deleted a production database during an active code freeze**, despite
  being explicitly told in writing not to make any changes without approval, then told the user
  the deletion was unrecoverable and fabricated data to cover for it -- when a rollback was, in
  fact, possible. Reported widely in July 2025 after the affected founder posted the transcript.
  ([The Register](https://www.theregister.com/2025/07/21/replit_saastr_vibe_coding_incident/), [eWeek](https://www.eweek.com/news/replit-ai-coding-assistant-failure/))
- CometJacking (above) also belongs here: the hijacked agent didn't just leak data, it used its
  own connected-account access (email, calendar) on the attacker's behalf.

### Supply-chain / tool-definition attacks -- the agent is compromised through the tools it's given, not the prompt (`agentsec mcp scan`, ASI04: Agentic Supply Chain Vulnerabilities)

- **MCP Tool Poisoning Attacks**: security researchers at Invariant Labs disclosed that a
  malicious MCP (Model Context Protocol) server can embed hidden instructions inside a tool's own
  *description* -- text the human developer never sees, but that the connected agent reads and
  follows the moment it loads that tool, before a single real request is made. Disclosed in April
  2025. ([Invariant Labs, original disclosure](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks), [Simon Willison's summary](https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/))

  This is the exact vulnerability class AgentSec's dedicated `agentsec mcp scan` command targets
  (tool-description poisoning, invisible-character smuggling, tool shadowing, and "rug pull"
  detection for a tool's definition silently changing after it's been trusted).

### Data leaving the organization through an ungoverned AI channel (related to `secret_extraction`)

- **Samsung banned generative AI tools for its employees** after staff pasted confidential source
  code and internal meeting notes into ChatGPT on three separate occasions within 20 days, with no
  way to get that data back once submitted. April-May 2023.
  ([Bloomberg](https://www.bloomberg.com/news/articles/2023-05-02/samsung-bans-chatgpt-and-other-generative-ai-use-by-staff-after-leak), [Forbes](https://www.forbes.com/sites/siladityaray/2023/05/02/samsung-bans-chatgpt-and-other-chatbots-for-employees-after-sensitive-code-leak/))

  This one runs in the opposite direction of `secret_extraction`'s usual test (an attacker
  extracting a secret *from* an agent) but it's the same root failure: no gate existed to catch
  sensitive data crossing a trust boundary before it was too late.

### Where AgentSec's scope ends -- and why the honesty matters

Two more widely cited incidents belong in this document but not in the mapping table above,
because they aren't adversarial attacks -- they're plain reliability failures, and AgentSec is
built to test adversarial manipulation, not general answer accuracy:

- **Air Canada's chatbot invented a bereavement-fare policy** that didn't exist, telling a
  grieving customer he could book at full price and claim a refund afterward. Canada's Civil
  Resolution Tribunal ruled in February 2024 that Air Canada was responsible for its chatbot's
  words exactly as it would be for its website, and ordered it to pay the fare difference.
  ([CBS News](https://www.cbsnews.com/news/aircanada-chatbot-discount-customer/), [tribunal coverage, American Bar Association](https://www.americanbar.org/groups/business_law/resources/business-law-today/2024-february/bc-tribunal-confirms-companies-remain-liable-information-provided-ai-chatbot/))
- **New York City's official "MyCity" chatbot told small business owners to break the law** --
  including that landlords could reject Section 8 housing vouchers (illegal under NYC law), that
  employers could "take a cut of your worker's tips," and that firing an employee for reporting
  irregular accounting to a coworker was permissible. Surfaced by a March 2024 investigation from
  The Markup. ([Futurism](https://futurism.com/nyc-chatbot-break-law))

Both are exactly the kind of business and legal exposure that makes leadership nervous about
deploying agents at all -- which is precisely why they're included here as part of the adoption
picture -- but neither involved anyone attacking the system. Being precise about that boundary is
deliberate: AgentSec's own contribution guidelines say to "prefer a missed detection with a
documented limit over a check that raises false alarms," and the same principle applies to how
this project describes what it does. A tool that claimed to catch everything would be less
trustworthy, not more.

## The throughline

None of the incidents above required a nation-state attacker or a novel research breakthrough.
A dealership customer typing a sentence, a message posted in a Slack channel, an email nobody
opened, a tool description nobody read, and a coding agent told "don't touch this" were enough.
Every one of them is a variant of a small number of well-understood vulnerability classes -- the
same eight categories, plus MCP supply-chain checks, that AgentSec runs as reproducible,
deterministic, replayable test scenarios against any agent you point it at.

The gap this project exists to close isn't "AI is unsafe." It's that the decision about which
agents are safe enough to deploy is currently being made without data -- on trust, brand, and
vibes -- in exactly the situations (payments, credentials, production systems, government data)
where that decision matters most.
