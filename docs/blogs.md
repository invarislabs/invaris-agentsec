# Blog

Posts from the people building AgentSec -- design notes, incidents that motivated a feature, and
write-ups of what adversarial testing turns up in practice.

| Date | Post | About |
|---|---|---|
| 2026-10-07 | [What Does a Passing Agent Security Test Actually Prove?](https://arunima-chaudhuri.hashnode.dev/what-does-a-passing-agent-security-test-actually-prove) by Arunima Chaudhuri | A research note on when a pass is real evidence. Using AgentSec's runs against seven frameworks, two memory stores and the Claude Code CLI, it finds five ways to get a pass without the agent resisting anything -- the attack never reached a decision point, the action wasn't observable, the evaluator couldn't see that failure, retrieval ranking hid it, or the harness failed silently -- and argues a pass only means something alongside a record of what was delivered, reached, observed and checked. |
| 2026-10-06 | [Allowed Isn't Authorized: Testing What Your AI Agent Does With the Permissions It Already Has](https://arunima-chaudhuri.hashnode.dev/allowed-isn-t-authorized-testing-what-your-ai-agent-does-with-the-permissions-it-already-has) by Arunima Chaudhuri | A hands-on guide to the authority checks in AgentSec 0.7 -- task scope, data flow, honest reporting, identity boundaries and multi-agent delegation -- for failures involving tools an agent is allowed to have but uses outside its task. Includes real output from the reference agents, seven frameworks, two memory stores and a live Claude Code CLI run over MCP. |
| 2026-09-30 | [AgentSec 101: How to Stop Your AI Agent From Going Rogue (A Beginner-to-Pro Guide)](https://arunima-chaudhuri.hashnode.dev/agentsec-101-how-to-stop-your-ai-agent-from-going-rogue-a-beginner-to-pro-guide) by Arunima Chaudhuri | A friendly, no-jargon walkthrough of using AgentSec itself -- installing it, running it against the bundled practice agent, writing a policy for your own agent, and leveling up to replay, compare, CI, and the optional judge. |
| 2026-09-26 | [I Asked My Coding Agent for a Yes or No. It Made a Commit.](https://arunima-chaudhuri.hashnode.dev/i-asked-my-coding-agent-for-a-yes-or-no-it-made-a-commit) by Arunima Chaudhuri | The origin story: an AI coding agent given a simple yes-or-no question instead made unauthorized changes and committed them, which is what led to building AgentSec as an open-source framework for testing whether an agent actually respects the boundaries it's given. |

Have something to add? Open a pull request adding a row to the table above, newest first.
