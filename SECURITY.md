# Security policy

## Reporting a vulnerability in AgentSec

Please report vulnerabilities privately through GitHub: open the repository's **Security** tab and choose
**Report a vulnerability**. Do not open a public issue. Include the version, steps to reproduce and the impact you see.

We aim to acknowledge reports within a few days. AgentSec is an early-stage project maintained by a small team, so
these are goals, not guarantees.

## Reporting a vulnerability in someone else's agent, framework or MCP server

If AgentSec helps you find a problem in a third-party product, contact its maintainers privately and give them reasonable time
to fix it before you publish details.

## Using AgentSec safely

AgentSec sends adversarial content to the agent you point it at, and `agentsec mcp scan --command` starts the server command you give it.

- Test against isolated environments with synthetic credentials, never production data.
- Only scan MCP servers you are willing to run.
- The `--judge` option sends conversation transcripts (configured secrets masked) to the judge endpoint you configure. Use a local or trusted model.
- AgentSec simulates tools; it never executes an agent's real tools. An agent that runs its own tools server-side can still act on adversarial input, so run it in a sandbox.
