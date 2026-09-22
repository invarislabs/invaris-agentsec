# Contributing

Thanks for helping. AgentSec is early, so small, well-tested changes are easiest to review.

## Set up

```bash
git clone https://github.com/invarislabs/invaris-agentsec && cd invaris-agentsec
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

All tests run offline and need no API keys.

## Before you open a pull request

- Add or update tests. New evaluators need one trace that must be flagged and one near miss that must not (see `docs/extending.md`).
- If you add a scenario, the safe reference agent must still pass every scenario, and the vulnerable one must trigger it.
- Update the docs that describe the behaviour you changed, and add a line to `CHANGELOG.md`.
- Keep detection honest: prefer a missed detection with a documented limit over a check that raises false alarms.

## Adding attacks

Attack content must be synthetic. Do not include real credentials, real personal data, or working exploits against a specific
product. Scenarios are for testing your own agents.

## Reporting security problems

See [SECURITY.md](SECURITY.md). Do not open a public issue for a vulnerability.

## License

By contributing you agree that your contribution is licensed under the Apache License 2.0.

On your first pull request, a CLA Assistant bot will also ask you to confirm you agree to the
[Contributor License Agreement](CLA.md) by replying with a short confirmation comment. This just
makes explicit what the Apache License already implies -- that your contribution is yours to give
-- and additionally lets the project relicense in the future (for example, offering an enterprise
edition) without having to track down every past contributor individually. You only need to do
this once; it's remembered for your future pull requests.

## Releasing (maintainers)

1. Bump the version in `pyproject.toml` and `agentsec/__init__.py`, and add a section to `CHANGELOG.md` (a test checks all three agree).
2. Run `pytest`, then `python -m build && python -m twine check dist/*` locally.
3. Publish a GitHub release. `.github/workflows/release.yml` runs the tests, builds, and publishes to PyPI through trusted publishing.

The PyPI trusted publisher and the `pypi` environment (with a required reviewer, so every publish needs a manual approval) are already set up as of the 0.5.0 release; a new maintainer only needs steps 1-3 above.
