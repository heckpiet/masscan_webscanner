# Contributing

1. Open an issue describing the problem, proposed behavior and safe test scope.
2. Create a focused branch and add tests for behavior changes.
3. Install development dependencies with `python -m pip install -e ".[dev,screenshots]"`.
4. Run `ruff format --check .`, `ruff check .`, `python -m pytest`,
   `python -m pip_audit` and `python -m build`.
5. Never commit scan targets, credentials, browser profiles or generated results.

Tests must not scan external systems. Mock process/network boundaries for new
integration tests. Keep changes compatible with all Python versions listed in
`.github/workflows/ci.yml`.

Behavioral changes must update README/options, `SECURITY.md` where trust
boundaries change, and `CHANGELOG.md`. Never weaken browser sandboxing or expand
network scope silently.
