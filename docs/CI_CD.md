# CI and releases

## Continuous integration

`.github/workflows/ci.yml` runs on pull requests, pushes to `main`/`master` and
manual dispatch. It performs:

- Ruff formatting and lint checks;
- tests on Python 3.10 through 3.14 with at least 80% coverage;
- dependency auditing;
- sdist and wheel builds plus metadata validation;
- installation of the built wheel and a CLI smoke test;
- upload of the distributions as a workflow artifact.

No CI job performs a real network scan.

## Dependency maintenance

Dependabot checks Python and GitHub Actions dependencies monthly. Actions are
pinned to full commit SHAs; the adjacent version comments make updates
reviewable. Treat action updates like code and require CI before merging them.

## Releases

`.github/workflows/release.yml` reacts to `v*` tags. It refuses a tag that does
not match `project.version`, repeats quality/build checks, installs the wheel,
attests the distributions and creates a GitHub Release.

Follow [RELEASING.md](../RELEASING.md). PyPI publication is intentionally not
enabled. If it is added later, use PyPI Trusted Publishing with a protected
GitHub environment rather than a long-lived token.

## Recommended repository rules

Protect `main` with a GitHub ruleset that requires:

- a pull request;
- successful `quality`, `package` and `dependency-audit` jobs;
- the branch to be current before merge;
- resolved review conversations;
- blocked force pushes and branch deletion.

Enable secret scanning, push protection and Dependabot security updates in the
repository settings. These are hosting settings and cannot be enforced by files
in this repository alone.
