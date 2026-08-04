# Releasing

1. Confirm `main` is clean and all required GitHub checks pass.
2. Move relevant entries from `Unreleased` to a dated version in
   `CHANGELOG.md`.
3. Set the same version in `pyproject.toml` and create a focused pull request.
4. After merge, create and push a signed or annotated tag such as `v2.0.0`.
5. Watch the Release workflow. It must test, build, validate, install and attest
   the distributions before creating the GitHub Release.
6. Download the release wheel in a clean environment and run
   `masscan-webscanner --help` plus an authorized dry-run.

Do not reuse or move a published tag. If validation fails, fix the cause through
a pull request and issue a new patch version. PyPI publication is not currently
configured.
