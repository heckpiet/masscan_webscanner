# Releasing

1. Confirm `main` is clean and all required GitHub checks pass.
2. Move relevant entries from `Unreleased` to a dated version in
   `CHANGELOG.md`.
3. Set the same version in `pyproject.toml` and create a focused pull request.
4. After merge, create and push a signed or annotated tag such as `v2.0.0`.
5. Watch the Release workflow. It must test, build, validate, install and attest
   the distributions before creating the GitHub Release.
6. Download the release wheel in a clean environment and run
   `masscan-webscanner --version`, `--help` and an authorized dry-run.
7. Confirm the source archive contains `README.md`, `CHANGELOG.md`,
   `SECURITY.md`, `RELEASING.md` and the `docs/` files.
8. Record SHA-256 hashes for the wheel and source archive in the release notes.

Do not reuse or move a published tag. If validation fails, fix the cause through
a pull request and issue a new patch version. PyPI publication is not currently
configured.
