# Changelog

This project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [2.1.0] - 2026-09-04

### Added

- Support optional inline IP and subnet exclusions in target ranges files:
  - Exclusion lines starting with `!` (e.g. `!192.168.1.1` or `!10.0.99.0/24`), `-`, or `exclude `/`exclude:`.
  - Single host addresses are automatically normalized to `/32` or `/128`.
  - Exclusions are completely optional; files containing only target ranges continue to work unchanged.
- Generate an `exclude.lst` file and pass it to masscan via `--excludefile` so excluded hosts are not probed at the network level.
- Defense-in-depth: `parse_masscan` filters out any excluded addresses in Python before attempting HTTP retrieval or screenshots.
- Report excluded target count during precheck and in `run-summary.json` (`ranges.excluded` and `excluded_cidrs`).

## [2.0.5] - 2026-08-04

### Added

- Add independently configurable `--http-timeout` and
  `--screenshot-timeout` options.
- Print both effective timeout values during the automatic precheck.
- Verify installed CLI/package version consistency in CI and release workflows.

### Changed

- Keep the HTTP timeout at 5 seconds and raise the screenshot page-load default
  to 15 seconds based on observed renderer timeouts in a completed scan.
- Retain `-t`/`--timeout` as a backward-compatible alias that sets both values.

## [2.0.4] - 2026-08-04

### Changed

- Keep terminal output compact by moving repetitive per-endpoint HTML and
  screenshot failures to the existing error log and JSON summary.
- Suppress repetitive `InsecureRequestWarning` blocks only when TLS certificate
  verification is intentionally disabled.
- Print a structured final result summary and direct operators to detailed logs.

## [2.0.3] - 2026-08-04

### Added

- Print an automatic precheck before every real scan and stop before sending
  packets when a required dependency or browser/driver compatibility check fails.
- Add `--version` and `--no-sudo`.
- Document Kali/PEP 668 installation, pipx upgrades, the privilege boundary and
  the complete release verification procedure.

### Changed

- Request sudo authorization once and apply it only to masscan child processes.
- Use the operating-system ChromeDriver directly instead of Selenium Manager.
- Archive HTTP 403/404 responses and report HTML-fetch and screenshot outcomes
  independently in `run-summary.json`.
- Preserve successfully archived HTML when screenshot capture fails.

## [2.0.1] - 2026-08-04

### Changed

- Document the verified Masscan 1.3.2/current-master CLI contract and current
  Python/browser toolchain requirements.
- Reject UDP port expressions and ignore non-TCP Masscan result lines because
  the archive stage supports HTTP over TCP only.

## [2.0.0] - 2026-08-04

### Changed

- Keep Python 3.10 compatibility by using `timezone.utc`.
- Treat `--rate` as a global limit shared by concurrent scan workers.
- Stream HTML with a configurable five-megabyte default limit.
- Disable HTTP redirects and make screenshots an explicit opt-in.
- Keep the Chrome sandbox enabled and make Selenium an optional dependency.
- Return status 1 for scan/fetch failures and write `run-summary.json`.
- Test Python 3.10 through 3.14 with coverage, dependency and package checks.
- Modernize input validation, bounded concurrency, IPv6 handling, packaging,
  tests and baseline documentation.

### Removed

- Remove the case-colliding `Masscan_Webscanner.py` compatibility filename.
- Remove unused Beautiful Soup and MechanicalSoup dependencies.
