# Changelog

This project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
