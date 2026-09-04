# Masscan Web Scanner

[![CI](https://github.com/heckpiet/masscan_webscanner/actions/workflows/ci.yml/badge.svg)](https://github.com/heckpiet/masscan_webscanner/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/heckpiet/masscan_webscanner?display_name=tag)](https://github.com/heckpiet/masscan_webscanner/releases/latest)
[![Python 3.10-3.14](https://img.shields.io/badge/python-3.10--3.14-blue)](https://github.com/heckpiet/masscan_webscanner/actions/workflows/ci.yml)

Current release: **2.1.0**. See [CI and releases](docs/CI_CD.md) for the
quality matrix, package validation and tagged-release workflow.

Masscan Web Scanner scans **explicitly authorized** IPv4/IPv6 networks with
[masscan](https://github.com/robertdavidgraham/masscan), extracts discovered web
endpoints and stores bounded raw HTML responses. Browser screenshots are an
explicit opt-in because pages may request resources outside the authorized
scan scope.

> [!WARNING]
> Port scanning can disrupt networks and may be unlawful without permission.
> Only scan systems for which you have explicit written authorization. Start
> with a conservative `--rate` and comply with the rules of engagement.

## Highlights

- validates, normalizes and de-duplicates input networks and optional exclusions before scanning;
- supports optional inline exclusions (individual IPs or subnets) via `!`, `-`, or `exclude `;
- applies defense-in-depth: passes exclusions to masscan via `--excludefile` to prevent SYN transmission and filters results in Python before archiving;
- splits oversized IPv6 networks lazily, avoiding an in-memory subnet list;
- a global packet-rate limit shared across concurrent scan workers;
- bounded parallelism and bounded HTML downloads;
- one-time interactive `sudo` authorization for masscan while Python and the
  sandboxed browser remain unprivileged;
- redirects disabled so HTML retrieval stays on the discovered endpoint;
- sandboxed Chrome screenshots available as an explicit opt-in;
- an automatic PASS/SKIP precheck before packets are sent;
- separate HTML and screenshot results in machine-readable run summaries;
- deterministic, de-duplicated summaries and IPv6-safe URLs;
- dry-run and scan-only modes for safe validation and automation;
- Python package metadata, automated tests, linting and GitHub Actions CI.

## Requirements

- Python 3.10 or newer;
- masscan 1.3.2 or a compatible newer build (unless using `--dry-run`);
- Chrome or Chromium, a matching ChromeDriver and the `screenshots` extra when
  screenshots are enabled.

The scanner uses the operating-system ChromeDriver directly instead of Selenium
Manager. On Debian/Kali, install the matched `chromium` and `chromium-driver`
packages together.

The Masscan 1.3.2 CLI and current upstream `master` both support the parameters
used here: CIDR targets, `-p`, `--rate`, `--excludefile` and list output via `-oL`.
Masscan supports IPv4 and IPv6 simultaneously and does not use a separate `-6` switch.
This application supports TCP ports only; UDP expressions such as `U:53` are
rejected because the archive stage uses HTTP/TCP.

## Installation

For development, create an isolated environment and install the project:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

For normal use on Kali/Debian, use pipx so PEP 668 system packages remain
untouched:

```bash
sudo apt install -y pipx
pipx ensurepath
pipx install masscan_webscanner-2.1.0-py3-none-any.whl
pipx inject masscan-webscanner "selenium>=4.18,<5"
masscan-webscanner --version
```

Do not use `pip --break-system-packages`.

See [Installation and operations](docs/OPERATIONS.md) for Linux packages,
permissions, systemd/cron guidance, retention and upgrades.

## Input

Create a text file containing one CIDR per line. Blank lines and text following
`#` are ignored. Host addresses are accepted and normalized to their network.

Target files containing only IP ranges work without changes. You can optionally
exclude specific individual IPs or subnets directly in the same file.

```text
# Authorized target networks
192.0.2.0/24
2001:db8:1234::/64

# Exclude individual IPs (host addresses are normalized to /32 or /128)
!192.0.2.1
!192.0.2.254
!2001:db8:1234::1

# Exclude subnets / sub-ranges
!192.0.2.128/28
!2001:db8:1234:ffff::/112

# Alternative optional exclusion prefixes:
# -192.0.2.5
# exclude 192.0.2.6
# exclude: 192.0.2.100
```

When exclusions are present:
- masscan is invoked with `--excludefile` so no probe packets are sent to excluded hosts;
- `parse_masscan` additionally verifies and discards any excluded addresses before HTTP retrieval or screenshots.

## Usage

A complete screenshot scan uses one unprivileged command. The scanner requests
sudo authorization once and applies it only to masscan child processes:

```bash
masscan-webscanner -r helios.txt -p 80,443 --screenshots
```

Before scanning, the automatic precheck prints PASS/SKIP results for the
application version, ranges, output path, Python dependencies, masscan, sudo,
Chromium and ChromeDriver. A failed required check stops the run before packets
are sent.

Validate a plan without requiring masscan or a browser:

```bash
masscan-webscanner \
  --ranges ranges.txt \
  --ports 80,443,8080,8443 \
  --rate 1000 \
  --dry-run
```

Run the scan but skip HTTP retrieval and screenshots:

```bash
masscan-webscanner -r ranges.txt -p 80,443 --skip-fetch
```

Do not prefix the complete command with `sudo`; Chromium must remain
unprivileged so its sandbox stays enabled. Use `--no-sudo` only when masscan
already has the required capabilities.

Run scanning and bounded HTML collection:

```bash
masscan-webscanner \
  -r ranges.txt \
  -p 80,443,8000-8100 \
  --output-dir ./scan-results \
  --http-timeout 5 \
  --screenshot-timeout 15 \
  --rate 1000 \
  --scan-workers 4 \
  --fetch-workers 8
```

Enable screenshots only when browser access to page subresources is permitted:

```bash
masscan-webscanner -r ranges.txt -p 80,443 --screenshots
```

Use the installed `masscan-webscanner` command or `python -m
masscan_webscanner`. The former case-only compatibility filename
`Masscan_Webscanner.py` was removed because it made Windows checkouts
ambiguous.

### Options

| Option | Default | Purpose |
| --- | ---: | --- |
| `-r`, `--ranges` | required | Input file containing authorized CIDRs. |
| `-p`, `--ports` | required | A TCP-only masscan port expression. |
| `-o`, `--output-dir` | timestamped | Root directory for this run. |
| `-R`, `--rate` | `1000` | Global packet rate shared by active masscan workers. |
| `--http-timeout` | `5` | HTTP request timeout in seconds. |
| `--screenshot-timeout` | `15` | Chromium page-load timeout in seconds. |
| `-t`, `--timeout` | unset | Backward-compatible alias that sets both timeouts. |
| `--scan-workers` | `4` | Maximum concurrent masscan processes. |
| `--fetch-workers` | `8` | Maximum concurrent archive jobs. |
| `--max-ipv6-host-bits` | `32` | Largest IPv6 host part per scan job (1–63). |
| `--masscan` | `masscan` | masscan executable name or path. |
| `--no-sudo` | off | Run masscan directly instead of requesting sudo authorization. |
| `--browser` | auto-detected | Chrome/Chromium executable name or path. |
| `--screenshots` | off | Start Chrome and capture screenshots; may load external resources. |
| `--verify-tls` | off | Verify HTTPS certificates during HTML retrieval. |
| `--max-html-bytes` | `5000000` | Maximum stored HTML response size per endpoint. |
| `--skip-fetch` | off | Do not fetch HTML or take screenshots. |
| `--dry-run` | off | Validate input and log commands without executing them. |

## Output

```text
scan-results/
├── run-summary.json
├── logs/
│   ├── scanner.log
│   └── errors.log
├── output/
│   ├── range_0001_192_0_2_0_28.lst
│   └── range_0001_192_0_2_0_28_summary.txt
└── html/
    └── 192_0_2_10/
        ├── 192_0_2_10_443.html
        └── 192_0_2_10_443.png
```

`run-summary.json` records scan, HTML-fetch and screenshot results separately.
A screenshot failure never removes successfully archived HTML. Reachable HTTP
responses such as 403 and 404 are archived rather than treated as transport
failures.

The console intentionally stays compact. Repetitive per-endpoint errors are
written to `logs/errors.log` and `run-summary.json`, while the terminal shows a
short final summary and the paths to those details.

HTTP and screenshot timeouts are independent because a streamed HTTP response
usually starts quickly, while Chromium may need longer to render scripts and
subresources. The defaults are 5 and 15 seconds respectively. For slower pages:

```bash
masscan-webscanner -r ranges.txt -p 80,443 --screenshots --screenshot-timeout 30
```
Raw HTML is intentionally stored without rewriting. Treat all scan artifacts as
untrusted, potentially sensitive data; do not open them with elevated privileges
or publish the result directory accidentally.

## Architecture

1. `load_ranges` validates and canonicalizes the scope (target networks and optional exclusions).
2. `expand_network` lazily divides IPv6 scopes according to the configured cap.
3. If exclusions are defined, an `exclude.lst` file is generated and passed to masscan via `--excludefile`.
4. A bounded thread pool invokes independent masscan processes.
5. `parse_masscan` discards any excluded addresses (safety net), creates stable summaries and a unique endpoint set.
6. A second bounded pool streams HTML without following redirects and enforces
   a per-response size limit.
7. With `--screenshots`, sandboxed headless browser sessions capture images.

A failed scan or web endpoint is logged without cancelling unrelated work. Exit
status `0` means success, `1` means at least one scan or fetch failed, and `2`
means invalid configuration or a missing dependency.

## Development and CI

Run the same checks used by GitHub Actions:

```bash
ruff check .
ruff format --check .
python -m pytest
python -m build
```

CI tests Python 3.10 through 3.14, enforces 80% coverage, audits dependencies,
builds both distributions, installs the wheel and smoke-tests the CLI. It does
not perform real network scans. See [CI and releases](docs/CI_CD.md).

## Known limitations

- Port-to-protocol selection is heuristic: ports 443, 8443 and 9443 use HTTPS;
  other ports use HTTP.
- Screenshots can load redirects or page subresources outside the input ranges;
  enable them only when the authorization permits this browser traffic.
- Each screenshot starts a browser process. Keep `--fetch-workers` conservative.
- Extremely broad IPv6 scopes can still create an impractical number of scan
  jobs. Scope scans narrowly even though subnet generation is lazy.
- masscan privileges and supported IPv6 behavior depend on the operating system
  and local installation.
- Masscan loads `/etc/masscan/masscan.conf` when present. Review system-wide
  interface, source-address and exclusion settings before automated scans.

## License

GNU General Public License v3.0 only. See [LICENSE](LICENSE).

## Further documentation

- [Installation and operations](docs/OPERATIONS.md)
- [Security model](SECURITY.md)
- [CI and releases](docs/CI_CD.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Release history](CHANGELOG.md)
