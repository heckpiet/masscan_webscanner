# Masscan Web Scanner

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

- validates, normalizes and de-duplicates input networks before scanning;
- splits oversized IPv6 networks lazily, avoiding an in-memory subnet list;
- a global packet-rate limit shared across concurrent scan workers;
- bounded parallelism and bounded HTML downloads;
- native masscan execution (no implicit `sudo`); run with the least privileges
  needed in your environment;
- redirects disabled so HTML retrieval stays on the discovered endpoint;
- sandboxed Chrome screenshots available as an explicit opt-in;
- machine-readable run summaries and non-zero status for partial failures;
- deterministic, de-duplicated summaries and IPv6-safe URLs;
- dry-run and scan-only modes for safe validation and automation;
- Python package metadata, automated tests, linting and GitHub Actions CI.

## Requirements

- Python 3.10 or newer;
- masscan (unless using `--dry-run`);
- Chrome or Chromium plus the `screenshots` extra when screenshots are enabled.

A separate ChromeDriver installation is usually unnecessary because Selenium
Manager resolves a compatible driver. In restricted/offline environments,
provision browser and driver using your operating-system tooling.

## Installation

For development, create an isolated environment and install the project:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

For normal use:

```bash
python -m pip install .
```

To enable the optional browser screenshot feature:

```bash
python -m pip install ".[screenshots]"
```

See [Installation and operations](docs/OPERATIONS.md) for Linux packages,
permissions, systemd/cron guidance, retention and upgrades.

## Input

Create a text file containing one CIDR per line. Blank lines and text following
`#` are ignored. Host addresses are accepted and normalized to their network.

```text
# Only networks included in the signed authorization
192.0.2.0/28
2001:db8:1234::/120
```

## Usage

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

Run scanning and bounded HTML collection:

```bash
masscan-webscanner \
  -r ranges.txt \
  -p 80,443,8000-8100 \
  --output-dir ./scan-results \
  --timeout 5 \
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
| `-p`, `--ports` | required | A masscan port expression. |
| `-o`, `--output-dir` | timestamped | Root directory for this run. |
| `-R`, `--rate` | `1000` | Global packet rate shared by active masscan workers. |
| `-t`, `--timeout` | `5` | HTTP and page-load timeout in seconds. |
| `--scan-workers` | `4` | Maximum concurrent masscan processes. |
| `--fetch-workers` | `8` | Maximum concurrent archive jobs. |
| `--max-ipv6-host-bits` | `32` | Largest IPv6 host part per scan job (1–63). |
| `--masscan` | `masscan` | masscan executable name or path. |
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

`run-summary.json` records scan/fetch successes and failures for automation.
Raw HTML is intentionally stored without rewriting. Treat all scan artifacts as
untrusted, potentially sensitive data; do not open them with elevated privileges
or publish the result directory accidentally.

## Architecture

1. `load_ranges` validates and canonicalizes the scope.
2. `expand_network` lazily divides IPv6 scopes according to the configured cap.
3. A bounded thread pool invokes independent masscan processes.
4. `parse_masscan` creates stable summaries and a unique endpoint set.
5. A second bounded pool streams HTML without following redirects and enforces
   a per-response size limit.
6. With `--screenshots`, sandboxed headless browser sessions capture images.

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

## License

GNU General Public License v3.0 only. See [LICENSE](LICENSE).

## Further documentation

- [Installation and operations](docs/OPERATIONS.md)
- [Security model](SECURITY.md)
- [CI and releases](docs/CI_CD.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Release history](CHANGELOG.md)
