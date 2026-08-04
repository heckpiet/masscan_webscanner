# Masscan Web Scanner

Masscan Web Scanner scans **explicitly authorized** IPv4/IPv6 networks with
[masscan](https://github.com/robertdavidgraham/masscan), extracts discovered web
endpoints and optionally stores their raw HTML plus a browser screenshot.

> [!WARNING]
> Port scanning can disrupt networks and may be unlawful without permission.
> Only scan systems for which you have explicit written authorization. Start
> with a conservative `--rate` and comply with the rules of engagement.

## Highlights

- validates, normalizes and de-duplicates input networks before scanning;
- splits oversized IPv6 networks lazily, avoiding an in-memory subnet list;
- bounded parallelism for scans and web requests;
- native masscan execution (no implicit `sudo`); run with the least privileges
  needed in your environment;
- ChromeDriver resolution through Selenium Manager;
- deterministic, de-duplicated summaries and IPv6-safe URLs;
- dry-run and scan-only modes for safe validation and automation;
- Python package metadata, automated tests, linting and GitHub Actions CI.

## Requirements

- Python 3.10 or newer;
- masscan (unless using `--dry-run`);
- Chrome or Chromium when screenshots are enabled.

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

Run the complete workflow:

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

`Masscan_Webscanner.py` remains as a compatibility entry point. New automation
should use the installed `masscan-webscanner` command or
`python -m masscan_webscanner`.

### Options

| Option | Default | Purpose |
| --- | ---: | --- |
| `-r`, `--ranges` | required | Input file containing authorized CIDRs. |
| `-p`, `--ports` | required | A masscan port expression. |
| `-o`, `--output-dir` | timestamped | Root directory for this run. |
| `-R`, `--rate` | `1000` | Packets per second passed to masscan. |
| `-t`, `--timeout` | `5` | HTTP and page-load timeout in seconds. |
| `--scan-workers` | `4` | Maximum concurrent masscan processes. |
| `--fetch-workers` | `8` | Maximum concurrent archive jobs. |
| `--max-ipv6-host-bits` | `32` | Largest IPv6 host part per scan job (1–63). |
| `--masscan` | `masscan` | masscan executable name or path. |
| `--browser` | auto-detected | Chrome/Chromium executable name or path. |
| `--skip-fetch` | off | Do not fetch HTML or take screenshots. |
| `--dry-run` | off | Validate input and log commands without executing them. |

## Output

```text
scan-results/
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

Raw HTML is intentionally stored without rewriting. Treat all scan artifacts as
untrusted, potentially sensitive data; do not open them with elevated privileges
or publish the result directory accidentally.

## Architecture

1. `load_ranges` validates and canonicalizes the scope.
2. `expand_network` lazily divides IPv6 scopes according to the configured cap.
3. A bounded thread pool invokes independent masscan processes.
4. `parse_masscan` creates stable summaries and a unique endpoint set.
5. A second bounded pool retrieves HTML and starts isolated headless browser
   sessions for screenshots.

A failed scan or web endpoint is logged without cancelling unrelated work. The
program returns `2` for configuration/dependency errors; individual masscan
failures are logged and the remaining ranges continue.

## Development and CI

Run the same checks used by GitHub Actions:

```bash
ruff check .
python -m pytest
python -m build
```

CI tests Python 3.10, 3.12 and 3.13 on pull requests and pushes to the default
branch. It does not perform real network scans.

## Known limitations

- Port-to-protocol selection is heuristic: ports 443, 8443 and 9443 use HTTPS;
  other ports use HTTP.
- Each screenshot starts a browser process. Keep `--fetch-workers` conservative
  on memory-limited systems.
- Extremely broad IPv6 scopes can still create an impractical number of scan
  jobs. Scope scans narrowly even though subnet generation is lazy.
- masscan privileges and supported IPv6 behavior depend on the operating system
  and local installation.

## License

GNU General Public License v3.0 only. See [LICENSE](LICENSE).
