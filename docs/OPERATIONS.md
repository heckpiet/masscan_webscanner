# Installation and operations

## Linux installation

Debian and Ubuntu example:

```bash
sudo apt update
sudo apt install masscan python3 python3-venv
python3 -m venv /opt/masscan-webscanner/venv
/opt/masscan-webscanner/venv/bin/python -m pip install --upgrade pip
/opt/masscan-webscanner/venv/bin/python -m pip install /path/to/masscan_webscanner
```

Install Chromium and the optional dependency only when screenshots are needed:

```bash
sudo apt install chromium
/opt/masscan-webscanner/venv/bin/python -m pip install '/path/to/masscan_webscanner[screenshots]'
```

Distribution package names differ. Confirm the packaged masscan and Chromium
versions against the distribution's supported repositories.

Verify the actual toolchain before the first run:

```bash
masscan --version
python3 --version
/opt/masscan-webscanner/venv/bin/python -m pip check
/opt/masscan-webscanner/venv/bin/masscan-webscanner --help
```

Masscan 1.3.2 is the latest tagged upstream release and is the compatibility
baseline. The upstream repository remains active. The scanner uses only stable
options present in 1.3.2 and current upstream: CIDR targets, `-p`, `--rate` and
`-oL`. Do not use Masscan UDP expressions; this application archives TCP web
services only.

## Privileges

Masscan needs raw-packet privileges. Prefer a dedicated service account and the
smallest mechanism supported by the host. Do not run the complete Python process
or browser as root merely to satisfy masscan. If capabilities or a privileged
wrapper are used, document and review that boundary locally.

Masscan automatically reads `/etc/masscan/masscan.conf`. Inspect it for adapter,
source IP/port, router MAC and exclusion settings. Command-line range, port,
rate and output arguments from this application take precedence, while other
system-wide settings can still affect routing and packet transmission.

The service account needs write access only to its output directory. A typical
starting point is mode `0700` for the root output directory and `0600` for
artifacts, adjusted to the authorized operator group.

## Safe rollout

1. Put only signed, authorized CIDRs in the ranges file.
2. Run `--dry-run` and review every generated command.
3. Start with `--scan-workers 1 --rate 100`.
4. Run with `--skip-fetch` before enabling HTML collection.
5. Enable `--screenshots` only when external browser resource traffic is allowed.
6. Review `run-summary.json` and the error log before increasing the global rate.

`--rate` is global. The scanner divides it across active Masscan processes, so
raising `--scan-workers` does not intentionally multiply the configured rate.

Selenium 4.6 and newer ships Selenium Manager. With screenshots enabled it can
resolve/download a matching driver into its cache. Restricted or offline hosts
must provision a compatible ChromeDriver themselves and make it available on
`PATH`; allow outbound access only if automated driver resolution is intended.

## Automation

Use the CLI's status codes:

- `0`: all selected work succeeded;
- `1`: at least one scan or fetch failed;
- `2`: configuration, input or dependency error.

Each invocation should use its own output directory. Monitor free disk space and
parse `run-summary.json` rather than relying only on log text. Keep ranges files
and outputs out of the repository.

For cron or systemd, set an explicit working directory, absolute paths and a
restrictive umask. Do not embed credentials in unit files or command lines.

## Retention and upgrades

Captured pages can contain sensitive data. Define an engagement-specific
retention period, encrypt backups where required and remove expired artifacts.

Upgrade in a fresh virtual environment, rerun `--help` and a dry-run, then scan a
small controlled range. Retain the previous environment until verification is
complete so rollback does not require reinstalling packages during an incident.
