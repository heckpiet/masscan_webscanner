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

### Kali with pipx

Kali enforces PEP 668. Install the application with pipx instead of using
`pip --user` or `--break-system-packages`:

```bash
sudo apt install -y masscan chromium chromium-driver pipx
pipx ensurepath
pipx install --force ./masscan_webscanner-2.1.0-py3-none-any.whl
pipx inject --force masscan-webscanner "selenium>=4.18,<5"
masscan-webscanner --version
```

Open a new terminal after `pipx ensurepath` if the command is not yet on `PATH`.

Verify the actual toolchain before the first run:

```bash
masscan --version
python3 --version
/opt/masscan-webscanner/venv/bin/python -m pip check
/opt/masscan-webscanner/venv/bin/masscan-webscanner --help
```

Masscan 1.3.2 is the latest tagged upstream release and is the compatibility
baseline. The upstream repository remains active. The scanner uses only stable
options present in 1.3.2 and current upstream: CIDR targets, `-p`, `--rate`,
`--excludefile` and `-oL`. Do not use Masscan UDP expressions; this application
archives TCP web services only.

## Privileges

Masscan needs raw-packet privileges. Start `masscan-webscanner` as the normal
desktop user. The automatic precheck requests sudo once, then runs only masscan
children through non-interactive sudo. Python, Selenium and Chromium stay
unprivileged. Do not run the complete command as root. If capabilities or a
privileged wrapper are already configured, use `--no-sudo` and document that
boundary locally.

Masscan automatically reads `/etc/masscan/masscan.conf`. Inspect it for adapter,
source IP/port, router MAC and exclusion settings. Command-line range, port,
rate and output arguments from this application take precedence, while other
system-wide settings can still affect routing and packet transmission.

The service account needs write access only to its output directory. A typical
starting point is mode `0700` for the root output directory and `0600` for
artifacts, adjusted to the authorized operator group.

## Safe rollout

1. Put only signed, authorized CIDRs in the ranges file (and specify any excluded IPs/subnets with `!`).
2. Run `--dry-run` and review every generated command.
3. Start with `--scan-workers 1 --rate 100`.
4. Run with `--skip-fetch` before enabling HTML collection.
5. Enable `--screenshots` only when external browser resource traffic is allowed.
6. Review `run-summary.json` and the error log before increasing the global rate.

`--rate` is global. The scanner divides it across active Masscan processes, so
raising `--scan-workers` does not intentionally multiply the configured rate.

With screenshots enabled, the precheck requires Selenium, Chromium and an
operating-system ChromeDriver on `PATH`. It reads both version strings and stops
before scanning unless their major versions match.

The precheck also prints the application version, authorized-range count,
excluded-target count (when exclusions are configured), writable output path,
effective HTTP/screenshot timeouts, Python dependencies, masscan location and
sudo status.
`--dry-run` intentionally skips runtime executable and sudo requirements.

## Timeouts

The default HTTP timeout is 5 seconds. The default screenshot timeout is 15
seconds because Chromium must render scripts and page subresources after the
initial response. Adjust them independently when required:

```bash
masscan-webscanner -r ranges.txt -p 80,443 --screenshots \
  --http-timeout 8 \
  --screenshot-timeout 30
```

The legacy `-t`/`--timeout` option remains supported and sets both values to the
same number. Independent options are preferred for new automation.

## Automation

Use the CLI's status codes:

- `0`: all selected work succeeded;
- `1`: at least one scan, fetch or screenshot failed;
- `2`: configuration, input or dependency error.

Each invocation should use its own output directory. Monitor free disk space and
parse `run-summary.json` rather than relying only on log text. Keep ranges files
and outputs out of the repository.

The console displays progress and aggregate results. Repetitive endpoint errors
remain available in `logs/errors.log` and `run-summary.json` without flooding an
interactive terminal.

For cron or systemd, set an explicit working directory, absolute paths and a
restrictive umask. Do not embed credentials in unit files or command lines.

## Retention and upgrades

Captured pages can contain sensitive data. Define an engagement-specific
retention period, encrypt backups where required and remove expired artifacts.

For pipx upgrades, install the new wheel with `pipx install --force`, inject the
screenshot dependency, confirm `masscan-webscanner --version`, and run a dry-run
before a small controlled scan. Retain the previous wheel until verification is
complete so rollback does not require rebuilding during an incident.
