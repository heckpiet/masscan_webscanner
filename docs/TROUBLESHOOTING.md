# Troubleshooting

## `externally-managed-environment`

Kali protects system Python under PEP 668. Do not use
`--break-system-packages`. Install the wheel with pipx as documented in
`OPERATIONS.md`.

## `masscan executable not found`

Install Masscan through the operating system or pass its absolute path with
`--masscan`. A dry-run does not require the executable.

## Permission errors from Masscan

Masscan cannot create raw packets with the current privileges. Follow the host's
approved raw-packet/capability policy. Avoid running Chrome or the complete
scanner as root.

Start the application normally. Its precheck prompts once for sudo and applies
that authorization only to masscan. Use `--no-sudo` only for an explicitly
configured capability or privilege setup.

## Unexpected interface or source address

Run `masscan --echo` in the same service environment and inspect
`/etc/masscan/masscan.conf`. Masscan can inherit adapter, source-address,
source-port, router-MAC and exclusion settings from that file.

## Browser not found

Screenshots are optional. Install Selenium plus Chrome/Chromium and a matching
ChromeDriver, pass `--browser /absolute/path`, or omit `--screenshots` to collect
HTML only.

Confirm that browser and driver major versions match. On offline systems, put a
compatible ChromeDriver on `PATH`. The precheck reports both versions and stops
before scanning when their major versions differ.

## HTTP 403 and 404

These are reachable HTTP responses and are archived. Connection resets,
timeouts and remote disconnects remain transport failures. A screenshot failure
is reported separately and does not remove valid HTML.

## HTTPS failures

Certificate verification is off by default. If `--verify-tls` is selected,
private certificate authorities must be available to the Python and browser
trust stores. Do not disable verification merely to hide an unexpected identity
or routing problem.

When verification is disabled (the default), repetitive urllib3 certificate
warning blocks are suppressed. Transport failures are still recorded in
`logs/errors.log` and `run-summary.json`. With `--verify-tls`, certificate
validation failures remain visible as endpoint errors.

## Redirect pages are not followed

This is intentional for HTML retrieval so an authorized IP cannot redirect the
scanner outside scope. The redirect response body may still be archived. Browser
screenshots have a wider network boundary; see `SECURITY.md`.

## Exit status 1

One or more scan, fetch or screenshot operations failed while other work continued. Inspect
`run-summary.json`, `logs/errors.log` and the individual Masscan output files.

## Screenshot renderer timeouts

Chromium pages often need longer than direct HTTP retrieval. The defaults are 5
seconds for HTTP and 15 seconds for screenshots. Increase only the browser value
first, for example `--screenshot-timeout 30`. Use `--http-timeout` separately
when the initial HTTP response itself is slow.

## Large IPv6 scopes

Subnet generation is lazy but the number of resulting scan jobs may still be
impractical. Narrow the authorized scope and review `--max-ipv6-host-bits` in a
dry-run before executing it.
