# Troubleshooting

## `masscan executable not found`

Install Masscan through the operating system or pass its absolute path with
`--masscan`. A dry-run does not require the executable.

## Permission errors from Masscan

Masscan cannot create raw packets with the current privileges. Follow the host's
approved raw-packet/capability policy. Avoid running Chrome or the complete
scanner as root.

## Browser not found

Screenshots are optional. Install the `screenshots` extra and Chrome/Chromium,
pass `--browser /absolute/path`, or omit `--screenshots` to collect HTML only.
Selenium Manager may need network access to resolve a compatible driver.

## HTTPS failures

Certificate verification is off by default. If `--verify-tls` is selected,
private certificate authorities must be available to the Python and browser
trust stores. Do not disable verification merely to hide an unexpected identity
or routing problem.

## Redirect pages are not followed

This is intentional for HTML retrieval so an authorized IP cannot redirect the
scanner outside scope. The redirect response body may still be archived. Browser
screenshots have a wider network boundary; see `SECURITY.md`.

## Exit status 1

One or more scan or fetch operations failed while other work continued. Inspect
`run-summary.json`, `logs/errors.log` and the individual Masscan output files.

## Large IPv6 scopes

Subnet generation is lazy but the number of resulting scan jobs may still be
impractical. Narrow the authorized scope and review `--max-ipv6-host-bits` in a
dry-run before executing it.
