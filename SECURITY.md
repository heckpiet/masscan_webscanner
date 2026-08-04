# Security policy

## Reporting a vulnerability

Do not disclose exploitable details in a public issue. Contact the repository
owner privately through the hosting platform and include affected versions,
impact, reproduction steps and a suggested mitigation. Do not scan third-party
systems while researching a report.

Supported versions are the latest GitHub release and the current `main` branch.

## Operational safety

This project is a dual-use network scanner. Operators are responsible for
written authorization, scope control, rate limits, data retention and applicable
law. Scan output and captured pages can contain secrets or malicious content;
store them with restricted permissions and treat them as untrusted data.

TLS certificate validation is disabled by default because inventory targets
commonly use self-signed certificates. Use `--verify-tls` when authenticated
transport is required. Without it, captured content is not proof of server
identity.

HTML retrieval never follows redirects and stops after `--max-html-bytes`. This
keeps the non-browser fetch on the discovered IP and limits memory/disk use.

Screenshots are disabled by default. `--screenshots` starts Chrome with its
sandbox enabled, but the page may still load redirects, scripts, images or other
resources outside the supplied ranges. Only enable it when the authorization
also permits that traffic. Never run the scanner or open captured HTML with
unnecessary elevated privileges.

The output directory can contain credentials, internal hostnames and malicious
content. Restrict access, define retention, keep it out of source control and
delete it according to the engagement's data-handling rules.
