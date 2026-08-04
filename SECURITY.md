# Security policy

## Reporting a vulnerability

Do not disclose exploitable details in a public issue. Contact the repository
owner privately through the hosting platform and include affected versions,
impact, reproduction steps and a suggested mitigation. Do not scan third-party
systems while researching a report.

## Operational safety

This project is a dual-use network scanner. Operators are responsible for
written authorization, scope control, rate limits, data retention and applicable
law. Scan output and captured pages can contain secrets or malicious content;
store them with restricted permissions and treat them as untrusted data.

The scanner disables TLS certificate validation because it inventories services
that commonly use self-signed certificates. Consequently, captured content is
not authenticated and must not be used as proof of server identity.
