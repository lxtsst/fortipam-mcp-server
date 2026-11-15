# Security Policy

## Supported version

The current development pre-release line is `4.0.x`. Beta versions require
deployment-specific validation. The earlier v3.1.3 source remains available;
do not assume V4 features exist in that version.

## Reporting a vulnerability

Use the repository's private security-advisory workflow when available.
Otherwise contact the maintainer privately before opening a public issue.
Provide the affected version, impact, and a minimal reproduction with synthetic
data. Do not attach credentials, private keys, addresses, customer data, Secret
values, recordings, cookies, sessions, or raw appliance responses.

## Runtime boundary

The default device surface is read-only. The planning profile cannot execute
device changes. Controlled actions require explicit binding, individual feature
gates, scoped authorization, current-state checks, and their fixed recovery
contracts. All execution gates default closed. Planning and metadata do not
grant execution authority. See [the security model](docs/SECURITY_MODEL.md).
