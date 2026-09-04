# Security Policy

## Supported version

Security fixes are maintained for the latest tagged release line. The current
supported release line is `3.1.x`.

## Reporting a vulnerability

Report vulnerabilities privately to the repository owner through GitHub's
private security-advisory workflow when available. If that workflow is not
available, contact the maintainer privately before opening an issue.

Do not include API tokens, passwords, SSH private keys, device addresses,
customer data, Secret values, recordings, raw FortiPAM responses, cookies, or
session material in an issue, pull request, or advisory attachment.

Include only the minimum reproducible information: affected version, component,
impact, safe reproduction steps using synthetic data, and a proposed mitigation
if known. Please allow reasonable time for triage and remediation before public
disclosure.

## Security boundary

This project is read-only by design. A report that proposes generic endpoint or
command execution, TLS-verification bypass, credential logging, Secret custody,
or configuration mutation is a design-boundary change and will not be accepted
as a routine fix.
