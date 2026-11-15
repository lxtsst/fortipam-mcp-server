# Privacy Policy

Effective date: 2026-09-04

FortiPAM Security Copilot MCP Server is self-hosted software. The project
maintainers do not operate a hosted service and do not receive data processed
by a deployment unless a user intentionally sends information through a
support or security-reporting channel.

## Data processed by a self-hosted deployment

Depending on the runtime profile and operator configuration, a deployment may
process:

- FortiPAM configuration-presence and minimized posture results;
- fixed API or CLI responses transiently inside the server process;
- OAuth identity and authorization data needed to authenticate the caller;
- local planning, confirmation, idempotency, baseline, and audit records; and
- operator-supplied non-secret identifiers required by an explicitly enabled
  fixed workflow.

The MCP interface is designed not to solicit or return passwords, API keys,
MFA codes, private keys, plaintext Secret values, recordings, raw device
responses, or unrestricted customer data. Deployers must not place those
values in MCP prompts or tool arguments.

## Purpose and sharing

Data is processed only to provide the requested FortiPAM observation,
diagnostic, planning, or explicitly enabled governed action. The software does
not include maintainer-operated analytics, advertising, tracking, or data-sale
features. A deployment communicates only with systems configured by its
operator, such as its FortiPAM appliance, identity provider, and reverse proxy.

## Storage and retention

Most device data is processed transiently and reduced before an MCP response is
returned. Features that require durable local state use operator-controlled
owner-only files or databases. Retention and deletion are controlled by the
deployer's configuration, backup, audit, and legal requirements. Some
tamper-evident audit records are intentionally append-only and should be
retained or destroyed only under the deployer's documented policy.

## Security and user control

Deployers are responsible for access control, TLS, OAuth configuration,
least-privilege FortiPAM identities, host security, retention, backups, and
compliance. Users should contact their deployment administrator to request
access, correction, or deletion of deployment-held data.

Do not report sensitive data in a public GitHub issue. Security reports must
follow [SECURITY.md](SECURITY.md). For other privacy questions, use the support
channel listed in the public repository.

This policy applies to this open-source project. A third party that deploys or
modifies the software may have its own privacy practices and must disclose them
to its users.
