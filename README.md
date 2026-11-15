# FortiPAM Security Copilot MCP Server

[简体中文](README.zh-CN.md)

An independent, self-hosted MCP server for FortiPAM posture checks, operational
diagnostics, administrative planning, and explicitly enabled controlled workflows.

**Version: 4.0.0b109 (Beta).** This is a pre-release, not a production certification.
[Download the current V4 source](https://github.com/lxtsst/fortipam-mcp-server/releases/tag/v4.0.0-beta.109).
GitHub may label the older [v3.1.3](https://github.com/lxtsst/fortipam-mcp-server/releases/tag/v3.1.3)
release as Latest because V4 is a pre-release. V3 does not include V4 capabilities.

This is not an official Fortinet product and is not endorsed by Fortinet.
Fortinet and FortiPAM are trademarks of Fortinet, Inc.

## Capabilities

- Read-only API posture checks and fixed SSH diagnostics by default.
- Offline API discovery, operational scenarios, and administrative planning.
- Separate `readonly`, `lab-simulated`, `v4-plan-only`, and `v4-controlled` profiles.
- Stdio and Streamable HTTP, with local OAuth or an external OAuth resource server.
- Versioned action contracts, state-drift checks, bounded execution, minimized
  readback, and tamper-evident local audit state for supported controlled workflows.
- Client-neutral MCP Resources and Prompts, plus optional FortiPAM workflow Skills.

The default profile exposes 28 read-only/offline tools. The authenticated HTTP
`v4-plan-only` profile exposes 97 tools and cannot execute device changes.
The `v4-controlled` profile registers only explicitly bound and individually
enabled actions. All execution gates are closed by default.

## Try a read-only example

[Run the offline MCP walkthrough](docs/READ_ONLY_EXAMPLE.md) to classify two
API operations and retrieve a FortiAnalyzer delivery evidence plan without a
device or credentials. It includes expected output and a separate guide to a
fixed live status read on your own authorized appliance.

## Install and verify

Use Python 3.11 or 3.12 on macOS or Linux in a dedicated environment.
The following installs the runtime without development or optional workflow dependencies:

```bash
git clone https://github.com/lxtsst/fortipam-mcp-server.git
cd fortipam-mcp-server
git checkout v4.0.0-beta.109
python3 -m venv .venv
.venv/bin/python -m pip install --constraint deploy/docker/runtime-constraints.txt .
.venv/bin/python -m pip check
.venv/bin/fortipam-mcp-smoke
.venv/bin/fortipam-mcp-http-smoke
```

These offline checks verify MCP initialization, 28 tools, five resources, and
seven prompts; the HTTP check also verifies rejection without authentication.
They do not contact a FortiPAM appliance. Full development/release checks are
documented in [Contributing](CONTRIBUTING.md).

Distribution uses GitHub source releases. The commands here build and install a
local Python package; no published PyPI package or GHCR image is required.
The optional workflow plugin has its own version, separate from the server.

Start the default stdio server:

```bash
.venv/bin/fortipam-mcp-server
```

Stdio waits for an MCP client; it is not an interactive shell. In a client that
supports local stdio servers, set the command to the **absolute path** of
`.venv/bin/fortipam-mcp-server`, with no arguments.

For a loopback-only HTTP server:

```bash
FORTIPAM_MCP_HTTP_AUTH_MODE=none .venv/bin/fortipam-mcp-http
```

Connect an HTTP-capable MCP client to `http://127.0.0.1:8000/mcp`.
The optional plugin contains an example HTTPS endpoint that must be replaced
with your own deployment URL.

Remote HTTP requires HTTPS and an appropriate OAuth configuration. See
[deployment](docs/DEPLOYMENT.md), [profiles and compatibility](docs/COMPATIBILITY.md),
and the [security model](docs/SECURITY_MODEL.md).

## Configuration

Use the sanitized [.env.example](.env.example) and
[configuration example](config/fortipam.example.json).
Keep real configuration in ignored, owner-only files. Supply your own authorized
FortiPAM endpoint, CA trust, API identity, and any separately required SSH identity.
Never commit credentials, tokens, private keys, device addresses, or customer data.

## Limitations

Action availability depends on the selected profile, explicit bindings, product
version, and required identity and state. Code or catalog presence does not prove
that a workflow is callable or qualified for a deployment. Service-account Target
creation/recovery has unresolved outcomes and remains isolated; its update entry
is not registered. HA, bulk import, Terraform, external identity/MFA, and native
client or hardware-dependent scenarios have incomplete qualification.
Do not retry an operation with an uncertain outcome before reconciling its state.

## Contributing and license

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
The project is licensed under [MIT](LICENSE). The license does not grant rights
to third-party API archives or vendor documentation. The repository contains
implementation, bounded metadata, synthetic tests, and sanitized examples;
it does not include shared credentials or a hosted FortiPAM service.
See [privacy](PRIVACY.md) and [terms](TERMS.md).
