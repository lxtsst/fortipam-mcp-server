# FortiPAM Security Copilot MCP Server

[简体中文](README.zh-CN.md)

An independently developed FortiPAM MCP server that gives AI clients fixed, minimized, and auditable capabilities for read-only posture checks, operational diagnostics, and controlled local simulation workflows.

> This project is not an official Fortinet product and is not endorsed by Fortinet. Fortinet and FortiPAM are trademarks of their respective owners.

## Capabilities

- Read-only FortiPAM API checks and restricted SSH diagnostics by default;
- fixed routes, bounded inputs, recursive redaction, and minimized outputs;
- stdio and Streamable HTTP MCP transports;
- embedded local OAuth or an external OAuth resource-server mode;
- an optional `lab-simulated` profile that modifies only isolated local fixtures, never FortiPAM;
- FortiPAM operational Skills, scenario catalogs, and automated tests.

## Install and verify

Python 3.11 or 3.12 is required.

```bash
git clone https://github.com/lxtsst/fortipam-mcp-server.git
cd fortipam-mcp-server
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python scripts/verify_release.py
```

Start the stdio server:

```bash
.venv/bin/fortipam-mcp-server
```

Start local Streamable HTTP:

```bash
FORTIPAM_MCP_HTTP_AUTH_MODE=none .venv/bin/fortipam-mcp-http
```

Unauthenticated HTTP is restricted to loopback. Remote deployments require HTTPS and an appropriate OAuth configuration.

## Configuration

The repository contains sanitized examples only:

- [`.env.example`](.env.example)
- [`config/fortipam.example.json`](config/fortipam.example.json)
- [`deploy/docker/fortipam-http.example.env`](deploy/docker/fortipam-http.example.env)

Never commit credentials, tokens, SSH private keys, device addresses, or customer data. See [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) and [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md) for deployment and trust boundaries.

## Repository layout

- `src/fortipam_mcp/`: MCP server implementation;
- `plugins/fortipam-security-copilot/`: Codex plugin and FortiPAM Skills;
- `registry/` and `schemas/`: controlled-operation and administration metadata;
- `tests/` and `evals/`: automated tests and scenario evaluation;
- `deploy/docker/`: Docker deployment assets.

## Security and license

Report vulnerabilities privately as described in [`SECURITY.md`](SECURITY.md); do not include sensitive information in a public issue. Licensed under the [MIT License](LICENSE).
