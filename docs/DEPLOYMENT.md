# Deployment

Use the installation commands in [README.md](../README.md) with Python 3.11 or
3.12. Install optional `saml-metadata` or `bulk-import` dependencies only for the
corresponding functionality. A dependency being installed does not enable a tool.

## Appliance configuration

The retained `FPA_HOME_LAB_FPA1_` prefix is the runtime configuration namespace.
Provide `FPA_HOME_LAB_FPA1_ENV_FILE` with an absolute path to an ignored, owner-only
environment file (mode 600). Alternatively use the process environment or an
ignored `.env.local`. Explicit process values take precedence. Only matching
prefixes are loaded, and the file is parsed without executing shell code.
See [.env.example](../.env.example) and [config.py](../src/fortipam_mcp/config.py)
for supported settings. No shared inventory or credentials are provided.

Use verified TLS with native system trust or an explicit CA file. API credentials
use an Authorization header. SSH diagnostics require their own least-privilege
identity and pinned known-hosts file; do not reuse a broad administrator identity.

## HTTP

For local use, `FORTIPAM_MCP_HTTP_AUTH_MODE=none` is restricted to loopback.
The default endpoint is `http://127.0.0.1:8000/mcp`.
Remote listeners require HTTPS and either local OAuth or a correctly configured
external OAuth resource server. Keep issuer, audience, resource, redirect, and
scope validation enabled. See [http_server.py](../src/fortipam_mcp/http_server.py)
and the [sanitized HTTP example](../deploy/docker/fortipam-http.example.env).

## Profiles and state

Select `FORTIPAM_MCP_RUNTIME_PROFILE` explicitly for a non-default profile.
Planning and controlled profiles require an authenticated HTTP composition;
profile selection alone does not bind an executor. Protect all state directories
and independently required authority/checkpoint components. Do not enable a
controlled action until its exact identity, version, authorization, readback,
and recovery prerequisites are met.

Preserve a previous tagged installation and its compatible state backup before
upgrading. Test V4 alongside an existing V3 deployment with separate state and
OAuth configuration. Do not replay old authorizations across versions.

For optional container packaging, see [Docker](../deploy/docker/README.md).
