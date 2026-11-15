# Changelog

## 4.0.0b109 — Beta

- Updates the installation guide with runtime-only installation and offline MCP checks.
- Adds a reproducible read-only walkthrough and separates contributor test dependencies.
- Includes Linux test portability fixes and sharded Python 3.11/3.12 release checks,
  with a separate macOS native-isolation job.
- Preserves existing workflow availability, authorization boundaries, and limitations.

## 4.0.0b108 — Beta

- Adds separate administrative planning and explicitly bound controlled profiles.
- Adds versioned planning, authorization, confirmation, state-drift, audit, and
  recovery components for fixed workflows.
- Includes access-domain and Secret onboarding components, administrative
  requirements, MCP Resources and Prompts, and optional workflow Skills.
- Preserves the default read-only posture and closed-by-default execution gates.
- Includes automated contract, redaction, failure-path, protocol, and packaging checks.

This is a pre-release. Workflow availability and product-version qualification
remain limited as described in [compatibility](docs/COMPATIBILITY.md).

## 3.1.3

- Initial minimized public source release with read-only checks, fixed diagnostics,
  isolated local simulation, stdio/HTTP transports, and OAuth support.
