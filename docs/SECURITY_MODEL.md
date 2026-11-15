# Security Model

The server does not expose arbitrary HTTP methods, URLs, headers, API paths,
SSH commands, shell commands, SQL, or SDK execution. It does not provide plaintext
Secret retrieval, credential checkout, recordings, or unrestricted administration.

Credentials and protected material stay outside model context, MCP arguments and
results, logs, fixtures, and Git. Operator-side components may consume required
material through explicit local channels; this does not make it model-visible.
TLS verification cannot be disabled. SSH diagnostics require a separate identity
and pinned host keys. Returned device observations are minimized and redacted.

Configuration and catalog entries cannot add runtime authority. The `readonly`
profile is the default. `lab-simulated` writes only isolated local fixtures.
The authenticated HTTP `v4-plan-only` profile cannot dispatch device changes.
The separate `v4-controlled` profile requires exact bindings and individually
enabled gates, scoped authorization, intent handling, drift rejection, bounded
dispatch, fixed readback, and durable audit/recovery state.

Never replay a consumed authorization or blindly retry an uncertain result.
Reconcile state before preparing another operation. Keep live state, credentials,
and audit files owner-only; use deployment-specific backups and recovery procedures.

Synthetic tests and protocol smoke do not establish production suitability.
Operators own host security, TLS, identity, network isolation, least privilege,
backups, change control, and target-version validation.
