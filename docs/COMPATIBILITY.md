# Profiles and Compatibility

| Profile | Purpose | Device effects |
| --- | --- | --- |
| `readonly` | 28 fixed read-only/offline tools | Fixed reads and diagnostics only |
| `lab-simulated` | Read-only surface plus local simulation | Writes isolated local fixtures only |
| `v4-plan-only` | 97 tools on authenticated HTTP for planning and requirements | No device mutation |
| `v4-controlled` | Explicitly bound, individually enabled workflows | Only the exact authorized action |

Stdio and Streamable HTTP are supported. V4 planning/control require their
authenticated HTTP bindings. Discover the actual registered tools from the
running server; an implementation module or registry row is not a live tool.

Version 4.0.0b108 is a Beta. Read-only contracts and the packaged API discovery
metadata originate from FortiPAM 1.9.x. Selected controlled workflow code has
version-specific branches, including FortiPAM 7.0.0 build 29. These branches
do not establish general compatibility with every release or workflow.

The source includes access-domain and Linux SSH/SFTP onboarding, existing-Target
Windows/RDP onboarding, targetless Web Account onboarding, approval planning,
and other fixed action components. Availability depends on the exact configured
bindings, identity, role, baseline, and target-version qualification.

Service-account Target creation/recovery has unresolved outcomes and remains
isolated; its update entry is not registered. HA, bulk import, Terraform,
external identity/MFA, native-client behavior, and hardware-dependent scenarios
have incomplete qualification. Unsupported or unqualified execution stays closed.
Local tests do not certify a production deployment or grant cross-product rights.

Native bulk-import worker components depend on macOS `sandbox-exec`. Their
OS-specific isolation tests run separately on macOS; Linux CI does not qualify
that execution path.

The v3.1.3 tag preserves the previous public source. Use separate configuration,
state, OAuth identities, and backups when evaluating V4 beside an existing V3
deployment. Review tool schemas, permissions, and recovery contracts before
migrating a client or enabling an action.
