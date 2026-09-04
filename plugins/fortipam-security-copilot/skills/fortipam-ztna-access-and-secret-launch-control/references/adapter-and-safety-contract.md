# ZTNA Adapter and Safety Contract

## Current coverage

The current V3 MCP server provides only the minimized aggregate
`get_ems_connection_posture_summary`. It does not prove endpoint enrollment,
same-EMS association, tag synchronization, Access Proxy effective values,
proxy-policy enforcement, WAD device context, Folder/Secret ZTNA control, or
Secret launch. No current Tool executes the CLI or changes FortiPAM.

## Future adapter split

REST is preferred only where a versioned, fixed, least-privilege FortiPAM API
contract has been accepted. It is suitable for minimized EMS connector
posture, certificate/health posture, Folder/Secret control reads, supported
object writes, and bounded log summaries when the exact contracts exist.

SSH CLI remains necessary for fields that FortiPAM 1.9.1 documents as CLI-only,
including Access Proxy and proxy-policy controls. It must be a set of fixed
adapters, never generic SSH, arbitrary command execution, caller-supplied CLI,
or a silent fallback. Adapter selection and its effects must be displayed in
the Final Intent Summary.

Candidate atomic packages are:

| Package | Purpose | Current state |
| --- | --- | --- |
| `ztna-access-proxy-client-certificate-policy` | Read and set `client-cert` plus an explicitly selected `empty-cert-action`. | Contract missing; disabled. |
| `ztna-access-level-proxy-policy` | Read and set `ztna-status` and the bounded EMS tag reference for portal enforcement. | Contract missing; disabled. |
| `ztna-folder-control` | Read and set one Folder's ZTNA control, tag references, and AND/OR logic. | API/body/permission contract missing; disabled. |
| `ztna-secret-control-override` | Read and set one Secret's inheritance/override and bounded ZTNA control. | API/body/permission contract missing; disabled. |
| `ztna-device-context-diagnostic` | Produce a categorical tag-sync/device-context projection from fixed diagnostics. | Projector and permission contract missing; disabled. |
| `ztna-wad-debug-capture` | Time-box a single sanitized WAD diagnostic capture and always disable debug. | High-risk contract missing; disabled. |

Do not combine these into one opaque write. Each product object requires its
own expected-current guard, preview, confirmation revision, authorization,
pre-write re-read, post-write readback, and rollback/reconciliation result.

## Required safety controls

- dedicated source-restricted REST and SSH identities with independent
  positive/negative permission acceptance;
- exact FortiPAM version and HA-node scope;
- no generic route, path, JSON, CLI, shell, or SSH argument from the caller;
- opaque server-side object and endpoint references only;
- no C3 material, raw response, tag value, address, identity, session data, or
  debug payload in model/MCP/audit context;
- automatic debug timeout and cleanup even on cancellation or error;
- access-lockout warning and recovery path before Access-level changes;
- explicit `empty-cert-action` decision rather than an inferred default;
- one bounded object per atomic action; and
- exact Actual State versus Expected State readback before success.

Until these gates are promoted separately, output
`execution_state=plan_only`, `adapter=none`, and the exact missing evidence.
