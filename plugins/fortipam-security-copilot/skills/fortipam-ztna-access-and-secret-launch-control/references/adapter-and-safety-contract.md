# ZTNA Adapter and Safety Contract

## Current coverage

The current V4 surface includes the minimized aggregate
`get_ems_connection_posture_summary`, separately gated read-only
`ztna-device-context-diagnostic` and `ztna-folder-control-posture` packages,
the separately gated Access Proxy
client-certificate prerequisite, and a disabled-by-default local Access-level
`ztna-user-control.configure` package. The two mutation packages require an
exact Current/Proposed/Expected preview, requester-bound confirmation, drift
rejection, and fixed categorical CLI readback. Neither is candidate-deployed or
lab-accepted. The surface still does not prove endpoint enrollment, same-EMS
association, tag synchronization, full Folder/Secret ZTNA control, Secret
launch, least-privilege permission, HA, rollback, or production readiness.

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
| `ztna-access-proxy-client-certificate-policy` | Read and set `client-cert` plus an explicitly selected `empty-cert-action`. | Local package complete, disabled, not candidate-deployed or lab-accepted. |
| `ztna-user-control.configure` | Read one private Access-level policy with its existing EMS tag and set only `ztna-status=enable` for portal enforcement. | Local package complete, disabled, not candidate-deployed or lab-accepted. |
| `ztna-folder-control` | Read one Folder's inheritance/tag observability, or future set one Folder's ZTNA control, tag references, and AND/OR logic. | A fixed no-value posture read is locally packaged and disabled; the exact FortiPAM 1.9.1 no-C3 write/readback contract is still missing, so all Folder writes remain disabled. |
| `ztna-secret-control-override` | Read and set one Secret's inheritance/override and bounded ZTNA control. | Product behavior is documented, but the Secret projection can include field values and no safe no-C3 update/readback contract is established; disabled. |
| `ztna-device-context-diagnostic` | Produce a categorical client-certificate, dynamic-list, and WAD-device-context projection from fixed diagnostics. | Local package complete, disabled, not candidate-deployed or live read-only accepted. |
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

For a requested control without one of the four local packages, output
`execution_state=plan_only`, `adapter=none`, and the exact missing evidence.
For a local package, disclose that it is disabled and unaccepted until its
runtime gates and separate candidate/live evidence are promoted.
