# Child Folder Action Boundary

## Candidate contract

| Property | Controlled V4 boundary |
| --- | --- |
| Action | `folder-create@3.2.0` |
| Object | One inherited Public child Folder |
| Parent | One existing positive product identifier, privately resolved |
| Create route | Fixed internal `POST /api/v2/cmdb/secret/folder` |
| Read routes | Fixed internal collection and detail reads |
| Inheritance | Policy, permission, and Folder ZTNA enabled |
| Local ACL entries | Empty for the inherited child |
| Permission class | Secret Folder read/write candidate; Root Folder not required |
| MCP Tool | `execute_confirmed_v4_child_folder` |
| Caller input | One opaque, protected `authorization_ref` only |
| OAuth authority | Explicit `fortipam:plan` and non-default `fortipam:operate` scopes |
| Enablement | Exact `v4-controlled` profile plus explicit feature flag and bound host |
| Current promotion state | Registered opt-in action; disabled by default; live MCP execution acceptance remains deployment-specific |

The route and request shape describe internal implementation evidence. They are
not caller inputs and must not be copied into a generic REST, browser, CLI, or
SSH operation.

## Excluded scope

- Root Folder creation, because the exact owner/ACL request encoding is not
  accepted.
- Folder ACL assignment, update, move, rename, delete, or bulk creation.
- Target, Secret, Local User, role, policy, ZTNA-control, or launcher changes.
- Caller-supplied product IDs, request JSON, paths, endpoints, credentials, or
  raw responses.
- Automatic compensation by deletion; timeout or ambiguity requires
  reconciliation until a separately accepted recovery contract exists.

## Truthful result

When the Tool is absent, disabled, unbound, or lacks a protected authorization,
return:

```text
execution_state=plan_only
m4_candidate_state=registered_disabled
device_write_executed=false
```

When the Tool is available, do not claim success from registration, dispatch,
or HTTP status. Only the fixed categorical result may establish:

```text
execution_state=executed
outcome=succeeded
verification=verified
```

Any unknown, failed, or reconciliation-required state remains unresolved and
must not be retried automatically.
