# Natural-Language Child Folder Demonstration

This is a conversation contract, not a claim that a second Folder was created
in a live lab.

## Request

> Create one child Folder named `team_ops` under the existing `core_infra`
> Public Folder. Inherit policy, permissions, and Folder ZTNA.

## Required preview

```text
Current
- Environment: approved FortiPAM lab
- Parent: core_infra, uniquely resolved by the private host
- Existing child named team_ops under that parent: none

Proposed
- Create exactly one Public child Folder named team_ops
- Parent: core_infra
- Inherit policy: enabled
- Inherit permissions: enabled
- Inherit Folder ZTNA: enabled
- Submitted local user/group ACL entries: empty

Expected
- Exactly one team_ops child exists under core_infra
- Collection and detail readback agree
- Effective inherited ACL may be expanded by FortiPAM
- No Root Folder, ACL, Target, Secret, Local User, update, delete, or bulk change
```

The assistant then asks the authenticated human to confirm this exact revision.
It does not call the execute Tool yet.

## Confirmed execution

After the human confirms, the trusted host—not the model—creates the protected
one-time binding. The authenticated MCP client must have explicitly requested
both `fortipam:plan` and the non-default `fortipam:operate` scope. The Skill
calls only:

```text
execute_confirmed_v4_child_folder(authorization_ref=<server-issued opaque ref>)
```

The Skill must not add or reconstruct a Folder name, parent ID, endpoint,
request body, API token, clock, or retry instruction.

## Result handling

- `succeeded + verified`: report verified creation.
- `reconciliation_required` or `verification=unknown`: report unresolved and
  perform read-only reconciliation; never redispatch automatically.
- `precondition_failed`: report Current State drift and require a new preview
  and confirmation.
- Tool unavailable or feature disabled: remain plan-only.
