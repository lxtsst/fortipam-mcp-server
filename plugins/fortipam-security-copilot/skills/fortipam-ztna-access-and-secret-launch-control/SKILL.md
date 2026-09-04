---
name: fortipam-ztna-access-and-secret-launch-control
description: Design, diagnose, and verify FortiPAM ZTNA access-level or Secret-level controls across EMS, FortiClient, Access Proxy, proxy policy, Folder/Secret tags, WAD device context, and launch evidence. Use when an administrator wants to enable ZTNA, choose its scope, or troubleshoot a protected Secret launch; current execution is plan-only and must not expose endpoint, token, or debug data.
---

# FortiPAM ZTNA Access and Secret Launch Control

Use this Skill for one of three bounded outcomes:

- design an Access-level control that restricts FortiPAM portal login;
- design a Secret-level control that restricts only selected Folders/Secrets;
  or
- locate the first failed ZTNA evidence gate in a Secret-launch incident.

The current V4 record is `design_only/catalogued`. It does not register a
write or diagnostic MCP Tool, enable an SSH adapter, or authorize a device
change. Treat the verified lab incident as version-scoped evidence, not as
permission to repeat its commands.

## Workflow

1. Establish the exact FortiPAM version, environment, accountable owners, and
   one requested mode: `access_level`, `secret_level`, or `diagnosis_only`.
2. Collect the non-secret decisions: managed-endpoint requirement, portal
   access intent, EMS/tag reference classes, Folder-or-Secret scope, AND/OR
   match logic, client-certificate policy, `empty-cert-action` intent, positive
   and negative test classes, and whether short-lived debug is authorized.
   Never request an endpoint IP, tag value, username, target address, Secret
   name, certificate material, JWT, cookie, token, or raw log.
3. Read a fixed minimized Current State in evidence order: EMS connection,
   endpoint readiness, tag synchronization, effective Access Proxy settings,
   proxy-policy enforcement, WAD device context, Folder/Secret control, then
   launch and traffic evidence. A positive earlier gate does not prove a later
   gate.
4. Select the scope before proposing a delta. Access-level tag enforcement can
   prevent portal login and is high impact. Secret-level control must preserve
   ordinary Secret behavior while checking tags only for protected resources.
   Do not add an interface/proxy-policy tag filter when the stated intent is
   mixed portal access with Secret-only enforcement.
5. Treat `empty-cert-action` as an explicit decision. Use `block` only when the
   requirement is managed endpoints for every login. Consider `accept` only
   when unmanaged endpoints must log in and use unprotected resources on the
   same interface. Never change it as an implicit workaround.
6. Render Current State, Proposed Changes, Expected State, unchanged scope,
   access-impact warning, rollback, positive/negative tests, evidence policy,
   and all gaps. Ask the authenticated requester to confirm that exact
   revision. Confirmation is not approval or execution authority.
7. Stop at preview unless every exact read/write/readback contract, dedicated
   least-privilege identity, policy decision, adapter, lab acceptance, and
   authorization gate has been separately promoted. Immediately before any
   future write, re-read Current State and invalidate confirmation on drift.
8. Verify with a managed positive case, a tag/certificate negative case, the
   intended unmanaged/unprotected case when applicable, WAD context outcome,
   Secret launch result, and sanitized ZTNA traffic evidence. Never report
   success from tag synchronization alone.

Read [references/control-modes-and-preflight.md](references/control-modes-and-preflight.md)
when choosing the enforcement scope or `empty-cert-action` behavior. Read
[references/diagnosis-and-acceptance.md](references/diagnosis-and-acceptance.md)
for a launch failure or acceptance run. Read
[references/adapter-and-safety-contract.md](references/adapter-and-safety-contract.md)
when evaluating REST, SSH CLI, WAD debug, or future MCP coverage.

For the cross-cutting Final Intent Summary and denial rules, use the
[`fortipam-administrator-router`](../fortipam-administrator-router/SKILL.md).
