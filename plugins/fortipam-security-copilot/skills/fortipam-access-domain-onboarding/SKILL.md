---
name: fortipam-access-domain-onboarding
description: Coordinate one Linux SSH/SFTP FortiPAM access-domain onboarding outcome across Folder ownership, direct ACL grants, optional Target creation, Secret creation, and final relationship readback. Use for FPA-BP-005 onboarding or a standalone FPA-BP-004 access domain; use policy-appropriate intent handling and never accept credential material.
---

Deployment authorization: this repository grants no standing authority. Lab-mode instructions require separate, explicit authorization for the exact isolated test workflow and a runtime policy that permits that mode. Manual administration still requires the documented parent confirmation. Product approvals and server-side authorization remain mandatory.

# FortiPAM Access Domain Onboarding

Own one coherent administrator conversation for `FPA-BP-004` or the combined
`FPA-BP-005` / `FPA-SK-005` Linux SSH/SFTP workflow. Use
`AccessDomainScheme` for a standalone Folder/ACL outcome and the combined
`SecretOnboardingScheme` when Folder/ACL, Target, Template, Launcher, and Secret
relationships belong to one onboarding result.

## Intake

Ask only for missing decisions: environment/scope, accountable owner, intended
user or group access and permissions, SSH versus SFTP, Target relationship,
Template/Launcher choice, and the observable success and negative-access result.
Do not ask the administrator to repeat information already present in the
server-issued Draft or owner-only binding.

An explicitly supplied non-secret lab name, address, account label, or URL may
be accepted once and moved to the owner-only binding. Do not echo private
selectors in summaries or results. Passwords, keys, tokens, and credential
values never enter model context, Scheme data, MCP arguments/results, tests,
logs, or Git; carry only categorical material-provider readiness.

## Plan Once

Use the current server's minimized projection and a server-issued
`scheme_draft_ref`. If no Draft has been issued, route one owner-only private
profile through `fortipam-mcp-v4-linux-onboarding-prepare`, then use the existing
Draft and Reference Authority bootstrap commands on its generated inputs. The
preparation command writes the mutually bound Scheme, reference, Access Domain,
and Secret onboarding files without printing their content. Do not ask the
administrator to handcraft Scheme, Authority, or binding JSON.
Derive `requester_digest` only inside trusted composition from the currently
validated OAuth principal; never ask the administrator to calculate or paste it.

For combined BP005, require `FolderBinding.folder_ref` to bind the same opaque
Public Folder relation and require both sources to agree whether it exists. A
missing Folder is one physical Folder create followed by owner ACL and declared
grants. A missing Target uses the fixed Target create. The Secret line depends
on every mutable Folder, ACL, and Target line. Do not create a second
FolderBinding action.

Present one Current/Proposed/Expected Final Intent Summary for the complete
parent Plan. Follow the intent policy in
`fortipam-governed-administration-workflow`: one parent interaction in manual
mode, or direct authenticated execution under standing authority for the
owner-authorized lab. Never request a human review or separate chat approval for
lab acceptance, its child actions, or an unchanged-scope read-only refresh.

## Execute and Verify

Treat execution as available only when current discovery shows the exact
`v4-controlled` workflow Tool, matching environment/scope authorization, and
final Gate. For an authorized external BP005 acceptance, use
`scripts/v4_linux_onboarding_mcp_oauth_acceptance.py` with the owner-only
pre-issued Draft-reference file and a new owner-only dispatch-state path. The
default remains `FPA-BP-005`; the same client accepts only the separately
routed BP006 and BP007 shapes through explicit `--blueprint-ref`, without
widening this Skill's Linux scope. It
performs the one parent preview, creates any runtime-required one-time intent
record directly under standing lab authority, then records the
dispatch attempt before invoking `execute_v4_secret_onboarding_workflow` once
with only `plan_ref` and `scheme_draft_ref`. Use the Access Domain workflow Tool
instead for a standalone BP004 parent Plan. Never call or retry child actions
directly, and never delete a dispatch record to create retry authority.

Success requires final source-backed readback of Folder ownership, every
declared direct grant, Target/Template/Secret binding, permission inheritance,
and declared Launcher readiness. On drift, partial completion, ambiguous
transport outcome, or readback mismatch, stop with `reconciliation_required`
and do not replay the consumed Plan.

Use `fortipam-administrator-router` for registry routing and
`fortipam-governed-administration-workflow` for the shared confirmation and
execution-state rules.
