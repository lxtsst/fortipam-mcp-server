---
name: fortipam-approval-workflow-design
description: Design or preview one FortiPAM FPA-BP-008 workflow that attaches an existing verified Approval Profile to an existing Secret and requires interactive approval. Use for approval-policy planning or request-lifecycle visibility; do not infer request creation, approval decisions, checkout, or launch capability.
---

Deployment authorization: this repository grants no standing authority. Lab-mode instructions require separate, explicit authorization for the exact isolated test workflow and a runtime policy that permits that mode. Manual administration still requires the documented parent confirmation. Product approvals and server-side authorization remain mandatory.

# FortiPAM Approval Workflow Design

Route the administrator's outcome to `FPA-BP-008`, `FPA-SK-008`, and
`ApprovalAndObserveScheme`. The currently supported core profile attaches one
existing, completely verified single-tier Approval Profile to one existing
Secret, enables interactive approval, disables job approval, and disables owner
bypass.

## Establish the Exact Scope

Use current server discovery to decide whether BP008 is source-backed,
plan-only, or controlled-executable. Ask only for genuinely missing decisions:
environment/scope, accountable owner, intended approval outcome, requester and
approver separation, expected postcondition, and rollback owner. An explicitly
supplied non-secret Secret or Profile selector may be moved once into the
owner-only binding; do not echo it in summaries, logs, tests, or Git. Never ask
for credentials, tokens, Secret values, custom-field answers, or approver lists.

Use only a server-issued `scheme_draft_ref` and the exact owner-only BP008
binding. If no Draft exists, route one closed private profile through
`fortipam-mcp-v4-approval-workflow-prepare`, then use its generated inputs with
the existing Draft and Reference Authority bootstrap commands. Do not ask the
administrator to handcraft Scheme, Authority, selector, or request JSON. The
live Tool surface is authoritative; source files and this Skill do not make an
executor available.

When the administrator already has one exact numeric request ID and wants only
its lifecycle state, the version `1.1.0` private profile may additionally bind
that ID and its expected `launcher` or `job` type to the same protected Secret,
requester, environment, and scope. The command generates an owner-only observer
binding plus a separate opaque request-reference file. Do not echo either
numeric ID or treat this local binding as Tool availability, collection
discovery, or request authorization.

## Preview the Supported Profile

The source-backed preview must independently verify the existing Secret and the
complete accepted Approval Profile, then show one Current / Proposed / Expected
summary using only opaque relations and categorical approval state. A different
attached Profile, incomplete Profile, unknown Secret state, or selector drift
fails closed.

Read-only discovery and an unchanged-scope refresh need no approval. Follow
`fortipam-governed-administration-workflow` for manual parent confirmation or
direct authenticated execution under standing owner-authorized lab authority.
The runtime's independent execution authorization remains required because it
is part of BP008 behavior; do not add a human-review or conversational-approval
gate around lab execution. Resolve the actual trusted lab binding under existing
authority or report the precise unsupported boundary once.

For an authorized external plan-only acceptance, use
`scripts/v4_approval_workflow_mcp_oauth_acceptance.py` with the owner-only login,
OAuth client state, and pre-issued Draft-reference files. It requests only
`fortipam:read` and `fortipam:plan`, performs one source-backed preview and one
parent confirmation, prepares a non-executable Plan, and revokes the token. It
never invokes a BP008 executor or creates a FortiPAM request. If the live Tool
is advertised and an owner-only opaque request-ref file is available, the same
client may add one `--request-ref-file` observation without another confirmation.

## Execute or Stop at Plan-Only

Invoke `execute_v4_approval_and_observe_workflow` only when that exact Tool is
advertised by the current controlled runtime and its protected authorization
and final Gate are available. Invoke it once with only `plan_ref` and
`scheme_draft_ref`. Require a fresh categorical pre-read and final expected-state
readback; on drift, ambiguity, or mismatch, report `reconciliation_required`
and do not replay the consumed authorization.

The current local BP008 request observer is not a request-creation capability.
Unless the live server advertises `observe_v4_bound_secret_request`, report
request-state observation as unavailable. When advertised, pass only the opaque
request reference; reading that already bound request needs no new conversational
approval. Never infer or submit a Secret-request POST body,
approve or deny a request, retrieve a Secret, check out credentials, launch a
session, or expose request, Secret, Profile, requester, or approver identifiers.

Use `fortipam-administrator-router` for initial routing and
`fortipam-governed-administration-workflow` for the shared confirmation and
readback rules.
