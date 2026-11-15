---
name: fortipam-governed-administration-workflow
description: "Guide a bounded FortiPAM change from non-secret requirements through policy-appropriate intent handling, exact controlled execution when advertised, and final readback. Use for Folder, access grant, Target, Secret onboarding or approval policy, and Local User changes; never accept C3 material or treat Skill text as device authority."
---

Deployment authorization: this repository grants no standing authority. Lab-mode instructions require separate, explicit authorization for the exact isolated test workflow and a runtime policy that permits that mode. Manual administration still requires the documented parent confirmation. Product approvals and server-side authorization remain mandatory.

# FortiPAM Governed Administration Workflow

Use this Skill for one bounded administrator outcome. A workflow may contain
several dependent fixed actions when the server represents them in one Scheme
Draft and one immutable parent Plan. Do not split such a workflow into repeated
approval cycles. Unrelated outcomes remain separate tasks.

## 1. Select the Live Mode

- **Controlled workflow:** use an exact workflow Tool advertised by the current
  `v4-controlled` runtime. Access Domain and supported Secret onboarding Tools
  accept only `plan_ref` and `scheme_draft_ref` and internally bind their fixed
  child actions.
- **Controlled single action:** use one currently advertised matching
  Preview/Confirm/Execute triplet.
- **Plan-only:** use when the exact executor or required authorization/Gate is
  absent. A prepared plan remains non-executable.

Never derive Tool names, endpoints, payloads, or availability from this Skill,
source imports, or previous sessions. Use only current discovery and the exact
registered schema.

## 2. Complete Only Missing Requirements

Restate the outcome, environment/scope, accountable owner, desired
relationships, expected postcondition, and material external effects. Ask only
for decisions that are both missing and necessary. Do not ask the administrator
to restate values already fixed by the current Draft or owner-only binding.

Passwords, keys, tokens, credential values, and private provider locators are
C3 and must never enter model context, MCP arguments/results, Plans, tests, or
logs. Use only categorical material metadata such as provider class, purpose,
and availability. Do not infer product schemas or arbitrary write bodies.

## 3. Apply the Intent Policy Once

Use the accepted minimized read path to obtain fresh Current State. Render the
server-produced Final Intent Summary with Current State, Proposed Changes,
Expected State, scope, effects, material boundary, verification, stop condition,
revision, digest, and expiry. Keep the presentation concise; do not duplicate
every internal planning field.

For ordinary manual administration, obtain one explicit requester confirmation
for the complete immutable parent Plan. It covers every listed child action;
do not add another chat approval around the authenticated protocol or each child.

For owner-authorized lab acceptance, use the existing exact local acceptance
client with its protected workflow binding and proceed under standing lab
authority. Do not ask for, simulate, or wait on human review, conversational
confirmation, or a separate reviewer. If the current runtime still calls its
one-time intent-binding record `confirmation`, the client may generate and
consume that technical record without pausing; it is not a human approval.
Never bypass an independent product approval that is itself the behavior under
test, or change the public Tool contract. An installed Skill alone grants no
lab authority.

Read-only discovery and an identical-scope refresh do not need approval. If a
preview expires, refresh it automatically. Regenerate valid technical records
through the existing authorized client only for the same C/P/E and protected
bindings; never reuse expired/consumed records. Ask only for a material change
outside current authority or an actual user action required by the runtime.
A missing binding, fixture, or Gate is a prerequisite to resolve within existing
authority, not a generic "approved?" prompt. Report an unsupported mode honestly.

## 4. Execute and Verify

For a controlled workflow, invoke the exact workflow Tool once with only its
parent Plan and Draft references. For a controlled single action, use only its
matched confirmation and execute pair. Do not call child actions separately
when the parent workflow owns them.

The runtime must re-read Current State immediately before the first write and
stop on drift. After execution, require fixed readback of the complete expected
relationship set. Report success only for an exact match; otherwise report the
returned failure or `reconciliation_required` without replaying a consumed
authorization.

## 5. Report Concisely

Return the selected mode, any genuinely missing decision, the C/P/E summary and
intent-policy state, execution/readback result, and next action. Do not expose
raw product data, private selectors, credentials, payloads, or internal object
identifiers.

Use `fortipam-administrator-router` to select the Blueprint, Skill SKU, and
Scheme. Use `fortipam-child-folder-create` only for a standalone child-Folder
request, not for a Folder already owned by a combined onboarding parent Plan.
