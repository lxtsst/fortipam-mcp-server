---
name: fortipam-temporary-access-management
description: Design a bounded FortiPAM sponsored or temporary-access plan with a named sponsor, fixed scope, end date, review cadence, and revocation owner. Use for FPA-BP-015 planning and evidence gaps; do not claim that access, expiry, or revocation has been enforced.
---

# FortiPAM Temporary Access Management

Route sponsored and temporary-access requests to `FPA-BP-015`, `FPA-SK-015`,
and the registry-backed `IdentityLifecycleScheme`,
`ApprovalAndObserveScheme`, and `AccessReviewScheme`. The current package is
plan-only. No BP015 composite executor or accepted product write is available.

## Establish the Bounded Outcome

Collect only decisions that change the plan: environment and scope, accountable
sponsor, end date, intended group or entitlement boundary, review cadence,
revocation owner, and the expected expiry or revoke result. Treat a missing end
date, sponsor, scope, or revocation owner as a coverage gap rather than creating
open-ended access.

Use current minimized reads to distinguish:

- the identity and group relation that already exists;
- any current Schedule or time boundary;
- any approval relation that controls the requested access; and
- available audit evidence for grant, use, expiry, and revocation.

Do not request or expose passwords, tokens, Secret values, private keys,
session recordings, raw logs, private selectors, or unrestricted identity
inventories. An explicitly supplied non-secret selector may be moved once into
an owner-only binding and must not be echoed in the Final Intent Summary, logs,
tests, or Git.

## Render the Plan

Produce one Current State / Proposed Changes / Expected State summary. Bind the
sponsor, scope, end date, group boundary, review cadence, revocation owner,
negative test, evidence owner, and compensation to the same revision and
digest. Keep these product effects separate:

1. identity or group membership;
2. Role, Folder, Secret, or other entitlement assignment;
3. login Schedule or another actual product-enforced time control;
4. interactive approval or sponsor visibility; and
5. audit and access-review evidence.

Do not infer that a Schedule revokes an existing session, that an approval
profile supplies sponsor semantics, or that disabling one identity removes all
group-, Role-, Folder-, or Secret-derived access. State the exact unproven join
and its owning control.

Verification must include sponsor visibility, one denied-after-expiry or
explicit-revoke test, and minimized audit evidence. Define reconciliation for
partial results, including access that remains after the intended end date.
Compensation must name the fixed relation to remove or restore; never represent
manual follow-up as automatic product expiry.

## Stop at the Current Boundary

Use `sponsored-and-temporary-access-plan` only as the catalogued action-family
placeholder. It is not atomic, executable, or an API contract. Existing Local
User, User Group membership, Role assignment, Schedule assignment, and approval
components may supply current-state evidence or future child actions, but their
separate acceptance does not prove a BP015 parent workflow.

Return `plan_only` unless the live controlled server advertises an exact BP015
workflow Tool with a server-issued Draft, protected environment/scope binding,
current-state projection, policy authorization, and enabled final Gate. Do not
compose or call child mutation Tools independently to simulate that parent
workflow. Do not create, extend, disable, or revoke access from this Skill.

Follow `fortipam-administrator-router` for initial routing and
`fortipam-governed-administration-workflow` for the shared intent and readback
rules. Current discovery and an unchanged-scope refresh are read-only. If a
future exact executor becomes available, it must re-read Current State before
dispatch, stop on drift, and prove the Expected State through fixed readback;
an uncertain or partially applied result is `reconciliation_required` and must
not be replayed.
