---
name: fortipam-governed-administration-workflow
description: "Guide a FortiPAM administrator through a bounded mutable-workflow conversation: complete non-secret requirements, render a Final Intent Summary, obtain explicit confirmation, evaluate execution readiness, and require readback. Use for a proposed Folder, access grant, Target, Secret metadata, or Local User change. Never treat this Skill as device authority or accept C3 material."
---

# FortiPAM Governed Administration Workflow

Use this Skill to structure an administrative change request. It works in two
modes:

- **Current V3.1 lab mode:** only a separately implemented adapter that reports
  `lab_simulated` and `device_contacted=false` may perform the bounded
  demonstration action.
- **Future real-device mode:** currently unavailable. Do not claim it is ready
  until the exact V3.2 FortiPAM 1.9.1 adapter and all enablement gates are
  independently accepted.

The Skill cannot create an MCP Tool, select an endpoint, infer a request body,
hold credentials, invoke a GUI/API/CLI, issue an approval, or bypass the
empty V3 action registry and deny-all product adapter.

## 1. Classify the Request

Accept only one bounded outcome at a time:

- create one Public Folder;
- configure one Public Folder access relation;
- create one Target metadata record;
- create one Secret metadata record; or
- create one Local User metadata record.

If one request contains several outcomes, decompose it into a dependency-ordered
backlog and process each item through a separate preview and confirmation. A
typical onboarding order is Local User, Public Folder, Target, Secret metadata,
then Folder access assignment; adjust only when an authoritative Current State
proves a different dependency. Never use one confirmation for the whole batch.

For a Public Folder access relation, keep four decisions separate:

```text
User or Group -> Folder Permission -> Secret Permission -> Allowed Service
```

For Secret onboarding, explain the observed GUI order:

```text
Template -> Folder -> Target -> Host -> Username -> Password
```

Only Template, Folder, Target, and non-secret metadata may enter the normal
workflow. Host/Username are sensitive locators/identifiers and Password is
C3. Do not ask for, display, store, summarize, hash, or pass them through the
Skill, model context, MCP argument/result, plan, test, or audit record.

Treat Local User as a six-step GUI wizard, but do not infer the six page
schemas from that observation. The current lab workflow may use only its
bounded metadata fixture.

## 2. Complete Requirements

Restate the intended outcome and clearly separate facts, assumptions, and
unknowns. Ask only for missing non-secret information:

1. environment and bounded scope reference;
2. requester and accountable owner;
3. one object class and one object reference or simulated fixture reference;
4. desired relationships/permissions/allowed service as applicable;
5. expected state and observable acceptance condition;
6. risk class, external effect, maintenance window, reversibility and
   reconciliation expectation; and
7. evidence owner and expiry expectation.

Stop rather than guess if the request requires an unknown API field, a real
product locator, a bulk operation, a real user/group entitlement, a password,
a token, a key, a raw response, an unbounded list, or an unaccepted adapter.

## 3. Read and Render the Final Intent Summary

Perform optional discovery only through already accepted read-only tools or a
fixed lab-simulated projection. Obtain a minimized authoritative Current State
for the target. If it is unavailable, stale, incomplete, contradictory,
unauthorized, raw, or C3-bearing, stop before a prepared plan.

Render a versioned **Final Intent Summary** with these exact headings:

1. Requested outcome and bounded scope
2. Current State (source/version, freshness, digest, safety status)
3. Proposed Changes
4. Expected State and postcondition
5. Facts, assumptions, unresolved gaps, and excluded scope
6. Risk, external effects, maintenance, reversibility, and reconciliation
7. Required confirmation, policy approval, execution authorization, and
   readback gates
8. Evidence policy, stop conditions, summary revision, expiry, and digest

Confirmation is only the requester's acknowledgement of the exact summary. It
is not a security approval, an adapter permission, or execution authorization.
Any change to scope, objects, action family, assumptions, material boundary,
risk, external effects, compensation/reconciliation, current/expected state,
evidence, digest, revision, or expiry invalidates it.

## 4. Confirm, Execute, and Read Back

Ask the authenticated requester for an explicit affirmative confirmation of
the displayed Final Intent Summary revision/digest. Do not infer assent from
conversation, silence, a prior confirmation, or an approver's decision.

Before any action, re-read the fixed Current State and compare it to the
confirmed digest. Drift or expiry invalidates confirmation, the prepared plan,
and any approval; return to a new preview.

For **current lab mode only**, execute one action only after the runtime
proves `adapter_kind=lab_simulated` and `device_contacted=false`. Otherwise,
stop at the confirmed plan. Do not invoke or imitate a real FortiPAM API, GUI,
CLI, or credential flow.

After a permitted lab-simulated action, require a fixed post-action readback
and compare Actual State with Expected State. Report `completed` only for an
exact match. If readback is unavailable, malformed, stale, or mismatched,
report `verification_unknown` or `verification_failed`; never report success.

## 5. Output Format

Return a concise, redacted result containing:

- selected workflow mode (`plan_only`, `lab_simulated`, or
  `real_device_unavailable`);
- completed/missing requirements;
- Current/Proposed/Expected preview or the reason it cannot be rendered;
- Final Intent Summary revision/digest and confirmation status;
- pre-write comparison, bounded execution status, and post-readback status;
- evidence gaps and the next safe action; and
- an explicit `device_contacted=false` declaration for every V3.1 lab result.

Never output raw product data, URLs, endpoints, hostnames, account names,
passwords, tokens, keys, material-provider locators, or API/GUI/CLI payloads.

## 6. Reference

Use the repository's [`ARCHITECTURE.md`](../../../../docs/ARCHITECTURE.md) and
[`SECURITY_MODEL.md`](../../../../docs/SECURITY_MODEL.md) for the public runtime
and trust boundaries.
For broad plan-only administration requests, use
`fortipam-administrator-router` first.
