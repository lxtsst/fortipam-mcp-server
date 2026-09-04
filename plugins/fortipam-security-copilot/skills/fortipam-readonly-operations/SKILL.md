---
name: fortipam-readonly-operations
description: Answer FortiPAM health, control-posture, API-boundary, and diagnostic-next-step questions with source-traceable read-only evidence. Use when the user needs a safe conclusion rather than device administration; never retrieve secrets or change sessions, credentials, or configuration.
---

# FortiPAM Read-Only Operations

Use this skill to give the user a bounded diagnostic outcome: what is observed,
what remains unknown, and the smallest safe next check. FortiPAM is a
privileged-access control plane; a read can still disclose sensitive metadata.

## Workflow

1. Establish the decision the user needs: platform evidence, control posture,
   API boundary, first failed gate, or a missing-capability decision.
2. Select the exact scenario and follow its evidence ladder. Its `lab_state`
   limits the claim; candidate tools are not callable.
3. Prefer one existing minimized read that materially changes the conclusion.
   For platform questions, begin with aggregate health and separate evidence
   completeness from risk signal. Do not poll.
4. When evidence is absent, say so. Return the promotion gate or an
   authorized operator-runbook handoff rather than a raw API or CLI action.
5. Report the outcome, evidence and gaps, product/source version, `lab_state`,
   and smallest safe next check. Cross-product evidence remains with its owner.

Never retrieve or display clear-text credentials, secret fields, API tokens,
private keys, raw session recordings, or unrestricted logs. Do not perform
checkout/checkin, password change or verification, session launch, policy
change, maintenance mode, or generic command execution.

Read [references/field-guide.md](references/field-guide.md) when product-specific
version facts or cross-product evidence boundaries are needed. When refreshing
a FortiPAM API version, read
[references/api-catalog-refresh.md](references/api-catalog-refresh.md).
For outcome selection and conclusion shape, read
[references/outcome-routing.md](references/outcome-routing.md).
For a direct API or CLI evidence gap, read
[references/api-cli-evidence-paths.md](references/api-cli-evidence-paths.md).
