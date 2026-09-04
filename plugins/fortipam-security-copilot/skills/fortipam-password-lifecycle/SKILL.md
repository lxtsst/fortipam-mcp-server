---
name: fortipam-password-lifecycle
description: Explain the first evidenced compatibility gap in a FortiPAM password-lifecycle symptom without handling credentials. Use for password job, changer, target-policy, verification, or reconciliation questions; never read, verify, rotate, or disclose passwords.
---

# FortiPAM Password Lifecycle

Use this skill to distinguish definition availability, version compatibility,
transport, target policy, prompt handling, and reconciliation evidence. A
password-lifecycle symptom is never permission for a lifecycle action.

1. Classify the question as definition availability, target compatibility, or
   an unobserved job/reconciliation result. Add the FortiOS 7.6.3+ scenario
   only when that target version is evidenced.
2. Establish the non-secret compatibility tuple: FortiPAM version, target
   product/version band, target type, and changer class. Unknown is a valid
   result; do not guess.
3. Stop at the first layer with evidence: definition, compatibility, transport,
   target policy, prompt handling, or reconciliation.
4. Return what the minimized posture can and cannot show, source/version and
   `lab_state`, then the smallest human-runbook next check.

Never expose changer names or procedures, target/user identifiers,
generated-password rules, password job logs, prompts, connection strings,
passwords, or secrets. Do not invoke any password action or secret lifecycle
API. The fixed Password Changer collection read is the only password-lifecycle
configuration API authorized by this skill.

Read [references/compatibility-routes.md](references/compatibility-routes.md)
for target-version reasoning and escalation boundaries.
For API or CLI evidence, use the shared
[V2 evidence path](../fortipam-readonly-operations/references/api-cli-evidence-paths.md).
Password-job debugging, reconciliation, and every lifecycle action require a
separately authorized human operator runbook.
Use the shared [outcome-routing reference](../fortipam-readonly-operations/references/outcome-routing.md)
for conclusion shape and future diagnostic-boundary rules.
