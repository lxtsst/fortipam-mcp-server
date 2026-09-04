---
name: fortipam-identity-federation-triage
description: Locate the first unproven FortiPAM identity-federation stage across SAML, SCIM, Remote Groups, Auto Provision Rules, and roles. Use when login succeeds but access, provisioning, group mapping, or launcher identity is wrong; do not expose identities or change federation settings.
---

# FortiPAM Identity Federation Triage

Use this skill when an identity can authenticate but provisioning,
authorization, or the selected target identity is not the expected outcome.

1. Classify the outcome as authentication failure, missing user provisioning,
   missing group linkage, Auto Provision Rule mismatch, role mismatch, or
   shared-IdP launcher identity reuse.
2. Keep the evidence chain ordered: IdP authentication, SAML subject mapping,
   SCIM user link, SCIM group membership, FortiPAM Remote Group, Auto Provision
   Rule, effective role, then Secret or launcher authorization.
3. State the last observed stage and the first unproven stage. A successful
   SAML login proves neither SCIM linking nor FortiPAM authorization.
4. Use only fixed existing FortiPAM posture Tools for platform context. No
   current Tool validates a user, group, assertion, Remote Group, or APL.
5. Return one least-privileged owning-system check and preserve the source
   version and `lab_state`.

Never request or return assertion contents, SCIM tokens or endpoints, user or
group names, email addresses, role assignments, Secret names, browser cookies,
or JWTs. Never modify an IdP, SCIM service, Remote Group, APL, role, or launcher.

Read [references/identity-evidence-chain.md](references/identity-evidence-chain.md)
for version and ownership boundaries. Use the shared
[outcome-routing reference](../fortipam-readonly-operations/references/outcome-routing.md)
to express observed, unobserved, and unavailable evidence without inventing a
root cause.
