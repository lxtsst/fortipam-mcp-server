---
name: fortipam-windows-rdp-onboarding
description: Coordinate one existing-Target Windows/RDP FortiPAM Secret onboarding outcome with a fixed native-RDP Launcher, Folder Policy, Session Recording, clipboard blocking, and optional fixed RDP Event Filter. Use for FPA-BP-006; use policy-appropriate intent handling and never accept credential material.
---

Deployment authorization: this repository grants no standing authority. Lab-mode instructions require separate, explicit authorization for the exact isolated test workflow and a runtime policy that permits that mode. Manual administration still requires the documented parent confirmation. Product approvals and server-side authorization remain mandatory.

# FortiPAM Windows RDP Onboarding

Own one bounded administrator conversation for `FPA-BP-006` /
`FPA-SK-006` using `SecretOnboardingScheme`. The base creation profile creates only the
Secret. The Folder, RDP Target, Windows Template, native-RDP Launcher, Folder
Policy, and optional fixed RDP Event Filter must already exist and pass their
complete source-backed checks.

## Intake

Ask only for missing non-secret decisions: environment/scope, Folder, existing
Target and address, Windows Template, native-RDP Launcher, selected Folder
Policy, optional existing fixed RDP Event Filter, Secret label, purpose, and
the observable readback result. Do not request a password, username value,
private key, token, or session content. Material readiness is categorical and
stays in the protected provider boundary.

Accept an explicitly supplied lab selector once and move it to the owner-only
binding without echoing it in summaries, MCP results, logs, tests, or Git. Do
not make the administrator calculate opaque references or a requester digest.

## Plan Once

Use the exact source-backed projection and a server-issued
`scheme_draft_ref`. If no Draft exists, route one closed BP006 private profile
through `fortipam-mcp-v4-secret-onboarding-prepare`, then use its generated
Draft and Reference bootstrap inputs and Secret binding. Do not handcraft the
three correlated files.

Require exactly one each of `FolderBinding`, RDP `Target`,
`TemplateBinding`, `SecretMetadata`, `LauncherBinding`, and `PolicyBinding`,
with at most one `RdpEventFilterBinding`. Target creation, a missing Launcher or
Policy, a partial native-RDP baseline, disabled recording, allowed RDP
clipboard, or an unverified selected Event Filter is a stop condition.

For an existing Secret, require observed Proxy enabled and RDP TCP Forwarding
disabled before treating the native-RDP clipboard requirement as compatible.
Missing or unknown mode evidence is a stop condition. Native RDP itself is
supported: the 1.9.1 restriction applies when TCP Forwarding is enabled or the
Secret uses non-proxy mode. Clipboard blocking means remote-to-local transfer
blocking; it does not prohibit copy/paste within the remote computer. A Policy
setting alone does not prove either compatibility or actual session behavior.

For the local existing-Secret controls candidate, use the shared preparation
profile version `1.1.0`, `mode=existing_session_controls`, and the actual
existing Folder, Template, Target, Secret ID, and inheritance state. Its six
objects omit Launcher and Policy and add `SecretSessionControlsBinding`; only
that object may UPDATE. No new material is required. This is a Secret-field
configuration step, not full onboarding or effective-policy acceptance. The
candidate is not bound by the default HTTP factory; do not route it through the
Secret CREATE runner or infer execution availability from its planning support.

Present one Current State / Proposed Changes / Expected State preview for the
complete parent Plan. Follow the intent policy in
`fortipam-governed-administration-workflow`: one parent interaction in manual
mode, or direct authenticated execution under standing authority for the
owner-authorized lab. Do not request a human review or split the Secret,
Launcher, Policy, recording, clipboard, or Event Filter relations into approval
prompts. Read-only discovery and an unchanged-scope refresh require no approval.

## Execute and Verify

Treat execution as available only when current discovery advertises
`execute_v4_secret_onboarding_workflow` for the exact source-backed profile and
the server-side scope, authorization, and final Gate are valid. Invoke it once
with only `plan_ref` and `scheme_draft_ref`; never call a child Secret action or
retry a consumed dispatch.

Success requires fresh readback of the exact existing Folder, Target,
Template, complete native-RDP Launcher, selected Policy, Session Recording,
clipboard blocking, optional Event Filter association, Secret permission
inheritance, and expected Secret presence. On drift, partial completion,
ambiguous transport outcome, or mismatch, stop with reconciliation required.

This Skill does not create a Target, Launcher, Policy, or Event Filter; rotate
credentials; launch RDP; inspect recording content; prove Active Directory or
Kerberos behavior; or claim laboratory acceptance from local tests. Use
`fortipam-governed-administration-workflow` for shared execution-state rules.
