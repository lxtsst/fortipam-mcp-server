---
name: fortipam-web-account-onboarding
description: Coordinate one targetless FortiPAM Web Account Secret onboarding outcome with the built-in Web Account Template, permission inheritance, and Session Recording. Use for FPA-BP-007; use policy-appropriate intent handling and never accept credential material.
---

Deployment authorization: this repository grants no standing authority. Lab-mode instructions require separate, explicit authorization for the exact isolated test workflow and a runtime policy that permits that mode. Manual administration still requires the documented parent confirmation. Product approvals and server-side authorization remain mandatory.

# FortiPAM Web Account Onboarding

Own one bounded administrator conversation for `FPA-BP-007` /
`FPA-SK-007` using `SecretOnboardingScheme`. This exact profile creates one
targetless Secret with the built-in `Web Account` Template, HTTP(S) URL,
permission inheritance, and Session Recording enabled.

For an already accepted Web Secret whose HTTP service is disabled, reuse that
Secret through the exact `existing_web_service` preparation profile. Require
the same three relationship objects as NO_OP and one additional
`WebSecretServiceBinding` changing only `http_service_enabled` from false to
true. This profile has no material reference and must not trigger CREATE or
credential preflight. Execution requires the separately configured fixed Web
service runner and onboarding Gate; a successful create does not authorize a
generic Secret update. Verify the enabled service together with the retained
relationships through fresh readback. Ambiguous dispatch is non-replayable.

## Intake

Ask only for missing non-secret decisions: environment/scope, existing Folder,
Secret label, HTTP(S) URL, access purpose, and the observable readback result.
Do not ask for a username value, password, token, browser cookie, MFA value, or
session/recording content. Material readiness is categorical and remains in the
protected provider boundary.

Accept an explicitly supplied lab selector or URL once and move it to the
owner-only binding without echoing it in summaries, MCP results, logs, tests,
or Git. Do not ask the administrator to select another Template, calculate
opaque references, or paste a requester digest.

## Plan Once

Use the exact source-backed projection and a server-issued
`scheme_draft_ref`. If no Draft exists, route one closed BP007 private profile
through `fortipam-mcp-v4-secret-onboarding-prepare`, then use its generated
Draft and Reference bootstrap inputs and Secret binding. Do not handcraft the
three correlated files.

For CREATE, require exactly `FolderBinding`, `TemplateBinding`, and `WebSecretMetadata` in
that order. The Template is fixed to `Web Account`; Session Recording and
permission inheritance are fixed true. A Target, Launcher, Policy, ordinary
`SecretMetadata`, non-HTTP(S) URL, embedded URL credential, or fragment is a
stop condition.

Present one Current State / Proposed Changes / Expected State preview for the
complete parent Plan. Follow the intent policy in
`fortipam-governed-administration-workflow`: one parent interaction in manual
mode, or direct authenticated execution under standing authority for the
owner-authorized lab. Do not request a human review or split Folder, Template,
recording, or Secret relations into approval prompts. Read-only discovery and an
unchanged-scope refresh require no approval.

## Execute and Verify

Treat execution as available only when current discovery advertises
`execute_v4_secret_onboarding_workflow` for the exact source-backed profile and
the server-side scope, authorization, and final Gate are valid. Invoke it once
with only `plan_ref` and `scheme_draft_ref`; never call a child Secret action or
retry a consumed dispatch.

Success requires fresh metadata-only readback of the exact Folder, built-in
Template, absent Target relation, permission inheritance, Session Recording,
and expected Secret presence. On drift, partial completion, ambiguous transport
outcome, or mismatch, stop with reconciliation required.

This Skill does not configure Web Proxy, browser extensions, MFA, launch paths,
or a Target; reveal credentials; inspect recording content; launch a session;
or claim laboratory acceptance from local tests. Use
`fortipam-governed-administration-workflow` for shared execution-state rules.
