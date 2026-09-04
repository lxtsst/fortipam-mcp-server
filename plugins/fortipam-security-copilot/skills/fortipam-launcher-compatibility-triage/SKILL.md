---
name: fortipam-launcher-compatibility-triage
description: Distinguish FortiPAM launcher definition, client compatibility, version defect, target path, policy precedence, and session-control failures. Use for Web Launcher, WebRDP, Browser Extension, SSMS, RDP, custom-port, or Proxy Mode symptoms; do not launch sessions or collect client secrets.
---

# FortiPAM Launcher Compatibility Triage

Use this skill when a Secret is approved and visible but its launcher behaves
incorrectly, is disabled, selects the wrong identity, or fails to establish or
retain a session.

1. Classify the symptom before recommending a check: permission/UI state,
   identity selection, URL construction, FQDN-only failure, client integration,
   target reachability, policy precedence, duration, or recording.
2. Establish the FortiPAM, launcher/extension, client, browser, and target
   version bands without collecting raw logs or identifiers.
3. Apply only a matching version gate from the reference. A version-mismatched
   Community case is a hypothesis, not a conclusion.
4. Keep FortiPAM configuration, local client preparation, network path, target
   authentication, and recording as separate evidence owners.
5. Return the first evidenced gap, unproven later stages, and one bounded next
   check. Do not weaken authentication or recording controls as a diagnostic.

Never return a rendered URL, hostname, address, port, JWT, cookie, credential,
launcher definition, target identity, session ID, recording, or raw error.
Never start, terminate, or take over a session, change Proxy Mode, alter folder
policy, or enable a compatibility workaround.

Read [references/version-gates.md](references/version-gates.md) before using a
Community compatibility lead. Use
[`fortipam_access_session_triage`](../fortipam-access-session-triage/SKILL.md)
when the main question is the end-to-end access gate rather than the launcher
implementation.
