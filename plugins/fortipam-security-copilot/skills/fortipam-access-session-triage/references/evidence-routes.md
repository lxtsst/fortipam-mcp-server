# Access and Session Evidence Routes

## Route selection

| Symptom | Scenario | Distinguishing evidence |
| --- | --- | --- |
| Approved but unavailable | `approval-request-blocked` | Approval is only one gate; preserve the remaining gates separately. |
| Generic launch failure | `secret-launch-failure` | Start with authorization, then temporary gates, client path, and target evidence. |
| Web Launcher greyed out or clear-text permission error | `web-launcher-permission-mismatch` | Compare Web Launcher Access mode with effective permission class; this is a 1.6.x Community lead. |
| SSMS timeout or connection error | `ssms-launcher-compatibility` | Classify client version, standard/custom launcher, local preparation, then target path. |
| Repeatable near-two-hour disconnect | `expected-session-duration-limit` | Establish whether the pattern matches a global session duration before treating it as a fault. |
| Recording-related disconnect | `agentless-recording-disconnect` | Apply the 1.9.1 Agentless recording fix gate before investigating client or storage. |
| Web launch uses the SSO user instead of the managed Secret identity | `secret-launch-failure` | When FortiPAM and the target share an IdP, an existing browser SSO session can remove the login form needed for injection. |
| WebBrowsing fails after an extension/browser update | `secret-launch-failure` | Classify the extension and browser version before changing an authentication control; the 8.0.0.0100 JWT issue has a fixed extension release. |
| Web Launcher fails only on a custom port after upgrade | `secret-launch-failure` | Inspect the rendered URL without retaining it; 1.9.1 custom-port placement is a distinct version defect. |
| WebRDP accepts an IP but fails only for FQDN on 1.9.0 | `secret-launch-failure` | Verify the 1.9.0 / 1.9.1 version gate before treating it as a general DNS failure. |
| Live monitor can see sessions beyond the operator's Secret scope | `active-session-monitoring-boundary` | Treat the monitoring Role as a global privileged-session visibility grant; Secret ACLs are not proven to narrow it. |
| Active Session video appears delayed on 1.9.x | `active-session-monitoring-boundary` | Classify mode and a coarse delay band; Community Staff reports buffering by design, but the MCP must not collect timestamps, video, session IDs, or debug output. |

## Source boundary

- The [FortiPAM Administration Guide](https://docs.fortinet.com/product/fortipam/1.9)
  is the product-behavior authority.
- Community staff guidance on [Web Launcher access and permissions](https://community.fortinet.com/fortipam-52/technical-tip-clarification-of-using-web-launcher-access-with-correct-permission-profile-209579),
  [SSMS launch troubleshooting](https://community.fortinet.com/fortipam-52/troubleshooting-tip-error-connection-timeout-expired-unable-to-connect-to-server-secret-launcher-for-ssms-client-213676),
  and [two-hour session duration](https://community.fortinet.com/fortipam-52/technical-tip-secret-sessions-get-disconnected-every-2-hours-227720)
  is version-scoped operational evidence. Do not generalize it to another release
  or use it as authority for a configuration change.

Keep browser errors, client settings, requestors, approvers, target names,
session identifiers, and recordings outside MCP output.

## Version gates and ownership boundary

- The shared-IdP Web Launcher behavior is a SAML session-reuse design outcome,
  not evidence of a bad Secret. Changing browser cookies, IdP configuration, or
  injection behavior remains an authorized operator decision.
- Fortinet Community documents Browser Extension 8.0.0.0100 JWT/legacy-token
  launch failure and a 8.0.1.114 fix. Do not retain extension logs or weaken
  token validation as a permanent workaround.
- Fortinet Community documents a 1.9.1 custom-port URL-placement defect with a
  1.9.2 planned fix, and WebRDP FQDN Bug 1294395 in 1.9.0 fixed in 1.9.1.
  The current Fortinet Document Library publishes 1.9.1 and 1.9.0 release
  information, not a 1.9.2 Release Notes authority. Treat the 1.9.2 statement
  as an unverified Community roadmap lead until an official release note,
  Support hotfix record, or installed-build evidence confirms it. Neither
  article authorizes a raw launcher/session lookup.
- Community Staff describes Active Session Monitoring as Role-level global
  visibility and gives mode-specific buffering guidance for 1.9.x. This is a
  security design warning and a coarse triage lead, not a latency SLA. A
  monitoring-role change, WAD debug, session inspection, or video collection is
  always a human-owned operation outside MCP.

Current official release index: [FortiPAM 1.9 documentation](https://docs.fortinet.com/product/fortipam/1.9).

These are Community Staff troubleshooting leads. Preserve their exact version
scope and the scenario's `lab_state`; none is validated on this project's lab.
