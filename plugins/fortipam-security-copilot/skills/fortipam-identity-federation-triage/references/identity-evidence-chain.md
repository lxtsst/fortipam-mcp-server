# Identity Federation Evidence Chain

## Decision ladder

| Stage | What success establishes | What it does not establish |
| --- | --- | --- |
| IdP authentication | The identity provider authenticated a subject. | SAML mapping, SCIM linkage, or FortiPAM authorization. |
| SAML mapping | FortiPAM accepted the configured SAML identity mapping. | SCIM user linkage, group membership, or effective role. |
| SCIM user link | A synchronized lifecycle identity is linked. | Current group membership or Remote Group match. |
| SCIM group membership | The identity belongs to a synchronized group. | Remote Group, APL, or role selection. |
| Remote Group | FortiPAM can match the external group construct. | APL match or effective permission. |
| Auto Provision Rule | A matching rule selects the intended provisioning path. | Effective access to a specific Secret or launcher. |
| Effective role | The bounded authorization class is established. | Target authentication or session launch success. |

## Version and source boundary

- The FortiPAM 1.9 Administration Guide is the primary behavior source for
  SAML SSO, SCIM, Remote Groups, and Auto Provision Rules.
- Community cases are troubleshooting leads. A local FortiPAM 1.9.x with
  FortiAuthenticator 8.0.3 observation found that correctly linked SCIM data
  can supply group/profile attributes after SAML identifies the user. Treat
  that as `lab_state=local-case-validated` for that exact pairing, not as a
  portable minimum-attribute rule.
- When FortiPAM and a Web Launcher target share an IdP, an existing browser SSO
  session may cause the target to use the SSO identity instead of presenting a
  form for managed credential injection. This is a session-reuse explanation,
  not evidence that the Secret is wrong.

No current MCP Tool reads identity objects. Route IdP, directory, SCIM, group,
and browser evidence to the separately authorized owner. Keep all identity
values and tokens outside MCP output and audit labels.
