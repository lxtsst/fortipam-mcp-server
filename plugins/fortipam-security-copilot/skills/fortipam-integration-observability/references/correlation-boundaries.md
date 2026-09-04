# Integration Correlation Boundaries

## FortiAnalyzer path

Treat these as separate states:

1. FortiPAM sender configuration and certificate-verification posture.
2. Sender connection/authorization and upload progression.
3. FortiAnalyzer device authorization and ingestion.
4. Receiver parser/platform support for the FortiPAM version/model.
5. Expected event category and display behavior.

`get_fortianalyzer_delivery_posture_summary` proves only the project-defined,
minimized FortiPAM sender posture. It cannot prove receiver ingestion or parsing.

The [Fortinet Community parsing compatibility tip](https://community.fortinet.com/fortipam-52/technical-tip-fortipam-secret-related-logs-not-parsed-correctly-by-fortianalyzer-225627)
covers named FortiPAM 1.7/1.8 and FortiAnalyzer release pairs. It must not be
used to infer support for FortiPAM 1.9.1. Query FortiAnalyzer's supported
platform information only through a separately authorized FortiAnalyzer tool or
administrative process.

## Other integration routes

- Secret Gateway: separate control-plane connection, mTLS chain role, terminal
  gateway target reachability, and session outcome.
- ZTNA/EMS: `get_ems_connection_posture_summary` observes only aggregate
  FortiPAM-side connector/certificate state. Keep endpoint enrollment,
  same-EMS association, EMS authorization, tag state, FortiPAM proxy policy,
  and session outcome as separate evidence layers.
- HA: distinguish configuration posture from peer health and checksum equality.

## Identity lifecycle and HA version gates

- SAML authenticates the current user; SCIM synchronizes user/group lifecycle;
  Remote Group and Auto Provision Rules determine FortiPAM authorization.
  A successful IdP login does not prove SCIM linking, group membership, APL
  match, or the resulting FortiPAM role.
- The ordinary SAML baseline requires the documented user/group mapping.
  A local FortiPAM 1.9.x plus FortiAuthenticator 8.0.3 observation found that
  a correctly linked SCIM identity can supply group/profile attributes after
  SAML identifies the user. Treat that reduced-attribute pattern as
  `lab_state=local-case-validated`, not a portable product contract.
- Never return assertion attributes, SCIM endpoint/token data, user/group
  names, email addresses, role assignments, or lifecycle events. Configuration
  and provisioning changes belong to the owning identity runbook.
- For HA out-of-sync following EMS ZTNA Tag updates, Bug 1263843 is documented
  as fixed in FortiPAM 1.9.0. First establish the EMS-tag timing and installed
  version. The field-level peer comparison and any synchronization action stay
  outside MCP; other HA causes remain possible.

Primary behavior sources: [FortiPAM 1.9 SAML SSO](https://docs.fortinet.com/document/fortipam/1.9.0/administration-guide/519315/saml-single-sign-on-sso),
[SCIM service](https://docs.fortinet.com/document/fortipam/1.9.0/administration-guide/627102/scim-service),
and [FortiPAM 1.9.0 resolved issues](https://docs.fortinet.com/document/fortipam/1.9.0/release-notes/655580/resolved-issues).
The local SCIM observation and the Community HA article are version-scoped
evidence, not a reason to expand appliance authority.

The [FortiPAM integration documentation](https://docs.fortinet.com/product/fortipam/1.9)
is the product-behavior authority. The scenario catalog retains the source,
version, review, and lab boundary for each route.
