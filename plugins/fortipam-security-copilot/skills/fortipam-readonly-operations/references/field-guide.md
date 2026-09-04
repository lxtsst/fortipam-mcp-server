# FortiPAM 1.9.1 Read-Only Field Guide

## Scenario catalog routing

Use the packaged operational scenario catalog before free-form diagnosis. It
currently covers platform/API health, API-user least privilege, approval and
Self Approval, secret launch, Agentless recording, Secret Gateway, ZTNA,
identity provisioning, FortiAnalyzer delivery, HA synchronization, and password
lifecycle.

Scenario records deliberately separate:

- official documented behavior;
- the 1.9.0 API metadata boundary;
- accepted 1.9.1 lab observations;
- derived operational structure; and
- maker review from live validation.

A scenario's `candidate_tools` are backlog proposals. Use only names listed in
`available_tools`, and only when the project still exposes them.

## Evidence classes

| Class | Meaning |
| --- | --- |
| Official fact | FortiPAM 1.9 Administration Guide, Examples, Release Notes, or official source code. |
| Community experience | Fortinet Community technical or troubleshooting article; validate version and target type. |
| Lab observation | Sanitized result observed on the configured lab FortiPAM; do not generalize without a product source. |
| Assumption | A hypothesis awaiting a safe check. |

## Scenario routing

### Platform and API health

- Begin with `get_api_catalog_status`, `fortipam_configuration_status`, and
  `plan_curated_reads`.
- Use `get_overall_health_summary` to establish whether all seven accepted
  reads completed and whether their minimized contracts contain a warning or
  critical signal. Read `evidence_completeness` and `risk_signal` separately:
  `none_observed` is not proof of platform health.
- If the aggregate is partial or unavailable, use only the relevant component
  tools to narrow the evidence gap. Use `get_system_status_summary` for a live
  transport/shape check, not a health verdict.
- Use `get_license_support_posture_summary` for subscription, support, VM
  license, capacity, and FortiGuard health bands without exact account, date,
  count, or server values.
- The packaged catalog targets 1.9.0; the current lab observation is 1.9.1.
  Record the difference rather than claiming full contract equivalence.

### Approval and access control

- FortiPAM roles use None, Read, and Read/Write controls. Read permits GUI view
  plus `get`/`show` CLI access but not configuration changes.
- `get_approval_profile_summary` intentionally returns structure and counts
  only. It does not identify approvers or reveal policy contents.
- Prefer a dedicated least-privilege API user for production. The
  1.9.0 guide shows an API token is displayed once and cannot be retrieved.
- The 2026-08-21 lab audit found the current development identity has nine
  write-capable permission categories despite a trusted-host restriction. Keep
  it development-only; validate production with a separate profile and account.
- FortiPAM 1.9.1 adds `Self Approval` for one-tier approval profiles. The
  official default is `Block`; assess its posture without returning profile,
  requestor, or approver identities.

### Session launch and recording

- Use `get_recording_storage_health_summary` to check video/log storage
  presence, capacity bands, and recording-history presence. It never returns
  byte counts, timestamps, session identities, or recordings.
- FortiClient, browser extension, and agentless launch modes have different
  paths and limitations. Native-session recording involves endpoint processes,
  so FortiPAM-only evidence may be insufficient.
- Correlate FortiPAM session state with FortiClient/EMS posture and, where
  applicable, FortiGate ZTNA access. Never download raw recordings through this
  MCP.
- FortiPAM 1.9.1 resolves issue 1277720, where Agentless launch with Video
  Recording could disconnect. Confirm the appliance build before attributing a
  current disconnect to that fixed defect.

### Secret Gateway and FortiGate ZTNA

- Validate deployment mode before diagnosis: direct, FortiGate VIP, FortiGate
  ZTNA gateway, agentless portal, or Secret Gateway chain.
- FortiPAM 1.9 supports gateway chaining with mutual TLS between gateways.
- Keep FortiGate policy and FortiPAM secret/target evidence separate. Use the
  FortiGate MCP only for its authorized FortiGate scope.
- The fixed no-parameter Secret Gateway collection returned HTTP 400 on the
  current 1.9.1 lab. `get_secret_gateway_posture_summary` remains a candidate;
  do not add a query or gateway identifier through a generic call.

### FortiAnalyzer logging

- FortiPAM can send logs to FortiAnalyzer and optionally allow FortiAnalyzer
  access to FortiPAM REST API. Certificate verification is a distinct setting.
- Correlate FortiPAM connector/queue posture with FortiAnalyzer ingestion and
  device authorization. Do not assume a configured connector is authorized or
  delivering logs.
- Use `get_fortianalyzer_delivery_posture_summary` for the fixed 1.9.1
  configuration projection. It returns delivery/security state without server
  address, serial values, certificate name, preshared key, source/interface,
  upload values, or raw configuration.

### HA synchronization

- Begin with `get_ha_configuration_posture_summary`. It reports whether HA is
  enabled plus normalized heartbeat and session-security posture, without
  serials, addresses, interface names, group values, credentials, priorities,
  or checksums.
- Treat `synchronization_state=not_observed` literally. The accepted 1.9.1 lab
  is standalone, so it cannot prove peer reachability, role parity, or checksum
  equality.
- Distinguish peer reachability and role from configuration-table checksum
  equality. Return only version parity, role counts, match booleans, and
  mismatch counts.
- FortiPAM 1.9.1 resolves issue 1291206 involving a fresh secondary joining a
  primary with `gui-access-role` configured. Do not force synchronization,
  disconnect a peer, or reboot through this MCP.

### Password change and verification

- Do not invoke password APIs from this skill or MCP.
- Treat failures as a compatibility workflow: target type, changer procedure,
  connection, authentication, generated-password policy, prompt matching, and
  product/target versions.
- Community evidence notes that FortiOS 7.6.3+ changed the administrator
  password prompt and requires a compatible FortiPAM password changer. AD
  password verification also depends on Domain Controller/LDAPS conditions.
- Debug commands and any real password action require a separately authorized
  operational workflow with strict log redaction.

## Maintained sources

Accessed 2026-08-21:

- FortiPAM 1.9 product documentation:
  https://docs.fortinet.com/product/fortipam/1.9
- FortiPAM 1.9.1 Administration Guide; relevant sections: What's new,
  Approval profile, User management, Monitoring, Log & report, Secret Gateway,
  ZTNA, HA, Troubleshooting, Security and hardening, and Terraform provider:
  https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/4603b8e3-650f-11f1-a33a-02356ffb40d9/FortiPAM-1.9.1-Administration_Guide.pdf
- FortiPAM 1.9.1 Release Notes, build 1758:
  https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/4603d000-650f-11f1-a33a-02356ffb40d9/FortiPAM-1.9.1-Release-Notes.pdf
- FortiPAM ZTNA examples:
  https://docs.fortinet.com/document/fortipam/1.9.0/examples/145338/ztna
- FortiAnalyzer logging:
  https://docs.fortinet.com/document/fortipam/1.9.0/administration-guide/321685/fortianalyzer-logging
- Fortinet Community API approval-profile example:
  https://community.fortinet.com/fortipam-52/technical-tip-how-to-use-api-to-query-approval-profile-in-fortipam-178193
- Fortinet Community password-changing failure guide:
  https://community.fortinet.com/fortipam-52/troubleshooting-tip-password-changing-failed-134103
- Fortinet Community FortiOS 7.6.3+ changer compatibility note:
  https://community.fortinet.com/fortipam-52/technical-tip-fortipam-password-changer-for-fortios-v7-6-3-and-above-228919
- Fortinet Community client-side launch/recording troubleshooting:
  https://community.fortinet.com/fortipam-52/troubleshooting-tip-general-client-side-debugging-tips-info-131456

Refresh time-sensitive compatibility claims before a production recommendation.
