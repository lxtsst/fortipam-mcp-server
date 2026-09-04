# Launcher Compatibility Version Gates

| Symptom pattern | Version-scoped lead | Safe conclusion boundary |
| --- | --- | --- |
| Browser launch fails after extension update with a JWT/legacy-token symptom | Browser Extension 8.0.0.0100 issue; Community reports a fix in 8.0.1.114. | Confirm only the bounded version/symptom pairing. Do not collect tokens or weaken validation. |
| Web Launcher fails only when a custom port is used after a 1.9.1 upgrade | FortiPAM 1.9.1 custom-port URL-placement defect; Community describes a Support hotfix and planned 1.9.2 fix, while the current official release index does not publish 1.9.2 Release Notes. | Inspect only a sanitized URL-shape assertion. Never retain the URL, host, or port. Treat the target release as unverified until official release or Support evidence exists. |
| WebRDP works with an IP but fails only with an FQDN | Bug 1294395 is reported for 1.9.0 and fixed in 1.9.1. | Confirm the version and bounded IP/FQDN contrast before diagnosing general DNS. |
| SSMS custom launcher times out | Community guidance is version-scoped and depends on local client preparation and target path. | Separate launcher definition, local client, and target reachability. Do not infer target health from FortiPAM posture. |
| Native RDP works only through TCP forwarding | The workaround can remove required drive, clipboard, or recording controls. | Treat as a security-control tradeoff requiring owner approval, not a routine fix. |
| Proxy Mode is locked or ineffective | Folder policy or launcher-inherent behavior may own the setting. | Establish policy precedence; do not override a folder policy through MCP. |
| Session ends at a repeatable duration or during recording | Global duration and Agentless recording are distinct gates. | Use the installed-version and recording posture evidence; do not inspect session content. |

These entries are Community or local troubleshooting leads, not live lab
acceptance for this project. The FortiPAM 1.9.1 Administration Guide and
Release Notes remain the primary product authorities. If the installed version
or symptom pattern differs, return `not_assessed` and route the next check to
the owning operator.

Current official release index: [FortiPAM 1.9 documentation](https://docs.fortinet.com/product/fortipam/1.9).
