# ZTNA Diagnosis and Acceptance

## First-failed-gate method

Evaluate these gates in order and report the first failure or evidence gap:

1. FortiPAM has an accepted connection to the intended EMS class.
2. The endpoint is associated with that EMS and has the required FortiClient
   ZTNA/PAM and certificate posture.
3. The intended tag class is synchronized to FortiPAM for the endpoint.
4. The effective Access Proxy has client-certificate handling consistent with
   the requested mode.
5. The proxy policy has the intended `ztna-status` and tag scope.
6. WAD has a device context for the current authenticated browser session.
7. The Folder/Secret has the intended inheritance, override, tag set, and
   AND/OR logic.
8. The current tag set matches the protected-resource requirement.
9. The launch authorization, token check, launcher handoff, target path, and
   ZTNA traffic result are separately evidenced.

The verified FortiPAM 1.9.1 lab incident matched this signature:

```text
EMS connection observed
endpoint tag synchronization observed
Access Proxy effective client-cert disabled
WAD browser-session device context unavailable
protected Secret launch denied
```

After the authorized operator enabled client-certificate handling on the
named Access Proxy, the managed endpoint produced a matching device tag and
the protected RDP launch succeeded. This evidence validates the causal chain
for that lab and version only. It does not establish a general write contract,
least-privilege permission, HA behavior, or production readiness.

## Fixed diagnostic candidates

These commands are candidates for future fixed SSH projection adapters or a
separately authorized operator runbook. They are not callable through the
current V3 MCP surface:

```text
get firewall access-proxy
diagnose firewall dynamic list
diagnose wad dev query-by ipv4 <private-adapter-resolved-ip>
```

Use `get` for effective Access Proxy values; `show` may omit defaults. The
endpoint address must be resolved inside the private adapter from an authorized
opaque reference. It must not be accepted from or returned to the model.

Short-lived WAD debug is higher risk because it can contain identity, target,
and token material. A future fixed runbook may use only this bounded sequence
after a separate explicit confirmation:

```text
diagnose wad debug enable level verbose
diagnose wad debug enable category secret
diagnose wad debug enable category gateway
diagnose wad debug enable category svc-conn
diagnose debug enable
diagnose debug disable
```

The implementation must enforce an automatic timeout, a `finally` cleanup that
disables debug, a single incident scope, bounded capture size, and a strict
projector. Return categorical evidence such as `device_context_present`,
`tag_match`, `launch_allowed`, and a stop reason. Never return raw debug,
endpoint/tag values, JWTs, cookies, tokens, usernames, target addresses,
session identifiers, or credentials.

## Acceptance matrix

| Case | Access-level expected result | Secret-level expected result |
| --- | --- | --- |
| Managed endpoint with matching posture | Portal login allowed; protected launch tested separately. | Portal login allowed and protected launch allowed. |
| Managed endpoint without required tag | Portal login denied. | Portal login follows mixed-access intent; protected launch denied. |
| Endpoint without client certificate | Follows explicit `empty-cert-action`, normally denied for managed-only access. | May log in only when mixed access is explicitly designed; protected launch denied. |
| Ordinary unprotected Secret | Not a separate control after the global portal gate. | Remains launchable only when ordinary authorization allows it. |
| Stale/missing WAD context | Do not infer tag match from EMS data; fail the protected decision. | Protected launch denied or unassessed; remediation remains a preview. |

Acceptance also requires sanitized ZTNA traffic/log evidence, exact effective
configuration readback, and a rollback/recovery result. A successful GUI launch
without these boundaries is a functional observation, not complete control
acceptance.
