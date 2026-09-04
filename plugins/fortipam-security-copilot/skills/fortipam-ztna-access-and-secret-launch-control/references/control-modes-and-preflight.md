# ZTNA Control Modes and Preflight

## Evidence chain

```text
EMS posture and endpoint certificate
              |
FortiClient ZTNA and PAM readiness
              |
Access Proxy client-certificate handling
              |
WAD device context for the browser session
              +-- Access-level policy: portal login decision
              `-- Secret-level control: protected launch decision
```

The FortiPAM 1.9.1 Administration Guide establishes these product facts:

- page 111: a Secret normally inherits its parent Folder ZTNA control, can
  override it, and supports AND/OR device-tag matching;
- page 176: a Secret Folder can apply ZTNA control to Folder access;
- pages 496-503: ZTNA servers and new proxy rules are CLI-defined, the Access
  Proxy requires client-certificate handling, and enforcement can be
  Access-level or Secret-level; and
- pages 500-501: `empty-cert-action` controls certificate-absent login behavior,
  while proxy-policy tag enforcement can restrict portal access.

This is product-behavior evidence, not an API, permission, or execution
contract.

## Mode decision

| Mode | Portal behavior | Protected resource behavior | Critical decision |
| --- | --- | --- | --- |
| `access_level` | Only endpoints satisfying the selected ZTNA policy may log in. | All later access occurs after the portal gate. | Confirm that a global login restriction is intended. |
| `secret_level` | Managed and, when explicitly intended, unmanaged endpoints may log in. | Only a protected Folder/Secret evaluates the selected tags and AND/OR logic. | Do not add a global tag filter; preserve ordinary Secret behavior. |
| `diagnosis_only` | No intended configuration change. | Identify the first unproven gate. | Stop after bounded evidence and a remediation preview. |

## Required preflight decisions

- FortiPAM version and HA/standalone mode;
- EMS owner and same-EMS association expectation;
- FortiClient ZTNA/PAM readiness and certificate lifecycle owner;
- `access_level` or `secret_level` scope;
- one Folder or one Secret scope for Secret-level control;
- tag/group reference classes and `AND` or `OR` logic;
- managed-only or mixed managed/unmanaged portal requirement;
- explicit `empty-cert-action` intent;
- positive, negative, and unaffected-control test classes;
- evidence retention/redaction owner; and
- maintenance, rollback, and lockout recovery route.

If the user cannot state whether untrusted endpoints must be able to log in,
stop before proposing `empty-cert-action` or a proxy-policy tag delta.

## Scope invariants

- Access-level and Secret-level are separate outcomes; one must not be inferred
  from the other.
- `client-cert enable` is a prerequisite for a managed browser session to
  contribute client-certificate identity to device-context evaluation.
- A synchronized endpoint tag does not prove a WAD device context for the
  current browser session.
- A WAD device context does not prove Folder/Secret tag match or successful
  launcher/session delivery.
- Secret-level acceptance must prove an unprotected Secret remains unaffected
  when that behavior is part of the stated requirement.
- In HA, effective configuration and synchronization require a separate
  version-specific check before any claim of cluster-wide readiness.
