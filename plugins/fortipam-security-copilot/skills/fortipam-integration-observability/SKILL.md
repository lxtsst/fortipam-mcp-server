---
name: fortipam-integration-observability
description: Explain which FortiPAM integration evidence stage is observed and which owning system must supply the next check. Use for logging, receiver compatibility, gateway, ZTNA, EMS, or HA symptoms; do not modify any integrated product.
---

# FortiPAM Integration Observability

Use this skill to answer whether the gap is on FortiPAM's sender/configuration
side, an integration transport boundary, or another product's receiver/endpoint
side. It does not turn FortiPAM MCP into a cross-product control plane.

1. Classify the outcome as delivery, parsing, gateway path, ZTNA/EMS, or HA
   synchronization.
2. State the last observed evidence stage and the first unobserved stage:
   configured, connected, delivered, ingested, parsed, displayed, or retained.
3. Keep FortiPAM sender posture separate from FortiAnalyzer, FortiGate, EMS,
   endpoint, or peer evidence. An earlier observed stage cannot prove a later
   one.
4. Return a version-paired conclusion, `lab_state`, and the least-privileged
   owning-system next check; do not infer authority across products.

Never export logs, recordings, certificates, serials, topology, endpoint tags,
addresses, identities, or raw cross-product responses. Do not issue CLI,
modify integration settings, or change HA/ZTNA/Gateway state.

A positive EMS result does not prove endpoint enrollment, ZTNA tag assignment,
proxy-policy enforcement, per-node EMS authorization, or Secret launch. Route
those checks to their owning system and preserve their separate authorization.
For a FortiPAM Access-level or protected Folder/Secret decision, route to
[`fortipam-ztna-access-and-secret-launch-control`](../fortipam-ztna-access-and-secret-launch-control/SKILL.md)
after establishing the aggregate EMS posture boundary.

Read [references/correlation-boundaries.md](references/correlation-boundaries.md)
for FortiAnalyzer parsing and cross-product evidence routes.
For any API or CLI evidence gap, use the shared
[V2 evidence path](../fortipam-readonly-operations/references/api-cli-evidence-paths.md).
Receiver, gateway, EMS, endpoint, and HA intervention remains with the owning
operator runbook.
Use the shared [outcome-routing reference](../fortipam-readonly-operations/references/outcome-routing.md)
for conclusion shape and future diagnostic-boundary rules.
