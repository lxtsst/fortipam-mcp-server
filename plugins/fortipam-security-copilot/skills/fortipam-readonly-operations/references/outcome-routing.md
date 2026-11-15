# Outcome-First Diagnostic Routing

Start with the user's decision, then select the smallest evidence route. The
scenario catalog remains the authority for `lab_state`, source boundary, and
candidate status.

| User outcome | Scenario family | Safe conclusion |
| --- | --- | --- |
| Is FortiPAM healthy enough to investigate further? | `platform-health` | Evidence completeness and observed risk are separate; no signal is not proof of health. |
| Can this documented API behavior be relied on here? | `api-contract-compatibility` | State the 1.9.0 catalog / 1.9.1 behavior boundary and whether the proposed read is unvalidated. |
| Is a control configured without exposing its contents? | Approval, logging, HA, recording, Password Changer, EMS | Return only the named minimized posture and identify unobserved controls. |
| Why did an access, integration, or lifecycle outcome fail? | Route to the focused Skill | Identify the first evidenced gate, not a presumed cause. |
| Is the missing evidence worth a new MCP capability? | Candidate-tool scenario | Return promotion gates or a human-runbook handoff; do not probe raw API or CLI. |

Every conclusion contains: outcome state, observed and unobserved evidence,
product/source version, `lab_state`, and the smallest authorized next check.
Never convert a scenario candidate, a catalog result, or a Community article
into a device call.

For diagnostic authorization and minimized evidence boundaries, see the
[security model](../../../../../docs/SECURITY_MODEL.md) and
[diagnostic authorization implementation](../../../../../src/fortipam_mcp/diagnostic_authorization.py).
