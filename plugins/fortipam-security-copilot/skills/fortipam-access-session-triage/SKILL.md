---
name: fortipam-access-session-triage
description: Explain where FortiPAM access, session delivery, or live-monitoring evidence first becomes incomplete and name the smallest safe next check. Use for approved-but-unavailable access, launch, timeout, recording, monitoring visibility, or monitoring-delay symptoms; do not launch or inspect sessions or alter access.
---

# FortiPAM Access and Session Triage

Use this skill when the user needs to know whether approval, authorization,
client launch, network/gateway, target authentication, or recording is the
first evidenced gap. It does not make a session work.

1. Classify the requested outcome: approved-but-unavailable, launch failure,
   expected-duration question, recording disconnect, monitoring visibility, or
   monitoring delay.
2. Keep the gates ordered. Approval does not prove authorization; authorization
   does not prove launch; launch does not prove target authentication or
   recording.
3. Use the matching scenario's existing evidence only. Name a candidate as a
   gap, never as a call to make.
4. Give the first evidenced failed gate, unobserved gates, version/source and
   `lab_state`, plus one least-privileged next check.

Never retrieve a secret, display session metadata or video, launch or terminate
a session, alter a request, change permissions, or collect browser/client files.

Read [references/evidence-routes.md](references/evidence-routes.md) when the
question involves a Web Launcher, SSMS, duration-based disconnect, recording,
or Active Session Monitoring.
For API or CLI evidence, follow the shared
[V2 evidence path](../fortipam-readonly-operations/references/api-cli-evidence-paths.md):
only fixed read-only evidence is eligible; client debugging and all state
changes remain an operator-runbook activity.
Use the shared [outcome-routing reference](../fortipam-readonly-operations/references/outcome-routing.md)
when shaping the conclusion or considering an identifier-based future diagnostic.
If the symptom includes EMS tags, client certificates, `device context`, or a
ZTNA-protected Folder/Secret, use
[`fortipam-ztna-access-and-secret-launch-control`](../fortipam-ztna-access-and-secret-launch-control/SKILL.md)
for the ordered ZTNA gates; return here only after ZTNA authorization is no
longer the first unproven stage.
