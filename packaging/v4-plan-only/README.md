# FortiPAM MCP V4 Plan-Only Runtime

This separate pre-release wheel packages the four-operation V4 plan-only
facade contract: `status`, `preview`, `consume_confirmation`, and
`prepare_plan`.

It does not package the V3 server, register a FortiPAM product adapter, contact
a device, retrieve material, or expose execute/apply/rollback operations.
Planner packaging is true. MCP Tool exposure, executor packaging, product write
authority, and dispatch remain false until the facade is bound to a separately
reviewed authenticated host runtime.

The wheel includes the owner-only persistent Scheme Draft Authority contract,
but packaging does not configure its state paths, issue a Draft reference, or
bind it to a Host. Issue and revoke remain private trusted-composition actions.
It also includes the local planning-tail compare-and-swap Authority contract.
Packaging does not place that Authority in an independent failure domain or
clear the external-checkpoint deployment blocker.

Build it only through `scripts/build_v4_plan_runtime.py`, which stages the
single authoritative `v4_planning/` source tree into a temporary build root.
