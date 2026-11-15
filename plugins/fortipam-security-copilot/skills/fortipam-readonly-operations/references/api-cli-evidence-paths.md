# Read-only API and CLI Evidence Paths

Use this reference when a diagnostic needs evidence beyond the minimized MCP
projection. It defines an evidence route, not additional access authority.

## Choose the path by risk

| Need | Permitted path | Boundary |
| --- | --- | --- |
| A current exposed posture | Call only the scenario's `available_tools` through MCP. | Each live tool is no-input, fixed-path, TLS-verified, and minimized. |
| A documented API question or a missing MCP capability | Use `search_api_catalog` and `classify_api_operation`, then record a candidate and its promotion gates. | The 1.9.0 catalog is incomplete discovery metadata; it never authorizes a request. |
| Evidence requires a direct API observation | An authorized operator follows the project operator runbook using an already-approved, fixed read-only `GET` route. | No raw REST request, path, header, query, or body is supplied through a Skill or MCP call. Capture only the sanitized acceptance outcome. |
| Evidence requires FortiPAM CLI | An authorized operator follows a per-case runbook with a fixed, non-mutating `get` or `show` command. | Do not invent, parameterize, or execute a CLI command from a Skill. Keep output, identifiers, topology, secrets, and session data out of MCP. |
| The proposed check configures, debugs, repairs, synchronizes, or forces state | Stop at diagnosis and hand off to the human operator runbook. | `config`, `execute`, forced synchronization, service restart, password work, session control, all writes, and every `diagnose` command except the compiled read-only V2 HA checksum workflow are outside this diagnostic Skill. |

For ZTNA evidence, use only the fixed tools currently advertised by the selected
server profile. A scenario or proposed projection does not make a diagnostic
available and does not change the boundary in this table.

The currently compiled API evidence surface is limited to the nine exact `GET`
routes defined in [read_only.py](../../../../../src/fortipam_mcp/read_only.py): system
status, system global, approval profile, FortiAnalyzer setting, license status,
HA, current disk usage, Password Changer, and EMS status summary. A candidate
may reuse a permitted route only after it has a dedicated minimized projection,
schema/denial tests, source review, and separate lab acceptance.

## Required conclusion labels

For every route, report the product version, source tier, and `lab_state` from
the selected scenario. Use `unvalidated`, `current-tools-validated`, or the
more specific scenario state literally. A passing existing fixed tool does not
validate a candidate projection, a target/client condition, another product, or
a production identity.

## Official FortiPAM 1.9.x sources

- [FortiPAM 1.9 documentation](https://docs.fortinet.com/product/fortipam/1.9)
- [FortiPAM 1.9.1 Administration Guide](https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/4603b8e3-650f-11f1-a33a-02356ffb40d9/FortiPAM-1.9.1-Administration_Guide.pdf)
- [FortiPAM 1.9.1 Release Notes, build 1758](https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/4603d000-650f-11f1-a33a-02356ffb40d9/FortiPAM-1.9.1-Release-Notes.pdf)

Use Community material only as a version-scoped troubleshooting lead, never as
authorization for a command or configuration change.
