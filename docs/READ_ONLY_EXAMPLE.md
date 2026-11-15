# Read-only example: discover an operation and its evidence plan

This example uses the real MCP stdio protocol to answer two questions:

- How does the packaged catalog classify system-status and approval-profile reads?
- Which existing read-only tools can help investigate FortiAnalyzer log delivery?

It needs no FortiPAM appliance, API token, or SSH identity.
The three calls read packaged metadata only. They do not inspect live health,
retrieve Secret values, or change configuration. Installation downloads Python
dependencies; the example itself makes no appliance or external API calls.

## Run the offline example

Use Python 3.11 or 3.12 on macOS or Linux. From a new checkout of `main`:

```bash
git clone https://github.com/lxtsst/fortipam-mcp-server.git
cd fortipam-mcp-server
python3 -m venv .venv
.venv/bin/python -m pip install --constraint deploy/docker/runtime-constraints.txt hatchling==1.32.0 -e .
```

Run this from that directory. It starts a child server in the `readonly` profile,
initializes MCP, calls three fixed offline queries, and closes the session:

```bash
.venv/bin/python - <<'PYTHON'
import asyncio
import json
import sys

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


async def main():
    server = StdioServerParameters(
        command=sys.executable,
        args=["-m", "fortipam_mcp.server"],
        env={"FORTIPAM_MCP_RUNTIME_PROFILE": "readonly"},
    )
    async with stdio_client(server) as (read, write):
        async with ClientSession(read, write, read_timeout_seconds=20) as session:
            await session.initialize()
            requests = [
                ("classify_api_operation", {"method": "GET", "path": "/api/v2/monitor/system/status"}),
                ("classify_api_operation", {"method": "GET", "path": "/api/v2/cmdb/secret/approval-profile"}),
                ("get_operational_scenario", {"scenario_id": "fortianalyzer-delivery"}),
            ]
            for name, arguments in requests:
                result = await session.call_tool(name, arguments)
                if result.is_error:
                    raise RuntimeError(f"Offline example failed: {name}")
                payload = json.loads(next(item.text for item in result.content if item.type == "text"))
                assert payload["found"] is True
                assert payload["network_call_executed"] is False
                assert payload["live_call_permitted"] is False
                summary = {"tool": name, "network_call_executed": False, "live_call_permitted": False}
                if "operation" in payload:
                    operation = payload["operation"]
                    summary.update(path=operation["path"], risk_tier=operation["risk_tier"])
                else:
                    summary.update(scenario_id=arguments["scenario_id"],
                                   available_tools=payload["scenario"]["available_tools"])
                print(json.dumps(summary, indent=2))


asyncio.run(main())
PYTHON
```

## Expected result

For runtime version `4.0.0b108`, the printed summaries have these values:

| Query | Expected result |
| --- | --- |
| Classify `GET /api/v2/monitor/system/status` | `risk_tier: "read"` |
| Classify `GET /api/v2/cmdb/secret/approval-profile` | `risk_tier: "high"` |
| Get `fortianalyzer-delivery` scenario | Available tools: `search_api_catalog`, `classify_api_operation`, `get_fortianalyzer_delivery_posture_summary` |

Every summary reports `network_call_executed: false` and
`live_call_permitted: false`. The script checks that each catalog/scenario lookup
succeeds and remains offline; an unexpected result raises an error.

The catalog describes FortiPAM 1.9.x operations. A documented operation is not
permission to call it, and a read method may still expose sensitive information.
Scenario results are an evidence plan, not a diagnosis of an appliance.
See [compatibility and limitations](COMPATIBILITY.md) before using another version.

## Optional: a fixed read against your own appliance

After separately configuring an authorized FortiPAM endpoint, verified TLS and
a least-privilege API identity using [Deployment](DEPLOYMENT.md), connect your
MCP client to that configured server in the `readonly` profile. Keep credentials
in the server's owner-only configuration; do not put them in prompts or tool
arguments. The offline client above intentionally does not pass device credentials.

Call these tools in order, with empty arguments (`{}`):

1. `fortipam_configuration_status` checks required setting presence without
   returning their values. This is a local configuration check, not connectivity.
2. `get_system_status_summary` makes the server's fixed system-status GET. It
   returns HTTP status/content type and a structural summary, with
   `response_body_returned: false`; it does not return the raw response body.

This second step is a real device read. It requires the deployment's version,
endpoint and identity to be valid. A successful structural read does not prove
overall appliance health or end-to-end log delivery. This walkthrough's verified
example is the offline section above; no live appliance result is claimed here.
