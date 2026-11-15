"""Deterministic Streamable HTTP MCP protocol smoke without appliance access."""

from __future__ import annotations

import json
from typing import Any

from starlette.testclient import TestClient

from .http_server import HTTP_PREFIX, HttpServerSettings, create_http_app
from .mcp_smoke import (
    EXPECTED_PROMPTS,
    EXPECTED_RESOURCES,
    EXPECTED_TOOLS,
    STRICT_NO_INPUT_TOOLS,
    assert_expected_native_content,
)

_SMOKE_TOKEN = "http-smoke-only-token-0123456789abcdef"


def run_smoke() -> dict[str, Any]:
    """Initialize MCP and list the accepted surface over Streamable HTTP."""

    settings = HttpServerSettings.from_environment(
        {
            f"{HTTP_PREFIX}AUTH_MODE": "bearer",
            f"{HTTP_PREFIX}BEARER_TOKEN": _SMOKE_TOKEN,
        }
    )
    headers = {
        "accept": "application/json, text/event-stream",
        "authorization": f"Bearer {_SMOKE_TOKEN}",
        "content-type": "application/json",
        "host": f"127.0.0.1:{settings.port}",
        "mcp-protocol-version": "2025-11-25",
    }
    initialize = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "fortipam-http-smoke", "version": "1"},
        },
    }
    with TestClient(create_http_app(settings)) as client:
        rejected = client.post(
            settings.path,
            headers={key: value for key, value in headers.items() if key != "authorization"},
            json=initialize,
        )
        initialized = client.post(settings.path, headers=headers, json=initialize)
        listed = client.post(
            settings.path,
            headers=headers,
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        resources_listed = client.post(
            settings.path,
            headers=headers,
            json={"jsonrpc": "2.0", "id": 3, "method": "resources/list", "params": {}},
        )
        prompts_listed = client.post(
            settings.path,
            headers=headers,
            json={"jsonrpc": "2.0", "id": 4, "method": "prompts/list", "params": {}},
        )
        resource_read = client.post(
            settings.path,
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 5,
                "method": "resources/read",
                "params": {"uri": "fortipam://v2.1/safety-boundaries"},
            },
        )
        prompt_rendered = client.post(
            settings.path,
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 6,
                "method": "prompts/get",
                "params": {
                    "name": "fortipam_ha_diagnostics_triage",
                    "arguments": {"detail_level": "incident"},
                },
            },
        )
        prompt_rejected = client.post(
            settings.path,
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 7,
                "method": "prompts/get",
                "params": {
                    "name": "fortipam_ha_diagnostics_triage",
                    "arguments": {
                        "detail_level": "incident",
                        "command": "not-accepted",
                    },
                },
            },
        )
    if rejected.status_code != 401:
        raise RuntimeError("Streamable HTTP smoke did not reject a missing credential.")
    if (
        initialized.status_code != 200
        or listed.status_code != 200
        or resources_listed.status_code != 200
        or prompts_listed.status_code != 200
        or resource_read.status_code != 200
        or prompt_rendered.status_code != 200
        or prompt_rejected.status_code != 200
    ):
        raise RuntimeError("Streamable HTTP MCP negotiation failed.")
    initialize_result = initialized.json().get("result", {})
    tools = listed.json().get("result", {}).get("tools", [])
    names = {tool.get("name") for tool in tools if isinstance(tool, dict)}
    if names != set(EXPECTED_TOOLS):
        raise RuntimeError("Streamable HTTP exposed an unexpected tool surface.")
    resources = resources_listed.json().get("result", {}).get("resources", [])
    prompts = prompts_listed.json().get("result", {}).get("prompts", [])
    resource_uris = {
        uri
        for resource in resources
        if isinstance(resource, dict)
        and isinstance((uri := resource.get("uri")), str)
    }
    prompt_names = {
        name
        for prompt in prompts
        if isinstance(prompt, dict)
        and isinstance((name := prompt.get("name")), str)
    }
    assert_expected_native_content(resource_uris, prompt_names)
    if not resource_read.json().get("result", {}).get("contents"):
        raise RuntimeError("Streamable HTTP Resource read returned no content.")
    if not prompt_rendered.json().get("result", {}).get("messages"):
        raise RuntimeError("Streamable HTTP Prompt rendering returned no messages.")
    if "error" not in prompt_rejected.json():
        raise RuntimeError("Streamable HTTP Prompt accepted an undeclared argument.")
    rejected_prompt_response = json.dumps(prompt_rejected.json(), sort_keys=True)
    if "not-accepted" in rejected_prompt_response or "input_value" in rejected_prompt_response:
        raise RuntimeError("Streamable HTTP Prompt reflected a rejected argument value.")
    tools_by_name = {
        tool.get("name"): tool for tool in tools if isinstance(tool, dict)
    }
    for name in STRICT_NO_INPUT_TOOLS:
        schema = tools_by_name[name].get("inputSchema")
        if not isinstance(schema, dict) or (
            schema.get("type") != "object"
            or schema.get("properties") not in ({}, None)
            or schema.get("required") not in (None, [])
            or schema.get("additionalProperties") is not False
        ):
            raise RuntimeError(
                "Streamable HTTP exposed a non-strict CLI tool input schema."
            )
    return {
        "transport": "streamable_http",
        "protocol_version": initialize_result.get("protocolVersion"),
        "tool_count": len(names),
        "resource_count": len(resource_uris),
        "prompt_count": len(prompt_names),
        "missing_credential_rejected": True,
        "undeclared_prompt_argument_rejected": True,
        "live_fortipam_contacted": False,
    }


def main() -> None:
    print(json.dumps(run_smoke(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
