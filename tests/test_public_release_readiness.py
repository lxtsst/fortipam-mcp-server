from __future__ import annotations

import asyncio
from pathlib import Path
import tomllib

from mcp import Client

from fortipam_mcp.runtime_profile import RuntimeProfile
from fortipam_mcp.server import FortiPamMcpServer


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PUBLIC_REPOSITORY = "https://github.com/lxtsst/fortipam-mcp-server"
MCP_NAME_MARKER = "mcp-name: io.github.lxtsst/fortipam-mcp-server"


def test_public_package_urls_and_readmes_use_distribution_repository() -> None:
    metadata = tomllib.loads(
        (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )
    project = metadata["project"]
    urls = project["urls"]

    assert urls["Homepage"] == PUBLIC_REPOSITORY
    assert urls["Source"] == PUBLIC_REPOSITORY
    assert urls["Documentation"].startswith(PUBLIC_REPOSITORY)
    assert urls["Issues"].startswith(PUBLIC_REPOSITORY)

    for name in ("README.md", "README.zh-CN.md"):
        readme = (PROJECT_ROOT / name).read_text(encoding="utf-8")
        assert PUBLIC_REPOSITORY in readme
        assert project["version"] in readme






def test_v4_plan_surface_has_explicit_review_hints_and_output_schemas() -> None:
    server = FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_PLAN_ONLY,
        v4_http_oauth=True,
    )

    async def _inspect() -> list[object]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
        return list(tools.tools)

    tools = asyncio.run(_inspect())
    assert len(tools) == 97
    for tool in tools:
        descriptor = tool.model_dump(by_alias=True)  # type: ignore[attr-defined]
        annotations = descriptor.get("annotations")
        assert isinstance(annotations, dict)
        for hint in ("readOnlyHint", "openWorldHint", "destructiveHint"):
            assert isinstance(annotations.get(hint), bool)
        assert isinstance(descriptor.get("outputSchema"), dict)
