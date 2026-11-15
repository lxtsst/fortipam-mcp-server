from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "install_local_codex_plugin.py"
SPEC = importlib.util.spec_from_file_location("install_local_codex_plugin", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
INSTALLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALLER)


def test_validate_mcp_url_accepts_only_exact_https_v3_path() -> None:
    assert (
        INSTALLER.validate_mcp_url("https://mcp.example.com/fpamcp-v3\n")
        == "https://mcp.example.com/fpamcp-v3"
    )

    invalid_urls = (
        "http://mcp.example.com/fpamcp-v3",
        "https://mcp.example.com/fpamcp",
        "https://mcp.example.com/fpamcp-v3?token=value",
        "https://user:password@mcp.example.com/fpamcp-v3",
        "https://mcp.example.com/fpamcp-v3\nhttps://other.example.com/fpamcp-v3",
    )
    for invalid_url in invalid_urls:
        with pytest.raises(ValueError):
            INSTALLER.validate_mcp_url(invalid_url)


def test_validate_mcp_url_accepts_exact_https_v4_path_when_selected() -> None:
    assert (
        INSTALLER.validate_mcp_url(
            "https://mcp.example.com/fpamcp-v4\n",
            INSTALLER.V4_MCP_PATH,
        )
        == "https://mcp.example.com/fpamcp-v4"
    )


def test_validate_mcp_url_keeps_v3_and_v4_selection_separate() -> None:
    with pytest.raises(ValueError, match="exact /fpamcp-v4 path"):
        INSTALLER.validate_mcp_url(
            "https://mcp.example.com/fpamcp-v3",
            INSTALLER.V4_MCP_PATH,
        )


def test_plugin_identity_is_derived_from_endpoint_without_collision() -> None:
    assert INSTALLER.plugin_name_for_mcp_path(INSTALLER.V3_MCP_PATH) == INSTALLER.EXPECTED_PLUGIN_NAME
    assert INSTALLER.plugin_name_for_mcp_path(INSTALLER.V4_MCP_PATH) == INSTALLER.V4_PLUGIN_NAME
    with pytest.raises(ValueError):
        INSTALLER.validate_plugin_name(
            INSTALLER.EXPECTED_PLUGIN_NAME,
            INSTALLER.V4_MCP_PATH,
        )
    with pytest.raises(ValueError):
        INSTALLER.validate_plugin_name(
            INSTALLER.V4_PLUGIN_NAME,
            INSTALLER.V3_MCP_PATH,
        )


def test_install_plugin_preserves_source_and_writes_private_local_url(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    manifest_dir = source / ".codex-plugin"
    manifest_dir.mkdir(parents=True)
    (manifest_dir / "plugin.json").write_text(
        json.dumps({"name": INSTALLER.EXPECTED_PLUGIN_NAME}),
        encoding="utf-8",
    )
    (source / ".mcp.json").write_text(
        json.dumps({"mcpServers": {}}),
        encoding="utf-8",
    )
    skill_dir = source / "skills" / "example"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("example\n", encoding="utf-8")

    destination = tmp_path / "destination"
    private_url = "https://private.example.test/fpamcp-v3"
    INSTALLER.install_plugin(source, destination, private_url)

    local_config = json.loads((destination / ".mcp.json").read_text(encoding="utf-8"))
    assert local_config["mcpServers"][INSTALLER.EXPECTED_PLUGIN_NAME]["url"] == private_url
    assert json.loads(
        (destination / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8")
    )["name"] == INSTALLER.EXPECTED_PLUGIN_NAME
    assert ((destination / ".mcp.json").stat().st_mode & 0o777) == 0o600
    assert (destination / "skills" / "example" / "SKILL.md").is_file()
    assert json.loads((source / ".mcp.json").read_text(encoding="utf-8")) == {
        "mcpServers": {}
    }


def test_v4_install_derives_distinct_manifest_and_mcp_identity(tmp_path: Path) -> None:
    source = tmp_path / "source"
    manifest_dir = source / ".codex-plugin"
    manifest_dir.mkdir(parents=True)
    (manifest_dir / "plugin.json").write_text(
        json.dumps({"name": INSTALLER.EXPECTED_PLUGIN_NAME}),
        encoding="utf-8",
    )
    destination = tmp_path / "destination-v4"

    INSTALLER.install_plugin(
        source,
        destination,
        "https://private.example.test/fpamcp-v4",
    )

    assert json.loads(
        (destination / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8")
    )["name"] == INSTALLER.V4_PLUGIN_NAME
    local_config = json.loads((destination / ".mcp.json").read_text(encoding="utf-8"))
    assert list(local_config["mcpServers"]) == [INSTALLER.V4_PLUGIN_NAME]
    assert local_config["mcpServers"][INSTALLER.V4_PLUGIN_NAME]["url"].endswith(
        INSTALLER.V4_MCP_PATH
    )
    assert json.loads((manifest_dir / "plugin.json").read_text(encoding="utf-8"))["name"] == (
        INSTALLER.EXPECTED_PLUGIN_NAME
    )


def test_destination_with_different_plugin_identity_is_not_overwritten(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    manifest_dir = source / ".codex-plugin"
    manifest_dir.mkdir(parents=True)
    (manifest_dir / "plugin.json").write_text(
        json.dumps({"name": INSTALLER.EXPECTED_PLUGIN_NAME}),
        encoding="utf-8",
    )
    destination = tmp_path / "destination"
    existing_manifest = destination / ".codex-plugin"
    existing_manifest.mkdir(parents=True)
    (existing_manifest / "plugin.json").write_text(
        json.dumps({"name": INSTALLER.EXPECTED_PLUGIN_NAME}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="different plugin identity"):
        INSTALLER.install_plugin(
            source,
            destination,
            "https://mcp.example.com/fpamcp-v4",
        )

    assert json.loads((existing_manifest / "plugin.json").read_text(encoding="utf-8"))[
        "name"
    ] == INSTALLER.EXPECTED_PLUGIN_NAME


def test_install_plugin_rejects_same_or_nested_destination(tmp_path: Path) -> None:
    source = tmp_path / "source"
    manifest_dir = source / ".codex-plugin"
    manifest_dir.mkdir(parents=True)
    (manifest_dir / "plugin.json").write_text(
        json.dumps({"name": INSTALLER.EXPECTED_PLUGIN_NAME}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="separate"):
        INSTALLER.install_plugin(
            source,
            source,
            "https://mcp.example.com/fpamcp-v3",
        )
    with pytest.raises(ValueError, match="separate"):
        INSTALLER.install_plugin(
            source,
            source / "nested",
            "https://mcp.example.com/fpamcp-v3",
        )


def test_tracked_plugin_configuration_remains_sanitized_v3_example() -> None:
    tracked_config = json.loads(
        (
            PROJECT_ROOT
            / "plugins"
            / INSTALLER.EXPECTED_PLUGIN_NAME
            / ".mcp.json"
        ).read_text(encoding="utf-8")
    )

    assert tracked_config == {
        "mcpServers": {
            INSTALLER.EXPECTED_PLUGIN_NAME: {
                "type": "http",
                "url": "https://mcp.example.com/fpamcp-v3",
            }
        }
    }
