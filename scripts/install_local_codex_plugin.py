#!/usr/bin/env python3
"""Install a sanitized Codex plugin copy and inject a private MCP URL safely."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from pathlib import Path
from urllib.parse import urlsplit


EXPECTED_PLUGIN_NAME = "fortipam-security-copilot"
V4_PLUGIN_NAME = "fortipam-security-copilot-v4"
V3_MCP_PATH = "/fpamcp-v3"
V4_MCP_PATH = "/fpamcp-v4"
EXPECTED_MCP_PATH = V3_MCP_PATH
SUPPORTED_MCP_PATHS = (V3_MCP_PATH, V4_MCP_PATH)
SUPPORTED_PLUGIN_NAMES = (EXPECTED_PLUGIN_NAME, V4_PLUGIN_NAME)
_PLUGIN_NAME_PATTERN = re.compile(r"^fortipam-security-copilot(?:-v4)?$")


def validate_mcp_url(raw_url: str, expected_path: str = EXPECTED_MCP_PATH) -> str:
    """Return a normalized HTTPS MCP URL without exposing its host in errors."""
    if expected_path not in SUPPORTED_MCP_PATHS:
        raise ValueError("The selected FortiPAM MCP path is unsupported.")
    candidate = raw_url.strip()
    parsed = urlsplit(candidate)
    if (
        len(raw_url.splitlines()) != 1
        or any(
            ord(character) < 32 or ord(character) == 127
            for character in candidate
        )
        or parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path.rstrip("/") != expected_path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "MCP URL must use HTTPS, contain no user info/query/fragment, "
            f"and use the exact {expected_path} path."
        )
    return candidate.rstrip("/")


def validate_source(source: Path) -> None:
    manifest_path = source / ".codex-plugin" / "plugin.json"
    if not manifest_path.is_file():
        raise ValueError("Source plugin manifest is missing.")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("name") != EXPECTED_PLUGIN_NAME:
        raise ValueError("Source plugin name is not the expected FortiPAM plugin.")


def plugin_name_for_mcp_path(mcp_path: str) -> str:
    """Return the collision-free plugin identity for a selected endpoint."""
    if mcp_path == V3_MCP_PATH:
        return EXPECTED_PLUGIN_NAME
    if mcp_path == V4_MCP_PATH:
        return V4_PLUGIN_NAME
    raise ValueError("The selected FortiPAM MCP path is unsupported.")


def validate_plugin_name(plugin_name: str, mcp_path: str) -> str:
    """Require the explicit plugin identity to match its V3/V4 endpoint."""
    if (
        not isinstance(plugin_name, str)
        or _PLUGIN_NAME_PATTERN.fullmatch(plugin_name) is None
        or plugin_name not in SUPPORTED_PLUGIN_NAMES
        or plugin_name != plugin_name_for_mcp_path(mcp_path)
    ):
        raise ValueError("Plugin name must match the selected FortiPAM MCP path.")
    return plugin_name


def _destination_identity(destination: Path) -> str | None:
    """Read an existing destination identity before allowing a copy."""
    if not destination.exists():
        return None
    if destination.is_symlink():
        raise ValueError("Destination plugin tree must not be a symbolic link.")
    manifest_path = destination / ".codex-plugin" / "plugin.json"
    if not manifest_path.is_file():
        raise ValueError("Existing destination is not an installed plugin tree.")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("Existing destination plugin manifest is invalid.") from exc
    identity = manifest.get("name")
    if not isinstance(identity, str):
        raise ValueError("Existing destination plugin identity is invalid.")
    return identity


def install_plugin(
    source: Path,
    destination: Path,
    mcp_url: str,
    plugin_name: str | None = None,
) -> None:
    validate_source(source)
    if (
        source == destination
        or source in destination.parents
        or destination in source.parents
    ):
        raise ValueError("Source and destination plugin trees must be separate.")
    parsed_path = urlsplit(mcp_url).path.rstrip("/")
    selected_name = validate_plugin_name(
        plugin_name or plugin_name_for_mcp_path(parsed_path),
        parsed_path,
    )
    normalized_url = validate_mcp_url(mcp_url, parsed_path)
    existing_identity = _destination_identity(destination)
    if existing_identity is not None and existing_identity != selected_name:
        raise ValueError(
            "Destination already contains a different plugin identity; "
            "choose a separate destination."
        )
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, destination, dirs_exist_ok=True)

    manifest_path = destination / ".codex-plugin" / "plugin.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["name"] = selected_name
    manifest_path.write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )

    mcp_path = destination / ".mcp.json"
    if mcp_path.is_symlink():
        raise ValueError("Destination MCP configuration must not be a symbolic link.")
    payload = {
        "mcpServers": {
            selected_name: {
                "type": "http",
                "url": normalized_url,
            }
        }
    }
    mcp_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    mcp_path.chmod(0o600)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Copy the FortiPAM Codex plugin and read its private MCP URL "
            "from standard input."
        )
    )
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument(
        "--mcp-path",
        choices=SUPPORTED_MCP_PATHS,
        default=EXPECTED_MCP_PATH,
        help="Select the stable V3 or isolated V4 planning endpoint.",
    )
    parser.add_argument(
        "--plugin-name",
        choices=SUPPORTED_PLUGIN_NAMES,
        default=None,
        help=(
            "Optional collision-free plugin identity. Defaults to the stable "
            "V3 name or the isolated V4 name based on --mcp-path."
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    raw_url = sys.stdin.read()
    if not raw_url.strip():
        print("No MCP URL was provided on standard input.", file=sys.stderr)
        return 2

    try:
        mcp_url = validate_mcp_url(raw_url, args.mcp_path)
        selected_name = validate_plugin_name(
            args.plugin_name or plugin_name_for_mcp_path(args.mcp_path),
            args.mcp_path,
        )
        install_plugin(
            args.source.resolve(),
            args.destination.expanduser().resolve(),
            mcp_url,
            selected_name,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Plugin installation failed: {exc}", file=sys.stderr)
        return 1

    print(f"Installed {selected_name} with a private MCP configuration.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
