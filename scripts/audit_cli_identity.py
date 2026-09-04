#!/usr/bin/env python3
"""Audit the dedicated V2 CLI identity without returning protected values."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any
from urllib.parse import quote, urljoin

import asyncssh
import httpx

from fortipam_mcp import __version__
from fortipam_mcp.cli_identity import (
    CliIdentityExpectation,
    evaluate_cli_identity,
)
from fortipam_mcp.config import ConfigurationError, FortiPamConfig, load_cli_config, load_config
from fortipam_mcp.env import DEVICE_PREFIX, EnvironmentFileError, load_runtime_environment
from fortipam_mcp.rest import MAX_RESPONSE_BYTES, build_ssl_context


ADMIN_PATH = "/api/v2/cmdb/system/admin"
PROFILE_PATH = "/api/v2/cmdb/system/accprofile"
ROLE_VARIABLE = f"{DEVICE_PREFIX}_MCP_CLI_ROLE_NAME"
SOURCE_VARIABLE = f"{DEVICE_PREFIX}_MCP_CLI_TRUSTED_SOURCE"


class CliIdentityAuditError(RuntimeError):
    """A non-disclosing failure in the fixed operator audit."""


async def run_audit() -> dict[str, object]:
    """Read two fixed administrative collections and evaluate exact gates."""

    report = load_runtime_environment()
    api_config = load_config()
    cli_config = load_cli_config()
    profile_name = os.environ.get(ROLE_VARIABLE, "").strip()
    trusted_source = os.environ.get(SOURCE_VARIABLE, "").strip()
    if not profile_name or not trusted_source:
        raise ConfigurationError(
            "The CLI Role name and trusted-source expectation are required."
        )
    try:
        key = asyncssh.read_private_key(str(cli_config.target.identity_file))
        public_key_bytes = key.export_public_key("openssh")
        public_key = public_key_bytes.decode("ascii").strip()
    except (asyncssh.Error, OSError, UnicodeDecodeError) as exc:
        raise CliIdentityAuditError("The dedicated CLI key is invalid.") from exc

    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    admin_path = _named_api_path(ADMIN_PATH, cli_config.target.username)
    profile_path = _named_api_path(PROFILE_PATH, profile_name)
    allowed_paths = frozenset({admin_path, profile_path})
    async with httpx.AsyncClient(
        verify=build_ssl_context(api_config),
        timeout=api_config.timeout_seconds,
        follow_redirects=False,
        trust_env=False,
    ) as client:
        admin_payload = await _fixed_get(
            client, api_config, admin_path, allowed_paths=allowed_paths
        )
        profile_payload = await _fixed_get(
            client, api_config, profile_path, allowed_paths=allowed_paths
        )

    return {
        "audit_version": "1.0",
        "credential_source_loaded": report.loaded,
        "tls_verification_enabled": True,
        "request_count": 2,
        "posture": evaluate_cli_identity(
            admin_payload,
            profile_payload,
            CliIdentityExpectation(
                username=cli_config.target.username,
                profile_name=profile_name,
                trusted_source=trusted_source,
                public_key=public_key,
            ),
        ),
    }


async def _fixed_get(
    client: httpx.AsyncClient,
    config: FortiPamConfig,
    path: str,
    *,
    allowed_paths: frozenset[str] | None = None,
) -> Any:
    accepted_paths = allowed_paths or frozenset({ADMIN_PATH, PROFILE_PATH})
    if path not in accepted_paths:
        raise CliIdentityAuditError("CLI identity audit path is outside the fixed set.")
    try:
        async with client.stream(
            "GET",
            urljoin(f"{config.base_url}/", path.lstrip("/")),
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {config.authentication.token}",
                "User-Agent": f"fortipam-mcp-cli-identity-audit/{__version__}",
            },
        ) as response:
            if not 200 <= response.status_code < 300:
                raise CliIdentityAuditError(
                    f"CLI identity audit returned HTTP {response.status_code}."
                )
            received = 0
            chunks: list[bytes] = []
            async for chunk in response.aiter_bytes():
                received += len(chunk)
                if received > MAX_RESPONSE_BYTES:
                    raise CliIdentityAuditError(
                        "CLI identity audit response exceeded the safety limit."
                    )
                chunks.append(chunk)
            if "json" not in (response.headers.get("content-type") or "").lower():
                raise CliIdentityAuditError("CLI identity audit returned non-JSON content.")
    except CliIdentityAuditError:
        raise
    except httpx.RequestError as exc:
        raise CliIdentityAuditError("CLI identity audit request failed.") from exc
    try:
        return json.loads(b"".join(chunks))
    except json.JSONDecodeError as exc:
        raise CliIdentityAuditError("CLI identity audit returned malformed JSON.") from exc


def _named_api_path(collection_path: str, name: str) -> str:
    """Build one exact CMDB member path from a trusted configured name."""

    if collection_path not in {ADMIN_PATH, PROFILE_PATH} or not name:
        raise CliIdentityAuditError("CLI identity audit target is invalid.")
    return f"{collection_path}/{quote(name, safe='')}"


def main() -> None:
    try:
        result = asyncio.run(run_audit())
    except (
        CliIdentityAuditError,
        ConfigurationError,
        EnvironmentFileError,
    ) as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
