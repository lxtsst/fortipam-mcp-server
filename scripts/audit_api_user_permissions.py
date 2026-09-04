#!/usr/bin/env python3
"""Audit the fixed FortiPAM API identity without returning protected values."""

from __future__ import annotations

import asyncio
import argparse
import json
import logging
import os
from typing import Any
from urllib.parse import urljoin

import httpx

from fortipam_mcp import __version__
from fortipam_mcp.config import ConfigurationError, FortiPamConfig, load_config
from fortipam_mcp.env import (
    DEVICE_PREFIX,
    EnvironmentFileError,
    load_runtime_environment,
)
from fortipam_mcp.permission_audit import (
    ACCESS_PROFILE_AUDIT_PATH,
    API_USER_AUDIT_PATH,
    PERMISSION_AUDIT_PATHS,
    PermissionAuditError,
    summarize_permission_audit,
)
from fortipam_mcp.rest import build_ssl_context, MAX_RESPONSE_BYTES


class PermissionAuditRequestError(RuntimeError):
    """A non-disclosing error for the fixed operator audit."""


RUNTIME_PROFILE_VERSION_VARIABLE = f"{DEVICE_PREFIX}_MCP_PROFILE_VERSION"


def _runtime_profile_version(environment: dict[str, str] | None = None) -> str:
    """Select the explicitly configured runtime profile, defaulting to V1.5."""

    source = os.environ if environment is None else environment
    profile_version = source.get(
        RUNTIME_PROFILE_VERSION_VARIABLE, "v15"
    ).strip().lower()
    if profile_version not in {"v15", "v16", "v17"}:
        raise ConfigurationError(
            "The runtime permission-audit profile version is invalid."
        )
    return profile_version


async def run_audit(target: str = "runtime") -> dict[str, object]:
    """Read exactly two administrative objects and return derived posture."""

    report = load_runtime_environment()
    if target == "dedicated":
        expected_api_username = os.environ.get(
            f"{DEVICE_PREFIX}_MCP_API_USERNAME"
        )
        if not expected_api_username:
            raise ConfigurationError(
                "The dedicated MCP API identity is not configured."
            )
        profile_version = "v15"
    elif target == "v16":
        expected_api_username = os.environ.get(
            f"{DEVICE_PREFIX}_MCP_V16_API_USERNAME"
        )
        if not expected_api_username:
            raise ConfigurationError(
                "The V1.6 MCP API identity is not configured."
            )
        profile_version = "v16"
    elif target == "v17":
        expected_api_username = os.environ.get(
            f"{DEVICE_PREFIX}_MCP_V17_API_USERNAME"
        )
        if not expected_api_username:
            raise ConfigurationError(
                "The V1.7 MCP API identity is not configured."
            )
        profile_version = "v17"
    elif target == "runtime":
        expected_api_username = os.environ.get(f"{DEVICE_PREFIX}_API_USERNAME")
        profile_version = _runtime_profile_version()
    else:
        raise ConfigurationError("Permission-audit target is invalid.")
    config = load_config()
    _configure_safe_logging()
    async with httpx.AsyncClient(
        verify=build_ssl_context(config),
        timeout=config.timeout_seconds,
        follow_redirects=False,
        trust_env=False,
    ) as client:
        api_user_payload = await _fixed_get(
            client, config, API_USER_AUDIT_PATH, "API-user"
        )
        access_profile_payload = await _fixed_get(
            client, config, ACCESS_PROFILE_AUDIT_PATH, "access-profile"
        )
    return {
        "audit_version": "1.0",
        "audit_target": target,
        "credential_source_loaded": report.loaded,
        "tls_verification_enabled": True,
        "requests": [
            {"method": "GET", "purpose": "API identity visibility"},
            {"method": "GET", "purpose": "effective access profile"},
        ],
        "posture": summarize_permission_audit(
            api_user_payload,
            access_profile_payload,
            expected_api_username=expected_api_username,
            profile_version=profile_version,
        ),
    }


async def _fixed_get(
    client: httpx.AsyncClient,
    config: FortiPamConfig,
    path: str,
    label: str,
) -> Any:
    if path not in PERMISSION_AUDIT_PATHS:
        raise PermissionAuditRequestError(
            "Requested permission-audit path is outside the fixed boundary."
        )
    url = urljoin(f"{config.base_url}/", path.lstrip("/"))
    try:
        async with client.stream(
            "GET",
            url,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {config.authentication.token}",
                "User-Agent": f"fortipam-mcp-permission-audit/{__version__}",
            },
        ) as response:
            if response.status_code < 200 or response.status_code >= 300:
                raise PermissionAuditRequestError(
                    f"FortiPAM {label} audit returned HTTP {response.status_code}."
                )
            content = await _bounded_content(response)
            content_type = response.headers.get("content-type") or ""
    except PermissionAuditRequestError:
        raise
    except httpx.RequestError as exc:
        raise PermissionAuditRequestError(
            f"Unable to complete the FortiPAM {label} audit."
        ) from exc
    if "json" not in content_type.lower():
        raise PermissionAuditRequestError(
            f"FortiPAM {label} audit returned non-JSON content."
        )
    try:
        return json.loads(content)
    except json.JSONDecodeError as exc:
        raise PermissionAuditRequestError(
            f"FortiPAM {label} audit returned malformed JSON."
        ) from exc


async def _bounded_content(response: httpx.Response) -> bytes:
    chunks: list[bytes] = []
    received = 0
    async for chunk in response.aiter_bytes():
        received += len(chunk)
        if received > MAX_RESPONSE_BYTES:
            raise PermissionAuditRequestError(
                "FortiPAM permission audit response exceeded the safety limit."
            )
        chunks.append(chunk)
    return b"".join(chunks)


def _configure_safe_logging() -> None:
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Audit one configured FortiPAM API identity without disclosure."
    )
    parser.add_argument(
        "--target",
        choices=("runtime", "dedicated", "v16", "v17"),
        default="runtime",
        help=(
            "Select the current runtime, V1.5 dedicated identity, or separate "
            "V1.6 candidate identity, or V1.7 candidate identity."
        ),
    )
    args = parser.parse_args(argv)
    try:
        result = asyncio.run(run_audit(args.target))
    except (
        ConfigurationError,
        EnvironmentFileError,
        PermissionAuditError,
        PermissionAuditRequestError,
    ) as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
