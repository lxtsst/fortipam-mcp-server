#!/usr/bin/env python3
"""Capture or compare non-disclosing baselines for non-target CLI identities."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any, Mapping

import httpx

from fortipam_mcp.config import FortiPamConfig, load_config
from fortipam_mcp.env import DEVICE_PREFIX, load_runtime_environment
from fortipam_mcp.rest import build_ssl_context

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.audit_cli_identity import ADMIN_PATH, PROFILE_PATH, _fixed_get


BASELINE_CONTRACT = "fortipam_cli_non_target_baseline_v1"


class BaselineError(RuntimeError):
    """Raised when a baseline cannot be captured or compared safely."""


def collection_fingerprint(
    payload: object,
    *,
    excluded_name: str,
) -> tuple[int, str]:
    """Hash canonical non-target objects without returning their values."""

    if not isinstance(payload, Mapping) or not isinstance(payload.get("results"), list):
        raise BaselineError("The administrative collection is malformed.")
    canonical_objects: list[str] = []
    for item in payload["results"]:
        if not isinstance(item, Mapping):
            raise BaselineError("The administrative collection contains a malformed item.")
        if item.get("name") == excluded_name:
            continue
        canonical_objects.append(
            json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        )
    canonical_objects.sort()
    digest = hashlib.sha256("\n".join(canonical_objects).encode("utf-8")).hexdigest()
    return len(canonical_objects), digest


async def capture() -> dict[str, object]:
    """Read two fixed collections and derive non-target fingerprints."""

    load_runtime_environment()
    config = load_config()
    username = os.environ.get(f"{DEVICE_PREFIX}_MCP_CLI_SSH_USERNAME", "").strip()
    profile_name = os.environ.get(f"{DEVICE_PREFIX}_MCP_CLI_ROLE_NAME", "").strip()
    if not username or not profile_name:
        raise BaselineError("The dedicated CLI username and Role name are required.")
    admin_payload, profile_payload = await _read_collections(config)
    admin_count, admin_digest = collection_fingerprint(
        admin_payload,
        excluded_name=username,
    )
    profile_count, profile_digest = collection_fingerprint(
        profile_payload,
        excluded_name=profile_name,
    )
    return {
        "contract": BASELINE_CONTRACT,
        "admin_count": admin_count,
        "admin_digest": admin_digest,
        "profile_count": profile_count,
        "profile_digest": profile_digest,
    }


async def _read_collections(config: FortiPamConfig) -> tuple[Any, Any]:
    async with httpx.AsyncClient(
        verify=build_ssl_context(config),
        timeout=config.timeout_seconds,
        follow_redirects=False,
        trust_env=False,
    ) as client:
        return (
            await _fixed_get(client, config, ADMIN_PATH),
            await _fixed_get(client, config, PROFILE_PATH),
        )


def write_baseline(path: Path, baseline: Mapping[str, object]) -> None:
    """Create one owner-only baseline without replacing existing evidence."""

    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise BaselineError("The baseline file already exists.") from exc
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(dict(baseline), handle, sort_keys=True, separators=(",", ":"))
        handle.write("\n")


def compare_baseline(path: Path, current: Mapping[str, object]) -> dict[str, object]:
    """Compare owner-only evidence and return booleans rather than digests."""

    if not path.is_file() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise BaselineError("The baseline file must exist and be owner-only.")
    try:
        baseline = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BaselineError("The baseline file is invalid.") from exc
    required = {
        "contract",
        "admin_count",
        "admin_digest",
        "profile_count",
        "profile_digest",
    }
    if not isinstance(baseline, dict) or set(baseline) != required:
        raise BaselineError("The baseline file has an unexpected shape.")
    contract_exact = baseline["contract"] == BASELINE_CONTRACT
    admin_unchanged = bool(
        baseline["admin_count"] == current["admin_count"]
        and baseline["admin_digest"] == current["admin_digest"]
    )
    profile_unchanged = bool(
        baseline["profile_count"] == current["profile_count"]
        and baseline["profile_digest"] == current["profile_digest"]
    )
    return {
        "contract": BASELINE_CONTRACT,
        "baseline_contract_exact": contract_exact,
        "non_target_admins_unchanged": admin_unchanged,
        "non_target_profiles_unchanged": profile_unchanged,
        "baseline_accepted": contract_exact and admin_unchanged and profile_unchanged,
        "identity_values_returned": False,
        "profile_values_returned": False,
        "digests_returned": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Capture or compare the FortiPAM non-target identity baseline."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", type=Path)
    mode.add_argument("--compare", type=Path)
    args = parser.parse_args()
    try:
        current = asyncio.run(capture())
        if args.write is not None:
            write_baseline(args.write, current)
            result = {
                "contract": BASELINE_CONTRACT,
                "baseline_written": True,
                "tls_verification_enabled": True,
                "identity_values_returned": False,
                "profile_values_returned": False,
                "digests_returned": False,
            }
        else:
            result = compare_baseline(args.compare, current)
    except BaselineError as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
