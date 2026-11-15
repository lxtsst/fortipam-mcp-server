#!/usr/bin/env python3
"""Probe the fixed FortiPAM folder collection GET without disclosing values.

This is an engineering-evidence helper, not an MCP Tool.  It loads the existing
owner-only FortiPAM runtime environment, performs exactly one verified-TLS GET
to the compiled folder collection path, and emits only response-shape metadata.
It never prints the target, credential, folder names, raw response, or Secret
material.
"""

from __future__ import annotations

import argparse
import asyncio
from collections.abc import Mapping, Sequence
import json
from typing import Any
from urllib.parse import urljoin

from fortipam_mcp import __version__
from fortipam_mcp.config import load_config
from fortipam_mcp.env import load_runtime_environment
from fortipam_mcp.folder_create_contract import COLLECTION_READ_PATH
from fortipam_mcp.rest import MAX_RESPONSE_BYTES, build_ssl_context


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--acknowledge-live-read",
        action="store_true",
        help="Required acknowledgement that this performs one live GET.",
    )
    return parser


async def _bounded_json(response: Any) -> object:
    declared = response.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > MAX_RESPONSE_BYTES:
                raise RuntimeError("response_exceeded_limit")
        except ValueError:
            pass
    chunks: list[bytes] = []
    size = 0
    async for chunk in response.aiter_bytes():
        size += len(chunk)
        if size > MAX_RESPONSE_BYTES:
            raise RuntimeError("response_exceeded_limit")
        chunks.append(chunk)
    content_type = response.headers.get("content-type", "").lower()
    if "json" not in content_type:
        raise RuntimeError("unexpected_content_type")
    return json.loads(b"".join(chunks))


def _shape(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, Mapping):
        return "object"
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return "array"
    return "unknown"


def project_shape(payload: object, status_code: int) -> dict[str, object]:
    """Return only structural metadata for one response payload."""

    if not isinstance(payload, Mapping):
        raise RuntimeError("top_level_not_object")
    result: dict[str, object] = {
        "probe_contract": "fortipam_folder_collection_shape_v1",
        "runtime_version": __version__,
        "method": "GET",
        "path": COLLECTION_READ_PATH,
        "http_status": status_code,
        "top_level_keys": sorted(str(key) for key in payload),
        "top_level_shapes": {
            str(key): _shape(value) for key, value in sorted(payload.items(), key=lambda item: str(item[0]))
        },
        "raw_values_returned": False,
        "device_write_executed": False,
    }
    entries = payload.get("results")
    if isinstance(entries, Sequence) and not isinstance(entries, (str, bytes, bytearray)):
        result["result_count"] = len(entries)
        object_entries = [entry for entry in entries if isinstance(entry, Mapping)]
        result["result_object_count"] = len(object_entries)
        result["result_item_keys"] = sorted(
            {str(key) for entry in object_entries for key in entry}
        )
        result["result_item_shapes"] = {
            str(key): sorted({_shape(entry[key]) for entry in object_entries if key in entry})
            for key in sorted({key for entry in object_entries for key in entry}, key=str)
        }
    return result


async def _run() -> dict[str, object]:
    load_runtime_environment()
    config = load_config()
    try:
        import httpx
    except ModuleNotFoundError as exc:  # pragma: no cover - dependency guard.
        raise RuntimeError("httpx is required for the fixed live-read probe") from exc
    url = urljoin(f"{config.base_url}/", COLLECTION_READ_PATH.lstrip("/"))
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {config.authentication.token}",
        "User-Agent": f"fortipam-mcp-contract-probe/{__version__}",
    }
    async with httpx.AsyncClient(
        verify=build_ssl_context(config),
        timeout=config.timeout_seconds,
        follow_redirects=False,
        trust_env=False,
    ) as client:
        async with client.stream("GET", url, headers=headers) as response:
            if response.status_code < 200 or response.status_code >= 300:
                raise RuntimeError(f"FortiPAM returned HTTP {response.status_code}.")
            payload = await _bounded_json(response)
            return project_shape(payload, response.status_code)


def main() -> int:
    args = _parser().parse_args()
    if not args.acknowledge_live_read:
        raise SystemExit("Refusing live read without --acknowledge-live-read.")
    print(json.dumps(asyncio.run(_run()), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
