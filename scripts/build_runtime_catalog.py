#!/usr/bin/env python3
"""Build the packaged FortiPAM runtime catalog from a sanitized source file."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from fortipam_mcp.catalog_import import build_runtime_catalog, sha256_bytes


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build a bounded FortiPAM MCP runtime API catalog."
    )
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--expected-sha256", required=True)
    args = parser.parse_args()

    content = args.input.read_bytes()
    actual_sha256 = sha256_bytes(content)
    if actual_sha256 != args.expected_sha256.lower():
        raise SystemExit("Input catalog SHA-256 does not match the approved source.")
    source = json.loads(content)
    runtime_catalog = build_runtime_catalog(source, source_sha256=actual_sha256)
    operations = runtime_catalog["operations"]
    if not isinstance(operations, list):
        raise SystemExit("Generated runtime catalog operations are invalid.")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(runtime_catalog, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "operation_count": len(operations),
                "product": runtime_catalog["product"],
                "source_sha256": actual_sha256,
                "version": runtime_catalog["version"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
