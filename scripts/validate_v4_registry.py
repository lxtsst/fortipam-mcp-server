#!/usr/bin/env python3
"""Validate the packaged FortiPAM V4 administrative registry."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.v4_registry import RegistryValidationError, load_registry


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", type=Path, help="optional registry JSON path")
    args = parser.parse_args()
    try:
        load_registry(args.path)
    except RegistryValidationError as exc:
        for error in exc.errors:
            print(f"DENY: {error}")
        return 1
    print("PASS: FortiPAM V4 administrative registry is valid and non-executable")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
