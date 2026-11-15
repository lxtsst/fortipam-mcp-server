#!/usr/bin/env python3
"""Project the BP007 pre-bound central-lab account into fixture-only files.

This script runs inside the already trusted candidate container.  It accepts no
credential, binding, or source-path argument: those are resolved only from the
candidate's pre-existing owner-only runtime configuration.  It creates the two
fixture inputs once with strict ownership and never renders their values.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import stat
import sys
from typing import Mapping

import yaml  # type: ignore[import-untyped]


_PREFIX = "FORTIPAM_MCP_V4_SECRET_CREATE_LAB_AUTO_"
_MAX_BYTES = 65_536
_VARIABLE_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_BINDING_ID = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_NAMES = {"username": "username", "password": "password"}


class FixtureMaterialError(RuntimeError):
    """Stable no-detail error for unavailable fixture material."""


def _required(environment: Mapping[str, str], suffix: str) -> str:
    value = environment.get(f"{_PREFIX}{suffix}")
    if not isinstance(value, str) or not value or value != value.strip():
        raise FixtureMaterialError("BP007 fixture material is unavailable.")
    return value


def _owner_only_file(path: Path) -> bytearray:
    try:
        details = path.stat()
        if (
            not path.is_absolute()
            or not path.is_file()
            or stat.S_IMODE(details.st_mode) & 0o077
            or details.st_size > _MAX_BYTES
        ):
            raise ValueError
        return bytearray(path.read_bytes())
    except (OSError, ValueError) as exc:
        raise FixtureMaterialError("BP007 fixture material is unavailable.") from exc


def _binding_variables(binding_path: Path, binding_id: str) -> tuple[str, str]:
    if _BINDING_ID.fullmatch(binding_id) is None:
        raise FixtureMaterialError("BP007 fixture material is unavailable.")
    content = _owner_only_file(binding_path)
    try:
        parsed = yaml.safe_load(bytes(content))
    finally:
        content[:] = b"\x00" * len(content)
    if (
        not isinstance(parsed, dict)
        or parsed.get("schema_version") != "credential-bindings-v1"
        or not isinstance(parsed.get("bindings"), list)
        or set(parsed) != {"schema_version", "bindings"}
    ):
        raise FixtureMaterialError("BP007 fixture material is unavailable.")
    matches = [item for item in parsed["bindings"] if isinstance(item, dict) and item.get("id") == binding_id]
    if len(matches) != 1:
        raise FixtureMaterialError("BP007 fixture material is unavailable.")
    item = matches[0]
    variables = item.get("variables")
    if (
        set(item) != {"id", "provider", "variables"}
        or item.get("provider") != "env-file"
        or not isinstance(variables, dict)
        or set(variables) != {"username", "password"}
        or not all(isinstance(value, str) and _VARIABLE_NAME.fullmatch(value) for value in variables.values())
    ):
        raise FixtureMaterialError("BP007 fixture material is unavailable.")
    return variables["username"], variables["password"]


def _load_values(secret_env: Path, username_name: str, password_name: str) -> tuple[bytearray, bytearray]:
    content = _owner_only_file(secret_env)
    wanted = {username_name: "username", password_name: "password"}
    values: dict[str, bytearray] = {}
    try:
        for raw_line in bytes(content).splitlines():
            name, separator, value = raw_line.partition(b"=")
            try:
                decoded_name = name.decode("ascii")
            except UnicodeDecodeError:
                continue
            if separator and decoded_name in wanted and decoded_name not in values:
                candidate = bytearray(value)
                if not candidate or len(candidate) > 255 or any(char < 32 or char == 127 for char in candidate):
                    raise ValueError
                values[decoded_name] = candidate
    except ValueError as exc:
        raise FixtureMaterialError("BP007 fixture material is unavailable.") from exc
    finally:
        content[:] = b"\x00" * len(content)
    if set(values) != set(wanted):
        for stored_value in values.values():
            stored_value[:] = b"\x00" * len(stored_value)
        raise FixtureMaterialError("BP007 fixture material is unavailable.")
    return values[username_name], values[password_name]


def _write_once(directory: Path, name: str, value: bytearray) -> None:
    try:
        details = directory.stat()
        if not directory.is_absolute() or not directory.is_dir() or stat.S_IMODE(details.st_mode) & 0o077:
            raise ValueError
        target = directory / name
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.write(descriptor, value)
        finally:
            os.close(descriptor)
    except (OSError, ValueError) as exc:
        raise FixtureMaterialError("BP007 fixture material is unavailable.") from exc


def _empty_owner_only_directory(directory: Path) -> None:
    try:
        details = directory.stat()
        if (
            not directory.is_absolute()
            or not directory.is_dir()
            or stat.S_IMODE(details.st_mode) & 0o077
            or any(directory.iterdir())
        ):
            raise ValueError
    except (OSError, ValueError) as exc:
        raise FixtureMaterialError("BP007 fixture material is unavailable.") from exc


def project_fixture_material(output_directory: Path, environment: Mapping[str, str]) -> None:
    _empty_owner_only_directory(output_directory)
    binding_path = Path(_required(environment, "CREDENTIAL_BINDINGS_FILE"))
    secret_env_path = Path(_required(environment, "SECRET_ENV_FILE"))
    binding_id = _required(environment, "CREDENTIAL_BINDING_ID")
    username_name, password_name = _binding_variables(binding_path, binding_id)
    username, password = _load_values(secret_env_path, username_name, password_name)
    created: list[Path] = []
    try:
        _write_once(output_directory, _NAMES["username"], username)
        created.append(output_directory / _NAMES["username"])
        _write_once(output_directory, _NAMES["password"], password)
        created.append(output_directory / _NAMES["password"])
    except FixtureMaterialError:
        for path in created:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        raise
    finally:
        username[:] = b"\x00" * len(username)
        password[:] = b"\x00" * len(password)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args()
    try:
        project_fixture_material(args.output_directory, os.environ)
    except FixtureMaterialError:
        raise SystemExit("BP007 fixture material is unavailable.") from None
    print('{"material_disclosed":false,"status":"ready"}')


if __name__ == "__main__":
    main()
