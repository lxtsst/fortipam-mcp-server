"""Operator-controlled environment loading without secret disclosure."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import stat

DEVICE_PREFIX = "FPA_HOME_LAB_FPA1"
ENV_FILE_VARIABLE = f"{DEVICE_PREFIX}_ENV_FILE"
_ENV_ASSIGNMENT = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")


@dataclass(frozen=True, slots=True)
class EnvironmentLoadReport:
    """Sanitized report about runtime environment loading."""

    source: str
    loaded: bool


class EnvironmentFileError(PermissionError):
    """Raised when a credential file is not protected as local owner-only state."""


def project_root() -> Path:
    """Return the project root without relying on the caller's working directory."""

    return Path(__file__).resolve().parents[2]


def load_runtime_environment() -> EnvironmentLoadReport:
    """Load an explicit owner-only environment file or a project-local file.

    Explicit process environment values always win. Neither paths nor values are
    returned, logged, or placed in MCP results.
    """

    configured = os.environ.get(ENV_FILE_VARIABLE)
    candidates: list[tuple[str, Path]] = []
    if configured:
        candidates.append(("operator_env_file", Path(configured).expanduser()))
    candidates.append(("project_local_env_file", project_root() / ".env.local"))

    for source, path in candidates:
        if path.is_file():
            load_prefixed_environment_file(path, f"{DEVICE_PREFIX}_")
            return EnvironmentLoadReport(source=source, loaded=True)
    return EnvironmentLoadReport(source="process_environment_only", loaded=False)


def load_prefixed_environment_file(
    path: Path,
    prefix: str,
    *,
    overwrite: bool = False,
    required_keys: tuple[str, ...] = (),
) -> int:
    """Load one owner-only dotenv file without executing it.

    Only keys with the requested prefix are imported. Existing process values
    win by default; credential-consuming entrypoints may explicitly make their
    owner-only input file authoritative with ``overwrite=True``. The return
    value is a count, never a key, path, or secret value. Required keys must
    exist in the selected file itself before any process values are changed.
    """

    _assert_owner_only(path)
    values = _parse_env_file(path)
    if any(not key.startswith(prefix) or not values.get(key) for key in required_keys):
        raise EnvironmentFileError(
            "Required credential fields are missing from the selected file."
        )
    loaded = 0
    for key, value in values.items():
        if key.startswith(prefix) and (overwrite or key not in os.environ):
            os.environ[key] = value
            loaded += 1
    return loaded


def _parse_env_file(path: Path) -> dict[str, str]:
    """Parse a minimal dotenv file without executing shell syntax."""

    parsed: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line.removeprefix("export ").lstrip()
        match = _ENV_ASSIGNMENT.match(line)
        if not match:
            continue
        key, raw_value = match.groups()
        value = raw_value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        parsed[key] = value
    return parsed


def _assert_owner_only(path: Path) -> None:
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise EnvironmentFileError(
            "FortiPAM credential files must not be accessible to group or other users."
        )
