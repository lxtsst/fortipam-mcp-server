#!/usr/bin/env python3
"""Run the deterministic FortiPAM MCP release verification suite."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from zipfile import ZipFile

from fortipam_mcp import __version__

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPRODUCIBLE_BUILD_EPOCH = "1735689600"
REQUIRED_WHEEL_MEMBERS = frozenset(
    {
        "fortipam_mcp/server.py",
        "fortipam_mcp/native_content.py",
        "fortipam_mcp/capabilities.py",
        "fortipam_mcp/baseline_drift.py",
        "fortipam_mcp/approval_service.py",
        "fortipam_mcp/controlled_operation_store.py",
        "fortipam_mcp/controlled_operations.py",
        "fortipam_mcp/evidence_correlation.py",
        "fortipam_mcp/diagnostic_authorization.py",
        "fortipam_mcp/diagnostic_profiles.py",
        "fortipam_mcp/diagnostic_service.py",
        "fortipam_mcp/diagnostic_store.py",
        "fortipam_mcp/http_server.py",
        "fortipam_mcp/local_oauth.py",
        "fortipam_mcp/http_smoke.py",
        "fortipam_mcp/config.py",
        "fortipam_mcp/cli_parsers.py",
        "fortipam_mcp/cli_identity.py",
        "fortipam_mcp/cli_safety.py",
        "fortipam_mcp/cli_tools.py",
        "fortipam_mcp/least_privilege.py",
        "fortipam_mcp/read_only.py",
        "fortipam_mcp/posture_contracts.py",
        "fortipam_mcp/data/fortipam_1_9_runtime_catalog.json",
        "fortipam_mcp/data/fortipam_1_9_scenarios.json",
    }
)
FORBIDDEN_WHEEL_PREFIXES = (
    "v4_planning/",
    "scripts/v4_planning",
)


class ReleaseVerificationError(RuntimeError):
    """Raised when a deterministic release check fails."""


@dataclass(frozen=True, slots=True)
class Check:
    """One project-owned deterministic verification command."""

    name: str
    command: tuple[str, ...]


def deterministic_checks(python: str) -> tuple[Check, ...]:
    """Return the stable local checks required before packaging."""

    return (
        Check(
            "repository_hygiene",
            (python, "scripts/check_repository_hygiene.py"),
        ),
        Check("pytest", (python, "-m", "pytest", "-q")),
        Check("mypy", (python, "-m", "mypy", "src", "scripts", "v4_planning")),
        Check(
            "scenario_catalog",
            (python, "-m", "fortipam_mcp.scenario_check"),
        ),
        Check(
            "v4_administrative_registry",
            (python, "scripts/validate_v4_registry.py"),
        ),
        Check(
            "scenario_routing",
            (python, "scripts/evaluate_scenario_routing.py"),
        ),
        Check("mcp_stdio", (python, "-m", "fortipam_mcp.mcp_smoke")),
        Check("mcp_http", (python, "-m", "fortipam_mcp.http_smoke")),
        Check("diff_format", ("git", "diff", "--check")),
    )


def inspect_wheel(path: Path, expected_version: str) -> dict[str, object]:
    """Validate required runtime members and return sanitized wheel metadata."""

    if not path.is_file():
        raise ReleaseVerificationError("The built wheel is unavailable.")
    with ZipFile(path) as archive:
        members = set(archive.namelist())
    missing = sorted(REQUIRED_WHEEL_MEMBERS - members)
    if missing:
        raise ReleaseVerificationError(
            "The built wheel is missing required FortiPAM runtime members."
        )
    if any(
        member.startswith(prefix)
        for member in members
        for prefix in FORBIDDEN_WHEEL_PREFIXES
    ):
        raise ReleaseVerificationError(
            "The V4 M2 planning model must not enter the released V3 wheel."
        )
    if not any(member.endswith(".dist-info/licenses/LICENSE") for member in members):
        raise ReleaseVerificationError(
            "The built wheel is missing the project license artifact."
        )
    expected_fragment = f"fortipam_mcp_server-{expected_version}.dist-info/"
    if not any(member.startswith(expected_fragment) for member in members):
        raise ReleaseVerificationError(
            "The built wheel version does not match the package version."
        )
    return {
        "filename": path.name,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "required_member_count": len(REQUIRED_WHEEL_MEMBERS),
        "license_included": True,
    }


def verify_manifest_wheel(
    manifest_path: Path,
    wheel: Path,
) -> dict[str, object]:
    """Require the current release manifest to match the built wheel bytes."""

    if not manifest_path.is_file() or not wheel.is_file():
        raise ReleaseVerificationError(
            "The wheelhouse manifest or current release wheel is unavailable."
        )
    entries: dict[str, str] = {}
    for raw_line in manifest_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            raise ReleaseVerificationError("The wheelhouse manifest is invalid.")
        digest, filename = parts
        entries[filename] = digest
    expected = entries.get(wheel.name)
    actual = hashlib.sha256(wheel.read_bytes()).hexdigest()
    if expected is None or expected != actual:
        raise ReleaseVerificationError(
            "The current release wheel does not match the wheelhouse manifest."
        )
    return {"filename": wheel.name, "sha256": actual, "matched": True}


def run_verification(*, keep_wheel: Path | None = None) -> dict[str, object]:
    """Run deterministic checks, build a wheel, and smoke-test its installation."""

    python = sys.executable
    checks = deterministic_checks(python)
    for check in checks:
        _run(check.command, cwd=PROJECT_ROOT, name=check.name)

    with tempfile.TemporaryDirectory(prefix="fortipam-mcp-release-") as temp_name:
        temp_root = Path(temp_name)
        wheel_dir = temp_root / "wheel"
        wheel_dir.mkdir()
        build_environment = dict(os.environ)
        build_environment["SOURCE_DATE_EPOCH"] = REPRODUCIBLE_BUILD_EPOCH
        _run(
            (
                python,
                "-m",
                "pip",
                "wheel",
                ".",
                "--no-deps",
                "--no-build-isolation",
                "--wheel-dir",
                str(wheel_dir),
            ),
            cwd=PROJECT_ROOT,
            name="wheel_build",
            environment=build_environment,
        )
        wheels = sorted(wheel_dir.glob("fortipam_mcp_server-*.whl"))
        if len(wheels) != 1:
            raise ReleaseVerificationError(
                "Release verification expected exactly one FortiPAM wheel."
            )
        wheel = wheels[0]
        wheel_metadata = inspect_wheel(wheel, __version__)
        manifest_metadata = verify_manifest_wheel(
            PROJECT_ROOT / "deploy/docker/wheelhouse-manifest.sha256",
            wheel,
        )
        _smoke_installed_wheel(python, wheel, temp_root)
        if keep_wheel is not None:
            keep_wheel.mkdir(parents=True, exist_ok=True)
            destination = keep_wheel / wheel.name
            destination.write_bytes(wheel.read_bytes())

    return {
        "status": "passed",
        "version": __version__,
        "deterministic_check_count": len(checks),
        "wheel": wheel_metadata,
        "wheelhouse_manifest": manifest_metadata,
        "installed_wheel_smoke": "passed",
        "network_device_contacted": False,
    }


def _smoke_installed_wheel(python: str, wheel: Path, temp_root: Path) -> None:
    install_root = temp_root / "installed"
    _run(
        (
            python,
            "-m",
            "pip",
            "install",
            "--no-deps",
            "--target",
            str(install_root),
            str(wheel),
        ),
        cwd=temp_root,
        name="wheel_install",
    )
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(install_root)
    environment["PYTHONNOUSERSITE"] = "1"
    import_check = (
        "from pathlib import Path; "
        "import fortipam_mcp; "
        "from fortipam_mcp.catalog import RuntimeCatalog; "
        "from fortipam_mcp.scenario_catalog import ScenarioCatalog; "
        f"root=Path({str(install_root)!r}).resolve(); "
        "module=Path(fortipam_mcp.__file__).resolve(); "
        "assert module.is_relative_to(root); "
        f"assert fortipam_mcp.__version__ == {__version__!r}; "
        "assert len(RuntimeCatalog.load().operations) == 1295; "
        "assert len(ScenarioCatalog.load().scenarios) == 19"
    )
    _run(
        (python, "-c", import_check),
        cwd=temp_root,
        name="installed_import",
        environment=environment,
    )
    _run(
        (python, "-m", "fortipam_mcp.mcp_smoke"),
        cwd=temp_root,
        name="installed_mcp_stdio",
        environment=environment,
    )


def _run(
    command: tuple[str, ...],
    *,
    cwd: Path,
    name: str,
    environment: dict[str, str] | None = None,
) -> None:
    result = subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise ReleaseVerificationError(
            f"Release verification check '{name}' failed with exit code "
            f"{result.returncode}."
        )


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Verify the local FortiPAM MCP release."
    )
    parser.add_argument(
        "--keep-wheel",
        type=Path,
        help="Optional directory for the verified wheel.",
    )
    args = parser.parse_args(argv)
    try:
        result = run_verification(keep_wheel=args.keep_wheel)
    except ReleaseVerificationError as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
