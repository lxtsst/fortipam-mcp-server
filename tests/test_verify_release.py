from __future__ import annotations

import hashlib
from pathlib import Path
from zipfile import ZipFile

import pytest

from scripts.verify_release import (
    FORBIDDEN_WHEEL_PREFIXES,
    REPRODUCIBLE_BUILD_EPOCH,
    inspect_wheel,
    REQUIRED_WHEEL_MEMBERS,
    ReleaseVerificationError,
    verify_manifest_wheel,
)


def _wheel(path: Path, *, version: str, include_required: bool) -> Path:
    wheel = path / f"fortipam_mcp_server-{version}-py3-none-any.whl"
    with ZipFile(wheel, "w") as archive:
        if include_required:
            for member in REQUIRED_WHEEL_MEMBERS:
                archive.writestr(member, "test fixture")
        archive.writestr(
            f"fortipam_mcp_server-{version}.dist-info/METADATA",
            f"Version: {version}\n",
        )
        archive.writestr(
            f"fortipam_mcp_server-{version}.dist-info/licenses/LICENSE",
            "test license",
        )
    return wheel


def test_inspect_wheel_accepts_required_runtime_members(tmp_path: Path) -> None:
    wheel = _wheel(tmp_path, version="1.2.3", include_required=True)

    result = inspect_wheel(wheel, "1.2.3")

    assert result["filename"] == wheel.name
    assert result["required_member_count"] == len(REQUIRED_WHEEL_MEMBERS)
    assert result["license_included"] is True
    assert len(result["sha256"]) == 64


def test_release_build_uses_a_stable_zip_compatible_epoch() -> None:
    assert REPRODUCIBLE_BUILD_EPOCH == "1735689600"


def test_inspect_wheel_rejects_missing_runtime_members(tmp_path: Path) -> None:
    wheel = _wheel(tmp_path, version="1.2.3", include_required=False)

    with pytest.raises(ReleaseVerificationError, match="missing required"):
        inspect_wheel(wheel, "1.2.3")


def test_inspect_wheel_rejects_version_mismatch(tmp_path: Path) -> None:
    wheel = _wheel(tmp_path, version="1.2.3", include_required=True)

    with pytest.raises(ReleaseVerificationError, match="version"):
        inspect_wheel(wheel, "9.9.9")


def test_inspect_wheel_rejects_missing_license(tmp_path: Path) -> None:
    wheel = _wheel(tmp_path, version="1.2.3", include_required=True)
    with ZipFile(wheel, "w") as archive:
        for member in REQUIRED_WHEEL_MEMBERS:
            archive.writestr(member, "test fixture")
        archive.writestr(
            "fortipam_mcp_server-1.2.3.dist-info/METADATA",
            "Version: 1.2.3\n",
        )

    with pytest.raises(ReleaseVerificationError, match="license"):
        inspect_wheel(wheel, "1.2.3")


@pytest.mark.parametrize("forbidden_prefix", FORBIDDEN_WHEEL_PREFIXES)
def test_inspect_wheel_rejects_repository_only_v4_planning_members(
    tmp_path: Path,
    forbidden_prefix: str,
) -> None:
    wheel = _wheel(tmp_path, version="1.2.3", include_required=True)
    with ZipFile(wheel, "a") as archive:
        archive.writestr(f"{forbidden_prefix}engine.py", "forbidden")

    with pytest.raises(ReleaseVerificationError, match="must not enter"):
        inspect_wheel(wheel, "1.2.3")


def test_verify_manifest_wheel_requires_existing_matching_bytes(
    tmp_path: Path,
) -> None:
    wheel = _wheel(tmp_path, version="1.2.3", include_required=True)
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    manifest = tmp_path / "manifest.sha256"
    manifest.write_text(f"{digest}  {wheel.name}\n", encoding="utf-8")

    assert verify_manifest_wheel(manifest, wheel)["matched"] is True

    manifest.write_text(f"{'0' * 64}  {wheel.name}\n", encoding="utf-8")
    with pytest.raises(ReleaseVerificationError, match="does not match"):
        verify_manifest_wheel(manifest, wheel)
