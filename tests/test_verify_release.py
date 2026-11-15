from __future__ import annotations

import hashlib
import inspect
import stat
import subprocess
from pathlib import Path
from zipfile import ZipFile

import pytest

import scripts.verify_release as verify_release

from scripts.verify_release import (
    BASE_REQUIRED_WHEEL_MEMBERS,
    REPRODUCIBLE_BUILD_EPOCH,
    inspect_wheel,
    ReleaseVerificationError,
    V3_FORBIDDEN_WHEEL_PREFIXES,
    V4_REQUIRED_WHEEL_MEMBERS,
    verify_manifest_wheel,
)


def test_failed_check_keeps_owner_only_captured_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    logs = tmp_path / "release-logs"

    def failed_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=("check",),
            returncode=7,
            stdout="diagnostic stdout",
            stderr="diagnostic stderr",
        )

    monkeypatch.setattr(verify_release.subprocess, "run", failed_run)

    with pytest.raises(
        ReleaseVerificationError,
        match="Release verification check 'pytest' failed with exit code 7.",
    ):
        verify_release._run(
            ("check",),
            cwd=tmp_path,
            name="pytest",
            log_directory=verify_release._prepare_log_directory(logs),
        )

    log = logs / "pytest.log"
    assert stat.S_IMODE(log.stat().st_mode) == 0o600
    assert log.read_text(encoding="utf-8") == (
        "[stdout]\ndiagnostic stdout\n[stderr]\ndiagnostic stderr"
    )


def test_hard_linked_check_log_rejection_preserves_existing_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    logs = verify_release._prepare_log_directory(tmp_path / "release-logs")
    log = logs / "pytest.log"
    log.write_text("preserved diagnostic", encoding="utf-8")
    linked_log = logs / "linked-pytest.log"
    linked_log.hardlink_to(log)

    def failed_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=("check",), returncode=7, stdout="new stdout", stderr="new stderr"
        )

    monkeypatch.setattr(verify_release.subprocess, "run", failed_run)

    with pytest.raises(ReleaseVerificationError, match="Release check log is unavailable."):
        verify_release._run(
            ("check",), cwd=tmp_path, name="pytest", log_directory=logs
        )

    assert log.read_text(encoding="utf-8") == "preserved diagnostic"
    assert linked_log.read_text(encoding="utf-8") == "preserved diagnostic"


def _wheel(path: Path, *, version: str, include_required: bool) -> Path:
    wheel = path / f"fortipam_mcp_server-{version}-py3-none-any.whl"
    with ZipFile(wheel, "w") as archive:
        if include_required:
            for member in BASE_REQUIRED_WHEEL_MEMBERS:
                archive.writestr(member, "test fixture")
            if version.startswith("4."):
                for member in V4_REQUIRED_WHEEL_MEMBERS:
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
    assert result["required_member_count"] == len(BASE_REQUIRED_WHEEL_MEMBERS)
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
        for member in BASE_REQUIRED_WHEEL_MEMBERS:
            archive.writestr(member, "test fixture")
        archive.writestr(
            "fortipam_mcp_server-1.2.3.dist-info/METADATA",
            "Version: 1.2.3\n",
        )

    with pytest.raises(ReleaseVerificationError, match="license"):
        inspect_wheel(wheel, "1.2.3")


@pytest.mark.parametrize("forbidden_prefix", V3_FORBIDDEN_WHEEL_PREFIXES)
def test_inspect_v3_wheel_rejects_v4_planning_members(
    tmp_path: Path,
    forbidden_prefix: str,
) -> None:
    wheel = _wheel(tmp_path, version="1.2.3", include_required=True)
    with ZipFile(wheel, "a") as archive:
        archive.writestr(f"{forbidden_prefix}engine.py", "forbidden")

    with pytest.raises(ReleaseVerificationError, match="must not enter"):
        inspect_wheel(wheel, "1.2.3")


def test_inspect_v4_wheel_requires_v4_runtime_members(tmp_path: Path) -> None:
    assert "v4_planning/approval.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "v4_planning/approver_authority.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "v4_planning/approver_checkpoint_authority.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "v4_planning/checkpoint_authority.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "approver_authorization_authority" in inspect.getsource(
        verify_release._smoke_installed_wheel
    )
    assert "v4_planning/execution_kernel.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "v4_planning/persistence.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "v4_planning/reference_authority.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "v4_planning/reference_checkpoint_authority.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "v4_planning/draft_authority.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "v4_planning/scheme_draft_checkpoint_authority.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/v4_runtime_host.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/planning_checkpoint_sidecar.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/approver_checkpoint_sidecar.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/approver_authority_sidecar.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/approval_receipt_sidecar.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/scheme_draft_authority_sidecar.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/scheme_draft_checkpoint_sidecar.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/reference_authority_sidecar.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/reference_checkpoint_sidecar.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/approver_delegation_bootstrap.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/scheme_draft_bootstrap.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/reference_grant_bootstrap.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/linux_onboarding_prepare.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/approval_workflow_prepare.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/folder_m4_adapter.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/folder_m4_authorization.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/m4_execution_store.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/folder_acl_revoke_live_workflow.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/folder_acl_revoke_mcp_action.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/folder_policy_assign_live_workflow.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/folder_policy_assign_mcp_action.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/folder_policy_detach_live_workflow.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/folder_policy_detach_mcp_action.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/address_group_ssh_transport.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/address_group_live_workflow.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert (
        "fortipam_mcp/address_group_delete_http_transport.py"
        in V4_REQUIRED_WHEEL_MEMBERS
    )
    assert (
        "fortipam_mcp/address_group_delete_live_workflow.py"
        in V4_REQUIRED_WHEEL_MEMBERS
    )
    assert "fortipam_mcp/address_delete_http_transport.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/address_delete_live_workflow.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/address_group_mcp_action.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/role_create_ssh_transport.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/role_create_live_workflow.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/role_create_mcp_action.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/role_update_live_workflow.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/role_update_mcp_action.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/role_assign_http_transport.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/role_assign_live_workflow.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/role_assign_mcp_action.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/launcher_ssh_transport.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/launcher_live_workflow.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/launcher_mcp_action.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/launcher_update_live_workflow.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/launcher_update_mcp_action.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/launcher_matcher_live_workflow.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/launcher_matcher_mcp_action.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/template_ssh_transport.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/template_live_workflow.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/template_mcp_action.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/secret_gateway_ssh_transport.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/secret_gateway_live_workflow.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/secret_gateway_mcp_action.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/client_integrity_ssh_transport.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/client_integrity_live_workflow.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/client_integrity_mcp_action.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/character_set_http_transport.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/character_set_live_workflow.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/character_set_mcp_action.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/password_policy_http_transport.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/password_policy_live_workflow.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/password_policy_delete_live_workflow.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/password_policy_mcp_action.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/automation_stitch_ssh_transport.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/automation_stitch_live_workflow.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/automation_stitch_delete_http_transport.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/automation_stitch_delete_live_workflow.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/automation_trigger_delete_http_transport.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/automation_trigger_delete_live_workflow.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/automation_action_delete_http_transport.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/automation_action_delete_live_workflow.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/automation_stitch_mcp_action.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/user_group_ssh_transport.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/user_group_live_workflow.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/user_group_mcp_action.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert (
        "fortipam_mcp/user_group_membership_live_workflow.py"
        in V4_REQUIRED_WHEEL_MEMBERS
    )
    assert (
        "fortipam_mcp/user_group_membership_mcp_action.py"
        in V4_REQUIRED_WHEEL_MEMBERS
    )
    assert "fortipam_mcp/apl_ssh_transport.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/apl_live_workflow.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/apl_mcp_action.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/apl_disable_live_workflow.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/apl_disable_mcp_action.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/schedule_ssh_transport.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/schedule_live_workflow.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/schedule_mcp_action.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert (
        "fortipam_mcp/ztna_access_proxy_client_certificate_ssh_transport.py"
        in V4_REQUIRED_WHEEL_MEMBERS
    )
    assert (
        "fortipam_mcp/ztna_access_proxy_client_certificate_live_workflow.py"
        in V4_REQUIRED_WHEEL_MEMBERS
    )
    assert (
        "fortipam_mcp/ztna_access_proxy_client_certificate_mcp_action.py"
        in V4_REQUIRED_WHEEL_MEMBERS
    )
    assert "fortipam_mcp/ztna_user_control_ssh_transport.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/ztna_user_control_live_workflow.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/ztna_user_control_mcp_action.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/snmp_agent_ssh_transport.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/snmp_agent_live_workflow.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/snmp_agent_mcp_action.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/logging_disk_ssh_transport.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/logging_disk_live_workflow.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/logging_disk_mcp_action.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/fortianalyzer_ssh_transport.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/fortianalyzer_live_workflow.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/fortianalyzer_mcp_action.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/maintenance_mode_ssh_transport.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/maintenance_mode_live_workflow.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/maintenance_mode_mcp_action.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/secret_audit_ssh_transport.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/secret_audit_live_workflow.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/secret_audit_mcp_action.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/local_user_reset_ssh_transport.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/local_user_reset_live_workflow.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/local_user_reset_mcp_action.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert (
        "fortipam_mcp/secret_policy_update_live_workflow.py"
        in V4_REQUIRED_WHEEL_MEMBERS
    )
    assert (
        "fortipam_mcp/ztna_device_context_diagnostic.py"
        in V4_REQUIRED_WHEEL_MEMBERS
    )
    assert (
        "fortipam_mcp/approval_email_template_update_live_workflow.py"
        in V4_REQUIRED_WHEEL_MEMBERS
    )
    assert (
        "fortipam_mcp/approval_email_template_delete_http_transport.py"
        in V4_REQUIRED_WHEEL_MEMBERS
    )
    assert (
        "fortipam_mcp/approval_profile_delete_http_transport.py"
        in V4_REQUIRED_WHEEL_MEMBERS
    )
    assert (
        "fortipam_mcp/approval_profile_delete_live_workflow.py"
        in V4_REQUIRED_WHEEL_MEMBERS
    )
    assert (
        "fortipam_mcp/approval_email_template_delete_live_workflow.py"
        in V4_REQUIRED_WHEEL_MEMBERS
    )
    assert (
        "fortipam_mcp/approval_email_template_update_mcp_action.py"
        in V4_REQUIRED_WHEEL_MEMBERS
    )
    assert "fortipam_mcp/classification_tag_assign_contract.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert (
        "fortipam_mcp/classification_tag_assign_live_workflow.py"
        in V4_REQUIRED_WHEEL_MEMBERS
    )
    assert (
        "fortipam_mcp/classification_tag_assign_mcp_action.py"
        in V4_REQUIRED_WHEEL_MEMBERS
    )
    assert (
        "fortipam_mcp/classification_tag_delete_http_transport.py"
        in V4_REQUIRED_WHEEL_MEMBERS
    )
    assert (
        "fortipam_mcp/classification_tag_delete_live_workflow.py"
        in V4_REQUIRED_WHEEL_MEMBERS
    )
    assert (
        "fortipam_mcp/classification_tag_reference_ssh_transport.py"
        in V4_REQUIRED_WHEEL_MEMBERS
    )
    assert "fortipam_mcp/target_reference_ssh_transport.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/target_delete_http_transport.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/target_delete_live_workflow.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert "fortipam_mcp/schedule_assign_contract.py" in V4_REQUIRED_WHEEL_MEMBERS
    assert (
        "fortipam_mcp/schedule_assign_http_transport.py"
        in V4_REQUIRED_WHEEL_MEMBERS
    )
    assert (
        "fortipam_mcp/schedule_assign_live_workflow.py"
        in V4_REQUIRED_WHEEL_MEMBERS
    )
    assert (
        "fortipam_mcp/schedule_assign_detach_live_workflow.py"
        in V4_REQUIRED_WHEEL_MEMBERS
    )
    assert (
        "fortipam_mcp/schedule_assign_mcp_action.py"
        in V4_REQUIRED_WHEEL_MEMBERS
    )
    assert (
        "fortipam_mcp/schedule_delete_http_transport.py"
        in V4_REQUIRED_WHEEL_MEMBERS
    )
    assert (
        "fortipam_mcp/schedule_delete_live_workflow.py"
        in V4_REQUIRED_WHEEL_MEMBERS
    )
    wheel = _wheel(tmp_path, version="4.0.0b3", include_required=True)

    assert inspect_wheel(wheel, "4.0.0b3")["required_member_count"] == len(
        BASE_REQUIRED_WHEEL_MEMBERS | V4_REQUIRED_WHEEL_MEMBERS
    )

    with ZipFile(wheel, "w") as archive:
        for member in BASE_REQUIRED_WHEEL_MEMBERS:
            archive.writestr(member, "test fixture")
        archive.writestr(
            "fortipam_mcp_server-4.0.0b3.dist-info/METADATA",
            "Version: 4.0.0b3\n",
        )
        archive.writestr(
            "fortipam_mcp_server-4.0.0b3.dist-info/licenses/LICENSE",
            "test license",
        )
    with pytest.raises(ReleaseVerificationError, match="missing required"):
        inspect_wheel(wheel, "4.0.0b3")


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
