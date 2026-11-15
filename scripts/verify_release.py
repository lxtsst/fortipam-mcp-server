#!/usr/bin/env python3
"""Run the deterministic FortiPAM MCP release verification suite."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from zipfile import ZipFile

from fortipam_mcp import __version__

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPRODUCIBLE_BUILD_EPOCH = "1735689600"
BASE_REQUIRED_WHEEL_MEMBERS = frozenset(
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
        "fortipam_mcp/data/v3_action_packages.json",
    }
)
V4_REQUIRED_WHEEL_MEMBERS = frozenset(
    {
        "fortipam_mcp/ha_reconciliation.py",
        "fortipam_mcp/address_http_transport.py",
        "fortipam_mcp/address_live_workflow.py",
        "fortipam_mcp/address_mcp_action.py",
        "fortipam_mcp/address_group_ssh_transport.py",
        "fortipam_mcp/address_group_live_workflow.py",
        "fortipam_mcp/address_group_delete_http_transport.py",
        "fortipam_mcp/address_group_delete_live_workflow.py",
        "fortipam_mcp/address_delete_http_transport.py",
        "fortipam_mcp/address_delete_live_workflow.py",
        "fortipam_mcp/address_group_mcp_action.py",
        "fortipam_mcp/folder_action_readiness.py",
        "fortipam_mcp/folder_acl_live_workflow.py",
        "fortipam_mcp/folder_acl_mcp_action.py",
        "fortipam_mcp/folder_acl_revoke_live_workflow.py",
        "fortipam_mcp/folder_acl_revoke_mcp_action.py",
        "fortipam_mcp/folder_rename_live_workflow.py",
        "fortipam_mcp/folder_rename_mcp_action.py",
        "fortipam_mcp/folder_policy_assign_live_workflow.py",
        "fortipam_mcp/folder_policy_assign_mcp_action.py",
        "fortipam_mcp/folder_policy_detach_live_workflow.py",
        "fortipam_mcp/folder_policy_detach_mcp_action.py",
        "fortipam_mcp/local_user_reset_ssh_transport.py",
        "fortipam_mcp/local_user_reset_live_workflow.py",
        "fortipam_mcp/local_user_reset_mcp_action.py",
        "fortipam_mcp/role_create_ssh_transport.py",
        "fortipam_mcp/role_create_live_workflow.py",
        "fortipam_mcp/role_create_mcp_action.py",
        "fortipam_mcp/role_update_live_workflow.py",
        "fortipam_mcp/role_update_mcp_action.py",
        "fortipam_mcp/role_assign_http_transport.py",
        "fortipam_mcp/role_assign_live_workflow.py",
        "fortipam_mcp/role_assign_mcp_action.py",
        "fortipam_mcp/dlp_file_pattern_ssh_transport.py",
        "fortipam_mcp/dlp_file_pattern_live_workflow.py",
        "fortipam_mcp/dlp_file_pattern_delete_http_transport.py",
        "fortipam_mcp/dlp_file_pattern_delete_live_workflow.py",
        "fortipam_mcp/dlp_file_pattern_mcp_action.py",
        "fortipam_mcp/dlp_sensor_ssh_transport.py",
        "fortipam_mcp/dlp_sensor_live_workflow.py",
        "fortipam_mcp/dlp_sensor_delete_http_transport.py",
        "fortipam_mcp/dlp_sensor_delete_live_workflow.py",
        "fortipam_mcp/dlp_sensor_mcp_action.py",
        "fortipam_mcp/antivirus_profile_ssh_transport.py",
        "fortipam_mcp/antivirus_profile_live_workflow.py",
        "fortipam_mcp/antivirus_profile_delete_http_transport.py",
        "fortipam_mcp/antivirus_profile_delete_live_workflow.py",
        "fortipam_mcp/antivirus_profile_mcp_action.py",
        "fortipam_mcp/rdp_event_filter_ssh_transport.py",
        "fortipam_mcp/rdp_event_filter_live_workflow.py",
        "fortipam_mcp/rdp_event_filter_delete_http_transport.py",
        "fortipam_mcp/rdp_event_filter_delete_live_workflow.py",
        "fortipam_mcp/rdp_event_filter_mcp_action.py",
        "fortipam_mcp/secret_policy_ssh_transport.py",
        "fortipam_mcp/secret_policy_live_workflow.py",
        "fortipam_mcp/secret_policy_update_live_workflow.py",
        "fortipam_mcp/secret_policy_mcp_action.py",
        "fortipam_mcp/ztna_device_context_diagnostic.py",
        "fortipam_mcp/ssh_filter_ssh_transport.py",
        "fortipam_mcp/ssh_filter_live_workflow.py",
        "fortipam_mcp/ssh_filter_delete_http_transport.py",
        "fortipam_mcp/ssh_filter_delete_live_workflow.py",
        "fortipam_mcp/ssh_filter_mcp_action.py",
        "fortipam_mcp/launcher_ssh_transport.py",
        "fortipam_mcp/launcher_live_workflow.py",
        "fortipam_mcp/launcher_mcp_action.py",
        "fortipam_mcp/launcher_update_live_workflow.py",
        "fortipam_mcp/launcher_update_mcp_action.py",
        "fortipam_mcp/launcher_matcher_live_workflow.py",
        "fortipam_mcp/launcher_matcher_mcp_action.py",
        "fortipam_mcp/template_ssh_transport.py",
        "fortipam_mcp/template_live_workflow.py",
        "fortipam_mcp/template_mcp_action.py",
        "fortipam_mcp/dependency_updater_ssh_transport.py",
        "fortipam_mcp/dependency_updater_live_workflow.py",
        "fortipam_mcp/dependency_updater_mcp_action.py",
        "fortipam_mcp/secret_gateway_ssh_transport.py",
        "fortipam_mcp/secret_gateway_live_workflow.py",
        "fortipam_mcp/secret_gateway_mcp_action.py",
        "fortipam_mcp/client_integrity_ssh_transport.py",
        "fortipam_mcp/client_integrity_live_workflow.py",
        "fortipam_mcp/client_integrity_mcp_action.py",
        "fortipam_mcp/character_set_http_transport.py",
        "fortipam_mcp/character_set_live_workflow.py",
        "fortipam_mcp/character_set_delete_live_workflow.py",
        "fortipam_mcp/character_set_mcp_action.py",
        "fortipam_mcp/windows_app_filter_delete_live_workflow.py",
        "fortipam_mcp/password_policy_http_transport.py",
        "fortipam_mcp/password_policy_live_workflow.py",
        "fortipam_mcp/password_policy_delete_live_workflow.py",
        "fortipam_mcp/password_policy_mcp_action.py",
        "fortipam_mcp/ztna_access_proxy_client_certificate_ssh_transport.py",
        "fortipam_mcp/ztna_access_proxy_client_certificate_live_workflow.py",
        "fortipam_mcp/ztna_access_proxy_client_certificate_mcp_action.py",
        "fortipam_mcp/ztna_user_control_ssh_transport.py",
        "fortipam_mcp/ztna_user_control_live_workflow.py",
        "fortipam_mcp/ztna_user_control_mcp_action.py",
        "fortipam_mcp/snmp_agent_ssh_transport.py",
        "fortipam_mcp/snmp_agent_status_http_transport.py",
        "fortipam_mcp/snmp_agent_live_workflow.py",
        "fortipam_mcp/snmp_agent_mcp_action.py",
        "fortipam_mcp/logging_disk_ssh_transport.py",
        "fortipam_mcp/logging_disk_live_workflow.py",
        "fortipam_mcp/logging_disk_mcp_action.py",
        "fortipam_mcp/fortianalyzer_ssh_transport.py",
        "fortipam_mcp/fortianalyzer_live_workflow.py",
        "fortipam_mcp/fortianalyzer_mcp_action.py",
        "fortipam_mcp/maintenance_mode_ssh_transport.py",
        "fortipam_mcp/maintenance_mode_status_http_transport.py",
        "fortipam_mcp/maintenance_mode_live_workflow.py",
        "fortipam_mcp/maintenance_mode_mcp_action.py",
        "fortipam_mcp/secret_audit_ssh_transport.py",
        "fortipam_mcp/secret_audit_live_workflow.py",
        "fortipam_mcp/secret_audit_mcp_action.py",
        "fortipam_mcp/automation_trigger_ssh_transport.py",
        "fortipam_mcp/automation_trigger_live_workflow.py",
        "fortipam_mcp/automation_trigger_mcp_action.py",
        "fortipam_mcp/automation_action_ssh_transport.py",
        "fortipam_mcp/automation_action_live_workflow.py",
        "fortipam_mcp/automation_action_mcp_action.py",
        "fortipam_mcp/automation_stitch_ssh_transport.py",
        "fortipam_mcp/automation_stitch_live_workflow.py",
        "fortipam_mcp/automation_stitch_delete_http_transport.py",
        "fortipam_mcp/automation_stitch_delete_live_workflow.py",
        "fortipam_mcp/automation_trigger_delete_http_transport.py",
        "fortipam_mcp/automation_trigger_delete_live_workflow.py",
        "fortipam_mcp/automation_action_delete_http_transport.py",
        "fortipam_mcp/automation_action_delete_live_workflow.py",
        "fortipam_mcp/automation_stitch_mcp_action.py",
        "fortipam_mcp/user_group_ssh_transport.py",
        "fortipam_mcp/user_group_live_workflow.py",
        "fortipam_mcp/user_group_mcp_action.py",
        "fortipam_mcp/user_group_membership_live_workflow.py",
        "fortipam_mcp/user_group_membership_mcp_action.py",
        "fortipam_mcp/apl_ssh_transport.py",
        "fortipam_mcp/apl_live_workflow.py",
        "fortipam_mcp/apl_mcp_action.py",
        "fortipam_mcp/apl_disable_live_workflow.py",
        "fortipam_mcp/apl_disable_mcp_action.py",
        "fortipam_mcp/schedule_ssh_transport.py",
        "fortipam_mcp/schedule_live_workflow.py",
        "fortipam_mcp/schedule_mcp_action.py",
        "fortipam_mcp/schedule_delete_http_transport.py",
        "fortipam_mcp/schedule_delete_live_workflow.py",
        "fortipam_mcp/approval_profile_ssh_transport.py",
        "fortipam_mcp/approval_profile_live_workflow.py",
        "fortipam_mcp/approval_profile_mcp_action.py",
        "fortipam_mcp/approval_profile_update_live_workflow.py",
        "fortipam_mcp/approval_profile_update_mcp_action.py",
        "fortipam_mcp/approval_profile_delete_http_transport.py",
        "fortipam_mcp/approval_profile_delete_live_workflow.py",
        "fortipam_mcp/approval_email_template_ssh_transport.py",
        "fortipam_mcp/approval_email_template_live_workflow.py",
        "fortipam_mcp/approval_email_template_mcp_action.py",
        "fortipam_mcp/approval_email_template_update_live_workflow.py",
        "fortipam_mcp/approval_email_template_delete_http_transport.py",
        "fortipam_mcp/approval_email_template_delete_live_workflow.py",
        "fortipam_mcp/approval_email_template_update_mcp_action.py",
        "fortipam_mcp/folder_create_contract.py",
        "fortipam_mcp/folder_http_transport.py",
        "fortipam_mcp/folder_mcp_action.py",
        "fortipam_mcp/folder_m4_adapter.py",
        "fortipam_mcp/folder_m4_authorization.py",
        "fortipam_mcp/folder_m4_runtime.py",
        "fortipam_mcp/m4_execution_store.py",
        "fortipam_mcp/target_contract.py",
        "fortipam_mcp/target_http_transport.py",
        "fortipam_mcp/classification_tag_assign_contract.py",
        "fortipam_mcp/classification_tag_assign_live_workflow.py",
        "fortipam_mcp/classification_tag_assign_mcp_action.py",
        "fortipam_mcp/classification_tag_delete_http_transport.py",
        "fortipam_mcp/classification_tag_delete_live_workflow.py",
        "fortipam_mcp/classification_tag_reference_ssh_transport.py",
        "fortipam_mcp/schedule_assign_contract.py",
        "fortipam_mcp/schedule_assign_http_transport.py",
        "fortipam_mcp/schedule_assign_detach_live_workflow.py",
        "fortipam_mcp/schedule_assign_live_workflow.py",
        "fortipam_mcp/schedule_assign_mcp_action.py",
        "fortipam_mcp/target_live_workflow.py",
        "fortipam_mcp/target_mcp_action.py",
        "fortipam_mcp/target_reference_ssh_transport.py",
        "fortipam_mcp/target_delete_http_transport.py",
        "fortipam_mcp/target_delete_live_workflow.py",
        "fortipam_mcp/v4_plan_runtime.py",
        "fortipam_mcp/v4_confirmation_http.py",
        "fortipam_mcp/planning_checkpoint_sidecar.py",
        "fortipam_mcp/approver_checkpoint_sidecar.py",
        "fortipam_mcp/approver_authority_sidecar.py",
        "fortipam_mcp/approval_receipt_sidecar.py",
        "fortipam_mcp/scheme_draft_authority_sidecar.py",
        "fortipam_mcp/scheme_draft_checkpoint_sidecar.py",
        "fortipam_mcp/reference_authority_sidecar.py",
        "fortipam_mcp/reference_checkpoint_sidecar.py",
        "fortipam_mcp/secret_create_runtime_sidecar.py",
        "fortipam_mcp/secret_create_readiness_sidecar.py",
        "fortipam_mcp/material_checkpoint_sidecar.py",
        "fortipam_mcp/approver_delegation_bootstrap.py",
        "fortipam_mcp/scheme_draft_bootstrap.py",
        "fortipam_mcp/reference_grant_bootstrap.py",
        "fortipam_mcp/linux_onboarding_prepare.py",
        "fortipam_mcp/approval_workflow_prepare.py",
        "fortipam_mcp/firmware_upgrade_plan.py",
        "fortipam_mcp/backup_restore_plan.py",
        "fortipam_mcp/license_install_plan.py",
        "fortipam_mcp/email_configuration_plan.py",
        "fortipam_mcp/glass_break_plan.py",
        "fortipam_mcp/network_configuration_plan.py",
        "fortipam_mcp/ha_configuration_plan.py",
        "fortipam_mcp/certificate_import_plan.py",
        "fortipam_mcp/identity_server_plan.py",
        "fortipam_mcp/jwt_key_plan.py",
        "fortipam_mcp/scim_client_plan.py",
        "fortipam_mcp/fortitoken_plan.py",
        "fortipam_mcp/apl_update_plan.py",
        "fortipam_mcp/discovery_job_plan.py",
        "fortipam_mcp/password_lifecycle_plan.py",
        "fortipam_mcp/secret_experience_plan.py",
        "fortipam_mcp/secret_onboarding_plan.py",
        "fortipam_mcp/integration_change_plan.py",
        "fortipam_mcp/lifecycle_gap_plan.py",
        "fortipam_mcp/v4_runtime_host.py",
        "v4_planning/approval.py",
        "v4_planning/approver_authority.py",
        "v4_planning/approver_checkpoint_authority.py",
        "v4_planning/adapter_registry.py",
        "v4_planning/checkpoint_authority.py",
        "v4_planning/confirmation.py",
        "v4_planning/confirmation_persistence.py",
        "v4_planning/draft_authority.py",
        "v4_planning/scheme_draft_checkpoint_authority.py",
        "v4_planning/execution_kernel.py",
        "v4_planning/execution_runtime.py",
        "v4_planning/engine.py",
        "v4_planning/mcp_facade.py",
        "v4_planning/material_provider.py",
        "v4_planning/material_runtime.py",
        "v4_planning/material_persistence.py",
        "v4_planning/material_checkpoint_authority.py",
        "v4_planning/models.py",
        "v4_planning/persistence.py",
        "v4_planning/reference_authority.py",
        "v4_planning/reference_checkpoint_authority.py",
        "v4_planning/secret_create_adapter.py",
        "v4_planning/secret_create_runtime.py",
        "v4_planning/workflow_service.py",
    }
)
V3_FORBIDDEN_WHEEL_PREFIXES = (
    "v4_planning/",
    "scripts/v4_planning",
)
_CHECK_LOG_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


class ReleaseVerificationError(RuntimeError):
    """Raised when a deterministic release check fails."""


@dataclass(frozen=True, slots=True)
class Check:
    """One project-owned deterministic verification command."""

    name: str
    command: tuple[str, ...]


def deterministic_checks(python: str) -> tuple[Check, ...]:
    """Return the stable local checks required before packaging."""

    mypy_cache = str(Path(tempfile.gettempdir()) / "fortipam-mcp-mypy-release")
    return (
        Check(
            "repository_hygiene",
            (python, "scripts/check_repository_hygiene.py"),
        ),
        Check(
            "pytest",
            (python, "-m", "pytest", "-p", "no:cacheprovider", "-q"),
        ),
        Check(
            "mypy",
            (
                python,
                "-m",
                "mypy",
                "--cache-dir",
                mypy_cache,
                "src",
                "scripts",
                "v4_planning",
            ),
        ),
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
    required_members = BASE_REQUIRED_WHEEL_MEMBERS
    if expected_version.startswith("4."):
        required_members |= V4_REQUIRED_WHEEL_MEMBERS
    missing = sorted(required_members - members)
    if missing:
        raise ReleaseVerificationError(
            "The built wheel is missing required FortiPAM runtime members."
        )
    if not expected_version.startswith("4.") and any(
        member.startswith(prefix)
        for member in members
        for prefix in V3_FORBIDDEN_WHEEL_PREFIXES
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
        "required_member_count": len(required_members),
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


def run_verification(
    *,
    keep_wheel: Path | None = None,
    log_directory: Path | None = None,
) -> dict[str, object]:
    """Run deterministic checks, build a wheel, and smoke-test its installation."""

    python = sys.executable
    checks = deterministic_checks(python)
    selected_log_directory = (
        _prepare_log_directory(log_directory) if log_directory is not None else None
    )
    for check in checks:
        _run(
            check.command,
            cwd=PROJECT_ROOT,
            name=check.name,
            log_directory=selected_log_directory,
        )

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
            log_directory=selected_log_directory,
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
        _smoke_installed_wheel(
            python, wheel, temp_root, log_directory=selected_log_directory
        )
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


def _smoke_installed_wheel(
    python: str,
    wheel: Path,
    temp_root: Path,
    *,
    log_directory: Path | None = None,
) -> None:
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
        log_directory=log_directory,
    )
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(install_root)
    environment["PYTHONNOUSERSITE"] = "1"
    import_check = (
        "from pathlib import Path; "
        "import inspect; "
        "import fortipam_mcp; "
        "import v4_planning; "
        "from fortipam_mcp.action_packages import get_action_package; "
        "from fortipam_mcp.catalog import RuntimeCatalog; "
        "from fortipam_mcp.scenario_catalog import ScenarioCatalog; "
        "from fortipam_mcp.folder_m4_runtime import ProtectedChildFolderM4Runtime; "
        "from fortipam_mcp.folder_m4_authorization import "
        "FolderM4AuthorizationStoreTail, "
        "MonotonicFolderM4AuthorizationCheckpoint, "
        "PersistentFolderM4AuthorizationStore; "
        "from fortipam_mcp.m4_execution_store import M4ExecutionStoreTail, "
        "MonotonicM4ExecutionCheckpoint, PersistentM4ExecutionStateStore; "
        "from fortipam_mcp.v4_runtime_host import "
        "V4PersistentReferenceAuthoritySettings, "
        "V4UnixSecretCreateRuntimeSettings; "
        "from fortipam_mcp.v4_runtime_host import synthetic_v4_plan_host_factory; "
        "from fortipam_mcp.planning_checkpoint_sidecar import "
        "UnixPlanningCheckpointClient; "
        "from fortipam_mcp.approver_checkpoint_sidecar import "
        "UnixApproverCheckpointClient; "
        "from fortipam_mcp.approver_authority_sidecar import "
        "UnixApproverAuthorizationClient; "
        "from fortipam_mcp.approval_receipt_sidecar import "
        "UnixApprovalReceiptAuthenticator; "
        "from fortipam_mcp.scheme_draft_authority_sidecar import "
        "UnixSchemeDraftAuthorityClient; "
        "from fortipam_mcp.scheme_draft_checkpoint_sidecar import "
        "UnixSchemeDraftCheckpointClient; "
        "from fortipam_mcp.reference_authority_sidecar import "
        "UnixReferenceAuthorityClient; "
        "from fortipam_mcp.reference_checkpoint_sidecar import "
        "UnixReferenceCheckpointClient; "
        "from fortipam_mcp.secret_create_runtime_sidecar import "
        "UnixSecretCreateRuntimeClient, UnixSecretCreateRuntimeReadinessProbe; "
        "from fortipam_mcp.secret_create_readiness_sidecar import "
        "SecretCreateReadinessSidecarSettings, "
        "UnixSecretCreateReadinessProxyClient; "
        "from fortipam_mcp.material_checkpoint_sidecar import "
        "UnixMaterialCheckpointClient; "
        "from fortipam_mcp.approver_delegation_bootstrap import "
        "ApproverDelegationBootstrapSettings; "
        "from fortipam_mcp.scheme_draft_bootstrap import "
        "SchemeDraftBootstrapSettings; "
        "from fortipam_mcp.reference_grant_bootstrap import "
        "ReferenceGrantBootstrapSettings; "
        "from fortipam_mcp.linux_onboarding_prepare import "
        "LinuxOnboardingPrepareSettings; "
        "from fortipam_mcp.v4_plan_runtime import approver_from_access_token, "
        "unbound_v4_plan_status; "
        "from v4_planning import ApprovalReceiptAuthenticator, "
        "ApproverAuthorizationAuthority, ApproverAuthorizationDecision, "
        "ApproverAuthorityStoreTail, "
        "C3MaterialBinding, DenyAllMaterialProvider, EmptyM4AdapterRegistry, "
        "MaterialBindingStatus, "
        "MaterialLeaseCoordinator, MaterialLeaseRequest, MaterialProviderClass, "
        "MaterialPurpose, MaterialRuntimeOutcome, MaterialUseClaimState, "
        "MaterialUseOutcome, MaterialUseStoreTail, "
        "PersistentMaterialUseStateStore, "
        "PersistentMaterialUseCheckpointAuthority, "
        "PackagedDenyAllSecretCreateMaterialRuntime, "
        "PackagedDenyAllM4ExecutionRuntime, "
        "PersistentApproverAuthorizationAuthority, "
        "PersistentApproverCheckpointAuthority, PersistentReferenceAuthority, "
        "PersistentReferenceCheckpointAuthority, "
        "ReferenceAuthorityStoreTail, "
        "PersistentPlanningCheckpointAuthority, PersistentSchemeDraftAuthority, "
        "PersistentSchemeDraftCheckpointAuthority, SchemeDraftAuthorityStoreTail, "
        "PlanningStoreTail, SecretCreateContractStatus, "
        "secret_create_source_contract; "
        f"root=Path({str(install_root)!r}).resolve(); "
        "module=Path(fortipam_mcp.__file__).resolve(); "
        "assert module.is_relative_to(root); "
        f"assert fortipam_mcp.__version__ == {__version__!r}; "
        "assert PersistentReferenceAuthority.__module__ == "
        "'v4_planning.reference_authority'; "
        "assert PersistentReferenceCheckpointAuthority.__module__ == "
        "'v4_planning.reference_checkpoint_authority'; "
        "assert ReferenceAuthorityStoreTail.empty('reference-store-smoke')"
        ".sequence == 0; "
        "assert isinstance(PersistentReferenceAuthority."
        "monotonic_checkpoint_protocol_bound, property); "
        "assert PersistentSchemeDraftAuthority.__module__ == "
        "'v4_planning.draft_authority'; "
        "assert PersistentSchemeDraftCheckpointAuthority.__module__ == "
        "'v4_planning.scheme_draft_checkpoint_authority'; "
        "assert SchemeDraftAuthorityStoreTail.empty('draft-store-smoke')"
        ".sequence == 0; "
        "assert isinstance(PersistentSchemeDraftAuthority."
        "monotonic_checkpoint_protocol_bound, property); "
        "assert callable(PersistentSchemeDraftAuthority.issue_for_requester_digest); "
        "assert callable(v4_planning.scheme_draft_from_mapping); "
        "assert PersistentPlanningCheckpointAuthority.__module__ == "
        "'v4_planning.checkpoint_authority'; "
        "assert PlanningStoreTail.__module__ == 'v4_planning.persistence'; "
        "assert ApprovalReceiptAuthenticator.__module__ == "
        "'v4_planning.approval'; "
        "assert ApproverAuthorizationAuthority.__module__ == "
        "'v4_planning.approval'; "
        "assert ApproverAuthorizationDecision.__module__ == "
        "'v4_planning.approval'; "
        "assert PersistentApproverAuthorizationAuthority.__module__ == "
        "'v4_planning.approver_authority'; "
        "assert ApproverAuthorityStoreTail.empty('approver-store-smoke')"
        ".sequence == 0; "
        "assert isinstance(PersistentApproverAuthorizationAuthority."
        "monotonic_checkpoint_protocol_bound, property); "
        "assert callable(PersistentApproverAuthorizationAuthority.verify_ready); "
        "assert PersistentApproverCheckpointAuthority.__module__ == "
        "'v4_planning.approver_checkpoint_authority'; "
        "assert callable(PersistentApproverCheckpointAuthority.verify_ready); "
        "assert unbound_v4_plan_status()"
        "['approver_authority_checkpoint_protocol_bound'] is False; "
        "assert unbound_v4_plan_status()"
        "['scheme_draft_authority_checkpoint_protocol_bound'] is False; "
        "assert unbound_v4_plan_status()"
        "['reference_authority_checkpoint_protocol_bound'] is False; "
        "assert unbound_v4_plan_status()"
        "['reference_authorization_protocol_bound'] is False; "
        "assert unbound_v4_plan_status()"
        "['secret_create_private_runtime_protocol_bound'] is False; "
        "assert unbound_v4_plan_status()"
        "['secret_create_readiness_proxy_protocol_bound'] is False; "
        "assert unbound_v4_plan_status()"
        "['secret_create_private_runtime_available'] is False; "
        "assert isinstance(UnixSchemeDraftAuthorityClient."
        "monotonic_checkpoint_protocol_bound, property); "
        "assert isinstance(UnixReferenceAuthorityClient."
        "monotonic_checkpoint_protocol_bound, property); "
        "assert C3MaterialBinding.__module__ == 'v4_planning.material_provider'; "
        "assert MaterialLeaseCoordinator.__module__ == "
        "'v4_planning.material_runtime'; "
        "assert MaterialRuntimeOutcome.RECONCILIATION_REQUIRED.value == "
        "'reconciliation_required'; "
        "assert MaterialUseOutcome.VERIFIED.value == 'verified'; "
        "assert MaterialUseClaimState.IN_PROGRESS.value == 'in_progress'; "
        "assert MaterialUseStoreTail.empty('material-store-smoke').sequence == 0; "
        "assert isinstance(PersistentMaterialUseStateStore."
        "monotonic_checkpoint_protocol_bound, property); "
        "assert PersistentMaterialUseStateStore.__module__ == "
        "'v4_planning.material_persistence'; "
        "assert callable(PersistentMaterialUseStateStore.verify_ready); "
        "assert PersistentMaterialUseCheckpointAuthority.__module__ == "
        "'v4_planning.material_checkpoint_authority'; "
        "assert PackagedDenyAllSecretCreateMaterialRuntime.status()"
        "['private_runtime_packaged']; "
        "assert not PackagedDenyAllSecretCreateMaterialRuntime.status()"
        "['dispatchable']; "
        "assert PackagedDenyAllM4ExecutionRuntime.status()"
        "['executor_runtime_packaged']; "
        "assert PackagedDenyAllM4ExecutionRuntime.status()"
        "['adapter_registry_bound']; "
        "assert EmptyM4AdapterRegistry().registered_adapter_count == 0; "
        "assert not PackagedDenyAllM4ExecutionRuntime.status()"
        "['executor_mcp_exposed']; "
        "assert DenyAllMaterialProvider().validate_binding(C3MaterialBinding(), "
        "MaterialLeaseRequest(action_id='secret-create-from-reference', "
        "action_version='1.0.0', plan_digest='1'*64, "
        "policy_decision_digest='2'*64, authorization_digest='3'*64, "
        "scope_digest='4'*64, audience_digest='5'*64, "
        "provider_class=MaterialProviderClass.EXTERNAL_VAULT_LEASE, "
        "purpose=MaterialPurpose.INITIAL_ONBOARDING, requested_at=1, "
        "expires_at=2)) is MaterialBindingStatus.UNAVAILABLE; "
        "assert secret_create_source_contract().status is "
        "SecretCreateContractStatus.SOURCE_PINNED_TARGET_UNVERIFIED; "
        "assert not secret_create_source_contract().target_version_validated; "
        "assert not secret_create_source_contract().live_call_permitted; "
        "assert approver_from_access_token.__module__ == "
        "'fortipam_mcp.v4_plan_runtime'; "
        "assert M4ExecutionStoreTail.__module__ == "
        "'fortipam_mcp.m4_execution_store'; "
        "assert MonotonicM4ExecutionCheckpoint.__module__ == "
        "'fortipam_mcp.m4_execution_store'; "
        "assert M4ExecutionStoreTail.empty('m4-execution-store-smoke').sequence == 0; "
        "assert isinstance(PersistentM4ExecutionStateStore."
        "monotonic_checkpoint_protocol_bound, property); "
        "assert callable(PersistentM4ExecutionStateStore.verify_ready); "
        "assert isinstance(ProtectedChildFolderM4Runtime."
        "execution_checkpoint_protocol_bound, property); "
        "assert isinstance(ProtectedChildFolderM4Runtime."
        "authorization_checkpoint_protocol_bound, property); "
        "assert FolderM4AuthorizationStoreTail."
        "empty('folder-authorization-store-smoke').sequence == 0; "
        "assert MonotonicFolderM4AuthorizationCheckpoint.__module__ == "
        "'fortipam_mcp.folder_m4_authorization'; "
        "assert isinstance(PersistentFolderM4AuthorizationStore."
        "monotonic_checkpoint_protocol_bound, property); "
        "assert callable(PersistentFolderM4AuthorizationStore.verify_ready); "
        "assert V4PersistentReferenceAuthoritySettings.__module__ == "
        "'fortipam_mcp.v4_runtime_host'; "
        "assert V4UnixSecretCreateRuntimeSettings.__module__ == "
        "'fortipam_mcp.v4_runtime_host'; "
        "assert UnixPlanningCheckpointClient.__module__ == "
        "'fortipam_mcp.planning_checkpoint_sidecar'; "
        "assert UnixApproverCheckpointClient.__module__ == "
        "'fortipam_mcp.approver_checkpoint_sidecar'; "
        "assert UnixApproverAuthorizationClient.__module__ == "
        "'fortipam_mcp.approver_authority_sidecar'; "
        "assert UnixApprovalReceiptAuthenticator.__module__ == "
        "'fortipam_mcp.approval_receipt_sidecar'; "
        "assert UnixSchemeDraftAuthorityClient.__module__ == "
        "'fortipam_mcp.scheme_draft_authority_sidecar'; "
        "assert UnixSchemeDraftCheckpointClient.__module__ == "
        "'fortipam_mcp.scheme_draft_checkpoint_sidecar'; "
        "assert UnixReferenceAuthorityClient.__module__ == "
        "'fortipam_mcp.reference_authority_sidecar'; "
        "assert UnixReferenceCheckpointClient.__module__ == "
        "'fortipam_mcp.reference_checkpoint_sidecar'; "
        "assert UnixSecretCreateRuntimeClient.__module__ == "
        "'fortipam_mcp.secret_create_runtime_sidecar'; "
        "assert UnixSecretCreateRuntimeReadinessProbe.__module__ == "
        "'fortipam_mcp.secret_create_runtime_sidecar'; "
        "assert not hasattr(UnixSecretCreateRuntimeReadinessProbe, 'execute_once'); "
        "assert SecretCreateReadinessSidecarSettings.__module__ == "
        "'fortipam_mcp.secret_create_readiness_sidecar'; "
        "assert UnixSecretCreateReadinessProxyClient.__module__ == "
        "'fortipam_mcp.secret_create_readiness_sidecar'; "
        "assert not hasattr(UnixSecretCreateReadinessProxyClient, 'execute_once'); "
        "assert UnixMaterialCheckpointClient.__module__ == "
        "'fortipam_mcp.material_checkpoint_sidecar'; "
        "assert ApproverDelegationBootstrapSettings.__module__ == "
        "'fortipam_mcp.approver_delegation_bootstrap'; "
        "assert SchemeDraftBootstrapSettings.__module__ == "
        "'fortipam_mcp.scheme_draft_bootstrap'; "
        "assert ReferenceGrantBootstrapSettings.__module__ == "
        "'fortipam_mcp.reference_grant_bootstrap'; "
        "assert LinuxOnboardingPrepareSettings.__module__ == "
        "'fortipam_mcp.linux_onboarding_prepare'; "
        "assert 'approval_receipt_authenticator' in "
        "inspect.signature(synthetic_v4_plan_host_factory).parameters; "
        "assert 'approver_authorization_authority' in "
        "inspect.signature(synthetic_v4_plan_host_factory).parameters; "
        "assert 'secret_create_readiness_proxy_client' in "
        "inspect.signature(synthetic_v4_plan_host_factory).parameters; "
        "assert get_action_package()['executable'] is False; "
        "assert get_action_package()['adapter'] == 'none'; "
        "assert len(RuntimeCatalog.load().operations) == 1295; "
        "assert len(ScenarioCatalog.load().scenarios) == 19"
    )
    _run(
        (python, "-c", import_check),
        cwd=temp_root,
        name="installed_import",
        environment=environment,
        log_directory=log_directory,
    )
    _run(
        (python, "-m", "fortipam_mcp.mcp_smoke"),
        cwd=temp_root,
        name="installed_mcp_stdio",
        environment=environment,
        log_directory=log_directory,
    )


def _run(
    command: tuple[str, ...],
    *,
    cwd: Path,
    name: str,
    environment: dict[str, str] | None = None,
    log_directory: Path | None = None,
) -> None:
    result = subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    if log_directory is not None:
        _write_check_log(log_directory, name, result.stdout, result.stderr)
    if result.returncode != 0:
        raise ReleaseVerificationError(
            f"Release verification check '{name}' failed with exit code "
            f"{result.returncode}."
        )


def _prepare_log_directory(path: Path) -> Path:
    """Create or validate one owner-only directory for raw check diagnostics."""

    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ReleaseVerificationError("Release log directory is unavailable.") from exc
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ReleaseVerificationError("Release log directory must be owner-only.")
    return path


def _write_check_log(
    directory: Path,
    name: str,
    stdout: str,
    stderr: str,
) -> None:
    """Persist one captured check result without exposing it on standard output."""

    if _CHECK_LOG_NAME.fullmatch(name) is None:
        raise ReleaseVerificationError("Release check log name is invalid.")
    flags = os.O_WRONLY | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(directory / f"{name}.log", flags, 0o600)
    except OSError as exc:
        raise ReleaseVerificationError("Release check log is unavailable.") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
        ):
            raise ReleaseVerificationError("Release check log is unavailable.")
        os.fchmod(descriptor, 0o600)
        os.ftruncate(descriptor, 0)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            handle.write("[stdout]\n")
            handle.write(stdout)
            handle.write("\n[stderr]\n")
            handle.write(stderr)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Verify the local FortiPAM MCP release."
    )
    parser.add_argument(
        "--keep-wheel",
        type=Path,
        help="Optional directory for the verified wheel.",
    )
    parser.add_argument(
        "--log-directory",
        type=Path,
        help="Optional owner-only directory for captured check output.",
    )
    args = parser.parse_args(argv)
    try:
        result = run_verification(
            keep_wheel=args.keep_wheel,
            log_directory=args.log_directory,
        )
    except ReleaseVerificationError as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
