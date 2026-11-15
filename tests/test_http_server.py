from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest
from mcp.server.auth.provider import AccessToken
from starlette.testclient import TestClient

from fortipam_mcp import __version__
from fortipam_mcp import http_server as http_server_module
from fortipam_mcp import server as server_module
from fortipam_mcp import material_checkpoint_sidecar as material_checkpoint_module
from fortipam_mcp import secret_create_readiness_sidecar as secret_readiness_module
from fortipam_mcp import secret_create_runtime_sidecar as secret_runtime_module
from fortipam_mcp.address_mcp_action import V4_ADDRESS_ACTION_FEATURE_ENV
from fortipam_mcp.address_group_mcp_action import (
    V4_ADDRESS_GROUP_ACTION_FEATURE_ENV,
    V4AddressGroupActionConfigurationError,
)
from fortipam_mcp.ztna_device_context_diagnostic import (
    V4_ZTNA_DEVICE_CONTEXT_DIAGNOSTIC_FEATURE_ENV,
)
from fortipam_mcp.ztna_user_control_mcp_action import (
    V4_ZTNA_USER_CONTROL_ACTION_FEATURE_ENV,
)
from fortipam_mcp.ztna_wad_debug_mcp_action import (
    V4_ZTNA_WAD_DEBUG_ACTION_FEATURE_ENV,
)
from fortipam_mcp.snmp_agent_mcp_action import V4_SNMP_AGENT_ACTION_FEATURE_ENV
from fortipam_mcp.logging_disk_mcp_action import V4_LOGGING_DISK_ACTION_FEATURE_ENV
from fortipam_mcp.fortianalyzer_mcp_action import V4_FORTIANALYZER_ACTION_FEATURE_ENV
from fortipam_mcp.maintenance_mode_mcp_action import (
    V4_MAINTENANCE_MODE_ACTION_FEATURE_ENV,
)
from fortipam_mcp.secret_audit_mcp_action import (
    V4_SECRET_AUDIT_ACTION_FEATURE_ENV,
)
from fortipam_mcp.secret_audit_summary_mcp_read import (
    V4_SECRET_AUDIT_SUMMARY_FEATURE_ENV,
)
from fortipam_mcp.active_launch_mcp_action import (
    V4_ACTIVE_LAUNCH_ACTION_FEATURE_ENV,
)
from fortipam_mcp.classification_tag_mcp_action import (
    V4_CLASSIFICATION_TAG_ACTION_FEATURE_ENV,
    V4_CLASSIFICATION_TAG_DELETE_ACCEPTED_DIGEST_ENV,
    V4_CLASSIFICATION_TAG_DELETE_ACTION_FEATURE_ENV,
    V4_CLASSIFICATION_TAG_DELETE_EXECUTION_ENV,
    V4_CLASSIFICATION_TAG_DELETE_TAG_ENV,
    V4_CLASSIFICATION_TAG_DELETE_TARGET_ENV,
)
from fortipam_mcp.classification_tag_assign_mcp_action import (
    V4_CLASSIFICATION_TAG_ASSIGN_ACTION_FEATURE_ENV,
)
from fortipam_mcp.config import HA_CONFIGURATION_PATH
from fortipam_mcp.folder_acl_mcp_action import V4_FOLDER_ACL_ACTION_FEATURE_ENV
from fortipam_mcp.folder_acl_revoke_mcp_action import (
    V4_FOLDER_ACL_REVOKE_ACTION_FEATURE_ENV,
)
from fortipam_mcp.folder_rename_mcp_action import V4_FOLDER_RENAME_ACTION_FEATURE_ENV
from fortipam_mcp.folder_archive_mcp_action import V4_FOLDER_ARCHIVE_ACTION_FEATURE_ENV
from fortipam_mcp.folder_policy_assign_mcp_action import (
    V4_FOLDER_POLICY_ASSIGN_ACTION_FEATURE_ENV,
)
from fortipam_mcp.folder_policy_detach_mcp_action import (
    V4_FOLDER_POLICY_DETACH_ACTION_FEATURE_ENV,
)
from fortipam_mcp.folder_mcp_action import V4_FOLDER_ACTION_FEATURE_ENV
from fortipam_mcp.target_mcp_action import (
    V4_TARGET_DELETE_ACCEPTED_DIGEST_ENV,
    V4_TARGET_DELETE_ACTION_FEATURE_ENV,
    V4_TARGET_DELETE_EXECUTION_ENV,
    V4_TARGET_DELETE_TAG_ENV,
    V4_TARGET_DELETE_TARGET_ENV,
)
from fortipam_mcp.local_user_mcp_action import (
    V4_LOCAL_USER_DISABLE_ACTION_FEATURE_ENV,
)
from fortipam_mcp.local_user_create_mcp_action import (
    V4_LOCAL_USER_CREATE_ACTION_FEATURE_ENV,
)
from fortipam_mcp.local_user_reset_mcp_action import (
    V4_LOCAL_USER_RESET_ACTION_FEATURE_ENV,
)
from fortipam_mcp.role_create_mcp_action import V4_ROLE_CREATE_ACTION_FEATURE_ENV
from fortipam_mcp.role_update_mcp_action import V4_ROLE_UPDATE_ACTION_FEATURE_ENV
from fortipam_mcp.role_assign_mcp_action import V4_ROLE_ASSIGN_ACTION_FEATURE_ENV
from fortipam_mcp.dlp_file_pattern_mcp_action import (
    V4_DLP_FILE_PATTERN_ACTION_FEATURE_ENV,
)
from fortipam_mcp.dlp_sensor_mcp_action import V4_DLP_SENSOR_ACTION_FEATURE_ENV
from fortipam_mcp.antivirus_profile_mcp_action import (
    V4_ANTIVIRUS_PROFILE_ACTION_FEATURE_ENV,
)
from fortipam_mcp.rdp_event_filter_mcp_action import (
    V4_RDP_EVENT_FILTER_ACTION_FEATURE_ENV,
)
from fortipam_mcp.secret_policy_mcp_action import (
    V4_SECRET_POLICY_ACTION_FEATURE_ENV,
)
from fortipam_mcp.ssh_filter_mcp_action import V4_SSH_FILTER_ACTION_FEATURE_ENV
from fortipam_mcp.launcher_mcp_action import V4_LAUNCHER_ACTION_FEATURE_ENV
from fortipam_mcp.launcher_update_mcp_action import (
    V4_LAUNCHER_UPDATE_ACTION_FEATURE_ENV,
)
from fortipam_mcp.launcher_matcher_mcp_action import (
    V4_LAUNCHER_MATCHER_ACTION_FEATURE_ENV,
)
from fortipam_mcp.template_mcp_action import V4_TEMPLATE_ACTION_FEATURE_ENV
from fortipam_mcp.template_archive_mcp_action import (
    V4_TEMPLATE_ARCHIVE_ACTION_FEATURE_ENV,
)
from fortipam_mcp.dependency_updater_mcp_action import (
    V4_DEPENDENCY_UPDATER_ACTION_FEATURE_ENV,
)
from fortipam_mcp.secret_gateway_mcp_action import (
    V4_SECRET_GATEWAY_ACTION_FEATURE_ENV,
)
from fortipam_mcp.client_integrity_mcp_action import (
    V4_CLIENT_INTEGRITY_ACTION_FEATURE_ENV,
)
from fortipam_mcp.character_set_mcp_action import (
    V4_CHARACTER_SET_ACTION_FEATURE_ENV,
)
from fortipam_mcp.windows_app_filter_mcp_action import (
    V4_WINDOWS_APP_FILTER_ACTION_FEATURE_ENV,
)
from fortipam_mcp.recording_policy_mcp_action import (
    V4_RECORDING_POLICY_ACTION_FEATURE_ENV,
)
from fortipam_mcp.password_policy_mcp_action import (
    V4_PASSWORD_POLICY_ACTION_FEATURE_ENV,
)
from fortipam_mcp.report_layout_mcp_action import (
    V4_REPORT_LAYOUT_ACTION_FEATURE_ENV,
)
from fortipam_mcp.ztna_access_proxy_client_certificate_mcp_action import (
    V4_ZTNA_ACCESS_PROXY_ACTION_FEATURE_ENV,
)
from fortipam_mcp.automation_trigger_mcp_action import (
    V4_AUTOMATION_TRIGGER_ACTION_FEATURE_ENV,
)
from fortipam_mcp.automation_action_mcp_action import (
    V4_AUTOMATION_ACTION_ACTION_FEATURE_ENV,
)
from fortipam_mcp.automation_stitch_mcp_action import (
    V4_AUTOMATION_STITCH_ACTION_FEATURE_ENV,
)
from fortipam_mcp.user_group_mcp_action import (
    V4_USER_GROUP_ACTION_FEATURE_ENV,
)
from fortipam_mcp.user_group_membership_mcp_action import (
    V4_USER_GROUP_MEMBERSHIP_ACTION_FEATURE_ENV,
)
from fortipam_mcp.apl_mcp_action import V4_APL_ACTION_FEATURE_ENV
from fortipam_mcp.apl_disable_mcp_action import (
    V4_APL_DISABLE_ACTION_FEATURE_ENV,
)
from fortipam_mcp.schedule_mcp_action import V4_SCHEDULE_ACTION_FEATURE_ENV
from fortipam_mcp.schedule_assign_mcp_action import (
    V4_SCHEDULE_ASSIGN_ACTION_FEATURE_ENV,
)
from fortipam_mcp.approval_profile_mcp_action import (
    V4_APPROVAL_PROFILE_ACTION_FEATURE_ENV,
)
from fortipam_mcp.approval_profile_update_mcp_action import (
    V4_APPROVAL_PROFILE_UPDATE_ACTION_FEATURE_ENV,
)
from fortipam_mcp.approval_email_template_mcp_action import (
    V4_APPROVAL_EMAIL_TEMPLATE_ACTION_FEATURE_ENV,
)
from fortipam_mcp.approval_email_template_update_mcp_action import (
    V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION_FEATURE_ENV,
)
from fortipam_mcp.secret_request_create_mcp_action import (
    V4_SECRET_REQUEST_CREATE_FEATURE_ENV,
)
from fortipam_mcp.target_mcp_action import V4_TARGET_ACTION_FEATURE_ENV
from fortipam_mcp.secret_metadata_mcp_action import (
    V4_SECRET_METADATA_ACTION_FEATURE_ENV,
)
from fortipam_mcp.interface_web_proxy_mcp_action import (
    V4_INTERFACE_WEB_PROXY_ACTION_FEATURE_ENV,
)
from fortipam_mcp.target_update_mcp_action import (
    V4_TARGET_UPDATE_ACTION_FEATURE_ENV,
    V4TargetUpdateActionConfigurationError,
)
from fortipam_mcp.certificate_csr_mcp_action import (
    V4_CERTIFICATE_CSR_ACTION_FEATURE_ENV,
)
from fortipam_mcp.http_server import (
    HTTP_ENV_FILE_VARIABLE,
    HttpConfigurationError,
    HttpServerSettings,
    create_http_app,
    load_http_runtime_environment,
)
from fortipam_mcp.ha_reconciliation import (
    HA_RECONCILIATION_FEATURE_ENV,
    HA_RECONCILIATION_PREREQUISITES_ENV,
    HA_RECONCILIATION_QUERY_PERMISSION_ENV,
)
from fortipam_mcp.http_smoke import run_smoke
from fortipam_mcp.local_oauth import hash_local_password, verify_local_password
from fortipam_mcp.mcp_smoke import (
    EXPECTED_TOOLS,
    LAB_EXPECTED_TOOLS,
    V4_EXPECTED_PROMPTS,
    V4_EXPECTED_RESOURCES,
    V4_EXPECTED_TOOLS,
    V4_PLAN_TOOLS,
)
from fortipam_mcp.runtime_profile import RUNTIME_PROFILE_ENV, RuntimeProfile
from fortipam_mcp.reference_grant_bootstrap import (
    ReferenceGrantBootstrapSettings,
    bootstrap_reference_grants,
)
from fortipam_mcp.scheme_draft_bootstrap import (
    SchemeDraftBootstrapSettings,
    bootstrap_scheme_draft,
)
from fortipam_mcp.v4_plan_runtime import (
    V4_FIXED_NO_INPUT_PLAN_TOOL_NAMES,
    V4_PLANNING_PRINCIPAL_HMAC_KEY_FILE_ENV,
    planning_authorization_settings_from_environment,
    requester_from_access_token,
)
from fortipam_mcp.v4_runtime_host import (
    V4PersistentReferenceAuthoritySettings,
    V4PersistentSchemeDraftAuthoritySettings,
    V4SyntheticHostSettings,
    V4UnixSecretCreateRuntimeSettings,
    V4_PERSISTENT_REFERENCE_AUTHORITY_REF,
    V4_SYNTHETIC_SCHEME_REF,
    _synthetic_access_draft,
    _synthetic_reference_bindings,
    synthetic_v4_plan_host_factory,
)
from v4_planning import (
    MonotonicCheckpointError,
    PersistentSchemeDraftAuthority,
    PlanningStoreTail,
    scheme_draft_as_mapping,
)

PREFIX = "FORTIPAM_MCP_HTTP_"
PRIVATE_LAB_IPV4 = str(ipaddress.ip_address(0x0A00020C))
TEST_TOKEN = "test-only-bearer-token-0123456789abcdef"


def test_launcher_clone_requires_controlled_oauth_authority() -> None:
    settings = HttpServerSettings.from_environment(_bearer_environment())
    with pytest.raises(HttpConfigurationError, match="Launcher clone requires"):
        create_http_app(settings, v4_launcher_clone_actions=object())


def test_native_client_integrity_requires_controlled_oauth_authority() -> None:
    settings = HttpServerSettings.from_environment(_bearer_environment())
    with pytest.raises(HttpConfigurationError, match="Native Client Integrity requires"):
        create_http_app(settings, v4_client_integrity_native_actions=object())


def test_unix_discovery_cleanup_requires_controlled_oauth_authority() -> None:
    settings = HttpServerSettings.from_environment(_bearer_environment())
    with pytest.raises(HttpConfigurationError, match="Unix Discovery cleanup requires"):
        create_http_app(settings, v4_unix_discovery_cleanup_action=object())


class _HttpExternalCheckpoint:
    authority_ref = "v4-http-external-checkpoint-test"

    def __init__(self, store_ref: str) -> None:
        self.tail = PlanningStoreTail(store_ref, 0, "chain-root")

    def verify(self, tail: PlanningStoreTail) -> None:
        if tail != self.tail:
            raise MonotonicCheckpointError("checkpoint mismatch")

    def advance(
        self,
        previous: PlanningStoreTail,
        current: PlanningStoreTail,
    ) -> None:
        if previous != self.tail or current.sequence != previous.sequence + 1:
            raise MonotonicCheckpointError("checkpoint compare-and-swap failed")
        self.tail = current


def _bearer_environment(**overrides: str) -> dict[str, str]:
    environment = {
        f"{PREFIX}AUTH_MODE": "bearer",
        f"{PREFIX}BEARER_TOKEN": TEST_TOKEN,
    }
    environment.update(overrides)
    return environment


def _initialize_payload() -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "pytest", "version": "1"},
        },
    }


def _local_oauth_environment(tmp_path: Path) -> dict[str, str]:
    state_dir = tmp_path / "oauth-state"
    state_dir.mkdir(mode=0o700, parents=True)
    return {
        f"{PREFIX}AUTH_MODE": "local_oauth",
        f"{PREFIX}PATH": "/fpamcp",
        f"{PREFIX}PUBLIC_URL": "https://mcp.example.com/fpamcp",
        f"{PREFIX}ALLOWED_HOSTS": "mcp.example.com",
        f"{PREFIX}LOCAL_OAUTH_DB": str(state_dir / "oauth.sqlite3"),
        f"{PREFIX}LOCAL_OAUTH_USERNAME": "operator",
        f"{PREFIX}LOCAL_OAUTH_PASSWORD_HASH": hash_local_password(
            "correct-horse-battery-staple",
            salt=b"0123456789abcdef",
        ),
    }


def _register_public_client(
    client: TestClient, scope: str = "fortipam:read"
) -> str:
    response = client.post(
        "/fpamcp/oauth/register",
        json={
            "client_name": "FortiPAM MCP test client",
            "redirect_uris": ["https://client.example/callback"],
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": scope,
        },
    )
    assert response.status_code == 201
    assert response.json().get("client_secret") is None
    return str(response.json()["client_id"])


def _authorize_and_login(
    client: TestClient,
    client_id: str,
    scope: str = "fortipam:read",
) -> tuple[str, str]:
    verifier = "test-code-verifier-with-more-than-forty-three-characters"
    import base64
    import hashlib

    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).decode("ascii").rstrip("=")
    authorization = client.get(
        "/fpamcp/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "https://client.example/callback",
            "scope": scope,
            "state": "state-123",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "resource": "https://mcp.example.com/fpamcp",
        },
        follow_redirects=False,
    )
    assert authorization.status_code == 302
    login_path = authorization.headers["location"]
    assert login_path.startswith("https://mcp.example.com/fpamcp/oauth/login?")

    login_page = client.get(login_path)
    assert login_page.status_code == 200
    if "fortipam:operate" in scope.split():
        assert (
            "controlled operations, including explicitly enabled and separately "
            "confirmed device actions"
        ) in login_page.text
    request_id = re.search(r'name="request_id" value="([^"]+)"', login_page.text)
    csrf_token = re.search(r'name="csrf_token" value="([^"]+)"', login_page.text)
    assert request_id is not None
    assert csrf_token is not None
    approved = client.post(
        "/fpamcp/oauth/login",
        data={
            "request_id": request_id.group(1),
            "csrf_token": csrf_token.group(1),
            "username": "operator",
            "password": "correct-horse-battery-staple",
            "action": "allow",
        },
        headers={"origin": "https://mcp.example.com"},
        follow_redirects=False,
    )
    assert approved.status_code == 302
    callback = urlsplit(approved.headers["location"])
    callback_query = parse_qs(callback.query)
    assert callback.scheme == "https"
    assert callback.netloc == "client.example"
    assert callback_query["state"] == ["state-123"]
    assert callback_query["iss"] == ["https://mcp.example.com/fpamcp/oauth"]
    return callback_query["code"][0], verifier


def _request_headers(token: str = TEST_TOKEN) -> dict[str, str]:
    return {
        "accept": "application/json, text/event-stream",
        "authorization": f"Bearer {token}",
        "content-type": "application/json",
        "host": "127.0.0.1:8000",
        "mcp-protocol-version": "2025-11-25",
    }


def _diagnostic_environment(tmp_path: Path) -> dict[str, str]:
    environment = _local_oauth_environment(tmp_path)
    diagnostic_dir = tmp_path / "diagnostic-state"
    diagnostic_dir.mkdir(mode=0o700)
    key_file = diagnostic_dir / "hmac.key"
    key_file.write_text("6b" * 32, encoding="ascii")
    key_file.chmod(0o600)
    environment.update(
        {
            "FORTIPAM_MCP_DIAGNOSTIC_DB": str(
                diagnostic_dir / "diagnostic.sqlite3"
            ),
            "FORTIPAM_MCP_DIAGNOSTIC_HMAC_KEY_FILE": str(key_file),
        }
    )
    return environment


def _v4_environment(tmp_path: Path) -> dict[str, str]:
    environment = _local_oauth_environment(tmp_path)
    state = tmp_path / "v4-plan-state"
    state.mkdir(mode=0o700)
    os.chmod(state, 0o700)
    key = state / "principal.hmac"
    key.write_text("71" * 32, encoding="ascii")
    os.chmod(key, 0o600)
    environment[RUNTIME_PROFILE_ENV] = "v4-plan-only"
    environment[V4_PLANNING_PRINCIPAL_HMAC_KEY_FILE_ENV] = str(key)
    return environment


def _v4_ha_reconciliation_environment(tmp_path: Path) -> dict[str, str]:
    environment = _v4_environment(tmp_path)
    diagnostic_dir = tmp_path / "diagnostic-state"
    diagnostic_dir.mkdir(mode=0o700)
    key_file = diagnostic_dir / "hmac.key"
    key_file.write_text("6b" * 32, encoding="ascii")
    key_file.chmod(0o600)
    reconciliation_dir = tmp_path / "ha-reconciliation"
    reconciliation_dir.mkdir(mode=0o700)
    prerequisite_file = reconciliation_dir / "prerequisites.json"
    prerequisite_file.write_text(
        json.dumps(
            {
                "schema_version": "1",
                "target_version": "1.9.1",
                "expected_member_inventory_verified": True,
                "expected_roles_verified": True,
                "compatibility_verified": True,
                "heartbeat_health_verified": True,
                "maintenance_failover_reviewed": True,
                "local_evidence_accounted_for": True,
            }
        ),
        encoding="utf-8",
    )
    prerequisite_file.chmod(0o600)
    permission_file = reconciliation_dir / "query-permission.json"
    permission_file.write_text(
        json.dumps(
            {
                "schema_version": "1",
                "target_version": "1.9.1",
                "api_configuration_read_verified": True,
                "cli_configuration_read_verified": True,
                "cli_status_read_verified": True,
                "cli_checksum_read_verified": True,
                "dedicated_identity_verified": True,
                "cross_domain_denial_verified": True,
            }
        ),
        encoding="utf-8",
    )
    permission_file.chmod(0o600)
    environment.update(
        {
            "FORTIPAM_MCP_DIAGNOSTIC_DB": str(
                diagnostic_dir / "diagnostic.sqlite3"
            ),
            "FORTIPAM_MCP_DIAGNOSTIC_HMAC_KEY_FILE": str(key_file),
            HA_RECONCILIATION_FEATURE_ENV: "true",
            HA_RECONCILIATION_PREREQUISITES_ENV: str(prerequisite_file),
            HA_RECONCILIATION_QUERY_PERMISSION_ENV: str(permission_file),
        }
    )
    return environment


def _v4_controlled_environment(tmp_path: Path) -> dict[str, str]:
    environment = _v4_environment(tmp_path)
    environment[RUNTIME_PROFILE_ENV] = "v4-controlled"
    environment[V4_FOLDER_ACTION_FEATURE_ENV] = "true"
    return environment


def _insecure_private_ip_lab_environment(tmp_path: Path) -> dict[str, str]:
    environment = _v4_environment(tmp_path)
    environment.update(
        {
            RUNTIME_PROFILE_ENV: "v4-controlled",
            f"{PREFIX}INSECURE_PRIVATE_IP_LAB": "true",
            f"{PREFIX}PUBLIC_URL": f"http://{PRIVATE_LAB_IPV4}/fpamcp",
            f"{PREFIX}LOCAL_OAUTH_ISSUER": (
                f"http://{PRIVATE_LAB_IPV4}/fpamcp/oauth"
            ),
            f"{PREFIX}ALLOWED_HOSTS": PRIVATE_LAB_IPV4,
            f"{PREFIX}ALLOWED_ORIGINS": f"http://{PRIVATE_LAB_IPV4}",
        }
    )
    return environment


def _v4_bound_environment(
    tmp_path: Path,
) -> tuple[dict[str, str], V4SyntheticHostSettings]:
    environment = _v4_environment(tmp_path)
    state = tmp_path / "v4-bound-state"
    state.mkdir(mode=0o700)
    os.chmod(state, 0o700)

    def key(name: str, value: str) -> Path:
        path = state / name
        path.write_text(value, encoding="ascii")
        os.chmod(path, 0o600)
        return path

    planning_key = key("planning.hmac", "72" * 32)
    confirmation_key = key("confirmation.hmac", "73" * 32)
    receipt_key = key("receipt.hmac", "74" * 32)
    environment.update(
        {
            "FORTIPAM_MCP_V4_PLAN_CONFIRMATION_DB": str(
                state / "confirmation.sqlite3"
            ),
            "FORTIPAM_MCP_V4_PLAN_CONFIRMATION_STORE_HMAC_KEY_FILE": str(
                confirmation_key
            ),
            "FORTIPAM_MCP_V4_PLAN_CONFIRMATION_RECEIPT_HMAC_KEY_FILE": str(
                receipt_key
            ),
        }
    )
    return environment, V4SyntheticHostSettings(
        state / "planning.sqlite3",
        planning_key,
    )


def _start_local_sidecar(
    module: str,
    environment: dict[str, str],
    socket_path: Path,
) -> subprocess.Popen[bytes]:
    process = subprocess.Popen(
        (sys.executable, "-m", module),
        cwd=Path(__file__).resolve().parents[1],
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if socket_path.exists():
            return process
        if process.poll() is not None:
            stderr = process.stderr.read() if process.stderr is not None else b""
            raise AssertionError(f"local sidecar stopped before ready: {stderr!r}")
        time.sleep(0.02)
    _stop_local_sidecar(process, socket_path)
    raise AssertionError("local sidecar did not create its Unix socket")


def _stop_local_sidecar(
    process: subprocess.Popen[bytes],
    socket_path: Path,
) -> None:
    if process.poll() is None:
        process.terminate()
        process.wait(timeout=5)
    if socket_path.exists() or socket_path.is_symlink():
        socket_path.unlink()


class _FixedDeviceTools:
    async def get_ha_configuration_posture_summary(self) -> dict[str, object]:
        return {
            "scenario": "ha_sync",
            "operation": "GET",
            "path": HA_CONFIGURATION_PATH,
            "sensitivity": "ha_configuration_posture",
            "status_code": 200,
            "content_type": "application/json",
            "response_body_returned": False,
            "posture": {
                "contract": "fortipam_ha_configuration_posture_v1",
                "ha_enabled": False,
                "topology_mode": "standalone",
                "heartbeat_authentication_enabled": True,
                "heartbeat_encryption_enabled": True,
                "heartbeat_interface_configured": True,
                "monitored_interface_configured": False,
                "dedicated_management_enabled": False,
                "management_interface_entry_count": 0,
                "unicast_heartbeat_enabled": False,
                "unicast_peer_entry_count": 0,
                "session_pickup_enabled": False,
                "connectionless_session_pickup_enabled": False,
                "override_enabled": False,
                "synchronization_state": "not_observed",
                "response_body_returned": False,
                "serial_values_returned": False,
                "network_values_returned": False,
                "interface_values_returned": False,
                "group_values_returned": False,
                "credential_values_returned": False,
                "priority_values_returned": False,
                "checksum_values_returned": False,
            },
        }


class _FixedCliTools:
    async def get_ha_configuration_summary(self) -> dict[str, object]:
        return {
            "workflow_id": "ha_configuration",
            "execution_status": "completed",
            "evidence": {
                "evidence_status": "complete",
                "ha_mode": "standalone",
                "session_pickup": "disabled",
                "override_state": "disabled",
                "configuration_security": "enabled",
                "identity_values_returned": False,
                "network_values_returned": False,
                "group_name_returned": False,
                "password_values_returned": False,
                "priority_values_returned": False,
                "exact_checksum_returned": False,
                "raw_cli_returned": False,
            },
            "raw_cli_returned": False,
            "credential_values_returned": False,
        }

    async def get_ha_status_summary(self) -> dict[str, object]:
        return {
            "workflow_id": "ha_status",
            "execution_status": "completed",
            "evidence": {
                "evidence_status": "complete",
                "ha_mode": "standalone",
                "ha_health": "healthy",
                "member_count_band": "single",
                "configuration_sync": "not_applicable",
                "peer_identity_returned": False,
                "network_values_returned": False,
                "exact_time_returned": False,
                "raw_cli_returned": False,
            },
            "raw_cli_returned": False,
            "credential_values_returned": False,
        }

    async def get_ha_checksum_summary(self) -> dict[str, object]:
        return {
            "workflow_id": "ha_checksum",
            "execution_status": "completed",
            "evidence": {
                "evidence_status": "complete",
                "ha_mode": "standalone",
                "checksum_assessment": "not_applicable",
                "member_count_band": "single",
                "exact_checksum_returned": False,
                "member_identity_returned": False,
                "table_name_returned": False,
                "raw_cli_returned": False,
            },
            "raw_cli_returned": False,
            "credential_values_returned": False,
        }


def test_bearer_is_the_secure_default_and_requires_a_strong_token() -> None:
    with pytest.raises(HttpConfigurationError, match="at least 32"):
        HttpServerSettings.from_environment({})
    with pytest.raises(HttpConfigurationError, match="at least 32"):
        HttpServerSettings.from_environment(
            {f"{PREFIX}AUTH_MODE": "bearer", f"{PREFIX}BEARER_TOKEN": "short"}
        )


def test_unauthenticated_mode_is_loopback_only() -> None:
    settings = HttpServerSettings.from_environment(
        {f"{PREFIX}AUTH_MODE": "none"}
    )
    assert settings.host == "127.0.0.1"

    with pytest.raises(HttpConfigurationError, match="allowed hosts"):
        HttpServerSettings.from_environment(
            {
                f"{PREFIX}AUTH_MODE": "none",
                f"{PREFIX}HOST": "0.0.0.0",
            }
        )
    with pytest.raises(HttpConfigurationError, match="restricted to loopback"):
        HttpServerSettings.from_environment(
            {
                f"{PREFIX}AUTH_MODE": "none",
                f"{PREFIX}HOST": "0.0.0.0",
                f"{PREFIX}ALLOWED_HOSTS": "mcp.example.com",
            }
        )


def test_oauth_requires_audience_bound_https_configuration() -> None:
    environment = {
        f"{PREFIX}AUTH_MODE": "oauth",
        f"{PREFIX}PATH": "/fpamcp",
        f"{PREFIX}PUBLIC_URL": "https://mcp.example.com/fpamcp",
        f"{PREFIX}OAUTH_ISSUER": "https://id.example.com",
        f"{PREFIX}OAUTH_JWKS_URL": "https://id.example.com/.well-known/jwks.json",
        f"{PREFIX}OAUTH_AUDIENCE": "https://mcp.example.com/fpamcp",
    }
    settings = HttpServerSettings.from_environment(environment)

    assert settings.oauth_audience == settings.public_url
    assert settings.oauth_required_scopes == ("fortipam:read",)

    environment[f"{PREFIX}OAUTH_AUDIENCE"] = "https://other.example.com/fpamcp"
    with pytest.raises(HttpConfigurationError, match="exactly match"):
        HttpServerSettings.from_environment(environment)


def test_local_oauth_requires_owner_only_state_and_a_password_hash(tmp_path: Path) -> None:
    environment = _local_oauth_environment(tmp_path)
    settings = HttpServerSettings.from_environment(environment)

    assert settings.local_oauth is not None
    assert settings.local_oauth.issuer == "https://mcp.example.com/fpamcp/oauth"
    assert verify_local_password(
        "correct-horse-battery-staple",
        settings.local_oauth.password_hash,
    )
    assert not verify_local_password("wrong-password", settings.local_oauth.password_hash)

    unsafe_dir = tmp_path / "unsafe-state"
    unsafe_dir.mkdir(mode=0o755)
    environment[f"{PREFIX}LOCAL_OAUTH_DB"] = str(unsafe_dir / "oauth.sqlite3")
    unsafe = HttpServerSettings.from_environment(environment)
    with pytest.raises(ValueError, match="owner-only"):
        create_http_app(unsafe)


def test_local_oauth_private_ip_http_lab_exception_is_narrowly_bound(
    tmp_path: Path,
) -> None:
    settings = HttpServerSettings.from_environment(
        _insecure_private_ip_lab_environment(tmp_path)
    )

    assert settings.runtime_profile is RuntimeProfile.V4_CONTROLLED
    assert settings.public_url == f"http://{PRIVATE_LAB_IPV4}/fpamcp"
    assert settings.local_oauth is not None
    assert settings.local_oauth.insecure_private_ip_lab is True

    with TestClient(
        create_http_app(settings), base_url=f"http://{PRIVATE_LAB_IPV4}"
    ) as client:
        client_id = _register_public_client(client)
        authorization = client.get(
            "/fpamcp/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": "https://client.example/callback",
                "scope": "fortipam:read",
                "code_challenge": "a" * 43,
                "code_challenge_method": "S256",
                "resource": f"http://{PRIVATE_LAB_IPV4}/fpamcp",
            },
            follow_redirects=False,
        )
        login_page = client.get(authorization.headers["location"])

    assert authorization.status_code == 302
    assert login_page.status_code == 200
    assert "Secure" not in login_page.headers["set-cookie"]


def test_private_ip_http_lab_exception_rejects_broader_configurations(
    tmp_path: Path,
) -> None:
    environment = _insecure_private_ip_lab_environment(tmp_path / "host")
    environment[f"{PREFIX}PUBLIC_URL"] = "http://mcp.example.com/fpamcp"
    environment[f"{PREFIX}LOCAL_OAUTH_ISSUER"] = "http://mcp.example.com/fpamcp/oauth"
    environment[f"{PREFIX}ALLOWED_HOSTS"] = "mcp.example.com"
    environment[f"{PREFIX}ALLOWED_ORIGINS"] = "http://mcp.example.com"
    with pytest.raises(HttpConfigurationError, match="must be an HTTPS URL"):
        HttpServerSettings.from_environment(environment)

    environment = _insecure_private_ip_lab_environment(tmp_path / "profile")
    environment[RUNTIME_PROFILE_ENV] = "v4-plan-only"
    with pytest.raises(HttpConfigurationError, match="requires v4-controlled"):
        HttpServerSettings.from_environment(environment)

    environment = _insecure_private_ip_lab_environment(tmp_path / "origin")
    environment[f"{PREFIX}ALLOWED_ORIGINS"] = f"https://{PRIVATE_LAB_IPV4}"
    with pytest.raises(HttpConfigurationError, match="allowed origin"):
        HttpServerSettings.from_environment(environment)


def test_embedded_oauth_discovery_login_rotation_and_revocation(tmp_path: Path) -> None:
    settings = HttpServerSettings.from_environment(_local_oauth_environment(tmp_path))

    with TestClient(
        create_http_app(settings),
        base_url="https://mcp.example.com",
    ) as client:
        protected = client.get("/.well-known/oauth-protected-resource/fpamcp")
        authorization_server = client.get(
            "/.well-known/oauth-authorization-server/fpamcp/oauth"
        )
        rejected_host = client.get(
            "/.well-known/oauth-authorization-server/fpamcp/oauth",
            headers={"host": "untrusted.example"},
        )
        unauthorized = client.post(
            "/fpamcp",
            headers={
                "accept": "application/json, text/event-stream",
                "content-type": "application/json",
                "mcp-protocol-version": "2025-11-25",
            },
            json=_initialize_payload(),
        )

        assert protected.status_code == 200
        assert protected.json()["resource"] == "https://mcp.example.com/fpamcp"
        assert protected.json()["authorization_servers"] == [
            "https://mcp.example.com/fpamcp/oauth"
        ]
        assert authorization_server.status_code == 200
        assert rejected_host.status_code == 421
        metadata = authorization_server.json()
        assert metadata["authorization_endpoint"].endswith("/fpamcp/oauth/authorize")
        assert metadata["token_endpoint"].endswith("/fpamcp/oauth/token")
        assert metadata["registration_endpoint"].endswith("/fpamcp/oauth/register")
        assert "none" in metadata["token_endpoint_auth_methods_supported"]
        assert unauthorized.status_code == 401
        assert "resource_metadata=" in unauthorized.headers["www-authenticate"]

        client_id = _register_public_client(client)
        code, verifier = _authorize_and_login(client, client_id)
        token_response = client.post(
            "/fpamcp/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": code,
                "code_verifier": verifier,
                "redirect_uri": "https://client.example/callback",
                "resource": "https://mcp.example.com/fpamcp",
            },
        )
        assert token_response.status_code == 200
        access_token = token_response.json()["access_token"]
        refresh_token = token_response.json()["refresh_token"]

        replay = client.post(
            "/fpamcp/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": code,
                "code_verifier": verifier,
                "redirect_uri": "https://client.example/callback",
                "resource": "https://mcp.example.com/fpamcp",
            },
        )
        assert replay.status_code == 400
        assert replay.json()["error"] == "invalid_grant"

        accepted = client.post(
            "/fpamcp",
            headers={
                "accept": "application/json, text/event-stream",
                "authorization": f"Bearer {access_token}",
                "content-type": "application/json",
                "mcp-protocol-version": "2025-11-25",
            },
            json=_initialize_payload(),
        )
        assert accepted.status_code == 200

        refreshed = client.post(
            "/fpamcp/oauth/token",
            data={
                "grant_type": "refresh_token",
                "client_id": client_id,
                "refresh_token": refresh_token,
                "scope": "fortipam:read",
                "resource": "https://mcp.example.com/fpamcp",
            },
        )
        assert refreshed.status_code == 200
        rotated_access = refreshed.json()["access_token"]
        assert rotated_access != access_token

        old_access = client.post(
            "/fpamcp",
            headers={
                "accept": "application/json, text/event-stream",
                "authorization": f"Bearer {access_token}",
                "content-type": "application/json",
                "mcp-protocol-version": "2025-11-25",
            },
            json=_initialize_payload(),
        )
        assert old_access.status_code == 401

        revoked = client.post(
            "/fpamcp/oauth/revoke",
            data={"client_id": client_id, "client_secret": "", "token": rotated_access},
        )
        assert revoked.status_code == 200
        revoked_access = client.post(
            "/fpamcp",
            headers={
                "accept": "application/json, text/event-stream",
                "authorization": f"Bearer {rotated_access}",
                "content-type": "application/json",
                "mcp-protocol-version": "2025-11-25",
            },
            json=_initialize_payload(),
        )
        assert revoked_access.status_code == 401

    database_bytes = settings.local_oauth.database_path.read_bytes()  # type: ignore[union-attr]
    assert access_token.encode("ascii") not in database_bytes
    assert refresh_token.encode("ascii") not in database_bytes
    assert code.encode("ascii") not in database_bytes
    assert b"correct-horse-battery-staple" not in database_bytes


def test_http_oauth_diagnostic_scope_executes_only_fixed_local_state_workflows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        server_module.FortiPamMcpServer,
        "_require_device_tools",
        lambda self: _FixedDeviceTools(),
    )
    monkeypatch.setattr(
        server_module.FortiPamMcpServer,
        "_require_cli_tools",
        lambda self: _FixedCliTools(),
    )
    settings = HttpServerSettings.from_environment(
        _diagnostic_environment(tmp_path)
    )
    scope = "fortipam:read fortipam:diagnostic"

    with TestClient(
        create_http_app(settings),
        base_url="https://mcp.example.com",
    ) as client:
        client_id = _register_public_client(client, scope)
        code, verifier = _authorize_and_login(client, client_id, scope)
        token_response = client.post(
            "/fpamcp/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": code,
                "code_verifier": verifier,
                "redirect_uri": "https://client.example/callback",
                "resource": "https://mcp.example.com/fpamcp",
            },
        )
        assert token_response.status_code == 200
        assert set(token_response.json()["scope"].split()) == {
            "fortipam:read",
            "fortipam:diagnostic",
        }
        headers = _request_headers(token_response.json()["access_token"])
        headers["host"] = "mcp.example.com"

        def call(tool_name: str, arguments: dict[str, object]) -> dict[str, object]:
            response = client.post(
                "/fpamcp",
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": tool_name,
                    "method": "tools/call",
                    "params": {"name": tool_name, "arguments": arguments},
                },
            )
            assert response.status_code == 200
            payload = response.json()["result"]
            assert payload.get("isError", False) is False
            return payload["structuredContent"]

        assert call("create_ha_diagnostic_baseline", {"baseline_id": "known-ha"}) == {
            "status": "created"
        }
        assert call("compare_ha_diagnostic_baseline", {"baseline_id": "known-ha"}) == {
            "status": "unchanged"
        }
        assert call("correlate_ha_api_cli_posture", {}) == {
            "status": "operationally_consistent"
        }

        read_client_id = _register_public_client(client)
        read_code, read_verifier = _authorize_and_login(client, read_client_id)
        read_token_response = client.post(
            "/fpamcp/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": read_client_id,
                "code": read_code,
                "code_verifier": read_verifier,
                "redirect_uri": "https://client.example/callback",
                "resource": "https://mcp.example.com/fpamcp",
            },
        )
        assert read_token_response.status_code == 200
        read_headers = _request_headers(
            read_token_response.json()["access_token"]
        )
        read_headers["host"] = "mcp.example.com"
        denied = client.post(
            "/fpamcp",
            headers=read_headers,
            json={
                "jsonrpc": "2.0",
                "id": "scope-denied",
                "method": "tools/call",
                "params": {
                    "name": "create_ha_diagnostic_baseline",
                    "arguments": {"baseline_id": "other-ha"},
                },
            },
        )
        assert denied.status_code == 200
        assert denied.json()["result"]["isError"] is True
        assert "other-ha" not in denied.text

    state_bytes = (
        tmp_path / "diagnostic-state" / "diagnostic.sqlite3"
    ).read_bytes()
    assert b"known-ha" not in state_bytes


def test_embedded_oauth_rejects_redirect_resource_and_cross_origin_login(
    tmp_path: Path,
) -> None:
    settings = HttpServerSettings.from_environment(_local_oauth_environment(tmp_path))
    with TestClient(
        create_http_app(settings),
        base_url="https://mcp.example.com",
    ) as client:
        invalid_redirect = client.post(
            "/fpamcp/oauth/register",
            json={
                "client_name": "Unsafe client",
                "redirect_uris": ["http://remote.example/callback"],
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "scope": "fortipam:read",
            },
        )
        assert invalid_redirect.status_code == 400
        assert invalid_redirect.json()["error"] == "invalid_redirect_uri"

        client_id = _register_public_client(client)
        common_params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "https://client.example/callback",
            "scope": "fortipam:read",
            "state": "negative-state",
            "code_challenge": "A" * 43,
            "code_challenge_method": "S256",
        }
        wrong_resource = client.get(
            "/fpamcp/oauth/authorize",
            params={**common_params, "resource": "https://other.example/mcp"},
            follow_redirects=False,
        )
        assert wrong_resource.status_code == 302
        assert parse_qs(urlsplit(wrong_resource.headers["location"]).query)["error"] == [
            "invalid_target"
        ]

        authorization = client.get(
            "/fpamcp/oauth/authorize",
            params={
                **common_params,
                "resource": "https://mcp.example.com/fpamcp",
            },
            follow_redirects=False,
        )
        login_page = client.get(authorization.headers["location"])
        request_id = re.search(r'name="request_id" value="([^"]+)"', login_page.text)
        csrf_token = re.search(r'name="csrf_token" value="([^"]+)"', login_page.text)
        assert request_id is not None
        assert csrf_token is not None
        cross_origin = client.post(
            "/fpamcp/oauth/login",
            data={
                "request_id": request_id.group(1),
                "csrf_token": csrf_token.group(1),
                "username": "operator",
                "password": "correct-horse-battery-staple",
                "action": "allow",
            },
            headers={"origin": "https://attacker.example"},
            follow_redirects=False,
        )
        assert cross_origin.status_code == 400
        assert "rejected" in cross_origin.text


def test_embedded_oauth_access_survives_application_restart(tmp_path: Path) -> None:
    settings = HttpServerSettings.from_environment(_local_oauth_environment(tmp_path))
    with TestClient(
        create_http_app(settings),
        base_url="https://mcp.example.com",
    ) as client:
        client_id = _register_public_client(client)
        code, verifier = _authorize_and_login(client, client_id)
        tokens = client.post(
            "/fpamcp/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": code,
                "code_verifier": verifier,
                "redirect_uri": "https://client.example/callback",
                "resource": "https://mcp.example.com/fpamcp",
            },
        )
        assert tokens.status_code == 200
        access_token = tokens.json()["access_token"]

    with TestClient(
        create_http_app(settings),
        base_url="https://mcp.example.com",
    ) as restarted:
        accepted = restarted.post(
            "/fpamcp",
            headers={
                "accept": "application/json, text/event-stream",
                "authorization": f"Bearer {access_token}",
                "content-type": "application/json",
                "mcp-protocol-version": "2025-11-25",
            },
            json=_initialize_payload(),
        )
        assert accepted.status_code == 200
        assert accepted.json()["result"]["serverInfo"]["version"] == __version__


def test_http_environment_file_loads_isolated_folder_references_with_execution_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from fortipam_mcp.isolated_folder_mcp_action import PREFIX as isolated_prefix

    values = {
        isolated_prefix + "ENABLED": "true",
        isolated_prefix + "EXECUTION_ENABLED": "false",
        isolated_prefix + "BINDING_FILE": "/protected/isolated-binding.json",
        isolated_prefix + "OWNER_READBACK_ENABLED": "true",
        isolated_prefix + "OWNER_LOGIN_ENV_FILE": "/protected/login.env",
        isolated_prefix + "OWNER_USERNAME_VARIABLE": "EXISTING_OWNER_USERNAME",
        isolated_prefix + "OWNER_PASSWORD_VARIABLE": "EXISTING_OWNER_PASSWORD",
    }
    env_file = tmp_path / "isolated-http.env"
    env_file.write_text("".join(f"{key}={value}\n" for key, value in values.items()), encoding="utf-8")
    env_file.chmod(0o600)
    monkeypatch.setenv(HTTP_ENV_FILE_VARIABLE, str(env_file))
    for key in values:
        # Track absent keys too: the loader writes directly into os.environ.
        monkeypatch.setenv(key, "")
        monkeypatch.delenv(key, raising=False)
    assert load_http_runtime_environment()
    assert {key: os.environ.get(key) for key in values} == values


def test_http_environment_file_is_owner_only_and_prefix_filtered(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env_file = tmp_path / "http.env"
    env_file.write_text(
        f"{PREFIX}AUTH_MODE=bearer\n"
        f"{PREFIX}BEARER_TOKEN={TEST_TOKEN}\n"
        f"{RUNTIME_PROFILE_ENV}=lab-simulated\n"
        "FORTIPAM_MCP_DIAGNOSTIC_DB=/protected/diagnostic.sqlite3\n"
        f"{HA_RECONCILIATION_FEATURE_ENV}=true\n"
        f"{HA_RECONCILIATION_PREREQUISITES_ENV}=/protected/ha-prerequisites.json\n"
        f"{HA_RECONCILIATION_QUERY_PERMISSION_ENV}=/protected/ha-query-permission.json\n"
        f"{V4_TARGET_ACTION_FEATURE_ENV}=true\n"
        f"{V4_TARGET_DELETE_ACTION_FEATURE_ENV}=true\n"
        f"{V4_TARGET_DELETE_EXECUTION_ENV}=false\n"
        f"{V4_TARGET_DELETE_TARGET_ENV}=mcp-v4-target-b104\n"
        f"{V4_TARGET_DELETE_TAG_ENV}=mcp-v4-classification-tag-b29\n"
        f"{V4_TARGET_DELETE_ACCEPTED_DIGEST_ENV}={'b' * 64}\n"
        "FPA_HOME_LAB_FPA1_V4_TARGET_ENABLED=true\n"
        f"{V4_CLASSIFICATION_TAG_ACTION_FEATURE_ENV}=true\n"
        f"{V4_CLASSIFICATION_TAG_DELETE_ACTION_FEATURE_ENV}=true\n"
        f"{V4_CLASSIFICATION_TAG_DELETE_EXECUTION_ENV}=false\n"
        f"{V4_CLASSIFICATION_TAG_DELETE_TAG_ENV}=mcp-v4-classification-tag-b29\n"
        f"{V4_CLASSIFICATION_TAG_DELETE_TARGET_ENV}=mcp-v4-target-b104\n"
        f"{V4_CLASSIFICATION_TAG_DELETE_ACCEPTED_DIGEST_ENV}={'a' * 64}\n"
        f"{V4_ADDRESS_ACTION_FEATURE_ENV}=true\n"
        f"{V4_ADDRESS_GROUP_ACTION_FEATURE_ENV}=true\n"
        f"{V4_DLP_SENSOR_ACTION_FEATURE_ENV}=true\n"
        f"{V4_ANTIVIRUS_PROFILE_ACTION_FEATURE_ENV}=true\n"
        f"{V4_RDP_EVENT_FILTER_ACTION_FEATURE_ENV}=true\n"
        f"{V4_SECRET_POLICY_ACTION_FEATURE_ENV}=true\n"
        f"{V4_SSH_FILTER_ACTION_FEATURE_ENV}=true\n"
        f"{V4_DEPENDENCY_UPDATER_ACTION_FEATURE_ENV}=true\n"
        f"{V4_SECRET_GATEWAY_ACTION_FEATURE_ENV}=true\n"
        f"{V4_CLIENT_INTEGRITY_ACTION_FEATURE_ENV}=true\n"
        f"{V4_CHARACTER_SET_ACTION_FEATURE_ENV}=true\n"
        f"{V4_PASSWORD_POLICY_ACTION_FEATURE_ENV}=true\n"
        f"{V4_ZTNA_ACCESS_PROXY_ACTION_FEATURE_ENV}=true\n"
        f"{V4_AUTOMATION_TRIGGER_ACTION_FEATURE_ENV}=true\n"
        f"{V4_AUTOMATION_ACTION_ACTION_FEATURE_ENV}=true\n"
        f"{V4_AUTOMATION_STITCH_ACTION_FEATURE_ENV}=true\n"
        f"{V4_USER_GROUP_ACTION_FEATURE_ENV}=true\n"
        f"{V4_APL_DISABLE_ACTION_FEATURE_ENV}=true\n"
        f"{V4_SCHEDULE_ACTION_FEATURE_ENV}=true\n"
        f"{V4_APPROVAL_PROFILE_ACTION_FEATURE_ENV}=true\n"
        f"{V4_APPROVAL_PROFILE_UPDATE_ACTION_FEATURE_ENV}=true\n"
        f"{V4_APPROVAL_EMAIL_TEMPLATE_ACTION_FEATURE_ENV}=true\n"
        f"{V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION_FEATURE_ENV}=true\n"
        "UNRELATED_SECRET=must-not-load\n",
        encoding="utf-8",
    )
    env_file.chmod(0o600)
    monkeypatch.setenv(HTTP_ENV_FILE_VARIABLE, str(env_file))
    monkeypatch.delenv(f"{PREFIX}AUTH_MODE", raising=False)
    monkeypatch.delenv(f"{PREFIX}BEARER_TOKEN", raising=False)
    monkeypatch.delenv(RUNTIME_PROFILE_ENV, raising=False)
    monkeypatch.delenv("UNRELATED_SECRET", raising=False)
    monkeypatch.delenv("FORTIPAM_MCP_DIAGNOSTIC_DB", raising=False)
    monkeypatch.delenv(HA_RECONCILIATION_FEATURE_ENV, raising=False)
    monkeypatch.delenv(HA_RECONCILIATION_PREREQUISITES_ENV, raising=False)
    monkeypatch.delenv(HA_RECONCILIATION_QUERY_PERMISSION_ENV, raising=False)
    monkeypatch.delenv(V4_TARGET_ACTION_FEATURE_ENV, raising=False)
    monkeypatch.delenv(V4_TARGET_DELETE_ACTION_FEATURE_ENV, raising=False)
    monkeypatch.delenv(V4_TARGET_DELETE_EXECUTION_ENV, raising=False)
    monkeypatch.delenv(V4_TARGET_DELETE_TARGET_ENV, raising=False)
    monkeypatch.delenv(V4_TARGET_DELETE_TAG_ENV, raising=False)
    monkeypatch.delenv(V4_TARGET_DELETE_ACCEPTED_DIGEST_ENV, raising=False)
    monkeypatch.delenv("FPA_HOME_LAB_FPA1_V4_TARGET_ENABLED", raising=False)
    monkeypatch.delenv(V4_CLASSIFICATION_TAG_ACTION_FEATURE_ENV, raising=False)
    monkeypatch.delenv(V4_CLASSIFICATION_TAG_DELETE_ACTION_FEATURE_ENV, raising=False)
    monkeypatch.delenv(V4_CLASSIFICATION_TAG_DELETE_EXECUTION_ENV, raising=False)
    monkeypatch.delenv(V4_CLASSIFICATION_TAG_DELETE_TAG_ENV, raising=False)
    monkeypatch.delenv(V4_CLASSIFICATION_TAG_DELETE_TARGET_ENV, raising=False)
    monkeypatch.delenv(V4_CLASSIFICATION_TAG_DELETE_ACCEPTED_DIGEST_ENV, raising=False)
    monkeypatch.delenv(V4_ADDRESS_ACTION_FEATURE_ENV, raising=False)
    monkeypatch.delenv(V4_ADDRESS_GROUP_ACTION_FEATURE_ENV, raising=False)
    monkeypatch.delenv(V4_DLP_SENSOR_ACTION_FEATURE_ENV, raising=False)
    monkeypatch.delenv(V4_ANTIVIRUS_PROFILE_ACTION_FEATURE_ENV, raising=False)
    monkeypatch.delenv(V4_RDP_EVENT_FILTER_ACTION_FEATURE_ENV, raising=False)
    monkeypatch.delenv(V4_SECRET_POLICY_ACTION_FEATURE_ENV, raising=False)
    monkeypatch.delenv(V4_SSH_FILTER_ACTION_FEATURE_ENV, raising=False)
    monkeypatch.delenv(V4_DEPENDENCY_UPDATER_ACTION_FEATURE_ENV, raising=False)
    monkeypatch.delenv(V4_SECRET_GATEWAY_ACTION_FEATURE_ENV, raising=False)
    monkeypatch.delenv(V4_CLIENT_INTEGRITY_ACTION_FEATURE_ENV, raising=False)
    monkeypatch.delenv(V4_CHARACTER_SET_ACTION_FEATURE_ENV, raising=False)
    monkeypatch.delenv(V4_PASSWORD_POLICY_ACTION_FEATURE_ENV, raising=False)
    monkeypatch.delenv(V4_ZTNA_ACCESS_PROXY_ACTION_FEATURE_ENV, raising=False)
    monkeypatch.delenv(V4_AUTOMATION_TRIGGER_ACTION_FEATURE_ENV, raising=False)
    monkeypatch.delenv(V4_AUTOMATION_ACTION_ACTION_FEATURE_ENV, raising=False)
    monkeypatch.delenv(V4_AUTOMATION_STITCH_ACTION_FEATURE_ENV, raising=False)
    monkeypatch.delenv(V4_USER_GROUP_ACTION_FEATURE_ENV, raising=False)
    monkeypatch.delenv(V4_APL_DISABLE_ACTION_FEATURE_ENV, raising=False)
    monkeypatch.delenv(V4_SCHEDULE_ACTION_FEATURE_ENV, raising=False)
    monkeypatch.delenv(V4_APPROVAL_PROFILE_ACTION_FEATURE_ENV, raising=False)
    monkeypatch.delenv(V4_APPROVAL_PROFILE_UPDATE_ACTION_FEATURE_ENV, raising=False)
    monkeypatch.delenv(V4_APPROVAL_EMAIL_TEMPLATE_ACTION_FEATURE_ENV, raising=False)
    monkeypatch.delenv(
        V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION_FEATURE_ENV,
        raising=False,
    )

    assert load_http_runtime_environment() is True
    assert os.environ[f"{PREFIX}AUTH_MODE"] == "bearer"
    assert os.environ[f"{PREFIX}BEARER_TOKEN"] == TEST_TOKEN
    assert os.environ[RUNTIME_PROFILE_ENV] == "lab-simulated"
    assert os.environ["FORTIPAM_MCP_DIAGNOSTIC_DB"] == "/protected/diagnostic.sqlite3"
    assert os.environ[HA_RECONCILIATION_FEATURE_ENV] == "true"
    assert (
        os.environ[HA_RECONCILIATION_PREREQUISITES_ENV]
        == "/protected/ha-prerequisites.json"
    )
    assert (
        os.environ[HA_RECONCILIATION_QUERY_PERMISSION_ENV]
        == "/protected/ha-query-permission.json"
    )
    assert os.environ[V4_TARGET_ACTION_FEATURE_ENV] == "true"
    assert os.environ[V4_TARGET_DELETE_ACTION_FEATURE_ENV] == "true"
    assert os.environ[V4_TARGET_DELETE_EXECUTION_ENV] == "false"
    assert os.environ[V4_TARGET_DELETE_TARGET_ENV].startswith("mcp-v4-target-")
    assert os.environ[V4_TARGET_DELETE_TAG_ENV].startswith(
        "mcp-v4-classification-tag-"
    )
    assert os.environ[V4_TARGET_DELETE_ACCEPTED_DIGEST_ENV] == "b" * 64
    assert os.environ["FPA_HOME_LAB_FPA1_V4_TARGET_ENABLED"] == "true"
    assert os.environ[V4_CLASSIFICATION_TAG_ACTION_FEATURE_ENV] == "true"
    assert os.environ[V4_CLASSIFICATION_TAG_DELETE_ACTION_FEATURE_ENV] == "true"
    assert os.environ[V4_CLASSIFICATION_TAG_DELETE_EXECUTION_ENV] == "false"
    assert os.environ[V4_CLASSIFICATION_TAG_DELETE_TAG_ENV].startswith(
        "mcp-v4-classification-tag-"
    )
    assert os.environ[V4_CLASSIFICATION_TAG_DELETE_TARGET_ENV].startswith(
        "mcp-v4-target-"
    )
    assert os.environ[V4_CLASSIFICATION_TAG_DELETE_ACCEPTED_DIGEST_ENV] == "a" * 64
    assert os.environ[V4_ADDRESS_ACTION_FEATURE_ENV] == "true"
    assert os.environ[V4_ADDRESS_GROUP_ACTION_FEATURE_ENV] == "true"
    assert os.environ[V4_DLP_SENSOR_ACTION_FEATURE_ENV] == "true"
    assert os.environ[V4_ANTIVIRUS_PROFILE_ACTION_FEATURE_ENV] == "true"
    assert os.environ[V4_RDP_EVENT_FILTER_ACTION_FEATURE_ENV] == "true"
    assert os.environ[V4_SECRET_POLICY_ACTION_FEATURE_ENV] == "true"
    assert os.environ[V4_SSH_FILTER_ACTION_FEATURE_ENV] == "true"
    assert os.environ[V4_DEPENDENCY_UPDATER_ACTION_FEATURE_ENV] == "true"
    assert os.environ[V4_SECRET_GATEWAY_ACTION_FEATURE_ENV] == "true"
    assert os.environ[V4_CLIENT_INTEGRITY_ACTION_FEATURE_ENV] == "true"
    assert os.environ[V4_CHARACTER_SET_ACTION_FEATURE_ENV] == "true"
    assert os.environ[V4_PASSWORD_POLICY_ACTION_FEATURE_ENV] == "true"
    assert os.environ[V4_ZTNA_ACCESS_PROXY_ACTION_FEATURE_ENV] == "true"
    assert os.environ[V4_AUTOMATION_TRIGGER_ACTION_FEATURE_ENV] == "true"
    assert os.environ[V4_AUTOMATION_ACTION_ACTION_FEATURE_ENV] == "true"
    assert os.environ[V4_AUTOMATION_STITCH_ACTION_FEATURE_ENV] == "true"
    assert os.environ[V4_USER_GROUP_ACTION_FEATURE_ENV] == "true"
    assert os.environ[V4_APL_DISABLE_ACTION_FEATURE_ENV] == "true"
    assert os.environ[V4_SCHEDULE_ACTION_FEATURE_ENV] == "true"
    assert os.environ[V4_APPROVAL_PROFILE_ACTION_FEATURE_ENV] == "true"
    assert os.environ[V4_APPROVAL_PROFILE_UPDATE_ACTION_FEATURE_ENV] == "true"
    assert os.environ[V4_APPROVAL_EMAIL_TEMPLATE_ACTION_FEATURE_ENV] == "true"
    assert os.environ[V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION_FEATURE_ENV] == "true"
    assert "UNRELATED_SECRET" not in os.environ
    os.environ.pop(RUNTIME_PROFILE_ENV, None)


def test_streamable_http_requires_bearer_and_lists_frozen_tool_surface() -> None:
    settings = HttpServerSettings.from_environment(_bearer_environment())
    assert settings.runtime_profile is RuntimeProfile.READONLY

    with TestClient(create_http_app(settings)) as client:
        unauthorized = client.post(
            settings.path,
            headers={
                key: value
                for key, value in _request_headers().items()
                if key != "authorization"
            },
            json=_initialize_payload(),
        )
        initialized = client.post(
            settings.path,
            headers=_request_headers(),
            json=_initialize_payload(),
        )
        tools = client.post(
            settings.path,
            headers=_request_headers(),
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        rejected_host = client.post(
            settings.path,
            headers={**_request_headers(), "host": "untrusted.example"},
            json=_initialize_payload(),
        )

    assert unauthorized.status_code == 401
    assert unauthorized.headers["cache-control"] == "no-store"
    assert initialized.status_code == 200
    assert initialized.json()["result"]["serverInfo"]["version"] == __version__
    assert tools.status_code == 200
    assert {tool["name"] for tool in tools.json()["result"]["tools"]} == set(
        EXPECTED_TOOLS
    )
    assert rejected_host.status_code == 421


def test_streamable_http_lab_profile_is_explicit_and_offline(monkeypatch) -> None:
    def _unexpected_environment_load() -> None:
        raise AssertionError("Listing HTTP LAB tools must not load credentials.")

    monkeypatch.setattr(
        server_module,
        "load_runtime_environment",
        _unexpected_environment_load,
    )
    settings = HttpServerSettings.from_environment(
        _bearer_environment(**{RUNTIME_PROFILE_ENV: "lab-simulated"})
    )
    assert settings.runtime_profile is RuntimeProfile.LAB_SIMULATED

    with TestClient(create_http_app(settings)) as client:
        initialized = client.post(
            settings.path,
            headers=_request_headers(),
            json=_initialize_payload(),
        )
        tools = client.post(
            settings.path,
            headers=_request_headers(),
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )

    assert initialized.status_code == 200
    assert tools.status_code == 200
    assert {tool["name"] for tool in tools.json()["result"]["tools"]} == set(
        LAB_EXPECTED_TOOLS
    )
    assert len(tools.json()["result"]["tools"]) == 34


def test_v4_plan_profile_requires_oauth_and_owner_only_principal_key(
    tmp_path: Path,
) -> None:
    with pytest.raises(HttpConfigurationError, match="requires embedded local OAuth"):
        HttpServerSettings.from_environment(
            _bearer_environment(**{RUNTIME_PROFILE_ENV: "v4-plan-only"})
        )

    external_oauth = {
        f"{PREFIX}AUTH_MODE": "oauth",
        f"{PREFIX}PATH": "/fpamcp",
        f"{PREFIX}PUBLIC_URL": "https://mcp.example.com/fpamcp",
        f"{PREFIX}OAUTH_ISSUER": "https://id.example.com",
        f"{PREFIX}OAUTH_JWKS_URL": "https://id.example.com/.well-known/jwks.json",
        f"{PREFIX}OAUTH_AUDIENCE": "https://mcp.example.com/fpamcp",
        RUNTIME_PROFILE_ENV: "v4-plan-only",
    }
    with pytest.raises(HttpConfigurationError, match="requires embedded local OAuth"):
        HttpServerSettings.from_environment(external_oauth)

    environment = _local_oauth_environment(tmp_path)
    environment[RUNTIME_PROFILE_ENV] = "v4-plan-only"
    with pytest.raises(HttpConfigurationError, match="authorization denied"):
        HttpServerSettings.from_environment(environment)


def test_v4_controlled_profile_allows_independent_features_and_requires_bound_folder_action(
    tmp_path: Path,
) -> None:
    disabled = _v4_environment(tmp_path / "disabled")
    disabled[RUNTIME_PROFILE_ENV] = "v4-controlled"
    disabled_settings = HttpServerSettings.from_environment(disabled)
    assert disabled_settings.v4_folder_action_enabled is False
    assert create_http_app(disabled_settings) is not None

    wrong_profile = _v4_environment(tmp_path / "wrong-profile")
    wrong_profile[V4_FOLDER_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_environment(tmp_path / "invalid")
    invalid[V4_FOLDER_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    settings = HttpServerSettings.from_environment(
        _v4_controlled_environment(tmp_path / "controlled")
    )
    assert settings.runtime_profile is RuntimeProfile.V4_CONTROLLED
    assert settings.v4_folder_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="bound action host"):
        create_http_app(settings)

    app = create_http_app(settings, v4_folder_action=object())
    assert app is not None


def test_v4_target_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-target")
    wrong_profile[V4_TARGET_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-target")
    invalid[V4_TARGET_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-target")
    environment[V4_TARGET_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_target_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="Target feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_target_action=object(),
    )
    assert app is not None


def test_v4_secret_metadata_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-secret-metadata")
    wrong_profile[V4_SECRET_METADATA_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-secret-metadata")
    invalid[V4_SECRET_METADATA_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-secret-metadata")
    environment[V4_SECRET_METADATA_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_secret_metadata_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="Secret metadata feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_secret_metadata_action=object(),
    )
    assert app is not None


def test_v4_interface_web_proxy_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-interface-web-proxy")
    wrong_profile[V4_INTERFACE_WEB_PROXY_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-interface-web-proxy")
    invalid[V4_INTERFACE_WEB_PROXY_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-interface-web-proxy")
    environment[V4_INTERFACE_WEB_PROXY_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_interface_web_proxy_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="interface Explicit Web Proxy feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_interface_web_proxy_action=object(),
    )
    assert app is not None


def test_v4_target_update_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-target-update")
    wrong_profile[V4_TARGET_UPDATE_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-target-update")
    invalid[V4_TARGET_UPDATE_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-target-update")
    environment[V4_TARGET_UPDATE_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_target_update_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="Target update feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_target_update_action=object(),
    )
    assert app is not None


def test_v4_certificate_csr_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-certificate-csr")
    wrong_profile[V4_CERTIFICATE_CSR_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-certificate-csr")
    invalid[V4_CERTIFICATE_CSR_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-certificate-csr")
    environment[V4_CERTIFICATE_CSR_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_certificate_csr_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="certificate CSR feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_certificate_csr_action=object(),
    )
    assert app is not None


def test_main_redacts_target_update_action_configuration_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = SimpleNamespace(
        v4_confirmation=None,
        v4_folder_action_enabled=False,
        v4_folder_acl_action_enabled=False,
        v4_folder_acl_revoke_action_enabled=False,
        v4_classification_tag_action_enabled=False,
        v4_address_action_enabled=False,
        v4_address_group_action_enabled=False,
        v4_folder_rename_action_enabled=False,
        v4_folder_policy_assign_action_enabled=False,
        v4_folder_policy_detach_action_enabled=False,
        v4_target_action_enabled=False,
        v4_target_update_action_enabled=True,
        v4_local_user_disable_action_enabled=False,
        v4_local_user_create_action_enabled=False,
    )
    monkeypatch.setattr(http_server_module, "load_http_runtime_environment", lambda: False)
    monkeypatch.setattr(
        http_server_module.HttpServerSettings,
        "from_environment",
        classmethod(lambda cls: settings),
    )

    def _raise_configuration_error(_: object) -> object:
        raise V4TargetUpdateActionConfigurationError(
            "FortiPAM V4 Target update action is unavailable."
        )

    monkeypatch.setattr(
        http_server_module,
        "build_v4_target_update_action",
        _raise_configuration_error,
    )

    with pytest.raises(SystemExit, match="Target update action is unavailable"):
        http_server_module.main()


def test_main_redacts_address_group_action_configuration_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = SimpleNamespace(
        v4_confirmation=None,
        v4_folder_action_enabled=False,
        v4_folder_acl_action_enabled=False,
        v4_folder_acl_revoke_action_enabled=False,
        v4_classification_tag_action_enabled=False,
        v4_address_action_enabled=False,
        v4_address_group_action_enabled=True,
        v4_folder_rename_action_enabled=False,
        v4_folder_policy_assign_action_enabled=False,
        v4_target_action_enabled=False,
        v4_target_update_action_enabled=False,
        v4_local_user_disable_action_enabled=False,
        v4_local_user_create_action_enabled=False,
    )
    monkeypatch.setattr(http_server_module, "load_http_runtime_environment", lambda: False)
    monkeypatch.setattr(
        http_server_module.HttpServerSettings,
        "from_environment",
        classmethod(lambda cls: settings),
    )

    def _raise_configuration_error(_: object) -> object:
        raise V4AddressGroupActionConfigurationError(
            "FortiPAM V4 Address Group action is unavailable."
        )

    monkeypatch.setattr(
        http_server_module,
        "build_v4_address_group_action",
        _raise_configuration_error,
    )

    with pytest.raises(SystemExit, match="Address Group action is unavailable"):
        http_server_module.main()


def test_main_composes_source_backed_approval_host_and_request_create_action(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment, _ = _v4_bound_environment(tmp_path)
    environment[RUNTIME_PROFILE_ENV] = "v4-controlled"
    environment[V4_SECRET_REQUEST_CREATE_FEATURE_ENV] = "true"
    environment["FORTIPAM_MCP_V4_PLAN_HOST_MODE"] = (
        "source-backed-approval-and-observe"
    )
    settings = HttpServerSettings.from_environment(environment)
    binding_path = tmp_path / "approval-and-observe-binding.json"
    request_binding_path = tmp_path / "request-observation-binding.json"
    host_settings = SimpleNamespace(
        host_mode="source-backed-approval-and-observe",
        approval_and_observe_binding_path=binding_path,
        secret_request_observation_binding_path=request_binding_path,
    )
    secret_config = object()
    secret_transport = object()
    approval_transport = object()
    binding_resolver = object()
    request_transport = object()
    request_binding_resolver = object()
    request_observation = object()
    request_create_action = object()
    plan_host_factory = object()
    app = object()
    captured: dict[str, object] = {}

    monkeypatch.setattr(
        http_server_module,
        "load_http_runtime_environment",
        lambda: False,
    )
    monkeypatch.setattr(
        http_server_module.HttpServerSettings,
        "from_environment",
        classmethod(lambda cls: settings),
    )
    monkeypatch.setattr(
        http_server_module,
        "synthetic_host_settings_from_environment",
        lambda environment: host_settings,
    )
    monkeypatch.setattr(
        http_server_module,
        "load_secret_metadata_http_transport_config",
        lambda environment: secret_config,
    )
    monkeypatch.setattr(
        http_server_module,
        "FortiPamSecretMetadataHttpTransport",
        lambda config: secret_transport,
    )
    monkeypatch.setattr(
        http_server_module,
        "FortiPamApprovalProfileHttpTransport",
        lambda config: approval_transport,
    )
    monkeypatch.setattr(
        http_server_module,
        "load_approval_profile_ssh_transport_config",
        lambda environment: (_ for _ in ()).throw(
            AssertionError("BP008 HTTP host must not load an SSH credential")
        ),
    )
    monkeypatch.setattr(
        http_server_module,
        "OwnerOnlyApprovalAndObserveBindingResolver",
        lambda path: binding_resolver,
    )
    monkeypatch.setattr(
        http_server_module,
        "build_v4_secret_request_observation_transport",
        lambda config, environment: request_transport,
    )
    monkeypatch.setattr(
        http_server_module,
        "OwnerOnlySecretRequestObservationBindingResolver",
        lambda path: request_binding_resolver,
    )
    monkeypatch.setattr(
        http_server_module,
        "ProtectedSecretRequestMcpObservation",
        lambda transport, resolver: (
            request_observation
            if transport is request_transport and resolver is request_binding_resolver
            else None
        ),
    )

    def _build_plan_host_factory(
        actual_host_settings: object,
        **dependencies: object,
    ) -> object:
        captured["host_settings"] = actual_host_settings
        captured.update(dependencies)
        return plan_host_factory

    monkeypatch.setattr(
        http_server_module,
        "approval_and_observe_v4_plan_host_factory",
        _build_plan_host_factory,
    )

    def _build_request_create_action(actual_environment: object) -> object:
        assert actual_environment is os.environ
        return request_create_action

    monkeypatch.setattr(
        http_server_module,
        "build_v4_secret_request_create_action",
        _build_request_create_action,
    )

    def _create_http_app(
        actual_settings: object,
        **components: object,
    ) -> object:
        captured["settings"] = actual_settings
        captured["plan_host_factory"] = components["v4_plan_host_factory"]
        captured["request_observation"] = components[
            "v4_secret_request_observation"
        ]
        captured["request_create_action"] = components[
            "v4_secret_request_create_action"
        ]
        return app

    monkeypatch.setattr(http_server_module, "create_http_app", _create_http_app)

    class _Config:
        def __init__(self, actual_app: object, **options: object) -> None:
            assert actual_app is app

    class _Server:
        def __init__(self, config: _Config) -> None:
            self.config = config

        async def serve(self) -> None:
            captured["served"] = True

    monkeypatch.setitem(
        sys.modules,
        "uvicorn",
        SimpleNamespace(Config=_Config, Server=_Server),
    )

    http_server_module.main()

    assert captured == {
        "host_settings": host_settings,
        "secret_transport": secret_transport,
        "approval_profile_transport": approval_transport,
        "binding_resolver": binding_resolver,
        "settings": settings,
        "plan_host_factory": plan_host_factory,
        "request_observation": request_observation,
        "request_create_action": request_create_action,
        "served": True,
    }


def test_v4_folder_acl_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-folder-acl")
    wrong_profile[V4_FOLDER_ACL_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-folder-acl")
    invalid[V4_FOLDER_ACL_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-folder-acl")
    environment[V4_FOLDER_ACL_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_folder_acl_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="Folder ACL feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_folder_acl_action=object(),
    )
    assert app is not None


def test_v4_folder_acl_revoke_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-folder-acl-revoke")
    wrong_profile[V4_FOLDER_ACL_REVOKE_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-folder-acl-revoke")
    invalid[V4_FOLDER_ACL_REVOKE_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-folder-acl-revoke")
    environment[V4_FOLDER_ACL_REVOKE_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_folder_acl_revoke_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="Folder ACL revoke feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_folder_acl_revoke_action=object(),
    )
    assert app is not None


def test_v4_classification_tag_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-classification-tag")
    wrong_profile[V4_CLASSIFICATION_TAG_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-classification-tag")
    invalid[V4_CLASSIFICATION_TAG_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-classification-tag")
    environment[V4_CLASSIFICATION_TAG_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_classification_tag_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="Classification Tag feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_classification_tag_action=object(),
    )
    assert app is not None


def test_v4_classification_tag_assign_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-tag-assign")
    wrong_profile[V4_CLASSIFICATION_TAG_ASSIGN_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-tag-assign")
    invalid[V4_CLASSIFICATION_TAG_ASSIGN_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-tag-assign")
    environment[V4_CLASSIFICATION_TAG_ASSIGN_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_classification_tag_assign_action_enabled is True
    with pytest.raises(
        HttpConfigurationError,
        match="Classification Tag assignment feature requires",
    ):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_classification_tag_assign_action=object(),
    )
    assert app is not None


def test_v4_address_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-address")
    wrong_profile[V4_ADDRESS_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-address")
    invalid[V4_ADDRESS_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-address")
    environment[V4_ADDRESS_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_address_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="IPv4 Address feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_address_action=object(),
    )
    assert app is not None


def test_v4_address_group_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-address-group")
    wrong_profile[V4_ADDRESS_GROUP_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-address-group")
    invalid[V4_ADDRESS_GROUP_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-address-group")
    environment[V4_ADDRESS_GROUP_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_address_group_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="Address Group feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_address_group_action=object(),
    )
    assert app is not None


def test_v4_ztna_diagnostic_feature_requires_v4_http_profile_and_bound_host(
    tmp_path: Path,
) -> None:
    wrong_profile = _local_oauth_environment(tmp_path / "wrong-profile-ztna-diagnostic")
    wrong_profile[V4_ZTNA_DEVICE_CONTEXT_DIAGNOSTIC_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by a V4 HTTP profile"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_environment(tmp_path / "invalid-ztna-diagnostic")
    invalid[V4_ZTNA_DEVICE_CONTEXT_DIAGNOSTIC_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_environment(tmp_path / "plan-only-ztna-diagnostic")
    environment[V4_ZTNA_DEVICE_CONTEXT_DIAGNOSTIC_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.runtime_profile is RuntimeProfile.V4_PLAN_ONLY
    assert settings.v4_folder_action_enabled is False
    assert settings.v4_ztna_device_context_diagnostic_enabled is True
    with pytest.raises(HttpConfigurationError, match="requires a bound diagnostic host"):
        create_http_app(settings)

    app = create_http_app(
        settings,
        v4_ztna_device_context_diagnostic=object(),
    )
    assert app is not None


def test_v4_ha_reconciliation_feature_requires_v4_oauth_diagnostics_and_providers(
    tmp_path: Path,
) -> None:
    default = HttpServerSettings.from_environment(
        _v4_environment(tmp_path / "default-ha-reconciliation")
    )
    assert default.v4_ha_reconciliation_enabled is False
    assert default.v4_ha_reconciliation_prerequisite_provider is None
    assert default.v4_ha_reconciliation_query_permission_provider is None

    wrong_profile = _diagnostic_environment(tmp_path / "wrong-profile-ha")
    wrong_profile[HA_RECONCILIATION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by a V4 HTTP profile"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_environment(tmp_path / "invalid-ha-reconciliation")
    invalid[HA_RECONCILIATION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    missing = _v4_ha_reconciliation_environment(tmp_path / "missing-ha-provider")
    missing.pop(HA_RECONCILIATION_QUERY_PERMISSION_ENV)
    with pytest.raises(HttpConfigurationError, match="both owner-only provider files"):
        HttpServerSettings.from_environment(missing)

    disabled = _v4_ha_reconciliation_environment(tmp_path / "disabled-ha")
    disabled[HA_RECONCILIATION_FEATURE_ENV] = "false"
    with pytest.raises(HttpConfigurationError, match="feature is disabled"):
        HttpServerSettings.from_environment(disabled)

    enabled = HttpServerSettings.from_environment(
        _v4_ha_reconciliation_environment(tmp_path / "enabled-ha")
    )
    assert enabled.v4_ha_reconciliation_enabled is True
    assert enabled.diagnostic is not None
    assert enabled.v4_ha_reconciliation_prerequisite_provider is not None
    assert enabled.v4_ha_reconciliation_query_permission_provider is not None
    assert create_http_app(enabled) is not None


def test_v4_ha_reconciliation_executes_through_oauth_mcp_with_synthetic_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        server_module.FortiPamMcpServer,
        "_require_device_tools",
        lambda self: _FixedDeviceTools(),
    )
    monkeypatch.setattr(
        server_module.FortiPamMcpServer,
        "_require_cli_tools",
        lambda self: _FixedCliTools(),
    )
    settings = HttpServerSettings.from_environment(
        _v4_ha_reconciliation_environment(tmp_path)
    )
    scope = "fortipam:read fortipam:diagnostic"

    with TestClient(
        create_http_app(settings),
        base_url="https://mcp.example.com",
    ) as client:
        client_id = _register_public_client(client, scope)
        code, verifier = _authorize_and_login(client, client_id, scope)
        token_response = client.post(
            "/fpamcp/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": code,
                "code_verifier": verifier,
                "redirect_uri": "https://client.example/callback",
                "resource": "https://mcp.example.com/fpamcp",
            },
        )
        assert token_response.status_code == 200
        headers = _request_headers(token_response.json()["access_token"])
        headers["host"] = "mcp.example.com"

        tools_response = client.post(
            "/fpamcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": "ha-tools",
                "method": "tools/list",
                "params": {},
            },
        )
        assert tools_response.status_code == 200
        tools = tools_response.json()["result"]["tools"]
        tool = next(
            item
            for item in tools
            if item["name"] == "get_v4_ha_reconciliation_assessment"
        )
        assert tool["inputSchema"] == {
            "additionalProperties": False,
            "properties": {},
            "title": "get_v4_ha_reconciliation_assessmentArguments",
            "type": "object",
        }

        result_response = client.post(
            "/fpamcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": "ha-assessment",
                "method": "tools/call",
                "params": {
                    "name": "get_v4_ha_reconciliation_assessment",
                    "arguments": {},
                },
            },
        )
        assert result_response.status_code == 200
        result = result_response.json()["result"]
        assert result["isError"] is False
        assert result["structuredContent"] == {
            "status": "eligible_for_operator_review"
        }

        info_response = client.post(
            "/fpamcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": "server-info",
                "method": "tools/call",
                "params": {"name": "get_server_info", "arguments": {}},
            },
        )
        info = info_response.json()["result"]["structuredContent"]
        assert info["v4_ha_reconciliation_bound"] is True
        assert info["v4_ha_reconciliation_tool_count"] == 1
        assert info["device_write_enabled"] is False


def test_v4_ztna_folder_posture_feature_requires_v4_http_profile_and_bound_host(
    tmp_path: Path,
) -> None:
    wrong_profile = _local_oauth_environment(tmp_path / "wrong-profile-ztna-folder-posture")
    wrong_profile["FORTIPAM_MCP_V4_ZTNA_FOLDER_POSTURE_ENABLED"] = "true"
    with pytest.raises(HttpConfigurationError, match="only by a V4 HTTP profile"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_environment(tmp_path / "invalid-ztna-folder-posture")
    invalid["FORTIPAM_MCP_V4_ZTNA_FOLDER_POSTURE_ENABLED"] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_environment(tmp_path / "plan-only-ztna-folder-posture")
    environment["FORTIPAM_MCP_V4_ZTNA_FOLDER_POSTURE_ENABLED"] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.runtime_profile is RuntimeProfile.V4_PLAN_ONLY
    assert settings.v4_ztna_folder_posture_enabled is True
    with pytest.raises(HttpConfigurationError, match="requires a bound diagnostic host"):
        create_http_app(settings)

    app = create_http_app(settings, v4_ztna_folder_posture=object())
    assert app is not None


def test_v4_folder_rename_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-folder-rename")
    wrong_profile[V4_FOLDER_RENAME_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-folder-rename")
    invalid[V4_FOLDER_RENAME_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-folder-rename")
    environment[V4_FOLDER_RENAME_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_folder_rename_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="Folder rename feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_folder_rename_action=object(),
    )
    assert app is not None


def test_v4_folder_archive_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-folder-archive")
    wrong_profile[V4_FOLDER_ARCHIVE_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-folder-archive")
    invalid[V4_FOLDER_ARCHIVE_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-folder-archive")
    environment[V4_FOLDER_ARCHIVE_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_folder_archive_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="Folder archive feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_folder_archive_action=object(),
    )
    assert app is not None


def test_v4_folder_policy_assignment_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-folder-policy-assign")
    wrong_profile[V4_FOLDER_POLICY_ASSIGN_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-folder-policy-assign")
    invalid[V4_FOLDER_POLICY_ASSIGN_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-folder-policy-assign")
    environment[V4_FOLDER_POLICY_ASSIGN_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_folder_policy_assign_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="Folder policy assignment feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_folder_policy_assign_action=object(),
    )
    assert app is not None


def test_v4_folder_policy_detach_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-folder-policy-detach")
    wrong_profile[V4_FOLDER_POLICY_DETACH_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-folder-policy-detach")
    invalid[V4_FOLDER_POLICY_DETACH_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-folder-policy-detach")
    environment[V4_FOLDER_POLICY_DETACH_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_folder_policy_detach_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="Folder policy detach feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_folder_policy_detach_action=object(),
    )
    assert app is not None


def test_v4_local_user_disable_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-local-user")
    wrong_profile[V4_LOCAL_USER_DISABLE_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-local-user")
    invalid[V4_LOCAL_USER_DISABLE_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-local-user")
    environment[V4_LOCAL_USER_DISABLE_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_local_user_disable_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="Local User disable feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_local_user_disable_action=object(),
    )
    assert app is not None


def test_v4_local_user_create_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-local-user-create")
    wrong_profile[V4_LOCAL_USER_CREATE_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-local-user-create")
    invalid[V4_LOCAL_USER_CREATE_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-local-user-create")
    environment[V4_LOCAL_USER_CREATE_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_local_user_create_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="Local User create feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_local_user_create_action=object(),
    )
    assert app is not None


def test_v4_local_user_reset_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-local-user-reset")
    wrong_profile[V4_LOCAL_USER_RESET_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-local-user-reset")
    invalid[V4_LOCAL_USER_RESET_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-local-user-reset")
    environment[V4_LOCAL_USER_RESET_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_local_user_reset_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="Local User reset feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_local_user_reset_action=object(),
    )
    assert app is not None


def test_v4_role_create_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-role-create")
    wrong_profile[V4_ROLE_CREATE_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-role-create")
    invalid[V4_ROLE_CREATE_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-role-create")
    environment[V4_ROLE_CREATE_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_role_create_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="Role create feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_role_create_action=object(),
    )
    assert app is not None


def test_v4_role_update_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-role-update")
    wrong_profile[V4_ROLE_UPDATE_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-role-update")
    invalid[V4_ROLE_UPDATE_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-role-update")
    environment[V4_ROLE_UPDATE_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_role_update_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="Role update feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_role_update_action=object(),
    )
    assert app is not None


def test_v4_role_assign_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-role-assign")
    wrong_profile[V4_ROLE_ASSIGN_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-role-assign")
    invalid[V4_ROLE_ASSIGN_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-role-assign")
    environment[V4_ROLE_ASSIGN_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_role_assign_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="Role assignment feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_role_assign_action=object(),
    )
    assert app is not None


def test_v4_dlp_file_pattern_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-dlp-file-pattern")
    wrong_profile[V4_DLP_FILE_PATTERN_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-dlp-file-pattern")
    invalid[V4_DLP_FILE_PATTERN_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-dlp-file-pattern")
    environment[V4_DLP_FILE_PATTERN_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_dlp_file_pattern_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="DLP file-pattern feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_dlp_file_pattern_action=object(),
    )
    assert app is not None


def test_v4_dlp_sensor_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-dlp-sensor")
    wrong_profile[V4_DLP_SENSOR_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-dlp-sensor")
    invalid[V4_DLP_SENSOR_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-dlp-sensor")
    environment[V4_DLP_SENSOR_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_dlp_sensor_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="DLP Sensor feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_dlp_sensor_action=object(),
    )
    assert app is not None


def test_v4_antivirus_profile_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-antivirus-profile")
    wrong_profile[V4_ANTIVIRUS_PROFILE_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-antivirus-profile")
    invalid[V4_ANTIVIRUS_PROFILE_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-antivirus-profile")
    environment[V4_ANTIVIRUS_PROFILE_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_antivirus_profile_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="AntiVirus Profile feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_antivirus_profile_action=object(),
    )
    assert app is not None


def test_v4_rdp_event_filter_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-rdp-event-filter")
    wrong_profile[V4_RDP_EVENT_FILTER_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-rdp-event-filter")
    invalid[V4_RDP_EVENT_FILTER_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-rdp-event-filter")
    environment[V4_RDP_EVENT_FILTER_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_rdp_event_filter_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="RDP event-filter feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_rdp_event_filter_action=object(),
    )
    assert app is not None


def test_v4_secret_policy_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-secret-policy")
    wrong_profile[V4_SECRET_POLICY_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-secret-policy")
    invalid[V4_SECRET_POLICY_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-secret-policy")
    environment[V4_SECRET_POLICY_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_secret_policy_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="Secret Policy feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_secret_policy_action=object(),
    )
    assert app is not None


def test_v4_ssh_filter_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-ssh-filter")
    wrong_profile[V4_SSH_FILTER_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-ssh-filter")
    invalid[V4_SSH_FILTER_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-ssh-filter")
    environment[V4_SSH_FILTER_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_ssh_filter_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="SSH Filter feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_ssh_filter_action=object(),
    )
    assert app is not None


def test_v4_launcher_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-launcher")
    wrong_profile[V4_LAUNCHER_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-launcher")
    invalid[V4_LAUNCHER_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-launcher")
    environment[V4_LAUNCHER_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_launcher_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="Launcher feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_launcher_action=object(),
    )
    assert app is not None


def test_v4_launcher_update_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-launcher-update")
    wrong_profile[V4_LAUNCHER_UPDATE_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-launcher-update")
    invalid[V4_LAUNCHER_UPDATE_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-launcher-update")
    environment[V4_LAUNCHER_UPDATE_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_launcher_update_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="Launcher update feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_launcher_update_action=object(),
    )
    assert app is not None


def test_v4_launcher_matcher_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-launcher-matcher")
    wrong_profile[V4_LAUNCHER_MATCHER_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-launcher-matcher")
    invalid[V4_LAUNCHER_MATCHER_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-launcher-matcher")
    environment[V4_LAUNCHER_MATCHER_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_launcher_matcher_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="Launcher matcher feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_launcher_matcher_action=object(),
    )
    assert app is not None


def test_v4_template_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-template")
    wrong_profile[V4_TEMPLATE_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-template")
    invalid[V4_TEMPLATE_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-template")
    environment[V4_TEMPLATE_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_template_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="Template feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_template_action=object(),
    )
    assert app is not None


def test_v4_template_archive_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-template-archive")
    wrong_profile[V4_TEMPLATE_ARCHIVE_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-template-archive")
    invalid[V4_TEMPLATE_ARCHIVE_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-template-archive")
    environment[V4_TEMPLATE_ARCHIVE_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_template_archive_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="Template archive feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_template_archive_action=object(),
    )
    assert app is not None


def test_v4_dependency_updater_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-dependency-updater")
    wrong_profile[V4_DEPENDENCY_UPDATER_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-dependency-updater")
    invalid[V4_DEPENDENCY_UPDATER_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-dependency-updater")
    environment[V4_DEPENDENCY_UPDATER_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_dependency_updater_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="Dependency Updater feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_dependency_updater_action=object(),
    )
    assert app is not None


def test_v4_secret_gateway_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-secret-gateway")
    wrong_profile[V4_SECRET_GATEWAY_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-secret-gateway")
    invalid[V4_SECRET_GATEWAY_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-secret-gateway")
    environment[V4_SECRET_GATEWAY_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_secret_gateway_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="Secret Gateway feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_secret_gateway_action=object(),
    )
    assert app is not None


def test_v4_client_integrity_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-client-integrity")
    wrong_profile[V4_CLIENT_INTEGRITY_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-client-integrity")
    invalid[V4_CLIENT_INTEGRITY_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-client-integrity")
    environment[V4_CLIENT_INTEGRITY_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_client_integrity_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="client-integrity feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_client_integrity_action=object(),
    )
    assert app is not None


def test_v4_ztna_access_proxy_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-ztna-access-proxy")
    wrong_profile[V4_ZTNA_ACCESS_PROXY_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-ztna-access-proxy")
    invalid[V4_ZTNA_ACCESS_PROXY_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-ztna-access-proxy")
    environment[V4_ZTNA_ACCESS_PROXY_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_ztna_access_proxy_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="ZTNA Access Proxy feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_ztna_access_proxy_action=object(),
    )
    assert app is not None


def test_v4_ztna_user_control_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-ztna-user-control")
    wrong_profile[V4_ZTNA_USER_CONTROL_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-ztna-user-control")
    invalid[V4_ZTNA_USER_CONTROL_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-ztna-user-control")
    environment[V4_ZTNA_USER_CONTROL_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_ztna_user_control_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="ZTNA user-control feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_ztna_user_control_action=object(),
    )
    assert app is not None


def test_v4_ztna_wad_debug_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-ztna-wad-debug")
    wrong_profile[V4_ZTNA_WAD_DEBUG_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-ztna-wad-debug")
    invalid[V4_ZTNA_WAD_DEBUG_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-ztna-wad-debug")
    environment[V4_ZTNA_WAD_DEBUG_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_ztna_wad_debug_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="ZTNA WAD debug feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_ztna_wad_debug_action=object(),
    )
    assert app is not None


def test_v4_snmp_agent_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-snmp-agent")
    wrong_profile[V4_SNMP_AGENT_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-snmp-agent")
    invalid[V4_SNMP_AGENT_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-snmp-agent")
    environment[V4_SNMP_AGENT_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_snmp_agent_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="SNMP agent feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_snmp_agent_action=object(),
    )
    assert app is not None


def test_v4_logging_disk_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-logging-disk")
    wrong_profile[V4_LOGGING_DISK_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-logging-disk")
    invalid[V4_LOGGING_DISK_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-logging-disk")
    environment[V4_LOGGING_DISK_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_logging_disk_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="logging-disk feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_logging_disk_action=object(),
    )
    assert app is not None


def test_v4_fortianalyzer_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-fortianalyzer")
    wrong_profile[V4_FORTIANALYZER_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-fortianalyzer")
    invalid[V4_FORTIANALYZER_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-fortianalyzer")
    environment[V4_FORTIANALYZER_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_fortianalyzer_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="FortiAnalyzer feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_fortianalyzer_action=object(),
    )
    assert app is not None


def test_v4_maintenance_mode_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-maintenance-mode")
    wrong_profile[V4_MAINTENANCE_MODE_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-maintenance-mode")
    invalid[V4_MAINTENANCE_MODE_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-maintenance-mode")
    environment[V4_MAINTENANCE_MODE_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_maintenance_mode_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="maintenance-mode feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_maintenance_mode_action=object(),
    )
    assert app is not None


def test_v4_secret_audit_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-secret-audit")
    wrong_profile[V4_SECRET_AUDIT_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-secret-audit")
    invalid[V4_SECRET_AUDIT_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-secret-audit")
    environment[V4_SECRET_AUDIT_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_secret_audit_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="Secret Audit feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_secret_audit_action=object(),
    )
    assert app is not None


def test_v4_secret_audit_summary_requires_controlled_profile_and_bound_reader(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-secret-audit-summary")
    wrong_profile[V4_SECRET_AUDIT_SUMMARY_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    environment = _v4_controlled_environment(tmp_path / "controlled-secret-audit-summary")
    environment[V4_SECRET_AUDIT_SUMMARY_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_secret_audit_summary_enabled is True
    with pytest.raises(HttpConfigurationError, match="feature and host must match"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_secret_audit_summary=object(),
    )
    assert app is not None


def test_v4_active_launch_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-active-launch")
    wrong_profile[V4_ACTIVE_LAUNCH_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-active-launch")
    invalid[V4_ACTIVE_LAUNCH_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-active-launch")
    environment[V4_ACTIVE_LAUNCH_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_active_launch_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="active-launch feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_active_launch_action=object(),
    )
    assert app is not None


def test_v4_character_set_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-character-set")
    wrong_profile[V4_CHARACTER_SET_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-character-set")
    invalid[V4_CHARACTER_SET_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-character-set")
    environment[V4_CHARACTER_SET_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_character_set_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="Character Set feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_character_set_action=object(),
    )
    assert app is not None


def test_v4_windows_app_filter_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-windows-app-filter")
    wrong_profile[V4_WINDOWS_APP_FILTER_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-windows-app-filter")
    invalid[V4_WINDOWS_APP_FILTER_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-windows-app-filter")
    environment[V4_WINDOWS_APP_FILTER_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_windows_app_filter_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="Windows App Filter feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_windows_app_filter_action=object(),
    )
    assert app is not None


def test_v4_recording_policy_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-recording-policy")
    wrong_profile[V4_RECORDING_POLICY_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-recording-policy")
    invalid[V4_RECORDING_POLICY_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-recording-policy")
    environment[V4_RECORDING_POLICY_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_recording_policy_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="Recording Policy feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_recording_policy_action=object(),
    )
    assert app is not None


def test_v4_password_policy_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-password-policy")
    wrong_profile[V4_PASSWORD_POLICY_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-password-policy")
    invalid[V4_PASSWORD_POLICY_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-password-policy")
    environment[V4_PASSWORD_POLICY_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_password_policy_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="Password Policy feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_password_policy_action=object(),
    )
    assert app is not None


def test_v4_report_layout_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-report-layout")
    wrong_profile[V4_REPORT_LAYOUT_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-report-layout")
    invalid[V4_REPORT_LAYOUT_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-report-layout")
    environment[V4_REPORT_LAYOUT_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_report_layout_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="Report Layout feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_report_layout_action=object(),
    )
    assert app is not None


def test_v4_automation_trigger_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-automation-trigger")
    wrong_profile[V4_AUTOMATION_TRIGGER_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-automation-trigger")
    invalid[V4_AUTOMATION_TRIGGER_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-automation-trigger")
    environment[V4_AUTOMATION_TRIGGER_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_automation_trigger_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="Automation Trigger feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_automation_trigger_action=object(),
    )
    assert app is not None


def test_v4_automation_action_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-automation-action")
    wrong_profile[V4_AUTOMATION_ACTION_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-automation-action")
    invalid[V4_AUTOMATION_ACTION_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-automation-action")
    environment[V4_AUTOMATION_ACTION_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_automation_action_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="Automation Action feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_automation_action_action=object(),
    )
    assert app is not None


def test_v4_automation_stitch_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-automation-stitch")
    wrong_profile[V4_AUTOMATION_STITCH_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-automation-stitch")
    invalid[V4_AUTOMATION_STITCH_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-automation-stitch")
    environment[V4_AUTOMATION_STITCH_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_automation_stitch_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="Automation Stitch feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_automation_stitch_action=object(),
    )
    assert app is not None


def test_v4_user_group_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-user-group")
    wrong_profile[V4_USER_GROUP_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-user-group")
    invalid[V4_USER_GROUP_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-user-group")
    environment[V4_USER_GROUP_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_user_group_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="User Group feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_user_group_action=object(),
    )
    assert app is not None


def test_v4_user_group_membership_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-user-group-membership")
    wrong_profile[V4_USER_GROUP_MEMBERSHIP_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-user-group-membership")
    invalid[V4_USER_GROUP_MEMBERSHIP_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(
        tmp_path / "controlled-user-group-membership"
    )
    environment[V4_USER_GROUP_MEMBERSHIP_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_user_group_membership_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="User Group membership feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_user_group_membership_action=object(),
    )
    assert app is not None


def test_v4_apl_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-apl")
    wrong_profile[V4_APL_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-apl")
    invalid[V4_APL_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-apl")
    environment[V4_APL_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_apl_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="Auto-Provision Rule feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_apl_action=object(),
    )
    assert app is not None


def test_v4_apl_disable_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-apl-disable")
    wrong_profile[V4_APL_DISABLE_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-apl-disable")
    invalid[V4_APL_DISABLE_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-apl-disable")
    environment[V4_APL_DISABLE_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_apl_disable_action_enabled is True
    with pytest.raises(
        HttpConfigurationError,
        match="Auto-Provision Rule disable feature requires",
    ):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_apl_disable_action=object(),
    )
    assert app is not None


def test_v4_schedule_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-schedule")
    wrong_profile[V4_SCHEDULE_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-schedule")
    invalid[V4_SCHEDULE_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-schedule")
    environment[V4_SCHEDULE_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_schedule_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="Schedule feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_schedule_action=object(),
    )
    assert app is not None


def test_v4_schedule_assign_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-schedule-assign")
    wrong_profile[V4_SCHEDULE_ASSIGN_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-schedule-assign")
    invalid[V4_SCHEDULE_ASSIGN_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-schedule-assign")
    environment[V4_SCHEDULE_ASSIGN_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_schedule_assign_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="Schedule assignment feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_schedule_assign_action=object(),
    )
    assert app is not None


def test_v4_approval_profile_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-approval-profile")
    wrong_profile[V4_APPROVAL_PROFILE_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-approval-profile")
    invalid[V4_APPROVAL_PROFILE_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "controlled-approval-profile")
    environment[V4_APPROVAL_PROFILE_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_approval_profile_action_enabled is True
    with pytest.raises(HttpConfigurationError, match="Approval Profile feature requires"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_approval_profile_action=object(),
    )
    assert app is not None


def test_v4_secret_request_create_requires_exact_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-request-create")
    wrong_profile[V4_SECRET_REQUEST_CREATE_FEATURE_ENV] = "true"
    wrong_profile["FORTIPAM_MCP_V4_PLAN_HOST_MODE"] = (
        "source-backed-approval-and-observe"
    )
    with pytest.raises(HttpConfigurationError, match="v4-controlled local OAuth"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-request-create")
    invalid[V4_SECRET_REQUEST_CREATE_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(tmp_path / "request-create")
    environment[V4_SECRET_REQUEST_CREATE_FEATURE_ENV] = "true"
    environment["FORTIPAM_MCP_V4_PLAN_HOST_MODE"] = (
        "source-backed-approval-and-observe"
    )
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_secret_request_create_enabled is True

    with pytest.raises(HttpConfigurationError, match="requires a bound action host"):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_secret_request_create_action=object(),
    )
    assert app is not None


def test_v4_approval_profile_update_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-approval-profile-update")
    wrong_profile[V4_APPROVAL_PROFILE_UPDATE_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-approval-profile-update")
    invalid[V4_APPROVAL_PROFILE_UPDATE_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(
        tmp_path / "controlled-approval-profile-update"
    )
    environment[V4_APPROVAL_PROFILE_UPDATE_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_approval_profile_update_action_enabled is True
    with pytest.raises(
        HttpConfigurationError,
        match="Approval Profile update feature requires",
    ):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_approval_profile_update_action=object(),
    )
    assert app is not None


def test_v4_approval_email_template_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(tmp_path / "wrong-profile-approval-email-template")
    wrong_profile[V4_APPROVAL_EMAIL_TEMPLATE_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(tmp_path / "invalid-approval-email-template")
    invalid[V4_APPROVAL_EMAIL_TEMPLATE_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(
        tmp_path / "controlled-approval-email-template"
    )
    environment[V4_APPROVAL_EMAIL_TEMPLATE_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_approval_email_template_action_enabled is True
    with pytest.raises(
        HttpConfigurationError,
        match="Approval Email Template feature requires",
    ):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_approval_email_template_action=object(),
    )
    assert app is not None


def test_v4_approval_email_template_update_feature_requires_controlled_profile_and_bound_action(
    tmp_path: Path,
) -> None:
    wrong_profile = _v4_environment(
        tmp_path / "wrong-profile-approval-email-template-update"
    )
    wrong_profile[V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION_FEATURE_ENV] = "true"
    with pytest.raises(HttpConfigurationError, match="only by the v4-controlled"):
        HttpServerSettings.from_environment(wrong_profile)

    invalid = _v4_controlled_environment(
        tmp_path / "invalid-approval-email-template-update"
    )
    invalid[V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION_FEATURE_ENV] = "TRUE"
    with pytest.raises(HttpConfigurationError, match="exactly true or false"):
        HttpServerSettings.from_environment(invalid)

    environment = _v4_controlled_environment(
        tmp_path / "controlled-approval-email-template-update"
    )
    environment[V4_APPROVAL_EMAIL_TEMPLATE_UPDATE_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_approval_email_template_update_action_enabled is True
    with pytest.raises(
        HttpConfigurationError,
        match="Approval Email Template update feature requires",
    ):
        create_http_app(settings, v4_folder_action=object())

    app = create_http_app(
        settings,
        v4_folder_action=object(),
        v4_approval_email_template_update_action=object(),
    )
    assert app is not None


def test_v4_controlled_http_action_rejects_plan_only_oauth_token(
    tmp_path: Path,
) -> None:
    class _Action:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def execute(
            self,
            authorization_ref: str,
            principal: object,
        ) -> dict[str, object]:
            self.calls.append((authorization_ref, principal))
            return {
                "contract": "fortipam_v4_child_folder_execution_v1",
                "outcome": "succeeded",
                "verification": "verified",
            }

    action = _Action()
    settings = HttpServerSettings.from_environment(
        _v4_controlled_environment(tmp_path)
    )

    with TestClient(
        create_http_app(settings, v4_folder_action=action),
        base_url="https://mcp.example.com",
    ) as client:
        def action_call(scope: str, request_id: str) -> dict[str, object]:
            client_id = _register_public_client(client, scope)
            code, verifier = _authorize_and_login(client, client_id, scope)
            token_response = client.post(
                "/fpamcp/oauth/token",
                data={
                    "grant_type": "authorization_code",
                    "client_id": client_id,
                    "code": code,
                    "code_verifier": verifier,
                    "redirect_uri": "https://client.example/callback",
                    "resource": "https://mcp.example.com/fpamcp",
                },
            )
            assert token_response.status_code == 200
            headers = _request_headers(token_response.json()["access_token"])
            headers["host"] = "mcp.example.com"
            response = client.post(
                "/fpamcp",
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": "tools/call",
                    "params": {
                        "name": "execute_confirmed_v4_child_folder",
                        "arguments": {
                            "authorization_ref": "folder-authorization-ref-0001"
                        },
                    },
                },
            )
            assert response.status_code == 200
            return response.json()["result"]

        plan_only = action_call(
            "fortipam:read fortipam:plan",
            "plan-only-denied",
        )
        controlled = action_call(
            "fortipam:read fortipam:plan fortipam:operate",
            "controlled-accepted",
        )

    assert plan_only["isError"] is True
    assert controlled["isError"] is False
    assert len(action.calls) == 1


def test_v4_target_preview_uses_plan_scope_but_confirmation_requires_operate(
    tmp_path: Path,
) -> None:
    class _TargetAction:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def preview(
            self,
            target_name: str,
            address: str,
            principal: object,
        ) -> dict[str, object]:
            del principal
            assert target_name == "mcp-target-01"
            assert address == "192.0.2.10"
            self.calls.append("preview")
            return {"preview_ref": "target-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            del principal
            assert preview_ref == "target-preview-00000001"
            self.calls.append("confirm")
            return {"authorization_ref": "target-authorized-00000001"}

    target_action = _TargetAction()
    environment = _v4_controlled_environment(tmp_path)
    environment[V4_TARGET_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)

    with TestClient(
        create_http_app(
            settings,
            v4_folder_action=object(),
            v4_target_action=target_action,
        ),
        base_url="https://mcp.example.com",
    ) as client:
        def target_call(
            scope: str,
            tool_name: str,
            arguments: dict[str, object],
            request_id: str,
        ) -> dict[str, object]:
            client_id = _register_public_client(client, scope)
            code, verifier = _authorize_and_login(client, client_id, scope)
            token_response = client.post(
                "/fpamcp/oauth/token",
                data={
                    "grant_type": "authorization_code",
                    "client_id": client_id,
                    "code": code,
                    "code_verifier": verifier,
                    "redirect_uri": "https://client.example/callback",
                    "resource": "https://mcp.example.com/fpamcp",
                },
            )
            assert token_response.status_code == 200
            headers = _request_headers(token_response.json()["access_token"])
            headers["host"] = "mcp.example.com"
            response = client.post(
                "/fpamcp",
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": "tools/call",
                    "params": {"name": tool_name, "arguments": arguments},
                },
            )
            assert response.status_code == 200
            return response.json()["result"]

        preview = target_call(
            "fortipam:read fortipam:plan",
            "preview_v4_ssh_target_create",
            {"target_name": "mcp-target-01", "address": "192.0.2.10"},
            "target-plan-preview",
        )
        denied_confirmation = target_call(
            "fortipam:read fortipam:plan",
            "confirm_v4_ssh_target_create",
            {"preview_ref": "target-preview-00000001"},
            "target-plan-confirm-denied",
        )
        confirmed = target_call(
            "fortipam:read fortipam:plan fortipam:operate",
            "confirm_v4_ssh_target_create",
            {"preview_ref": "target-preview-00000001"},
            "target-operate-confirmed",
        )

    assert preview["isError"] is False
    assert denied_confirmation["isError"] is True
    assert confirmed["isError"] is False
    assert target_action.calls == ["preview", "confirm"]


def test_v4_local_user_preview_uses_plan_scope_but_write_requires_operate(
    tmp_path: Path,
) -> None:
    class _LocalUserAction:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def preview(self, username: str, principal: object) -> dict[str, object]:
            del principal
            assert username == "mcp-user-01"
            self.calls.append("preview")
            return {"preview_ref": "local-user-preview-00000001"}

        def confirm(self, preview_ref: str, principal: object) -> dict[str, object]:
            del principal
            assert preview_ref == "local-user-preview-00000001"
            self.calls.append("confirm")
            return {"authorization_ref": "local-user-authorized-00000001"}

        def execute(self, authorization_ref: str, principal: object) -> dict[str, object]:
            del principal
            assert authorization_ref == "local-user-authorized-00000001"
            self.calls.append("execute")
            return {"outcome": "succeeded", "verification": "verified"}

    local_user_action = _LocalUserAction()
    environment = _v4_controlled_environment(tmp_path)
    environment[V4_LOCAL_USER_DISABLE_ACTION_FEATURE_ENV] = "true"
    settings = HttpServerSettings.from_environment(environment)

    with TestClient(
        create_http_app(
            settings,
            v4_folder_action=object(),
            v4_local_user_disable_action=local_user_action,
        ),
        base_url="https://mcp.example.com",
    ) as client:
        def local_user_call(
            scope: str,
            tool_name: str,
            arguments: dict[str, object],
            request_id: str,
        ) -> dict[str, object]:
            client_id = _register_public_client(client, scope)
            code, verifier = _authorize_and_login(client, client_id, scope)
            token_response = client.post(
                "/fpamcp/oauth/token",
                data={
                    "grant_type": "authorization_code",
                    "client_id": client_id,
                    "code": code,
                    "code_verifier": verifier,
                    "redirect_uri": "https://client.example/callback",
                    "resource": "https://mcp.example.com/fpamcp",
                },
            )
            assert token_response.status_code == 200
            headers = _request_headers(token_response.json()["access_token"])
            headers["host"] = "mcp.example.com"
            response = client.post(
                "/fpamcp",
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": "tools/call",
                    "params": {"name": tool_name, "arguments": arguments},
                },
            )
            assert response.status_code == 200
            return response.json()["result"]

        preview = local_user_call(
            "fortipam:read fortipam:plan",
            "preview_v4_local_user_disable",
            {"username": "mcp-user-01"},
            "local-user-plan-preview",
        )
        denied_confirmation = local_user_call(
            "fortipam:read fortipam:plan",
            "confirm_v4_local_user_disable",
            {"preview_ref": "local-user-preview-00000001"},
            "local-user-plan-confirm-denied",
        )
        confirmed = local_user_call(
            "fortipam:read fortipam:plan fortipam:operate",
            "confirm_v4_local_user_disable",
            {"preview_ref": "local-user-preview-00000001"},
            "local-user-operate-confirmed",
        )
        executed = local_user_call(
            "fortipam:read fortipam:plan fortipam:operate",
            "execute_confirmed_v4_local_user_disable",
            {"authorization_ref": "local-user-authorized-00000001"},
            "local-user-operate-executed",
        )

    assert preview["isError"] is False
    assert denied_confirmation["isError"] is True
    assert confirmed["isError"] is False
    assert executed["isError"] is False
    assert local_user_action.calls == ["preview", "confirm", "execute"]


@pytest.mark.parametrize(
    "missing_name",
    (
        "FORTIPAM_MCP_V4_PLAN_CONFIRMATION_DB",
        "FORTIPAM_MCP_V4_PLAN_CONFIRMATION_STORE_HMAC_KEY_FILE",
        "FORTIPAM_MCP_V4_PLAN_CONFIRMATION_RECEIPT_HMAC_KEY_FILE",
    ),
)
def test_v4_confirmation_configuration_is_all_or_nothing(
    tmp_path: Path,
    missing_name: str,
) -> None:
    environment = _v4_environment(tmp_path)
    environment.update(
        {
            "FORTIPAM_MCP_V4_PLAN_CONFIRMATION_DB": str(
                tmp_path / "confirmation.sqlite3"
            ),
            "FORTIPAM_MCP_V4_PLAN_CONFIRMATION_STORE_HMAC_KEY_FILE": str(
                tmp_path / "confirmation-store.hmac"
            ),
            "FORTIPAM_MCP_V4_PLAN_CONFIRMATION_RECEIPT_HMAC_KEY_FILE": str(
                tmp_path / "confirmation-receipt.hmac"
            ),
        }
    )
    del environment[missing_name]

    with pytest.raises(HttpConfigurationError, match="requires database"):
        HttpServerSettings.from_environment(environment)


def test_v4_confirmation_requires_bound_host_factory(tmp_path: Path) -> None:
    environment = _v4_environment(tmp_path)
    environment.update(
        {
            "FORTIPAM_MCP_V4_PLAN_CONFIRMATION_DB": str(
                tmp_path / "confirmation.sqlite3"
            ),
            "FORTIPAM_MCP_V4_PLAN_CONFIRMATION_STORE_HMAC_KEY_FILE": str(
                tmp_path / "confirmation-store.hmac"
            ),
            "FORTIPAM_MCP_V4_PLAN_CONFIRMATION_RECEIPT_HMAC_KEY_FILE": str(
                tmp_path / "confirmation-receipt.hmac"
            ),
        }
    )
    settings = HttpServerSettings.from_environment(environment)
    assert settings.v4_confirmation is not None

    with pytest.raises(HttpConfigurationError, match="bound plan-only host factory"):
        create_http_app(settings)


def test_v4_bound_http_app_exposes_mcp_and_pre_auth_confirmation_route(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import asyncio
    from fortipam_mcp.v4_runtime_host import _SyntheticProjectionProvider

    original_project = _SyntheticProjectionProvider.project

    def synchronous_transport_project(self, draft, requester, *, now_epoch):
        async def read_projection():
            return original_project(self, draft, requester, now_epoch=now_epoch)

        # SSH projection transports own an event loop for their bounded read.
        pending = read_projection()
        try:
            return asyncio.run(pending)
        finally:
            pending.close()

    monkeypatch.setattr(
        _SyntheticProjectionProvider, "project", synchronous_transport_project
    )
    environment, host_settings = _v4_bound_environment(tmp_path)
    settings = HttpServerSettings.from_environment(environment)
    factory = synthetic_v4_plan_host_factory(
        host_settings,
        clock=lambda: 1_950_000_000,
    )
    scope = "fortipam:read fortipam:plan"

    with TestClient(
        create_http_app(settings, v4_plan_host_factory=factory),
        base_url="https://mcp.example.com",
    ) as client:
        client_id = _register_public_client(client, scope)
        code, verifier = _authorize_and_login(client, client_id, scope)
        token_response = client.post(
            "/fpamcp/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": code,
                "code_verifier": verifier,
                "redirect_uri": "https://client.example/callback",
                "resource": "https://mcp.example.com/fpamcp",
            },
        )
        assert token_response.status_code == 200
        headers = _request_headers(token_response.json()["access_token"])
        headers["host"] = "mcp.example.com"
        preview_response = client.post(
            "/fpamcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "preview_v4_administrative_intent",
                    "arguments": {"scheme_draft_ref": V4_SYNTHETIC_SCHEME_REF},
                },
            },
        )
        assert preview_response.status_code == 200
        result = preview_response.json()["result"]
        assert result["isError"] is False
        preview = result["structuredContent"]
        confirmation_path = urlsplit(preview["confirmation_url"]).path

        page = client.get(confirmation_path)
        assert page.status_code == 200
        assert preview["summary_ref"] not in page.text
        assert "Reauthenticate" in page.text
        rejected_host = client.get(
            confirmation_path,
            headers={"host": "untrusted.example"},
        )
        assert rejected_host.status_code >= 400


def test_v4_http_status_uses_real_deny_all_private_runtime_pair_across_restart(
    tmp_path: Path,
) -> None:
    environment, base_host_settings = _v4_bound_environment(tmp_path)
    settings = HttpServerSettings.from_environment(environment)
    state = tmp_path / "private-runtime-pair"
    state.mkdir(mode=0o700)
    os.chmod(state, 0o700)
    checkpoint_state = state / "checkpoint"
    checkpoint_state.mkdir(mode=0o700)
    os.chmod(checkpoint_state, 0o700)
    material_state = state / "material"
    material_state.mkdir(mode=0o700)
    os.chmod(material_state, 0o700)
    checkpoint_key = checkpoint_state / "checkpoint.hmac"
    checkpoint_key.write_bytes(b"c" * 32)
    os.chmod(checkpoint_key, 0o600)
    material_key = material_state / "material.hmac"
    material_key.write_bytes(b"m" * 32)
    os.chmod(material_key, 0o600)
    socket_dir = Path(tempfile.mkdtemp(prefix="fhr-", dir="/tmp"))
    os.chmod(socket_dir, 0o700)
    checkpoint_socket = socket_dir / "checkpoint.sock"
    runtime_socket = socket_dir / "runtime.sock"
    readiness_socket = socket_dir / "readiness.sock"
    authority_ref = "v4-http-material-checkpoint"
    store_ref = "v4-http-secret-material-store"
    checkpoint_environment = {
        **os.environ,
        material_checkpoint_module.MATERIAL_CHECKPOINT_DATABASE_ENV: str(
            checkpoint_state / "checkpoint.sqlite3"
        ),
        material_checkpoint_module.MATERIAL_CHECKPOINT_HMAC_KEY_FILE_ENV: str(
            checkpoint_key
        ),
        material_checkpoint_module.MATERIAL_CHECKPOINT_AUTHORITY_REF_ENV: (
            authority_ref
        ),
        material_checkpoint_module.MATERIAL_CHECKPOINT_SOCKET_ENV: str(
            checkpoint_socket
        ),
        "PYTHONPATH": "src:.",
    }
    runtime_environment = {
        **os.environ,
        secret_runtime_module.SECRET_CREATE_RUNTIME_SOCKET_ENV: str(runtime_socket),
        secret_runtime_module.SECRET_CREATE_MATERIAL_DATABASE_ENV: str(
            material_state / "material.sqlite3"
        ),
        secret_runtime_module.SECRET_CREATE_MATERIAL_HMAC_KEY_FILE_ENV: str(
            material_key
        ),
        secret_runtime_module.SECRET_CREATE_MATERIAL_CHECKPOINT_SOCKET_ENV: str(
            checkpoint_socket
        ),
        secret_runtime_module.SECRET_CREATE_MATERIAL_CHECKPOINT_AUTHORITY_REF_ENV: (
            authority_ref
        ),
        secret_runtime_module.SECRET_CREATE_MATERIAL_CHECKPOINT_STORE_REF_ENV: (
            store_ref
        ),
        "PYTHONPATH": "src:.",
    }
    readiness_environment = {
        **os.environ,
        secret_readiness_module.SECRET_CREATE_READINESS_SOCKET_ENV: str(
            readiness_socket
        ),
        secret_readiness_module.SECRET_CREATE_PRIVATE_RUNTIME_SOCKET_ENV: str(
            runtime_socket
        ),
        "PYTHONPATH": "src:.",
    }
    checkpoint_process = _start_local_sidecar(
        "fortipam_mcp.material_checkpoint_sidecar",
        checkpoint_environment,
        checkpoint_socket,
    )
    runtime_process = _start_local_sidecar(
        "fortipam_mcp.secret_create_runtime_sidecar",
        runtime_environment,
        runtime_socket,
    )
    readiness_process = _start_local_sidecar(
        "fortipam_mcp.secret_create_readiness_sidecar",
        readiness_environment,
        readiness_socket,
    )
    try:
        host_settings = V4SyntheticHostSettings(
            base_host_settings.planning_database_path,
            base_host_settings.planning_hmac_key_path,
            secret_create_runtime=V4UnixSecretCreateRuntimeSettings(
                readiness_socket
            ),
        )
        factory = synthetic_v4_plan_host_factory(host_settings)

        def assert_status() -> None:
            nonlocal runtime_process
            with TestClient(
                create_http_app(settings, v4_plan_host_factory=factory),
                base_url="https://mcp.example.com",
            ) as client:
                scope = "fortipam:read fortipam:plan"
                client_id = _register_public_client(client, scope)
                code, verifier = _authorize_and_login(client, client_id, scope)
                token = client.post(
                    "/fpamcp/oauth/token",
                    data={
                        "grant_type": "authorization_code",
                        "client_id": client_id,
                        "code": code,
                        "code_verifier": verifier,
                        "redirect_uri": "https://client.example/callback",
                        "resource": "https://mcp.example.com/fpamcp",
                    },
                )
                headers = _request_headers(token.json()["access_token"])
                headers["host"] = "mcp.example.com"
                def read_status(request_id: int) -> dict[str, object]:
                    response = client.post(
                        "/fpamcp",
                        headers=headers,
                        json={
                            "jsonrpc": "2.0",
                            "id": request_id,
                            "method": "tools/call",
                            "params": {
                                "name": "get_v4_plan_status",
                                "arguments": {},
                            },
                        },
                    )
                    return response.json()["result"]["structuredContent"]

                content = read_status(1)
                assert content["secret_create_private_runtime_protocol_bound"] is False
                assert content["secret_create_readiness_proxy_protocol_bound"] is True
                assert content["secret_create_private_runtime_available"] is True
                assert content["dispatchable"] is False
                assert content["executor_mcp_exposed"] is False
                assert not any(
                    "secret_create_runtime" in name
                    for name in content["mcp_tool_names"]
                )

                _stop_local_sidecar(runtime_process, runtime_socket)
                unavailable = read_status(2)
                assert unavailable["secret_create_private_runtime_protocol_bound"] is False
                assert unavailable["secret_create_readiness_proxy_protocol_bound"] is True
                assert unavailable["secret_create_private_runtime_available"] is False
                assert unavailable["dispatchable"] is False
                runtime_process = _start_local_sidecar(
                    "fortipam_mcp.secret_create_runtime_sidecar",
                    runtime_environment,
                    runtime_socket,
                )
                recovered = read_status(3)
                assert recovered["secret_create_private_runtime_protocol_bound"] is False
                assert recovered["secret_create_readiness_proxy_protocol_bound"] is True
                assert recovered["secret_create_private_runtime_available"] is True
                assert recovered["dispatchable"] is False

        assert_status()
        _stop_local_sidecar(runtime_process, runtime_socket)
        with pytest.raises(HttpConfigurationError, match="initialization failed closed"):
            with TestClient(
                create_http_app(settings, v4_plan_host_factory=factory),
                base_url="https://mcp.example.com",
            ):
                pass
    finally:
        _stop_local_sidecar(readiness_process, readiness_socket)
        _stop_local_sidecar(runtime_process, runtime_socket)
        _stop_local_sidecar(checkpoint_process, checkpoint_socket)
        socket_dir.rmdir()


def test_v4_persistent_authorities_complete_oauth_mcp_plan_chain_across_restart(
    tmp_path: Path,
) -> None:
    environment, base_host_settings = _v4_bound_environment(tmp_path)
    settings = HttpServerSettings.from_environment(environment)
    state = base_host_settings.planning_database_path.parent
    reference_key = state / "reference.hmac"
    reference_key.write_bytes(b"r" * 32)
    os.chmod(reference_key, 0o600)
    reference_database = state / "reference.sqlite3"
    planning_authorization = planning_authorization_settings_from_environment(
        environment,
        expected_resource="https://mcp.example.com/fpamcp",
    )
    requester = requester_from_access_token(
        AccessToken(
            token="preprovisioning-context-token",
            client_id="preprovisioning-context-client",
            scopes=["fortipam:read", "fortipam:plan"],
            expires_at=2_000_000_000,
            resource="https://mcp.example.com/fpamcp",
            subject="operator",
            claims={"iss": "https://mcp.example.com/fpamcp/oauth"},
        ),
        planning_authorization,
    )
    draft_key = state / "draft.hmac"
    draft_key.write_bytes(b"d" * 32)
    os.chmod(draft_key, 0o600)
    draft_database = state / "draft.sqlite3"
    bootstrap_input = state / "draft-bootstrap-input.json"
    bootstrap_output = state / "draft-bootstrap-output.json"
    bootstrap_input.write_text(
        json.dumps(
            {
                "draft": scheme_draft_as_mapping(_synthetic_access_draft()),
                "expires_at": 1_950_000_600,
                "requester_digest": requester.digest,
            }
        ),
        encoding="utf-8",
    )
    os.chmod(bootstrap_input, 0o600)
    bootstrap_scheme_draft(
        SchemeDraftBootstrapSettings(
            draft_database,
            draft_key,
            "v4-persistent-scheme-draft-authority",
            bootstrap_input,
            bootstrap_output,
        ),
        now_epoch=1_950_000_000,
    )
    draft_ref = json.loads(bootstrap_output.read_text(encoding="utf-8"))[
        "scheme_draft_ref"
    ]
    bootstrap_output.unlink()
    assert PersistentSchemeDraftAuthority(
        draft_database,
        draft_key,
        authority_ref="v4-persistent-scheme-draft-authority",
        clock=lambda: 1_950_000_000,
    ).resolve(draft_ref, requester) == _synthetic_access_draft()
    reference_input = state / "reference-bootstrap-input.json"
    reference_output = state / "reference-bootstrap-output.json"
    reference_input.write_text(
        json.dumps(
            {
                "environment_ref": _synthetic_access_draft().environment_ref,
                "expires_at": 1_950_000_600,
                "references": [
                    {"reference": reference, "reference_kind": kind}
                    for reference, kind in _synthetic_reference_bindings(
                        _synthetic_access_draft()
                    )
                ],
                "requester_digest": requester.digest,
                "scope_ref": _synthetic_access_draft().scope_ref,
            }
        ),
        encoding="utf-8",
    )
    os.chmod(reference_input, 0o600)
    bootstrap_reference_grants(
        ReferenceGrantBootstrapSettings(
            reference_database,
            reference_key,
            V4_PERSISTENT_REFERENCE_AUTHORITY_REF,
            reference_input,
            reference_output,
        ),
        now_epoch=1_950_000_000,
    )
    grant_refs = tuple(
        json.loads(reference_output.read_text(encoding="utf-8"))["grant_refs"]
    )
    reference_output.unlink()
    host_settings = V4SyntheticHostSettings(
        base_host_settings.planning_database_path,
        base_host_settings.planning_hmac_key_path,
        V4PersistentReferenceAuthoritySettings(
            reference_database,
            reference_key,
        ),
        V4PersistentSchemeDraftAuthoritySettings(
            draft_database,
            draft_key,
        ),
    )
    checkpoint_store_ref = "v4-http-planning-store-test"
    checkpoint = _HttpExternalCheckpoint(checkpoint_store_ref)
    factory = synthetic_v4_plan_host_factory(
        host_settings,
        clock=lambda: 1_950_000_000,
        monotonic_checkpoint=checkpoint,
        checkpoint_store_ref=checkpoint_store_ref,
    )
    scope = "fortipam:read fortipam:plan"
    first_app = create_http_app(settings, v4_plan_host_factory=factory)
    empty_planning_database = host_settings.planning_database_path.read_bytes()

    with TestClient(
        first_app,
        base_url="https://mcp.example.com",
    ) as client:
        client_id = _register_public_client(client, scope)
        code, verifier = _authorize_and_login(client, client_id, scope)
        token_response = client.post(
            "/fpamcp/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": code,
                "code_verifier": verifier,
                "redirect_uri": "https://client.example/callback",
                "resource": "https://mcp.example.com/fpamcp",
            },
        )
        assert token_response.status_code == 200
        headers = _request_headers(token_response.json()["access_token"])
        headers["host"] = "mcp.example.com"

        def call_tool(name: str, arguments: dict[str, object]) -> dict[str, object]:
            response = client.post(
                "/fpamcp",
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": name,
                    "method": "tools/call",
                    "params": {"name": name, "arguments": arguments},
                },
            )
            assert response.status_code == 200
            result = response.json()["result"]
            assert result["isError"] is False
            return result["structuredContent"]  # type: ignore[no-any-return]

        status = call_tool("get_v4_plan_status", {})
        assert status["monotonic_checkpoint_protocol_bound"] is True
        assert status["scheme_draft_issuance_protocol_bound"] is True
        assert "scheme_draft_issuance_unbound" not in status["blocker_codes"]
        assert "synthetic_scheme_draft_refs" not in status
        assert "external_monotonic_checkpoint_unbound" in status["blocker_codes"]
        preview = call_tool(
            "preview_v4_administrative_intent",
            {"scheme_draft_ref": draft_ref},
        )
        assert preview["reference_authority_ref"] == (
            V4_PERSISTENT_REFERENCE_AUTHORITY_REF
        )
        assert preview["reference_authorization_expires_at"] == 1_950_000_060
        confirmation_path = urlsplit(str(preview["confirmation_url"])).path
        page = client.get(confirmation_path)
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
        assert csrf is not None
        review = client.post(
            confirmation_path,
            data={
                "csrf_token": csrf.group(1),
                "username": "operator",
                "password": "correct-horse-battery-staple",
                "action": "review",
            },
            headers={"origin": "https://mcp.example.com"},
        )
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', review.text)
        assert csrf is not None
        recorded = client.post(
            confirmation_path,
            data={"csrf_token": csrf.group(1), "action": "affirm"},
            headers={"origin": "https://mcp.example.com"},
        )
        assert recorded.status_code == 200
        summary_revision = preview["revision"]
        assert type(summary_revision) is int
        confirmation = call_tool(
            "confirm_v4_administrative_intent",
            {
                "summary_ref": preview["summary_ref"],
                "summary_revision": summary_revision,
            },
        )
        access_token = token_response.json()["access_token"]

    with TestClient(
        create_http_app(settings, v4_plan_host_factory=factory),
        base_url="https://mcp.example.com",
    ) as restarted_client:
        restarted_headers = _request_headers(access_token)
        restarted_headers["host"] = "mcp.example.com"
        response = restarted_client.post(
            "/fpamcp",
            headers=restarted_headers,
            json={
                "jsonrpc": "2.0",
                "id": "prepare-after-restart",
                "method": "tools/call",
                "params": {
                    "name": "prepare_v4_non_executable_plan",
                    "arguments": {
                        "summary_ref": preview["summary_ref"],
                        "confirmation_ref": confirmation["confirmation_ref"],
                    },
                },
            },
        )
        assert response.status_code == 200
        result = response.json()["result"]
        assert result["isError"] is False
        plan = result["structuredContent"]
        assert plan["dispatchable"] is False
        assert plan["adapter_registry_bound"] is False
        assert plan["executor_runtime_packaged"] is False
        assert plan["executor_mcp_exposed"] is False
        assert all(
            private_ref not in repr((preview, confirmation, plan))
            for private_ref in (*grant_refs, draft_ref)
        )
    stored = reference_database.read_bytes()
    assert all(value.encode("utf-8") not in stored for value in grant_refs)
    assert draft_ref.encode("utf-8") not in draft_database.read_bytes()
    assert checkpoint.tail.sequence == 3

    host_settings.planning_database_path.write_bytes(empty_planning_database)
    with pytest.raises(HttpConfigurationError, match="initialization failed closed"):
        create_http_app(settings, v4_plan_host_factory=factory)


def test_v4_http_oauth_lists_97_tools_and_fails_closed_without_host_services(
    tmp_path: Path,
) -> None:
    settings = HttpServerSettings.from_environment(_v4_environment(tmp_path))
    assert settings.runtime_profile is RuntimeProfile.V4_PLAN_ONLY
    assert settings.local_oauth is not None
    assert "fortipam:plan" in settings.local_oauth.available_scopes
    assert "fortipam:plan" not in settings.local_oauth.default_scopes
    scope = "fortipam:read fortipam:plan"

    with TestClient(
        create_http_app(settings),
        base_url="https://mcp.example.com",
    ) as client:
        client_id = _register_public_client(client, scope)
        code, verifier = _authorize_and_login(client, client_id, scope)
        token_response = client.post(
            "/fpamcp/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": code,
                "code_verifier": verifier,
                "redirect_uri": "https://client.example/callback",
                "resource": "https://mcp.example.com/fpamcp",
            },
        )
        assert token_response.status_code == 200
        headers = _request_headers(token_response.json()["access_token"])
        headers["host"] = "mcp.example.com"

        called_tools: set[str] = set()

        def rpc(method: str, params: dict[str, object]) -> dict[str, object]:
            if method == "tools/call" and isinstance(params.get("name"), str):
                called_tools.add(params["name"])  # type: ignore[arg-type]
            response = client.post(
                "/fpamcp",
                headers=headers,
                json={"jsonrpc": "2.0", "id": method, "method": method, "params": params},
            )
            assert response.status_code == 200
            return response.json()

        tools = rpc("tools/list", {})
        resources = rpc("resources/list", {})
        prompts = rpc("prompts/list", {})
        tool_names = {
            item["name"] for item in tools["result"]["tools"]  # type: ignore[index]
        }
        assert tool_names == set(V4_EXPECTED_TOOLS)
        assert len(tool_names) == 97
        assert tool_names.isdisjoint(server_module.LAB_ADMIN_TOOLS)
        tools_by_name = {
            item["name"]: item
            for item in tools["result"]["tools"]  # type: ignore[index]
        }
        assert len(V4_FIXED_NO_INPUT_PLAN_TOOL_NAMES) == 53
        for name in V4_FIXED_NO_INPUT_PLAN_TOOL_NAMES:
            schema = tools_by_name[name]["inputSchema"]
            assert schema["properties"] == {}
            assert schema.get("required", []) == []
            assert schema["additionalProperties"] is False
        glass_break_tool = next(
            item
            for item in tools["result"]["tools"]  # type: ignore[index]
            if item["name"] == "get_v4_glass_break_plan_requirements"
        )
        assert glass_break_tool["inputSchema"]["properties"] == {}
        assert glass_break_tool["inputSchema"].get("required", []) == []
        assert {
            item["uri"] for item in resources["result"]["resources"]  # type: ignore[index]
        } == set(V4_EXPECTED_RESOURCES)
        assert {
            item["name"] for item in prompts["result"]["prompts"]  # type: ignore[index]
        } == set(V4_EXPECTED_PROMPTS)

        status = rpc(
            "tools/call",
            {"name": "get_v4_plan_status", "arguments": {}},
        )["result"]
        assert status["isError"] is False  # type: ignore[index]
        structured = status["structuredContent"]  # type: ignore[index]
        assert structured["host_services_bound"] is False
        assert structured["planner_mcp_exposed"] is True
        assert structured["product_write_enabled"] is False
        assert set(structured["mcp_tool_names"]) == set(V4_PLAN_TOOLS)
        assert structured["fixed_no_input_plan_tool_count"] == 53
        assert structured["fixed_no_input_plan_tool_names"] == list(
            V4_FIXED_NO_INPUT_PLAN_TOOL_NAMES
        )

        firmware_plan = rpc(
            "tools/call",
            {
                "name": "get_v4_firmware_upgrade_plan_requirements",
                "arguments": {},
            },
        )["result"]
        assert firmware_plan["isError"] is False  # type: ignore[index]
        firmware_plan_content = firmware_plan["structuredContent"]  # type: ignore[index]
        assert firmware_plan_content["action_family"] == "firmware.upgrade.plan"
        assert firmware_plan_content["target_version"] == "1.9.1"
        assert firmware_plan_content["execution_ready"] is False
        assert firmware_plan_content["fortipam_contacted"] is False

        firmware_plan = rpc(
            "tools/call",
            {
                "name": "build_v4_firmware_upgrade_plan",
                "arguments": {
                    "current_version_path_verified": False,
                    "deployment_ha_procedure_ready": True,
                    "backup_custody_verified": True,
                    "isolated_restore_test_passed": True,
                    "maintenance_window_approved": True,
                    "pre_post_checks_defined": True,
                    "failure_rollback_approved": True,
                },
            },
        )["result"]
        assert firmware_plan["isError"] is False  # type: ignore[index]
        firmware_plan_content = firmware_plan["structuredContent"]  # type: ignore[index]
        assert firmware_plan_content["action_family"] == "firmware.upgrade.plan"
        assert firmware_plan_content["planning_status"] == "incomplete_evidence"
        assert firmware_plan_content["missing_requirements"] == [
            "current_version_path_verified"
        ]
        assert firmware_plan_content["plan_ready"] is False
        assert firmware_plan_content["firmware_artifact_verified"] is False
        assert firmware_plan_content["upgrade_execution_ready"] is False
        assert firmware_plan_content["execution_authorized"] is False
        assert firmware_plan_content["fortipam_contacted"] is False

        backup_create_plan = rpc(
            "tools/call",
            {
                "name": "get_v4_backup_create_plan_requirements",
                "arguments": {},
            },
        )["result"]
        assert backup_create_plan["isError"] is False  # type: ignore[index]
        backup_create_content = backup_create_plan[  # type: ignore[index]
            "structuredContent"
        ]
        assert backup_create_content["action_family"] == "backup.create"
        assert backup_create_content["target_version"] == "1.9.1"
        assert backup_create_content["backup_ready"] is False
        assert backup_create_content["fortipam_contacted"] is False

        backup_create_plan = rpc(
            "tools/call",
            {
                "name": "build_v4_backup_create_plan",
                "arguments": {
                    "source_appliance_version_recorded": True,
                    "operator_destination_ready": True,
                    "encryption_policy_approved": True,
                    "protected_material_custody_ready": True,
                    "artifact_integrity_record_ready": True,
                    "retention_policy_verified": False,
                    "isolated_restore_test_defined": True,
                    "failure_recovery_approved": True,
                },
            },
        )["result"]
        assert backup_create_plan["isError"] is False  # type: ignore[index]
        backup_create_plan_content = backup_create_plan[  # type: ignore[index]
            "structuredContent"
        ]
        assert backup_create_plan_content["action_family"] == "backup.create"
        assert backup_create_plan_content["planning_status"] == "incomplete_evidence"
        assert backup_create_plan_content["missing_requirements"] == [
            "retention_policy_verified"
        ]
        assert backup_create_plan_content["plan_ready"] is False
        assert backup_create_plan_content["backup_execution_ready"] is False
        assert backup_create_plan_content["execution_authorized"] is False
        assert backup_create_plan_content["fortipam_contacted"] is False

        backup_restore_plan = rpc(
            "tools/call",
            {
                "name": "get_v4_backup_restore_plan_requirements",
                "arguments": {},
            },
        )["result"]
        assert backup_restore_plan["isError"] is False  # type: ignore[index]
        backup_restore_content = backup_restore_plan[  # type: ignore[index]
            "structuredContent"
        ]
        assert backup_restore_content["action_family"] == "backup.restore.plan"
        assert backup_restore_content["target_version"] == "1.9.1"
        assert backup_restore_content["backup_ready"] is False
        assert backup_restore_content["restore_ready"] is False
        assert backup_restore_content["fortipam_contacted"] is False

        backup_restore_plan = rpc(
            "tools/call",
            {
                "name": "build_v4_backup_restore_plan",
                "arguments": {
                    "source_destination_version_compatible": True,
                    "deployment_restore_procedure_ready": True,
                    "protected_material_custody_ready": True,
                    "artifact_integrity_verified": False,
                    "isolated_restore_test_passed": True,
                    "maintenance_window_approved": True,
                    "pre_post_checks_defined": True,
                    "failure_recovery_approved": True,
                },
            },
        )["result"]
        assert backup_restore_plan["isError"] is False  # type: ignore[index]
        backup_restore_plan_content = backup_restore_plan[  # type: ignore[index]
            "structuredContent"
        ]
        assert backup_restore_plan_content["action_family"] == "backup.restore.plan"
        assert backup_restore_plan_content["planning_status"] == "incomplete_evidence"
        assert backup_restore_plan_content["missing_requirements"] == [
            "artifact_integrity_verified"
        ]
        assert backup_restore_plan_content["plan_ready"] is False
        assert backup_restore_plan_content["restore_execution_ready"] is False
        assert backup_restore_plan_content["execution_authorized"] is False
        assert backup_restore_plan_content["fortipam_contacted"] is False

        license_plan = rpc(
            "tools/call",
            {
                "name": "get_v4_license_install_plan_requirements",
                "arguments": {},
            },
        )["result"]
        assert license_plan["isError"] is False  # type: ignore[index]
        license_content = license_plan["structuredContent"]  # type: ignore[index]
        assert license_content["action_family"] == "license.install"
        assert license_content["target_version"] == "1.9.1"
        assert license_content["license_ready"] is False
        assert license_content["fortipam_contacted"] is False
        assert license_content["forticloud_contacted"] is False

        license_plan = rpc(
            "tools/call",
            {"name": "build_v4_license_install_plan", "arguments": {
                "entitlement_owner_verified": True,
                "deployment_ha_mode_verified": True,
                "license_custody_ready": False,
                "backup_recovery_verified": True,
                "maintenance_reboot_approved": True,
                "break_fix_access_verified": True,
                "post_boot_checks_defined": True,
                "failure_recovery_approved": True,
            }},
        )["result"]
        assert license_plan["isError"] is False  # type: ignore[index]
        license_content = license_plan["structuredContent"]  # type: ignore[index]
        assert license_content["missing_requirements"] == ["license_custody_ready"]
        assert license_content["license_execution_ready"] is False
        assert license_content["execution_authorized"] is False

        system_email_plan = rpc(
            "tools/call",
            {"name": "get_v4_system_email_plan_requirements", "arguments": {}},
        )["result"]
        assert system_email_plan["isError"] is False  # type: ignore[index]
        system_email_content = system_email_plan[  # type: ignore[index]
            "structuredContent"
        ]
        assert system_email_content["action_family"] == "system-email.configure"
        assert system_email_content["configuration_ready"] is False
        assert system_email_content["fortipam_contacted"] is False
        assert system_email_content["mail_service_contacted"] is False

        system_email_plan = rpc(
            "tools/call",
            {"name": "build_v4_system_email_plan", "arguments": {
                "mail_scopes_separated": True,
                "nonproduction_service_approved": True,
                "network_dependencies_verified": True,
                "tls_trust_verified": False,
                "credential_custody_ready": True,
                "sender_relay_policy_verified": True,
                "delivery_test_separately_gated": True,
                "redacted_readback_defined": True,
                "failure_rollback_approved": True,
            }},
        )["result"]
        assert system_email_plan["isError"] is False  # type: ignore[index]
        system_email_content = system_email_plan["structuredContent"]  # type: ignore[index]
        assert system_email_content["missing_requirements"] == ["tls_trust_verified"]
        assert system_email_content["configuration_execution_ready"] is False
        assert system_email_content["execution_authorized"] is False

        email_alert_plan = rpc(
            "tools/call",
            {"name": "get_v4_email_alert_plan_requirements", "arguments": {}},
        )["result"]
        assert email_alert_plan["isError"] is False  # type: ignore[index]
        email_alert_content = email_alert_plan[  # type: ignore[index]
            "structuredContent"
        ]
        assert email_alert_content["action_family"] == "email-alert.configure"
        assert email_alert_content["configuration_ready"] is False
        assert email_alert_content["fortipam_contacted"] is False
        assert email_alert_content["mail_service_contacted"] is False

        email_alert_plan = rpc(
            "tools/call",
            {"name": "build_v4_email_alert_plan", "arguments": {
                "categories_thresholds_approved": True,
                "nonproduction_recipients_approved": True,
                "content_identity_exposure_reviewed": True,
                "mail_dependency_verified": True,
                "rate_loop_controls_verified": False,
                "notification_delivery_separately_gated": True,
                "redacted_readback_defined": True,
                "failure_rollback_approved": True,
            }},
        )["result"]
        assert email_alert_plan["isError"] is False  # type: ignore[index]
        email_alert_content = email_alert_plan["structuredContent"]  # type: ignore[index]
        assert email_alert_content["missing_requirements"] == [
            "rate_loop_controls_verified"
        ]
        assert email_alert_content["configuration_execution_ready"] is False
        assert email_alert_content["execution_authorized"] is False

        glass_break_plan = rpc(
            "tools/call",
            {"name": "get_v4_glass_break_plan_requirements", "arguments": {}},
        )["result"]
        assert glass_break_plan["isError"] is False  # type: ignore[index]
        glass_break_content = glass_break_plan[  # type: ignore[index]
            "structuredContent"
        ]
        assert glass_break_content["action_family"] == "glass-break.activate"
        assert glass_break_content["target_version"] == "1.9.1"
        assert glass_break_content["planning_status"] == "requirements_only"
        assert glass_break_content["activation_ready"] is False
        assert glass_break_content["access_elevated"] is False
        assert glass_break_content["execution_authorized"] is False
        assert glass_break_content["fortipam_contacted"] is False
        assert glass_break_content["local_state_written"] is False
        assert glass_break_content["protected_material_accepted"] is False
        assert glass_break_content["secret_material_returned"] is False
        assert glass_break_content["raw_source_content_returned"] is False
        assert set(glass_break_content["blocked_operations"]) == {
            "device_state_read",
            "identity_role_reason_or_incident_input",
            "glass_break_permission_change",
            "glass_break_activation",
            "glass_break_deactivation",
            "folder_secret_or_request_enumeration",
            "credential_or_clear_text_access",
            "secret_launch",
            "notification_configuration_or_delivery",
            "session_recording_change",
            "execution_authorization",
        }
        rejected_glass_break_input = rpc(
            "tools/call",
            {
                "name": "get_v4_glass_break_plan_requirements",
                "arguments": {"incident_ref": "not-accepted"},
            },
        )["result"]
        assert rejected_glass_break_input["isError"] is True  # type: ignore[index]
        assert "Tool arguments are invalid." in repr(rejected_glass_break_input)
        assert "input_value" not in repr(rejected_glass_break_input)
        assert "not-accepted" not in repr(rejected_glass_break_input)

        route_plan = rpc(
            "tools/call",
            {"name": "get_v4_route_plan_requirements", "arguments": {}},
        )["result"]
        assert route_plan["isError"] is False  # type: ignore[index]
        route_content = route_plan["structuredContent"]  # type: ignore[index]
        assert route_content["action_family"] == "route.configure"
        assert route_content["source_version"] == "1.9.0"
        assert route_content["target_version"] == "1.9.1"
        assert route_content["target_version_validation_required"] is True
        assert route_content["fortipam_contacted"] is False

        dns_plan = rpc(
            "tools/call",
            {"name": "get_v4_dns_plan_requirements", "arguments": {}},
        )["result"]
        assert dns_plan["isError"] is False  # type: ignore[index]
        dns_content = dns_plan["structuredContent"]  # type: ignore[index]
        assert dns_content["action_family"] == "dns.configure"
        assert dns_content["source_version"] == "1.9.0"
        assert dns_content["target_version"] == "1.9.1"
        assert dns_content["target_version_validation_required"] is True
        assert dns_content["fortipam_contacted"] is False

        for tool_name, action_family in (
            ("get_v4_ha_configure_plan_requirements", "ha.configure"),
            ("get_v4_ha_maintenance_plan_requirements", "ha.maintenance"),
            ("get_v4_ha_reconcile_plan_requirements", "ha.reconcile"),
        ):
            ha_plan = rpc(
                "tools/call",
                {"name": tool_name, "arguments": {}},
            )["result"]
            assert ha_plan["isError"] is False  # type: ignore[index]
            ha_content = ha_plan["structuredContent"]  # type: ignore[index]
            assert ha_content["action_family"] == action_family
            assert ha_content["source_version"] == "1.9.1"
            assert ha_content["target_version_validation_required"] is False
            assert ha_content["configuration_ready"] is False
            assert ha_content["fortipam_contacted"] is False

        builder_cases: tuple[tuple[str, dict[str, bool], str], ...] = (
            (
                "build_v4_route_plan",
                {
                    "target_contract_verified": True,
                    "current_route_table_verified": True,
                    "fixed_change_owner_approved": True,
                    "dependency_impact_analyzed": False,
                    "out_of_band_recovery_verified": True,
                    "ha_ordering_verified": True,
                    "pre_post_checks_defined": True,
                    "rollback_reconciliation_approved": True,
                },
                "dependency_impact_analyzed",
            ),
            (
                "build_v4_dns_plan",
                {
                    "target_contract_verified": True,
                    "current_dns_configuration_verified": True,
                    "fixed_change_owner_approved": True,
                    "dependency_impact_analyzed": True,
                    "resolver_tls_trust_verified": False,
                    "out_of_band_recovery_verified": True,
                    "pre_post_checks_defined": True,
                    "rollback_reconciliation_approved": True,
                },
                "resolver_tls_trust_verified",
            ),
            (
                "build_v4_ha_configure_plan",
                {
                    "target_contract_verified": True,
                    "complete_member_state_verified": True,
                    "fixed_topology_owner_approved": True,
                    "platform_license_compatibility_verified": True,
                    "heartbeat_failure_domains_reviewed": False,
                    "management_recovery_verified": True,
                    "backup_impact_window_approved": True,
                    "ordered_change_rollback_readback_approved": True,
                    "protected_material_custody_ready": True,
                },
                "heartbeat_failure_domains_reviewed",
            ),
            (
                "build_v4_ha_maintenance_plan",
                {
                    "target_contract_verified": True,
                    "current_cluster_state_verified": True,
                    "fixed_scope_owner_approved": True,
                    "service_impact_analyzed": True,
                    "expiry_recovery_verified": False,
                    "pre_post_health_checks_defined": True,
                    "deactivation_reconciliation_approved": True,
                },
                "expiry_recovery_verified",
            ),
            (
                "build_v4_ha_reconcile_plan",
                {
                    "readonly_contract_verified": True,
                    "expected_member_inventory_approved": True,
                    "categorical_health_grammar_verified": True,
                    "per_node_evidence_accounted_for": True,
                    "uncertain_states_fail_closed": True,
                    "automatic_changes_disabled": True,
                    "separate_remediation_control_verified": False,
                },
                "separate_remediation_control_verified",
            ),
        )
        for tool_name, arguments, missing_requirement in builder_cases:
            plan = rpc(
                "tools/call",
                {"name": tool_name, "arguments": arguments},
            )["result"]
            assert plan["isError"] is False  # type: ignore[index]
            plan_content = plan["structuredContent"]  # type: ignore[index]
            assert plan_content["missing_requirements"] == [missing_requirement]
            assert plan_content["plan_ready"] is False
            assert plan_content["configuration_execution_ready"] is False
            assert plan_content["execution_authorized"] is False
            assert plan_content["fortipam_contacted"] is False
            assert plan_content["local_state_written"] is False

        certificate_plan = rpc(
            "tools/call",
            {"name": "get_v4_certificate_import_plan_requirements", "arguments": {}},
        )["result"]
        assert certificate_plan["isError"] is False  # type: ignore[index]
        certificate_content = certificate_plan[  # type: ignore[index]
            "structuredContent"
        ]
        assert certificate_content["action_family"] == "certificate.import"
        assert certificate_content["source_version"] == "1.9.1"
        assert certificate_content["target_version_validation_required"] is False
        assert certificate_content["protected_material_loaded"] is False
        assert certificate_content["fortipam_contacted"] is False
        certificate_candidate = certificate_content["candidate_api_contract"]
        assert certificate_candidate["status"] == "catalogued_body_unproven"
        assert certificate_candidate["target_version_validated"] is False
        assert certificate_candidate["live_call_permitted"] is False

        crl_plan = rpc(
            "tools/call",
            {"name": "get_v4_crl_import_plan_requirements", "arguments": {}},
        )["result"]
        assert crl_plan["isError"] is False  # type: ignore[index]
        crl_content = crl_plan["structuredContent"]  # type: ignore[index]
        assert crl_content["action_family"] == "crl.import"
        assert crl_content["source_version"] == "1.0.3"
        assert crl_content["target_version"] == "1.9.1"
        assert crl_content["target_version_validation_required"] is True
        assert crl_content["external_service_contacted"] is False
        crl_candidate = crl_content["candidate_api_contract"]
        assert crl_candidate["status"] == "catalogued_body_unproven"
        assert crl_candidate["target_version_validated"] is False
        assert crl_candidate["live_call_permitted"] is False

        for tool_name, action_family, source_version in (
            ("get_v4_ldap_server_plan_requirements", "ldap-server.configure", "1.8.1"),
            ("get_v4_radius_server_plan_requirements", "radius-server.configure", "1.8.0"),
            ("get_v4_saml_server_plan_requirements", "saml-server.configure", "1.8.1"),
        ):
            identity_plan = rpc(
                "tools/call",
                {"name": tool_name, "arguments": {}},
            )["result"]
            assert identity_plan["isError"] is False  # type: ignore[index]
            identity_content = identity_plan["structuredContent"]  # type: ignore[index]
            assert identity_content["action_family"] == action_family
            assert identity_content["source_version"] == source_version
            assert identity_content["target_version"] == "1.9.1"
            assert identity_content["target_version_validation_required"] is True
            assert identity_content["protected_material_loaded"] is False
            assert identity_content["authentication_effect_applied"] is False
            assert identity_content["fortipam_contacted"] is False
            candidate = identity_content["candidate_api_contract"]
            assert candidate["status"] == "catalogued_body_unproven"
            assert candidate["target_version_validated"] is False
            assert candidate["live_call_permitted"] is False

        temporary_access_plan = rpc(
            "tools/call",
            {
                "name": "get_v4_temporary_access_plan_requirements",
                "arguments": {},
            },
        )["result"]
        assert temporary_access_plan["isError"] is False  # type: ignore[index]
        temporary_access_content = temporary_access_plan[  # type: ignore[index]
            "structuredContent"
        ]
        assert temporary_access_content["action_family"] == (
            "sponsored-and-temporary-access-plan"
        )
        assert temporary_access_content["target_version"] == "7.0.0"
        assert temporary_access_content["target_version_validation_required"] is True
        assert temporary_access_content["candidate_api_contract_available"] is False
        assert temporary_access_content["access_effect_applied"] is False
        assert temporary_access_content["fortipam_contacted"] is False

        for tool_name, action_family in (
            ("get_v4_jwt_key_create_plan_requirements", "jwt-key.create"),
            ("get_v4_jwt_key_rotate_plan_requirements", "jwt-key.rotate"),
        ):
            jwt_plan = rpc(
                "tools/call",
                {"name": tool_name, "arguments": {}},
            )["result"]
            assert jwt_plan["isError"] is False  # type: ignore[index]
            jwt_content = jwt_plan["structuredContent"]  # type: ignore[index]
            assert jwt_content["action_family"] == action_family
            assert jwt_content["source_version"] == "1.8.1"
            assert jwt_content["target_version"] == "1.9.1"
            assert jwt_content["target_version_validation_required"] is True
            assert jwt_content["protected_material_loaded"] is False
            assert jwt_content["authentication_effect_applied"] is False
            assert jwt_content["fortipam_contacted"] is False
            candidate = jwt_content["candidate_api_contract"]
            assert candidate["status"] == "catalogued_body_unproven"
            assert candidate["target_version_validated"] is False
            assert candidate["live_call_permitted"] is False

        for tool_name, action_family in (
            ("get_v4_scim_client_create_plan_requirements", "scim-client.create"),
            ("get_v4_scim_client_rotate_plan_requirements", "scim-client.rotate"),
            ("get_v4_scim_client_disable_plan_requirements", "scim-client.disable"),
        ):
            scim_plan = rpc(
                "tools/call",
                {"name": tool_name, "arguments": {}},
            )["result"]
            assert scim_plan["isError"] is False  # type: ignore[index]
            scim_content = scim_plan["structuredContent"]  # type: ignore[index]
            assert scim_content["action_family"] == action_family
            assert scim_content["source_version"] == "1.9.0"
            assert scim_content["target_version"] == "1.9.1"
            assert scim_content["target_version_validation_required"] is True
            assert scim_content["protected_material_loaded"] is False
            assert scim_content["provisioning_effect_applied"] is False
            assert scim_content["fortipam_contacted"] is False

        for tool_name, action_family in (
            ("get_v4_fortitoken_assign_plan_requirements", "fortitoken.assign"),
            ("get_v4_fortitoken_revoke_plan_requirements", "fortitoken.revoke"),
        ):
            fortitoken_plan = rpc(
                "tools/call",
                {"name": tool_name, "arguments": {}},
            )["result"]
            assert fortitoken_plan["isError"] is False  # type: ignore[index]
            fortitoken_content = fortitoken_plan[  # type: ignore[index]
                "structuredContent"
            ]
            assert fortitoken_content["action_family"] == action_family
            assert fortitoken_content["source_version"] == "1.9.0"
            assert fortitoken_content["target_version"] == "1.9.1"
            assert fortitoken_content["target_version_validation_required"] is True
            assert fortitoken_content["protected_material_loaded"] is False
            assert fortitoken_content["mfa_effect_applied"] is False
            assert fortitoken_content["fortipam_contacted"] is False

        for tool_name, action_family in (
            ("get_v4_apl_update_plan_requirements", "apl.update"),
            (
                "get_v4_discovery_entry_create_plan_requirements",
                "discovery-entry.create",
            ),
            ("get_v4_discovery_run_plan_requirements", "discovery.run"),
            ("get_v4_discovery_review_plan_requirements", "discovery.review"),
            ("get_v4_job_create_plan_requirements", "job.create"),
            ("get_v4_job_execute_plan_requirements", "job.execute"),
        ):
            workflow_plan = rpc(
                "tools/call",
                {"name": tool_name, "arguments": {}},
            )["result"]
            assert workflow_plan["isError"] is False  # type: ignore[index]
            workflow_content = workflow_plan["structuredContent"]  # type: ignore[index]
            assert workflow_content["action_family"] == action_family
            assert workflow_content["source_version"] == "1.9.0"
            assert workflow_content["target_version"] == "1.9.1"
            assert workflow_content["target_version_validation_required"] is True
            assert workflow_content["execution_authorized"] is False
            assert workflow_content["fortipam_contacted"] is False
            if action_family == "discovery-entry.create":
                candidate = workflow_content["candidate_api_contract"]
                assert candidate["status"] == "catalogued_body_unproven"
                assert candidate["target_version_validated"] is False
                assert candidate["live_call_permitted"] is False

        for tool_name, action_family in (
            (
                "get_v4_password_changer_create_plan_requirements",
                "password-changer.create",
            ),
            (
                "get_v4_password_verification_plan_requirements",
                "password-verification.configure",
            ),
            ("get_v4_checkout_policy_plan_requirements", "checkout-policy.configure"),
            ("get_v4_jit_policy_plan_requirements", "jit-policy.configure"),
            (
                "get_v4_service_account_update_plan_requirements",
                "service-account.update",
            ),
        ):
            lifecycle_plan = rpc(
                "tools/call",
                {"name": tool_name, "arguments": {}},
            )["result"]
            assert lifecycle_plan["isError"] is False  # type: ignore[index]
            lifecycle_content = lifecycle_plan[  # type: ignore[index]
                "structuredContent"
            ]
            assert lifecycle_content["action_family"] == action_family
            assert lifecycle_content["source_version"] == "1.9.0"
            assert lifecycle_content["target_version"] == "1.9.1"
            assert lifecycle_content["target_version_validation_required"] is True
            assert lifecycle_content["credential_changed_or_verified"] is False
            assert lifecycle_content["privilege_changed"] is False
            if action_family == "password-changer.create":
                candidate = lifecycle_content["candidate_api_contract"]
                assert candidate["status"] == "catalogued_body_unproven"
                assert candidate["target_version_validated"] is False
                assert candidate["live_call_permitted"] is False
            assert lifecycle_content["fortipam_contacted"] is False

        for tool_name, action_family in (
            (
                "get_v4_instruction_profile_create_plan_requirements",
                "instruction-profile.create",
            ),
            (
                "get_v4_event_subscription_plan_requirements",
                "event-subscription.configure",
            ),
        ):
            experience_plan = rpc(
                "tools/call",
                {"name": tool_name, "arguments": {}},
            )["result"]
            assert experience_plan["isError"] is False  # type: ignore[index]
            experience_content = experience_plan[  # type: ignore[index]
                "structuredContent"
            ]
            assert experience_content["action_family"] == action_family
            assert experience_content["source_version"] == "1.9.1"
            assert experience_content["target_version"] == "1.9.1"
            assert experience_content["target_version_validation_required"] is False
            assert experience_content["protected_material_loaded"] is False
            assert experience_content["notification_sent"] is False
            assert experience_content["fortipam_contacted"] is False

        for tool_name, action_family in (
            (
                "get_v4_secret_bulk_import_plan_requirements",
                "secret.bulk-import.plan",
            ),
            (
                "get_v4_secret_bulk_import_apply_requirements",
                "secret.bulk-import.apply",
            ),
            ("get_v4_launcher_clone_plan_requirements", "launcher.clone"),
            ("get_v4_policy_assign_plan_requirements", "policy.assign"),
        ):
            onboarding_plan = rpc(
                "tools/call",
                {"name": tool_name, "arguments": {}},
            )["result"]
            assert onboarding_plan["isError"] is False  # type: ignore[index]
            onboarding_content = onboarding_plan[  # type: ignore[index]
                "structuredContent"
            ]
            assert onboarding_content["action_family"] == action_family
            assert onboarding_content["source_version"] == "1.9.1"
            assert onboarding_content["target_version"] == "1.9.1"
            assert onboarding_content["target_version_validation_required"] is False
            assert onboarding_content["protected_material_loaded"] is False
            assert onboarding_content["secret_created"] is False
            assert onboarding_content["session_effect_applied"] is False
            assert onboarding_content["fortipam_contacted"] is False

        bulk_import_plan = rpc(
            "tools/call",
            {
                "name": "build_v4_secret_bulk_import_plan",
                "arguments": {
                    "template_schema_verified": True,
                    "fixed_scope_dependencies_verified": True,
                    "protected_file_custody_ready": True,
                    "value_free_preview_verified": True,
                    "duplicate_conflict_policy_verified": True,
                    "bounded_row_limits_defined": True,
                    "preview_binding_verified": False,
                    "cleanup_recovery_approved": True,
                },
            },
        )["result"]
        assert bulk_import_plan["isError"] is False  # type: ignore[index]
        bulk_import_content = bulk_import_plan[  # type: ignore[index]
            "structuredContent"
        ]
        assert bulk_import_content["action_family"] == "secret.bulk-import.plan"
        assert bulk_import_content["planning_status"] == "incomplete_evidence"
        assert bulk_import_content["missing_requirements"] == [
            "preview_binding_verified"
        ]
        assert bulk_import_content["plan_ready"] is False
        assert bulk_import_content["import_file_loaded"] is False
        assert bulk_import_content["preview_generated"] is False
        assert bulk_import_content["apply_execution_ready"] is False
        assert bulk_import_content["execution_authorized"] is False
        assert bulk_import_content["fortipam_contacted"] is False

        for tool_name, action_family in (
            (
                "get_v4_approval_delivery_plan_requirements",
                "approval-delivery.configure",
            ),
            (
                "get_v4_fabric_connector_plan_requirements",
                "fabric-connector.configure",
            ),
            (
                "get_v4_secret_gateway_chain_plan_requirements",
                "secret-gateway.chain.configure",
            ),
            ("get_v4_reverse_service_plan_requirements", "reverse-service.configure"),
            ("get_v4_ztna_tag_create_plan_requirements", "ztna-tag.create"),
            (
                "get_v4_ztna_tag_group_create_plan_requirements",
                "ztna-tag-group.create",
            ),
        ):
            integration_plan = rpc(
                "tools/call",
                {"name": tool_name, "arguments": {}},
            )["result"]
            assert integration_plan["isError"] is False  # type: ignore[index]
            integration_content = integration_plan[  # type: ignore[index]
                "structuredContent"
            ]
            assert integration_content["action_family"] == action_family
            assert integration_content["source_version"] == "1.9.1"
            assert integration_content["target_version"] == "1.9.1"
            assert integration_content["target_version_validation_required"] is False
            assert integration_content["protected_material_loaded"] is False
            assert integration_content["external_service_contacted"] is False
            assert integration_content["policy_effect_applied"] is False
            assert integration_content["fortipam_contacted"] is False

        for tool_name, action_family, validation_required in (
            ("get_v4_target_disable_plan_requirements", "target.disable", False),
            (
                "get_v4_secret_metadata_update_plan_requirements",
                "secret.update-metadata",
                True,
            ),
            (
                "get_v4_approval_profile_disable_plan_requirements",
                "approval-profile.disable",
                False,
            ),
            ("get_v4_secret_disable_contract_gap", "secret.disable", False),
            ("get_v4_launcher_disable_contract_gap", "launcher.disable", False),
        ):
            gap_plan = rpc(
                "tools/call",
                {"name": tool_name, "arguments": {}},
            )["result"]
            assert gap_plan["isError"] is False  # type: ignore[index]
            gap_content = gap_plan["structuredContent"]  # type: ignore[index]
            assert gap_content["action_family"] == action_family
            assert gap_content["target_version"] == "1.9.1"
            assert gap_content["target_version_validation_required"] is validation_required
            assert gap_content["lifecycle_contract_established"] is False
            assert gap_content["protected_material_loaded"] is False
            assert gap_content["access_or_session_effect_applied"] is False
            assert gap_content["fortipam_contacted"] is False
            if action_family in {
                "target.disable",
                "approval-profile.disable",
                "secret.disable",
                "launcher.disable",
            }:
                assert gap_content["planning_status"] == (
                    "product_unavailable_in_target_version"
                )
                assert gap_content["action_available"] is False
                assert gap_content["resolution_requires_implementation"] is False
                assert gap_content["resolution_scope"] == "fortipam_1_9_1_only"

        assert set(V4_FIXED_NO_INPUT_PLAN_TOOL_NAMES).issubset(called_tools)

        capability_matrix = rpc(
            "tools/call",
            {"name": "get_capability_matrix", "arguments": {}},
        )["result"]["structuredContent"]
        assert capability_matrix["tool_count"] == 235
        assert {
            item["tool_name"] for item in capability_matrix["tools"]
        } == set(V4_EXPECTED_TOOLS) | {
            "observe_v4_bound_secret_request",
            "get_v4_ha_reconciliation_assessment",
            "preview_v4_certificate_csr_generate",
            "confirm_v4_certificate_csr_generate",
            "execute_confirmed_v4_certificate_csr_generate",
            "preview_v4_dlp_file_pattern_create",
            "confirm_v4_dlp_file_pattern_create",
            "execute_confirmed_v4_dlp_file_pattern_create",
            "preview_v4_dlp_file_pattern_delete",
            "confirm_v4_dlp_file_pattern_delete",
            "execute_confirmed_v4_dlp_file_pattern_delete",
            "preview_v4_dlp_sensor_create",
            "confirm_v4_dlp_sensor_create",
            "execute_confirmed_v4_dlp_sensor_create",
            "preview_v4_dlp_sensor_delete",
            "confirm_v4_dlp_sensor_delete",
            "execute_confirmed_v4_dlp_sensor_delete",
            "preview_v4_antivirus_profile_create",
            "confirm_v4_antivirus_profile_create",
            "execute_confirmed_v4_antivirus_profile_create",
            "preview_v4_antivirus_profile_delete",
            "confirm_v4_antivirus_profile_delete",
            "execute_confirmed_v4_antivirus_profile_delete",
            "preview_v4_rdp_event_filter_create",
            "confirm_v4_rdp_event_filter_create",
            "execute_confirmed_v4_rdp_event_filter_create",
            "preview_v4_rdp_event_filter_delete",
            "confirm_v4_rdp_event_filter_delete",
            "execute_confirmed_v4_rdp_event_filter_delete",
            "preview_v4_secret_policy_create",
            "confirm_v4_secret_policy_create",
            "execute_confirmed_v4_secret_policy_create",
            "preview_v4_secret_policy_update",
            "confirm_v4_secret_policy_update",
            "execute_confirmed_v4_secret_policy_update",
            "preview_v4_ssh_filter_create",
            "confirm_v4_ssh_filter_create",
            "execute_confirmed_v4_ssh_filter_create",
            "preview_v4_ssh_filter_delete",
            "confirm_v4_ssh_filter_delete",
            "execute_confirmed_v4_ssh_filter_delete",
            "preview_v4_launcher_create",
            "confirm_v4_launcher_create",
            "execute_confirmed_v4_launcher_create",
            "preview_v4_launcher_timeout_update",
            "confirm_v4_launcher_timeout_update",
            "execute_confirmed_v4_launcher_timeout_update",
            "preview_v4_launcher_command_line_matcher_configure",
            "confirm_v4_launcher_command_line_matcher_configure",
            "execute_confirmed_v4_launcher_command_line_matcher_configure",
            "preview_v4_template_create",
            "confirm_v4_template_create",
            "execute_confirmed_v4_template_create",
            "preview_v4_template_web_vnc_port_update",
            "confirm_v4_template_web_vnc_port_update",
            "execute_confirmed_v4_template_web_vnc_port_update",
            "preview_v4_dependency_updater_create",
            "confirm_v4_dependency_updater_create",
            "execute_confirmed_v4_dependency_updater_create",
            "preview_v4_secret_gateway_create",
            "confirm_v4_secret_gateway_create",
            "execute_confirmed_v4_secret_gateway_create",
            "preview_v4_client_integrity_configure",
            "confirm_v4_client_integrity_configure",
            "execute_confirmed_v4_client_integrity_configure",
                    "preview_v4_windows_app_filter_create",
                    "confirm_v4_windows_app_filter_create",
                    "execute_confirmed_v4_windows_app_filter_create",
                    "preview_v4_windows_app_filter_delete",
                    "confirm_v4_windows_app_filter_delete",
                    "execute_confirmed_v4_windows_app_filter_delete",
                    "preview_v4_recording_policy_enable",
                "confirm_v4_recording_policy_enable",
                "execute_confirmed_v4_recording_policy_enable",
                "observe_v4_active_launches",
            "preview_v4_active_launch_disconnect",
            "confirm_v4_active_launch_disconnect",
            "execute_confirmed_v4_active_launch_disconnect",
            "preview_v4_automation_trigger_create",
            "confirm_v4_automation_trigger_create",
            "execute_confirmed_v4_automation_trigger_create",
            "preview_v4_automation_trigger_delete",
            "confirm_v4_automation_trigger_delete",
            "execute_confirmed_v4_automation_trigger_delete",
            "preview_v4_automation_action_create",
            "confirm_v4_automation_action_create",
            "execute_confirmed_v4_automation_action_create",
            "preview_v4_automation_action_delete",
            "confirm_v4_automation_action_delete",
            "execute_confirmed_v4_automation_action_delete",
            "preview_v4_automation_stitch_create",
            "confirm_v4_automation_stitch_create",
            "execute_confirmed_v4_automation_stitch_create",
            "preview_v4_automation_stitch_delete",
            "confirm_v4_automation_stitch_delete",
            "execute_confirmed_v4_automation_stitch_delete",
            "preview_v4_user_group_create",
            "confirm_v4_user_group_create",
            "execute_confirmed_v4_user_group_create",
            "preview_v4_user_group_membership_change",
            "confirm_v4_user_group_membership_change",
            "execute_confirmed_v4_user_group_membership_change",
            "preview_v4_auto_provision_rule_create",
            "confirm_v4_auto_provision_rule_create",
            "execute_confirmed_v4_auto_provision_rule_create",
            "preview_v4_auto_provision_rule_disable",
            "confirm_v4_auto_provision_rule_disable",
            "execute_confirmed_v4_auto_provision_rule_disable",
            "preview_v4_schedule_create",
            "confirm_v4_schedule_create",
            "execute_confirmed_v4_schedule_create",
            "preview_v4_schedule_delete",
            "confirm_v4_schedule_delete",
            "execute_confirmed_v4_schedule_delete",
            "preview_v4_schedule_assign",
            "confirm_v4_schedule_assign",
            "execute_confirmed_v4_schedule_assign",
            "preview_v4_schedule_assignment_detach",
            "confirm_v4_schedule_assignment_detach",
            "execute_confirmed_v4_schedule_assignment_detach",
            "preview_v4_approval_profile_create",
            "confirm_v4_approval_profile_create",
            "execute_confirmed_v4_approval_profile_create",
            "preview_v4_approval_profile_description_update",
            "confirm_v4_approval_profile_description_update",
            "execute_confirmed_v4_approval_profile_description_update",
            "preview_v4_approval_profile_delete",
            "confirm_v4_approval_profile_delete",
            "execute_confirmed_v4_approval_profile_delete",
            "preview_v4_approval_email_template_create",
            "confirm_v4_approval_email_template_create",
            "execute_confirmed_v4_approval_email_template_create",
            "preview_v4_approval_email_template_content_update",
            "confirm_v4_approval_email_template_content_update",
            "execute_confirmed_v4_approval_email_template_content_update",
            "preview_v4_approval_email_template_delete",
            "confirm_v4_approval_email_template_delete",
            "execute_confirmed_v4_approval_email_template_delete",
        }

        unavailable = rpc(
            "tools/call",
            {
                "name": "preview_v4_administrative_intent",
                "arguments": {"scheme_draft_ref": "server-draft-ref-0001"},
            },
        )["result"]
        assert unavailable["isError"] is True  # type: ignore[index]
        assert "server-draft-ref-0001" not in str(unavailable)

        read_client_id = _register_public_client(client)
        read_code, read_verifier = _authorize_and_login(client, read_client_id)
        read_token = client.post(
            "/fpamcp/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": read_client_id,
                "code": read_code,
                "code_verifier": read_verifier,
                "redirect_uri": "https://client.example/callback",
                "resource": "https://mcp.example.com/fpamcp",
            },
        )
        read_headers = _request_headers(read_token.json()["access_token"])
        read_headers["host"] = "mcp.example.com"
        lower_scope = client.post(
            "/fpamcp",
            headers=read_headers,
            json={
                "jsonrpc": "2.0",
                "id": "scope-denied",
                "method": "tools/call",
                "params": {"name": "get_v4_plan_status", "arguments": {}},
            },
        )
        assert lower_scope.status_code == 200
        assert lower_scope.json()["result"]["isError"] is True


def test_packaged_streamable_http_smoke_is_offline() -> None:
    result = run_smoke()

    assert result["transport"] == "streamable_http"
    assert result["tool_count"] == len(EXPECTED_TOOLS)
    assert result["missing_credential_rejected"] is True
    assert result["live_fortipam_contacted"] is False


@pytest.mark.parametrize("mode", ["valid", "path_mismatch", "invalid_binding"])
def test_main_selects_target_bound_web_without_loading_legacy_binding(tmp_path, monkeypatch, mode):
    from fortipam_mcp.secret_create_lab_auto_runtime import (
        LAB_AUTO_SECRET_CREATE_ENV_PREFIX, LAB_AUTO_SECRET_CREATE_TARGET_WEB_700_PROFILE,
    )
    from test_target_bound_web_projection_reader import binding_payload

    binding_path = tmp_path / "web-binding.json"
    binding_path.write_text(json.dumps(binding_payload()) if mode != "invalid_binding" else "{}")
    binding_path.chmod(0o600)
    monkeypatch.setenv(LAB_AUTO_SECRET_CREATE_ENV_PREFIX + "PROFILE", LAB_AUTO_SECRET_CREATE_TARGET_WEB_700_PROFILE)
    monkeypatch.setenv(LAB_AUTO_SECRET_CREATE_ENV_PREFIX + "TARGET_WEB_BINDING_FILE", str(binding_path))
    settings = SimpleNamespace(v4_confirmation=object())
    host_settings = SimpleNamespace(
        host_mode="source-backed-secret-onboarding",
        secret_onboarding_binding_path=(tmp_path / "different.json" if mode == "path_mismatch" else binding_path),
    )
    monkeypatch.setattr(http_server_module, "load_http_runtime_environment", lambda: False)
    monkeypatch.setattr(HttpServerSettings, "from_environment", classmethod(lambda cls: settings))
    monkeypatch.setattr(http_server_module, "synthetic_host_settings_from_environment", lambda env: host_settings)
    def forbidden(*args, **kwargs):
        pytest.fail("Target-bound startup must not load legacy selectors or Target actions")
    monkeypatch.setattr(http_server_module, "OwnerOnlySecretOnboardingBindingResolver", forbidden)
    monkeypatch.setattr(http_server_module, "load_target_http_transport_config", forbidden)
    captured = {}
    monkeypatch.setattr(http_server_module, "load_secret_metadata_http_transport_config", lambda env: "config")
    def transport(config, *, bound_secret_name):
        captured["bound_secret_name"] = bound_secret_name
        return "metadata-transport"
    monkeypatch.setattr(http_server_module, "FortiPamSecretMetadataHttpTransport", transport)
    class Selected(Exception):
        pass
    def selected(actual_settings, *, binding, secret_transport):
        assert actual_settings is host_settings
        assert secret_transport == "metadata-transport"
        captured["binding"] = binding
        raise Selected
    monkeypatch.setattr(http_server_module, "target_bound_web_v4_plan_host_factory", selected)
    if mode == "valid":
        with pytest.raises(Selected):
            http_server_module.main()
        assert captured["bound_secret_name"] == captured["binding"].create_binding.secret_name
    else:
        with pytest.raises(SystemExit, match="Target-bound Web"):
            http_server_module.main()
        assert captured == {}


@pytest.mark.parametrize("mode", ["valid", "path_mismatch", "invalid_binding", "missing_owner", "namespace", "bad_namespace"])
def test_main_selects_domain_secret_without_loading_legacy_binding(tmp_path, monkeypatch, mode):
    from fortipam_mcp import owner_collector_runtime, owner_domain_runtime
    from fortipam_mcp.secret_create_lab_auto_runtime import (
        LAB_AUTO_SECRET_CREATE_ENV_PREFIX, LAB_AUTO_SECRET_CREATE_DOMAIN_700_PROFILE,
    )
    from test_domain_secret_projection_reader import planning_source, Transport
    from fortipam_mcp.domain_secret_projection_reader import PLANNING_BINDING_CONTRACT
    from dataclasses import asdict
    _, source = planning_source(Transport())
    payload = asdict(source._binding)
    create = payload.pop("create_binding")
    payload.update({name: create[name] for name in (
        "folder_path", "secret_name", "target_name", "target_ipv4_address",
        "domain_dns_root", "target_owner_name", "target_classification_tag",
    )})
    payload["contract"] = PLANNING_BINDING_CONTRACT

    binding_path = tmp_path / "domain-binding.json"
    binding_path.write_text(json.dumps(payload) if mode != "invalid_binding" else "{}")
    binding_path.chmod(0o600)
    monkeypatch.setenv(LAB_AUTO_SECRET_CREATE_ENV_PREFIX + "PROFILE", LAB_AUTO_SECRET_CREATE_DOMAIN_700_PROFILE)
    monkeypatch.setenv(LAB_AUTO_SECRET_CREATE_ENV_PREFIX + "DOMAIN_BINDING_FILE", str(binding_path))
    if mode in {"namespace", "bad_namespace"}:
        from fortipam_mcp import domain_secret_namespace_candidate as namespace_module
        pin = tmp_path / "namespace-pin"; pin.write_text("synthetic"); pin.chmod(0o600)
        namespace_path = tmp_path / "namespace.json"
        namespace_path.write_text(json.dumps({"contract":namespace_module.CONTRACT,"folder_id":17,
            "witness_secret_ids":[51,52]}) if mode == "namespace" else "{}")
        namespace_path.chmod(0o600)
        for key,value in {"ENABLED":"true","BINDING_FILE":str(namespace_path),"SSH_HOST":"example.test",
            "SSH_KNOWN_HOSTS_FILE":str(pin)}.items():
            monkeypatch.setenv(namespace_module.PREFIX+key,value)
    settings = SimpleNamespace(v4_confirmation=object())
    host_settings = SimpleNamespace(
        host_mode="source-backed-secret-onboarding",
        secret_onboarding_binding_path=(tmp_path / "different.json" if mode == "path_mismatch" else binding_path),
    )
    monkeypatch.setattr(http_server_module, "load_http_runtime_environment", lambda: False)
    monkeypatch.setattr(HttpServerSettings, "from_environment", classmethod(lambda cls: settings))
    monkeypatch.setattr(http_server_module, "synthetic_host_settings_from_environment", lambda env: host_settings)

    def forbidden(*args, **kwargs):
        pytest.fail("Domain startup must not load legacy selectors or Target actions")

    monkeypatch.setattr(http_server_module, "OwnerOnlySecretOnboardingBindingResolver", forbidden)
    monkeypatch.setattr(http_server_module, "load_target_http_transport_config", forbidden)
    monkeypatch.setattr(http_server_module, "load_secret_metadata_http_transport_config", lambda env: "config")
    credentials = lambda: ("synthetic-owner", "synthetic-material")
    monkeypatch.setattr(owner_collector_runtime, "owner_login_provider", lambda env: None if mode == "missing_owner" else credentials)
    captured = {}

    def transport(config, binding, owner, *, allow_secret_create=False):
        assert config == "config" and owner is credentials
        assert allow_secret_create is False
        captured["binding"] = binding
        return "domain-owner-transport"

    monkeypatch.setattr(owner_domain_runtime, "owner_domain_transport", transport)
    if mode == "namespace":
        def composed(config, binding, owner, *, namespace_settings):
            assert namespace_settings.folder_id == 17 and namespace_settings.witness_secret_ids == (51,52)
            return transport(config,binding,owner)
        monkeypatch.setattr(namespace_module, "owner_domain_namespace_transport", composed)

    class Selected(Exception):
        pass

    def selected(actual_settings, *, binding, secret_transport):
        assert actual_settings is host_settings
        assert secret_transport == "domain-owner-transport"
        assert captured["binding"] == binding.create_binding
        raise Selected

    monkeypatch.setattr(http_server_module, "domain_secret_v4_plan_host_factory", selected)
    if mode in {"valid", "namespace"}:
        with pytest.raises(Selected):
            http_server_module.main()
    else:
        with pytest.raises(SystemExit, match="Domain Secret"):
            http_server_module.main()
        assert captured == {}
