from __future__ import annotations

import os

import pytest
from mcp.server.auth.provider import AccessToken

from fortipam_mcp.folder_mcp_action import (
    ProtectedChildFolderMcpAction,
    V4_FOLDER_ACTION_FEATURE_ENV,
    V4_FOLDER_ACTION_PREFIX,
    V4_FOLDER_ACTION_SCOPE,
    V4_FOLDER_ACTION_UNAVAILABLE,
    V4_FOLDER_EXECUTION_ENV,
    V4FolderActionConfigurationError,
    V4FolderActionRuntimeError,
    build_v4_folder_action,
    folder_action_principal_from_access_token,
    load_v4_folder_action_feature,
    load_v4_folder_execution_feature,
)
from fortipam_mcp.folder_live_workflow import ChildFolderLiveWorkflow
from fortipam_mcp.v4_plan_runtime import (
    V4PlanningAuthorizationSettings,
    V4PlanningPrincipal,
)
from test_v4_m3 import _requester


def test_feature_flag_is_disabled_by_default_and_requires_exact_value() -> None:
    assert load_v4_folder_action_feature({}) is False
    assert load_v4_folder_action_feature({V4_FOLDER_ACTION_FEATURE_ENV: "false"}) is False
    assert load_v4_folder_action_feature({V4_FOLDER_ACTION_FEATURE_ENV: "true"}) is True
    for invalid in ("TRUE", " true", "1", "enabled", ""):
        with pytest.raises(V4FolderActionConfigurationError, match="exactly true or false"):
            load_v4_folder_action_feature({V4_FOLDER_ACTION_FEATURE_ENV: invalid})


def test_final_dispatch_gate_defaults_false_and_is_exact() -> None:
    assert load_v4_folder_execution_feature({}) is False
    assert load_v4_folder_execution_feature({V4_FOLDER_EXECUTION_ENV: "true"}) is True
    with pytest.raises(V4FolderActionConfigurationError, match="exactly true or false"):
        load_v4_folder_execution_feature({V4_FOLDER_EXECUTION_ENV: "yes"})


def test_final_dispatch_gate_denies_after_confirmation(tmp_path) -> None:
    action, transport = _action(tmp_path, execution_enabled=False)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    preview = action.preview("MCP-Beta7-Test", 17, principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)

    with pytest.raises(V4FolderActionRuntimeError, match=V4_FOLDER_ACTION_UNAVAILABLE):
        action.execute(str(confirmation["authorization_ref"]), principal)
    assert transport.calls == ["read", "read"]


def test_folder_action_requires_non_default_operation_scope() -> None:
    resource = "https://mcp.example.test/fpamcp-v4"
    settings = V4PlanningAuthorizationSettings(resource, b"p" * 32)

    def token(scopes: list[str]) -> AccessToken:
        return AccessToken(
            token="opaque-sdk-validated-access-token",
            client_id="client-0001",
            scopes=scopes,
            expires_at=2_000_000_000,
            resource=resource,
            subject="operator-0001",
            claims={"iss": "https://mcp.example.test/oauth"},
        )

    with pytest.raises(V4FolderActionRuntimeError, match=V4_FOLDER_ACTION_UNAVAILABLE):
        folder_action_principal_from_access_token(
            token(["fortipam:read", "fortipam:plan"]),
            settings,
        )

    principal = folder_action_principal_from_access_token(
        token(["fortipam:read", "fortipam:plan", V4_FOLDER_ACTION_SCOPE]),
        settings,
    )

    assert isinstance(principal, V4PlanningPrincipal)


def test_protected_mcp_action_executes_only_the_bound_requester_and_reference(
    tmp_path,
) -> None:
    action, transport = _action(tmp_path)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview("MCP-Beta7-Test", 17, principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    result = action.execute(str(confirmation["authorization_ref"]), principal)

    assert result == {
        "contract": "fortipam_v4_child_folder_execution_v1",
        "compensation": "not_requested",
        "credentials_returned": False,
        "idempotent_replay": False,
        "outcome": "succeeded",
        "raw_response_returned": False,
        "verification": "verified",
    }
    assert transport.calls == ["read", "read", "read", "create", "read"]


def test_preview_identifies_the_requested_child_folder_before_confirmation(tmp_path) -> None:
    action, _ = _action(tmp_path)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)

    preview = action.preview("MCP-Beta7-Test", 17, principal)

    assert preview["Current State"] == {
        "selected_parent_folder_id": 17,
        "requested_child_folder_name": "MCP-Beta7-Test",
        "parent_exists": True,
        "matching_child_exists": False,
    }
    assert preview["Expected State"] == {
        "child_folder_name_matches": True,
        "matching_child_exists": True,
        "inherit_policy": "enable",
        "inherit_permission": "enable",
        "inherit_folder_ztna": "enable",
    }


def test_action_hides_identity_and_binding_failures(tmp_path) -> None:
    action, transport = _action(tmp_path)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    preview = action.preview("MCP-Beta7-Test", 17, principal)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    wrong = V4PlanningPrincipal(
        type(_requester())("different-subject-reference", "operator"),
        "b" * 64,
    )

    with pytest.raises(V4FolderActionRuntimeError, match=V4_FOLDER_ACTION_UNAVAILABLE):
        action.execute(str(confirmation["authorization_ref"]), wrong)
    with pytest.raises(V4FolderActionRuntimeError, match=V4_FOLDER_ACTION_UNAVAILABLE):
        action.execute("bad", wrong)
    assert transport.calls == ["read", "read"]


def test_host_builder_fails_closed_without_protected_configuration() -> None:
    with pytest.raises(
        V4FolderActionConfigurationError,
        match=V4_FOLDER_ACTION_UNAVAILABLE,
    ):
        build_v4_folder_action({})


def test_host_builder_accepts_only_complete_owner_protected_state(tmp_path) -> None:
    state = tmp_path / "controlled-action"
    state.mkdir(mode=0o700)

    def key(name: str, value: bytes):
        path = state / name
        path.write_bytes(value)
        os.chmod(path, 0o600)
        return path

    authorization_key = key("authorization.hmac", b"a" * 40)
    ca_file = state / "ca.pem"
    ca_file.write_text("test-only-ca-placeholder", encoding="ascii")
    os.chmod(ca_file, 0o600)
    environment = {
        f"{V4_FOLDER_ACTION_PREFIX}AUTHORIZATION_DB": str(
            state / "authorization.sqlite3"
        ),
        f"{V4_FOLDER_ACTION_PREFIX}AUTHORIZATION_HMAC_KEY_FILE": str(
            authorization_key
        ),
        "FPA_HOME_LAB_FPA1_V4_FOLDER_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_FOLDER_BASE_URL": "https://fpa.example.test",
        "FPA_HOME_LAB_FPA1_V4_FOLDER_API_TOKEN": "test-token-not-a-real-credential",
        "FPA_HOME_LAB_FPA1_V4_FOLDER_CA_FILE": str(ca_file),
    }

    action = build_v4_folder_action(environment)

    assert isinstance(action, ProtectedChildFolderMcpAction)
    assert (state / "authorization.sqlite3").is_file()


class _Transport:
    def __init__(self) -> None:
        self.exists = False
        self.calls: list[str] = []

    def read_collection(self) -> dict[str, object]:
        self.calls.append("read")
        results: list[dict[str, object]] = [{"id": 17, "name": "Parent"}]
        if self.exists:
            results.append(
                {
                    "id": 77,
                    "name": "MCP-Beta7-Test",
                    "parent-folder": 17,
                    "inherit-policy": "enable",
                    "inherit-permission": "enable",
                    "inherit-folder-ztna": "enable",
                    "user-permission": [],
                    "group-permission": [],
                }
            )
        return {"http_status": 200, "results": results}

    def create_child(self, body: object) -> dict[str, object]:
        self.calls.append("create")
        assert isinstance(body, dict)
        assert body["name"] == "MCP-Beta7-Test"
        self.exists = True
        return {"http_status": 200, "mkey": 77}


def _action(tmp_path, *, execution_enabled: bool = True):
    key = tmp_path / "workflow.hmac"
    key.write_bytes(b"a" * 40)
    transport = _Transport()
    workflow = ChildFolderLiveWorkflow(
        tmp_path / "workflow.sqlite3",
        key,
        transport,
        clock=lambda: 2_000_000_000,
    )
    return (
        ProtectedChildFolderMcpAction(
            workflow,
            execution_enabled=execution_enabled,
        ),
        transport,
    )
