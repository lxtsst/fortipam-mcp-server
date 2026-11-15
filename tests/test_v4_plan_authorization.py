from __future__ import annotations

import os
from pathlib import Path

import pytest
from mcp.server.auth.provider import AccessToken

from fortipam_mcp.local_oauth import LOCAL_SCOPES
from fortipam_mcp.v4_plan_runtime import (
    V4_APPROVAL_SCOPE,
    V4_PLANNING_PRINCIPAL_HMAC_KEY_FILE_ENV,
    V4PlanningAuthorizationSettings,
    V4PlanningRuntimeError,
    approver_from_access_token,
    planning_authorization_settings_from_environment,
    planning_principal_from_access_token,
    requester_from_access_token,
)


RESOURCE = "https://mcp.example.com/fpamcp-v4"


def _settings() -> V4PlanningAuthorizationSettings:
    return V4PlanningAuthorizationSettings(RESOURCE, b"p" * 32)


def _token(**changes: object) -> AccessToken:
    values: dict[str, object] = {
        "token": "opaque-sdk-validated-access-token",
        "client_id": "client-0001",
        "scopes": ["fortipam:read", "fortipam:plan"],
        "expires_at": 2_000_000_000,
        "resource": RESOURCE,
        "subject": "operator-0001",
        "claims": {"iss": "https://issuer.example/oauth"},
    }
    values.update(changes)
    return AccessToken(**values)  # type: ignore[arg-type]


def test_owner_only_planning_key_and_stable_opaque_requester(tmp_path: Path) -> None:
    state = tmp_path / "v4-state"
    state.mkdir(mode=0o700)
    os.chmod(state, 0o700)
    key = state / "principal.hmac"
    key.write_text("70" * 32, encoding="ascii")
    os.chmod(key, 0o600)
    settings = planning_authorization_settings_from_environment(
        {V4_PLANNING_PRINCIPAL_HMAC_KEY_FILE_ENV: str(key)},
        expected_resource=RESOURCE,
    )

    first = requester_from_access_token(_token(), settings)
    second = requester_from_access_token(_token(token="different-token"), settings)
    other = requester_from_access_token(_token(subject="operator-0002"), settings)
    other_client = planning_principal_from_access_token(
        _token(client_id="client-0002"),
        settings,
    )
    original_binding = planning_principal_from_access_token(_token(), settings)

    assert first == second
    assert first != other
    assert other_client.requester == first
    assert (
        other_client.transport_namespace_digest
        != original_binding.transport_namespace_digest
    )
    assert first.principal_class == "operator"
    assert len(first.subject_ref) == 64
    assert first.identity_authority_ref is not None
    assert first.subject_namespace is not None
    assert len(first.identity_authority_ref) == 64
    assert len(first.subject_namespace) == 64
    assert "operator" not in first.subject_ref


def test_scoped_approver_identity_is_comparable_without_raw_claims() -> None:
    settings = _settings()
    requester = requester_from_access_token(_token(), settings)
    same_human = approver_from_access_token(
        _token(scopes=[V4_APPROVAL_SCOPE]),
        settings,
    )
    other_human = approver_from_access_token(
        _token(
            scopes=[V4_APPROVAL_SCOPE],
            subject="reviewer-0002",
            client_id="approval-client-0002",
        ),
        settings,
    )

    assert same_human.identity_digest == requester.identity_digest
    assert same_human.subject_ref == requester.subject_ref
    assert other_human.identity_digest != requester.identity_digest
    assert other_human.identity_authority_ref == requester.identity_authority_ref
    assert other_human.subject_namespace == requester.subject_namespace
    serialized = repr((requester, same_human, other_human))
    assert "operator-0001" not in serialized
    assert "reviewer-0002" not in serialized
    assert "https://issuer.example" not in serialized


def test_approver_identity_requires_distinct_approval_scope() -> None:
    assert V4_APPROVAL_SCOPE not in LOCAL_SCOPES
    with pytest.raises(V4PlanningRuntimeError, match="authorization denied"):
        approver_from_access_token(_token(), _settings())
    with pytest.raises(V4PlanningRuntimeError, match="authorization denied"):
        approver_from_access_token(
            _token(scopes=[V4_APPROVAL_SCOPE, "fortipam:plan"]),
            _settings(),
        )
    with pytest.raises(V4PlanningRuntimeError, match="authorization denied"):
        requester_from_access_token(
            _token(scopes=["fortipam:plan", V4_APPROVAL_SCOPE]),
            _settings(),
        )


@pytest.mark.parametrize(
    "token",
    (
        None,
        _token(scopes=["fortipam:read"]),
        _token(resource="https://other.example/fpamcp-v4"),
        _token(expires_at=None),
        _token(claims={}),
        _token(scopes=["fortipam:plan", "fortipam:plan"]),
    ),
)
def test_planning_principal_denies_non_sdk_or_incomplete_authority(
    token: AccessToken | None,
) -> None:
    with pytest.raises(V4PlanningRuntimeError, match="authorization denied"):
        requester_from_access_token(token, _settings())


def test_planning_key_rejects_group_readable_or_partial_configuration(
    tmp_path: Path,
) -> None:
    state = tmp_path / "unsafe-state"
    state.mkdir(mode=0o700)
    key = state / "principal.hmac"
    key.write_text("70" * 32, encoding="ascii")
    os.chmod(key, 0o640)
    with pytest.raises(V4PlanningRuntimeError, match="authorization denied"):
        planning_authorization_settings_from_environment(
            {V4_PLANNING_PRINCIPAL_HMAC_KEY_FILE_ENV: str(key)},
            expected_resource=RESOURCE,
        )
    with pytest.raises(V4PlanningRuntimeError, match="authorization denied"):
        planning_authorization_settings_from_environment(
            {},
            expected_resource=RESOURCE,
        )

    safe_state = tmp_path / "safe-state"
    safe_state.mkdir(mode=0o700)
    safe_key = safe_state / "principal.hmac"
    safe_key.write_text("70" * 32, encoding="ascii")
    os.chmod(safe_key, 0o600)
    symlink = safe_state / "linked.hmac"
    symlink.symlink_to(safe_key)
    with pytest.raises(V4PlanningRuntimeError, match="authorization denied"):
        planning_authorization_settings_from_environment(
            {V4_PLANNING_PRINCIPAL_HMAC_KEY_FILE_ENV: str(symlink)},
            expected_resource=RESOURCE,
        )
