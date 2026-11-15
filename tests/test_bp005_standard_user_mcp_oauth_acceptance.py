from __future__ import annotations

import asyncio
import json
from pathlib import Path
import stat
import sys
from types import SimpleNamespace

import pytest

from scripts.bp005_standard_user_mcp_oauth_acceptance import (
    Bp005StandardUserMcpAcceptanceError,
    _consume_dispatch_state,
    run_bp005_standard_user_mcp_oauth_acceptance,
    _validate_confirmation,
    _validate_execution,
    _validate_preview,
)


USERNAME = "mcp-v4-user-bp005-standard-synthetic"
PREVIEW_REF = "local-user-create-preview-opaque"
AUTHORIZATION_REF = "local-user-create-authorized-opaque"


def _preview() -> dict[str, object]:
    return {
        "contract": "bp005_standard_user_create_v1",
        "preview_ref": PREVIEW_REF,
        "device_write_executed": False,
        "Current State": {"requested_username": USERNAME, "user_exists": False},
        "Proposed Changes": {
            "operation": "create_enabled_standard_local_user",
            "username": USERNAME,
            "access_profile": "pam_standard_user",
            "status": "enable",
            "initial_password": "generated_not_returned",
        },
        "Expected State": {
            "username_matches": True,
            "user_exists": True,
            "access_profile_matches": True,
            "status_enabled": True,
            "credentials_returned": False,
        },
    }


def test_acceptance_requires_exact_enabled_standard_preview_and_readback() -> None:
    assert _validate_preview(_preview(), USERNAME, False) == PREVIEW_REF
    assert _validate_confirmation({
        "contract": "bp005_standard_user_create_v1",
        "authorization_ref": AUTHORIZATION_REF,
        "confirmation": "recorded",
        "execution": "authorized_once",
        "device_write_executed": False,
    }, False) == AUTHORIZATION_REF
    _validate_execution({
        "contract": "bp005_standard_user_create_execution_v1",
        "outcome": "succeeded",
        "verification": "verified",
        "idempotent_replay": False,
        "compensation": "not_requested",
        "credentials_returned": False,
        "raw_cli_returned": False,
    }, False)


@pytest.mark.parametrize("field,value", [
    ("access_profile", "Guest"),
    ("status", "disable"),
    ("initial_password", "synthetic-secret"),
])
def test_acceptance_rejects_wrong_role_status_or_secret_projection(field: str, value: str) -> None:
    state = _preview()
    state["Proposed Changes"][field] = value  # type: ignore[index]
    with pytest.raises(Bp005StandardUserMcpAcceptanceError):
        _validate_preview(state, USERNAME, False)


def test_acceptance_requires_the_dedicated_bp005_name_namespace() -> None:
    with pytest.raises(Bp005StandardUserMcpAcceptanceError):
        _validate_preview(_preview(), "mcp-v4-user-reset-fixture", False)


def test_dispatch_record_is_owner_only_and_non_replayable(tmp_path: Path) -> None:
    parent = tmp_path / "dispatch"
    parent.mkdir(mode=0o700)
    parent.chmod(0o700)
    state = parent / "attempt.json"
    _consume_dispatch_state(state)
    assert stat.S_IMODE(state.stat().st_mode) == 0o600
    assert json.loads(state.read_text()) == {
        "contract": "bp005-standard-user-create/v1",
        "dispatch": "consumed",
    }
    with pytest.raises(Bp005StandardUserMcpAcceptanceError):
        _consume_dispatch_state(state)


def test_acceptance_forwards_only_explicit_loopback_tunnel_options(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "dispatch"
    parent.mkdir(mode=0o700)
    parent.chmod(0o700)
    dispatch = parent / "attempt.json"
    observed: dict[str, object] = {}

    async def fake_acceptance(*_args: object, **kwargs: object) -> dict[str, object]:
        observed.update(kwargs)
        return {
            "token_revoked": True,
            "credential_values_returned": False,
            "oauth_metadata_verified": True,
            "mcp_initialized": True,
        }

    from scripts import v4_address_mcp_oauth_surface_acceptance as oauth

    monkeypatch.setattr(oauth, "run_address_mcp_oauth_surface_acceptance", fake_acceptance)
    result = asyncio.run(run_bp005_standard_user_mcp_oauth_acceptance(
            "https://candidate.example/fpamcp-v4",
            Path("/unused/login.env"),
            Path("/unused/client.env"),
            username=USERNAME,
            dispatch_state_file=dispatch,
            ca_file=Path("/unused/ca.pem"),
            lab_connect_host="127.0.0.1",
            lab_connect_port=28443,
            allow_loopback_tunnel=True,
        ))

    assert result["oauth_metadata_verified"] is True
    assert observed["lab_connect_host"] == "127.0.0.1"
    assert observed["lab_connect_port"] == 28443
    assert observed["allow_loopback_tunnel"] is True
