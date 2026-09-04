from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re

from starlette.testclient import TestClient

from fortipam_mcp.approval_service import (
    CONTROLLED_OPERATION_DB_ENV,
    CONTROLLED_OPERATION_HMAC_KEY_FILE_ENV,
)
from fortipam_mcp.controlled_operation_store import ControlledOperationStateStore
from fortipam_mcp.controlled_operations import (
    ApprovalBinding,
    AuthenticatedPrincipal,
)
from fortipam_mcp.http_server import HttpServerSettings, create_http_app
from fortipam_mcp.local_oauth import hash_local_password


PREFIX = "FORTIPAM_MCP_HTTP_"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _environment(tmp_path: Path) -> dict[str, str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    oauth_state = tmp_path / "oauth-state"
    operation_state = tmp_path / "operation-state"
    oauth_state.mkdir(mode=0o700)
    operation_state.mkdir(mode=0o700)
    key = operation_state / "operation.key"
    key.write_bytes(b"controlled-operation-test-key!!!")
    os.chmod(key, 0o600)
    return {
        f"{PREFIX}AUTH_MODE": "local_oauth",
        f"{PREFIX}PATH": "/fpamcp",
        f"{PREFIX}PUBLIC_URL": "https://mcp.example.com/fpamcp",
        f"{PREFIX}ALLOWED_HOSTS": "mcp.example.com",
        f"{PREFIX}LOCAL_OAUTH_DB": str(oauth_state / "oauth.sqlite3"),
        f"{PREFIX}LOCAL_OAUTH_USERNAME": "operator",
        f"{PREFIX}LOCAL_OAUTH_PASSWORD_HASH": hash_local_password(
            "correct-horse-battery-staple",
            salt=b"0123456789abcdef",
        ),
        CONTROLLED_OPERATION_DB_ENV: str(operation_state / "operation.sqlite3"),
        CONTROLLED_OPERATION_HMAC_KEY_FILE_ENV: str(key),
    }


def _binding() -> ApprovalBinding:
    return ApprovalBinding(
        purpose="forward",
        principal_digest=_digest("operator"),
        action_id="synthetic-action",
        action_version="3.0.0",
        target_digest=_digest("synthetic-target-reference"),
        parameters_digest=_digest("{}"),
        expected_current_digest=_digest("expected-state"),
    )


def test_local_approval_page_is_csrf_origin_auth_and_nonce_protected(
    tmp_path: Path,
) -> None:
    settings = HttpServerSettings.from_environment(_environment(tmp_path))
    assert settings.controlled_operation is not None
    assert settings.local_oauth is not None
    assert "fortipam:operate" in settings.local_oauth.available_scopes
    assert "fortipam:operate" not in settings.local_oauth.default_scopes
    store = ControlledOperationStateStore(
        settings.controlled_operation.database_path,
        settings.controlled_operation.hmac_key_path,
    )
    binding = _binding()
    issued = store.issue_approval(binding)

    with TestClient(
        create_http_app(settings),
        base_url="https://mcp.example.com",
    ) as client:
        page = client.get("/fpamcp/oauth/approval")
        assert page.status_code == 200
        assert "no FortiPAM device action is registered" in page.text
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
        assert csrf is not None
        form = {
            "csrf_token": csrf.group(1),
            "approval_reference": issued.approval_reference,
            "approval_nonce": issued.approval_nonce,
            "username": "operator",
            "password": "correct-horse-battery-staple",
            "action": "approve",
        }
        cross_origin = client.post(
            "/fpamcp/oauth/approval",
            data=form,
            headers={"origin": "https://attacker.example"},
        )
        assert cross_origin.status_code == 400

        wrong_password = client.post(
            "/fpamcp/oauth/approval",
            data={**form, "password": "wrong-password-value"},
            headers={"origin": "https://mcp.example.com"},
        )
        assert wrong_password.status_code == 401
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', wrong_password.text)
        assert csrf is not None
        accepted = client.post(
            "/fpamcp/oauth/approval",
            data={**form, "csrf_token": csrf.group(1)},
            headers={"origin": "https://mcp.example.com"},
        )
        assert accepted.status_code == 200
        assert "Decision recorded" in accepted.text
        assert issued.approval_reference not in accepted.text
        assert issued.approval_nonce not in accepted.text

    restarted = ControlledOperationStateStore(
        settings.controlled_operation.database_path,
        settings.controlled_operation.hmac_key_path,
    )
    claims = restarted.verify(
        issued.approval_reference,
        AuthenticatedPrincipal("operator", "operator"),
        binding,
        now_epoch=issued.expires_at - 1,
    )
    assert claims.binding == binding


def test_controlled_operation_settings_require_local_oauth_and_complete_paths(
    tmp_path: Path,
) -> None:
    environment = _environment(tmp_path)
    environment.pop(CONTROLLED_OPERATION_HMAC_KEY_FILE_ENV)
    try:
        HttpServerSettings.from_environment(environment)
    except ValueError as exc:
        assert "both database and HMAC key" in str(exc)
    else:
        raise AssertionError("partial controlled-operation state was accepted")

    environment = _environment(tmp_path / "second")
    environment[f"{PREFIX}AUTH_MODE"] = "bearer"
    environment[f"{PREFIX}BEARER_TOKEN"] = "test-only-bearer-token-0123456789abcdef"
    try:
        HttpServerSettings.from_environment(environment)
    except ValueError as exc:
        assert "embedded local OAuth" in str(exc)
    else:
        raise AssertionError("non-local OAuth approval service was accepted")
