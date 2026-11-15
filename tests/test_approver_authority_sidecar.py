from __future__ import annotations

from collections.abc import Iterator
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

import pytest
from starlette.testclient import TestClient

import fortipam_mcp.approver_authority_sidecar as sidecar_module
from fortipam_mcp.approver_authority_sidecar import (
    ApproverAuthoritySidecarError,
    UnixApproverAuthorizationClient,
    UnixApproverAuthorizationClientSettings,
    authority_sidecar_settings_from_environment,
    create_approver_authority_sidecar_app,
)
from fortipam_mcp.approver_checkpoint_sidecar import (
    UnixApproverCheckpointClient,
    UnixApproverCheckpointClientSettings,
)
from fortipam_mcp.local_oauth import (
    LocalOAuthProvider,
    LocalOAuthSettings,
    hash_local_password,
)
from fortipam_mcp.v4_confirmation_http import V4ConfirmationSettings
from fortipam_mcp.v4_runtime_host import (
    V4SyntheticHostSettings,
    synthetic_v4_plan_host_factory,
)
from test_approver_authority import (
    AUTHORITY_REF,
    CHECKPOINT_STORE_REF,
    _ExternalApproverCheckpoint,
    _chain,
    _issue,
    _new_authority,
)
from v4_planning import ApprovalReceiptAuthenticator


CHECKPOINT_AUTHORITY_REF = "v4-approver-authority-sidecar-checkpoint"


@pytest.fixture
def socket_paths() -> Iterator[tuple[Path, Path]]:
    scratch = Path(__file__).resolve().parents[1] / ".codex_tmp"
    scratch.mkdir(mode=0o700, exist_ok=True)
    socket_dir = Path(tempfile.mkdtemp(prefix="faa-", dir=scratch))
    os.chmod(socket_dir, 0o700)
    paths = (socket_dir / "checkpoint.sock", socket_dir / "authority.sock")
    yield paths
    for path in paths:
        if path.exists() or path.is_symlink():
            path.unlink()
    socket_dir.rmdir()


def _owner_file(path: Path, value: bytes) -> Path:
    path.write_bytes(value)
    os.chmod(path, 0o600)
    return path


def test_approver_authority_app_exposes_only_ready_and_exact_authorize(
    tmp_path: Path,
) -> None:
    root = tmp_path / "authority"
    root.mkdir(mode=0o700)
    checkpoint = _ExternalApproverCheckpoint()
    authority, _database, _key = _new_authority(
        root,
        monotonic_checkpoint=checkpoint,
        checkpoint_store_ref=CHECKPOINT_STORE_REF,
    )
    requester, approver, plan, _issuer, policy = _chain()
    _issue(authority, approver, plan)
    request = {
        "approver": sidecar_module._approver_payload(approver),
        "authority_ref": AUTHORITY_REF,
        "now_epoch": policy.issued_at,
        "plan": sidecar_module._plan_payload(plan),
        "policy_decision": sidecar_module._policy_payload(policy),
        "requester": sidecar_module._requester_payload(requester),
    }

    with TestClient(create_approver_authority_sidecar_app(authority)) as client:
        ready = client.post(
            "/v1/approver-authority/ready",
            json={"authority_ref": AUTHORITY_REF},
        )
        authorized = client.post(
            "/v1/approver-authority/authorize",
            json=request,
        )
        unknown = client.get("/v1/approver-authority/authorize")
        extension = client.post(
            "/v1/approver-authority/authorize",
            json={**request, "private-marker": "must-not-reflect"},
        )
        altered_plan = dict(request["plan"])
        altered_plan["plan_digest"] = "f" * 64
        tampered = client.post(
            "/v1/approver-authority/authorize",
            json={**request, "plan": altered_plan},
        )

    assert ready.status_code == 204 and not ready.content
    assert authorized.status_code == 200
    decision = sidecar_module._authorization_from_payload(
        authorized.json()["decision"]
    )
    assert decision.authorized is True
    assert decision.execution_authorized is False
    assert unknown.status_code == 405
    assert extension.status_code == 409
    assert extension.json() == {"status": "rejected"}
    assert "must-not-reflect" not in extension.text
    assert tampered.status_code == 409


def test_approver_authority_sidecar_environment_is_complete(
    tmp_path: Path,
    socket_paths: tuple[Path, Path],
) -> None:
    checkpoint_socket, authority_socket = socket_paths
    environment = {
        "FORTIPAM_MCP_V4_APPROVER_AUTHORITY_DATABASE": str(
            tmp_path / "authority.sqlite3"
        ),
        "FORTIPAM_MCP_V4_APPROVER_AUTHORITY_HMAC_KEY_FILE": str(
            tmp_path / "authority.hmac"
        ),
        "FORTIPAM_MCP_V4_APPROVER_AUTHORITY_REF": AUTHORITY_REF,
        "FORTIPAM_MCP_V4_APPROVER_AUTHORITY_CHECKPOINT_SOCKET": str(
            checkpoint_socket
        ),
        "FORTIPAM_MCP_V4_APPROVER_AUTHORITY_CHECKPOINT_REF": (
            CHECKPOINT_AUTHORITY_REF
        ),
        "FORTIPAM_MCP_V4_APPROVER_AUTHORITY_CHECKPOINT_STORE_REF": (
            CHECKPOINT_STORE_REF
        ),
        "FORTIPAM_MCP_V4_APPROVER_AUTHORITY_SOCKET": str(authority_socket),
    }
    settings = authority_sidecar_settings_from_environment(environment)
    assert settings.authority_ref == AUTHORITY_REF
    assert settings.socket_path == authority_socket

    del environment["FORTIPAM_MCP_V4_APPROVER_AUTHORITY_SOCKET"]
    with pytest.raises(ApproverAuthoritySidecarError, match="incomplete"):
        authority_sidecar_settings_from_environment(environment)


def test_unix_approver_authority_client_survives_restart_and_binds_host(
    tmp_path: Path,
    socket_paths: tuple[Path, Path],
) -> None:
    checkpoint_socket, authority_socket = socket_paths
    checkpoint_state = tmp_path / "checkpoint-state"
    checkpoint_state.mkdir(mode=0o700)
    os.chmod(checkpoint_state, 0o700)
    checkpoint_key = _owner_file(checkpoint_state / "checkpoint.hmac", b"k" * 32)
    checkpoint_environment = {
        **os.environ,
        "FORTIPAM_MCP_V4_APPROVER_CHECKPOINT_DATABASE": str(
            checkpoint_state / "checkpoint.sqlite3"
        ),
        "FORTIPAM_MCP_V4_APPROVER_CHECKPOINT_HMAC_KEY_FILE": str(checkpoint_key),
        "FORTIPAM_MCP_V4_APPROVER_CHECKPOINT_AUTHORITY_REF": (
            CHECKPOINT_AUTHORITY_REF
        ),
        "FORTIPAM_MCP_V4_APPROVER_CHECKPOINT_SOCKET": str(checkpoint_socket),
        "PYTHONPATH": "src:.",
    }
    checkpoint_process = _start_sidecar(
        "fortipam_mcp.approver_checkpoint_sidecar",
        checkpoint_environment,
        checkpoint_socket,
    )
    authority_process: subprocess.Popen[bytes] | None = None
    try:
        authority_state = tmp_path / "authority-state"
        authority_state.mkdir(mode=0o700)
        os.chmod(authority_state, 0o700)
        authority_key = _owner_file(authority_state / "authority.hmac", b"a" * 32)
        checkpoint_client = UnixApproverCheckpointClient(
            UnixApproverCheckpointClientSettings(
                checkpoint_socket,
                CHECKPOINT_AUTHORITY_REF,
            )
        )
        from v4_planning import PersistentApproverAuthorizationAuthority

        authority = PersistentApproverAuthorizationAuthority(
            authority_state / "authority.sqlite3",
            authority_key,
            authority_ref=AUTHORITY_REF,
            monotonic_checkpoint=checkpoint_client,
            checkpoint_store_ref=CHECKPOINT_STORE_REF,
        )
        requester, approver, plan, _issuer, policy = _chain()
        _issue(authority, approver, plan)
        authority_environment = {
            **os.environ,
            "FORTIPAM_MCP_V4_APPROVER_AUTHORITY_DATABASE": str(
                authority_state / "authority.sqlite3"
            ),
            "FORTIPAM_MCP_V4_APPROVER_AUTHORITY_HMAC_KEY_FILE": str(authority_key),
            "FORTIPAM_MCP_V4_APPROVER_AUTHORITY_REF": AUTHORITY_REF,
            "FORTIPAM_MCP_V4_APPROVER_AUTHORITY_CHECKPOINT_SOCKET": str(
                checkpoint_socket
            ),
            "FORTIPAM_MCP_V4_APPROVER_AUTHORITY_CHECKPOINT_REF": (
                CHECKPOINT_AUTHORITY_REF
            ),
            "FORTIPAM_MCP_V4_APPROVER_AUTHORITY_CHECKPOINT_STORE_REF": (
                CHECKPOINT_STORE_REF
            ),
            "FORTIPAM_MCP_V4_APPROVER_AUTHORITY_SOCKET": str(authority_socket),
            "PYTHONPATH": "src:.",
        }
        client = UnixApproverAuthorizationClient(
            UnixApproverAuthorizationClientSettings(
                authority_socket,
                AUTHORITY_REF,
            )
        )

        authority_process = _start_sidecar(
            "fortipam_mcp.approver_authority_sidecar",
            authority_environment,
            authority_socket,
        )
        client.verify_ready()
        decision = client.authorize(
            plan,
            policy,
            requester,
            approver,
            now_epoch=policy.issued_at,
        )
        assert decision.authorized is True
        assert decision.execution_authorized is False
        _stop_sidecar(authority_process, authority_socket)
        authority_process = None

        authority_process = _start_sidecar(
            "fortipam_mcp.approver_authority_sidecar",
            authority_environment,
            authority_socket,
        )
        client.verify_ready()
        restarted_decision = client.authorize(
            plan,
            policy,
            requester,
            approver,
            now_epoch=policy.issued_at,
        )
        assert restarted_decision.authorization_digest != decision.authorization_digest

        host_state = tmp_path / "host-state"
        host_state.mkdir(mode=0o700)
        os.chmod(host_state, 0o700)
        planning_key = _owner_file(host_state / "planning.hmac", b"p" * 32)
        confirmation_key = _owner_file(host_state / "confirmation.hmac", b"c" * 32)
        browser_key = _owner_file(host_state / "browser.hmac", b"b" * 32)
        oauth_state = tmp_path / "oauth-state"
        oauth_state.mkdir(mode=0o700)
        os.chmod(oauth_state, 0o700)
        provider = LocalOAuthProvider(
            LocalOAuthSettings(
                issuer="https://mcp.example.com/fpamcp-v4/oauth",
                resource="https://mcp.example.com/fpamcp-v4",
                database_path=oauth_state / "oauth.sqlite3",
                username="operator",
                password_hash=hash_local_password(
                    "correct-horse-battery-staple",
                    salt=b"0123456789abcdef",
                ),
            )
        )
        components = synthetic_v4_plan_host_factory(
            V4SyntheticHostSettings(host_state / "planning.sqlite3", planning_key),
            approval_receipt_authenticator=ApprovalReceiptAuthenticator(b"r" * 32),
            approver_authorization_authority=client,
        )(
            provider,
            V4ConfirmationSettings(
                host_state / "confirmation.sqlite3",
                confirmation_key,
                browser_key,
            ),
        )
        status = components.plan_services.status()
        assert status["approver_authorization_protocol_bound"] is True
        assert status["approver_authority_checkpoint_protocol_bound"] is True
        assert status["dispatchable"] is False
    finally:
        if authority_process is not None:
            _stop_sidecar(authority_process, authority_socket)
        _stop_sidecar(checkpoint_process, checkpoint_socket)


def test_unix_approver_authority_client_rejects_missing_or_non_socket(
    tmp_path: Path,
) -> None:
    socket_path = tmp_path / "authority.sock"
    client = UnixApproverAuthorizationClient(
        UnixApproverAuthorizationClientSettings(socket_path, AUTHORITY_REF)
    )
    with pytest.raises(ApproverAuthoritySidecarError, match="unavailable"):
        client.verify_ready()
    socket_path.write_text("not-a-socket", encoding="utf-8")
    os.chmod(socket_path, 0o600)
    with pytest.raises(ApproverAuthoritySidecarError, match="boundary is invalid"):
        client.verify_ready()


def _start_sidecar(
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
            raise AssertionError(f"sidecar stopped before ready: {stderr!r}")
        time.sleep(0.02)
    _stop_sidecar(process, socket_path)
    raise AssertionError("sidecar did not create its Unix socket")


def _stop_sidecar(process: subprocess.Popen[bytes], socket_path: Path) -> None:
    process.terminate()
    try:
        process.wait(timeout=5.0)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5.0)
    if socket_path.exists() or socket_path.is_symlink():
        socket_path.unlink()
