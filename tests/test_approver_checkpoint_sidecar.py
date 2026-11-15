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

from fortipam_mcp.approver_checkpoint_sidecar import (
    ApproverCheckpointSidecarError,
    UnixApproverCheckpointClient,
    UnixApproverCheckpointClientSettings,
    approver_checkpoint_settings_from_environment,
    create_approver_checkpoint_sidecar_app,
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
from v4_planning import (
    ApprovalReceiptAuthenticator,
    ApproverAuthorityError,
    ApproverAuthorityStoreTail,
    AuthenticatedApprover,
    PersistentApproverAuthorizationAuthority,
    PersistentApproverCheckpointAuthority,
)


AUTHORITY_REF = "v4-approver-checkpoint-sidecar-test"
STORE_REF = "v4-sidecar-approver-store-test"


def _owner_file(path: Path, value: bytes) -> Path:
    path.write_bytes(value)
    os.chmod(path, 0o600)
    return path


@pytest.fixture
def checkpoint_paths(tmp_path: Path) -> Iterator[tuple[Path, Path, Path]]:
    state = tmp_path / "checkpoint-state"
    state.mkdir(mode=0o700)
    os.chmod(state, 0o700)
    scratch = Path(__file__).resolve().parents[1] / ".codex_tmp"
    scratch.mkdir(mode=0o700, exist_ok=True)
    socket_dir = Path(tempfile.mkdtemp(prefix="facp-", dir=scratch))
    os.chmod(socket_dir, 0o700)
    paths = (
        state / "checkpoint.sqlite3",
        _owner_file(state / "checkpoint.hmac", b"k" * 32),
        socket_dir / "checkpoint.sock",
    )
    yield paths
    socket_path = paths[2]
    if socket_path.exists() or socket_path.is_symlink():
        socket_path.unlink()
    socket_dir.rmdir()


def _tail(sequence: int, chain_mac: str, last_seen_at: int) -> ApproverAuthorityStoreTail:
    return ApproverAuthorityStoreTail(
        STORE_REF,
        sequence,
        chain_mac,
        last_seen_at,
    )


def test_approver_checkpoint_sidecar_app_exposes_only_exact_cas_operations(
    checkpoint_paths: tuple[Path, Path, Path],
) -> None:
    database, key_path, _socket_path = checkpoint_paths
    authority = PersistentApproverCheckpointAuthority(
        database,
        key_path,
        authority_ref=AUTHORITY_REF,
    )
    empty = ApproverAuthorityStoreTail.empty(STORE_REF)
    observed = _tail(0, empty.chain_mac, 10)

    with TestClient(create_approver_checkpoint_sidecar_app(authority)) as client:
        verified = client.post(
            "/v1/approver-checkpoints/verify",
            json={"authority_ref": AUTHORITY_REF, "tail": _payload(empty)},
        )
        advanced = client.post(
            "/v1/approver-checkpoints/advance",
            json={
                "authority_ref": AUTHORITY_REF,
                "previous": _payload(empty),
                "current": _payload(observed),
            },
        )
        stale = client.post(
            "/v1/approver-checkpoints/advance",
            json={
                "authority_ref": AUTHORITY_REF,
                "previous": _payload(empty),
                "current": _payload(observed),
            },
        )
        unknown = client.get("/v1/approver-checkpoints/verify")
        extension = client.post(
            "/v1/approver-checkpoints/verify",
            json={
                "authority_ref": AUTHORITY_REF,
                "tail": _payload(observed),
                "extra": "rejected-marker",
            },
        )
        wrong_authority = client.post(
            "/v1/approver-checkpoints/verify",
            json={"authority_ref": "wrong-authority-ref", "tail": _payload(observed)},
        )

    assert verified.status_code == 204 and not verified.content
    assert advanced.status_code == 204 and not advanced.content
    assert stale.status_code == 409 and stale.json() == {"status": "rejected"}
    assert unknown.status_code == 405
    assert extension.status_code == 409
    assert "rejected-marker" not in extension.text
    assert wrong_authority.status_code == 409


def test_approver_checkpoint_sidecar_environment_is_complete_and_path_bounded(
    checkpoint_paths: tuple[Path, Path, Path],
) -> None:
    database, key_path, socket_path = checkpoint_paths
    environment = {
        "FORTIPAM_MCP_V4_APPROVER_CHECKPOINT_DATABASE": str(database),
        "FORTIPAM_MCP_V4_APPROVER_CHECKPOINT_HMAC_KEY_FILE": str(key_path),
        "FORTIPAM_MCP_V4_APPROVER_CHECKPOINT_AUTHORITY_REF": AUTHORITY_REF,
        "FORTIPAM_MCP_V4_APPROVER_CHECKPOINT_SOCKET": str(socket_path),
    }
    settings = approver_checkpoint_settings_from_environment(environment)
    assert settings.database_path == database
    assert settings.socket_path == socket_path

    del environment["FORTIPAM_MCP_V4_APPROVER_CHECKPOINT_SOCKET"]
    with pytest.raises(ApproverCheckpointSidecarError, match="incomplete"):
        approver_checkpoint_settings_from_environment(environment)


def test_unix_approver_checkpoint_client_runs_across_process_restart(
    checkpoint_paths: tuple[Path, Path, Path],
) -> None:
    database, key_path, socket_path = checkpoint_paths
    environment = _environment(database, key_path, socket_path)
    empty = ApproverAuthorityStoreTail.empty(STORE_REF)
    observed = _tail(0, empty.chain_mac, 10)
    issued = _tail(1, "a" * 64, 10)
    authorized = _tail(1, "a" * 64, 11)
    client = UnixApproverCheckpointClient(
        UnixApproverCheckpointClientSettings(socket_path, AUTHORITY_REF)
    )

    process = _start_sidecar(environment, socket_path)
    try:
        client.verify(empty)
        client.advance(empty, observed)
        client.advance(observed, issued)
        client.verify(issued)
    finally:
        _stop_sidecar(process, socket_path)

    restarted = _start_sidecar(environment, socket_path)
    try:
        client.verify(issued)
        client.advance(issued, authorized)
        client.verify(authorized)
        with pytest.raises(ApproverCheckpointSidecarError, match="rejected"):
            client.verify(issued)
    finally:
        _stop_sidecar(restarted, socket_path)


def test_unix_approver_checkpoint_client_rejects_non_socket_and_unsafe_socket(
    checkpoint_paths: tuple[Path, Path, Path],
) -> None:
    _database, _key_path, socket_path = checkpoint_paths
    client = UnixApproverCheckpointClient(
        UnixApproverCheckpointClientSettings(socket_path, AUTHORITY_REF)
    )
    with pytest.raises(ApproverCheckpointSidecarError, match="unavailable"):
        client.verify(ApproverAuthorityStoreTail.empty(STORE_REF))

    socket_path.write_text("not-a-socket", encoding="utf-8")
    os.chmod(socket_path, 0o600)
    with pytest.raises(ApproverCheckpointSidecarError, match="boundary is invalid"):
        client.verify(ApproverAuthorityStoreTail.empty(STORE_REF))


def test_persistent_approver_authority_uses_sidecar_and_detects_rollback(
    checkpoint_paths: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    checkpoint_database, checkpoint_key, socket_path = checkpoint_paths
    state = tmp_path / "approver-state"
    state.mkdir(mode=0o700)
    os.chmod(state, 0o700)
    approver_database = state / "approver.sqlite3"
    approver_key = _owner_file(state / "approver.hmac", b"a" * 32)
    client = UnixApproverCheckpointClient(
        UnixApproverCheckpointClientSettings(socket_path, AUTHORITY_REF)
    )
    environment = _environment(checkpoint_database, checkpoint_key, socket_path)

    process = _start_sidecar(environment, socket_path)
    try:
        authority = PersistentApproverAuthorizationAuthority(
            approver_database,
            approver_key,
            authority_ref="v4-sidecar-approver-authority",
            monotonic_checkpoint=client,
            checkpoint_store_ref=STORE_REF,
            clock=lambda: 100,
        )
        empty_database = approver_database.read_bytes()
        authority.issue(
            AuthenticatedApprover(
                "approver-subject-ref",
                identity_authority_ref="approver-identity-authority",
                subject_namespace="approver-subject-namespace",
            ),
            environment_ref="synthetic-environment-ref",
            scope_ref="synthetic-scope-ref",
            action_bindings=(("folder-create", "1.0.0"),),
            policy_version="1.0.0",
            expires_at=200,
            now_epoch=100,
        )
        authority.verify_ready()
        oauth = tmp_path / "oauth"
        oauth.mkdir(mode=0o700)
        os.chmod(oauth, 0o700)
        planning_key = _owner_file(state / "planning.hmac", b"p" * 32)
        confirmation_key = _owner_file(state / "confirmation.hmac", b"c" * 32)
        browser_receipt_key = _owner_file(
            state / "browser-receipt.hmac",
            b"r" * 32,
        )
        provider = LocalOAuthProvider(
            LocalOAuthSettings(
                issuer="https://mcp.example.com/fpamcp-v4/oauth",
                resource="https://mcp.example.com/fpamcp-v4",
                database_path=oauth / "oauth.sqlite3",
                username="operator",
                password_hash=hash_local_password(
                    "correct-horse-battery-staple",
                    salt=b"0123456789abcdef",
                ),
            )
        )
        components = synthetic_v4_plan_host_factory(
            V4SyntheticHostSettings(state / "planning.sqlite3", planning_key),
            clock=lambda: 100,
            approval_receipt_authenticator=ApprovalReceiptAuthenticator(b"s" * 32),
            approver_authorization_authority=authority,
        )(
            provider,
            V4ConfirmationSettings(
                state / "confirmation.sqlite3",
                confirmation_key,
                browser_receipt_key,
            ),
        )
        status = components.plan_services.status()
        assert status["approver_authorization_protocol_bound"] is True
        assert status["approver_authority_checkpoint_protocol_bound"] is True
        blocker_codes = status["blocker_codes"]
        assert isinstance(blocker_codes, list)
        assert "independent_approver_identity_unbound" in blocker_codes
        assert status["dispatchable"] is False
    finally:
        _stop_sidecar(process, socket_path)

    restarted = _start_sidecar(environment, socket_path)
    try:
        PersistentApproverAuthorizationAuthority(
            approver_database,
            approver_key,
            authority_ref="v4-sidecar-approver-authority",
            monotonic_checkpoint=client,
            checkpoint_store_ref=STORE_REF,
            clock=lambda: 100,
        ).verify_ready()
        approver_database.write_bytes(empty_database)
        with pytest.raises(ApproverAuthorityError, match="verification failed"):
            PersistentApproverAuthorizationAuthority(
                approver_database,
                approver_key,
                authority_ref="v4-sidecar-approver-authority",
                monotonic_checkpoint=client,
                checkpoint_store_ref=STORE_REF,
                clock=lambda: 100,
            )
    finally:
        _stop_sidecar(restarted, socket_path)


def _payload(tail: ApproverAuthorityStoreTail) -> dict[str, object]:
    return {
        "store_ref": tail.store_ref,
        "sequence": tail.sequence,
        "chain_mac": tail.chain_mac,
        "last_seen_at": tail.last_seen_at,
    }


def _environment(database: Path, key_path: Path, socket_path: Path) -> dict[str, str]:
    environment = dict(os.environ)
    environment.update(
        {
            "FORTIPAM_MCP_V4_APPROVER_CHECKPOINT_DATABASE": str(database),
            "FORTIPAM_MCP_V4_APPROVER_CHECKPOINT_HMAC_KEY_FILE": str(key_path),
            "FORTIPAM_MCP_V4_APPROVER_CHECKPOINT_AUTHORITY_REF": AUTHORITY_REF,
            "FORTIPAM_MCP_V4_APPROVER_CHECKPOINT_SOCKET": str(socket_path),
            "PYTHONPATH": "src:.",
        }
    )
    return environment


def _start_sidecar(
    environment: dict[str, str],
    socket_path: Path,
) -> subprocess.Popen[bytes]:
    process = subprocess.Popen(
        (sys.executable, "-m", "fortipam_mcp.approver_checkpoint_sidecar"),
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
