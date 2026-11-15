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

from fortipam_mcp.scheme_draft_checkpoint_sidecar import (
    SchemeDraftCheckpointSidecarError,
    UnixSchemeDraftCheckpointClient,
    UnixSchemeDraftCheckpointClientSettings,
    create_scheme_draft_checkpoint_sidecar_app,
    scheme_draft_checkpoint_settings_from_environment,
)
from v4_planning import (
    AuthenticatedRequester,
    PersistentSchemeDraftAuthority,
    PersistentSchemeDraftCheckpointAuthority,
    SchemeDraftAuthorityError,
    SchemeDraftAuthorityStoreTail,
)
from test_v4_draft_authority import _draft


AUTHORITY_REF = "v4-scheme-draft-checkpoint-sidecar-test"
STORE_REF = "v4-sidecar-scheme-draft-store-test"
DRAFT_AUTHORITY_REF = "v4-sidecar-scheme-draft-authority-test"
NOW = 1_950_000_000


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
    socket_dir = Path(tempfile.mkdtemp(prefix="frcp-", dir=scratch))
    os.chmod(socket_dir, 0o700)
    paths = (
        state / "checkpoint.sqlite3",
        _owner_file(state / "checkpoint.hmac", b"k" * 32),
        socket_dir / "checkpoint.sock",
    )
    yield paths
    if paths[2].exists() or paths[2].is_symlink():
        paths[2].unlink()
    socket_dir.rmdir()


def _tail(sequence: int, chain_mac: str, last_seen_at: int) -> SchemeDraftAuthorityStoreTail:
    return SchemeDraftAuthorityStoreTail(STORE_REF, sequence, chain_mac, last_seen_at)


def test_scheme_draft_checkpoint_sidecar_app_exposes_only_exact_cas_operations(
    checkpoint_paths: tuple[Path, Path, Path],
) -> None:
    database, key_path, _socket_path = checkpoint_paths
    authority = PersistentSchemeDraftCheckpointAuthority(
        database,
        key_path,
        authority_ref=AUTHORITY_REF,
    )
    empty = SchemeDraftAuthorityStoreTail.empty(STORE_REF)
    observed = _tail(0, empty.chain_mac, 10)
    payload = {
        "chain_mac": empty.chain_mac,
        "last_seen_at": empty.last_seen_at,
        "sequence": empty.sequence,
        "store_ref": empty.store_ref,
    }
    with TestClient(create_scheme_draft_checkpoint_sidecar_app(authority)) as client:
        verified = client.post(
            "/v1/scheme-draft-checkpoints/verify",
            json={"authority_ref": AUTHORITY_REF, "tail": payload},
        )
        advanced = client.post(
            "/v1/scheme-draft-checkpoints/advance",
            json={
                "authority_ref": AUTHORITY_REF,
                "previous": payload,
                "current": _payload(observed),
            },
        )
        stale = client.post(
            "/v1/scheme-draft-checkpoints/advance",
            json={
                "authority_ref": AUTHORITY_REF,
                "previous": payload,
                "current": _payload(observed),
            },
        )
        extension = client.post(
            "/v1/scheme-draft-checkpoints/verify",
            json={
                "authority_ref": AUTHORITY_REF,
                "tail": _payload(observed),
                "private-marker": "must-not-reflect",
            },
        )
        unknown = client.get("/v1/scheme-draft-checkpoints/verify")

    assert verified.status_code == 204 and not verified.content
    assert advanced.status_code == 204 and not advanced.content
    assert stale.status_code == 409
    assert extension.status_code == 409
    assert "must-not-reflect" not in extension.text
    assert unknown.status_code == 405


def test_scheme_draft_checkpoint_environment_is_complete(
    checkpoint_paths: tuple[Path, Path, Path],
) -> None:
    database, key_path, socket_path = checkpoint_paths
    environment = _environment(database, key_path, socket_path)
    settings = scheme_draft_checkpoint_settings_from_environment(environment)
    assert settings.database_path == database
    assert settings.socket_path == socket_path
    del environment["FORTIPAM_MCP_V4_SCHEME_DRAFT_CHECKPOINT_SOCKET"]
    with pytest.raises(SchemeDraftCheckpointSidecarError, match="incomplete"):
        scheme_draft_checkpoint_settings_from_environment(environment)


def test_unix_scheme_draft_checkpoint_client_survives_restart(
    checkpoint_paths: tuple[Path, Path, Path],
) -> None:
    database, key_path, socket_path = checkpoint_paths
    environment = _environment(database, key_path, socket_path)
    client = UnixSchemeDraftCheckpointClient(
        UnixSchemeDraftCheckpointClientSettings(socket_path, AUTHORITY_REF)
    )
    empty = SchemeDraftAuthorityStoreTail.empty(STORE_REF)
    observed = _tail(0, empty.chain_mac, 10)
    issued = _tail(1, "a" * 64, 10)
    process = _start_sidecar(environment, socket_path)
    try:
        client.verify(empty)
        client.advance(empty, observed)
        client.advance(observed, issued)
    finally:
        _stop_sidecar(process, socket_path)
    process = _start_sidecar(environment, socket_path)
    try:
        client.verify(issued)
        with pytest.raises(SchemeDraftCheckpointSidecarError, match="rejected"):
            client.verify(observed)
    finally:
        _stop_sidecar(process, socket_path)


def test_scheme_draft_authority_uses_sidecar_and_rejects_time_rollback(
    checkpoint_paths: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    checkpoint_database, checkpoint_key, socket_path = checkpoint_paths
    environment = _environment(checkpoint_database, checkpoint_key, socket_path)
    client = UnixSchemeDraftCheckpointClient(
        UnixSchemeDraftCheckpointClientSettings(socket_path, AUTHORITY_REF)
    )
    state = tmp_path / "scheme-draft-state"
    state.mkdir(mode=0o700)
    os.chmod(state, 0o700)
    database = state / "scheme-draft.sqlite3"
    key = _owner_file(state / "scheme-draft.hmac", b"r" * 32)
    requester = AuthenticatedRequester("scheme-draft-checkpoint-subject", "operator")
    process = _start_sidecar(environment, socket_path)
    try:
        authority = PersistentSchemeDraftAuthority(
            database,
            key,
            authority_ref=DRAFT_AUTHORITY_REF,
            monotonic_checkpoint=client,
            checkpoint_store_ref=STORE_REF,
            clock=lambda: NOW,
        )
        draft_ref = authority.issue(
            _draft(),
            requester,
            expires_at=NOW + 600,
            now_epoch=NOW,
        )
        issued_database = database.read_bytes()
        authority.resolve(
            draft_ref,
            requester,
            now_epoch=NOW + 1,
        )
        authority.verify_ready()
    finally:
        _stop_sidecar(process, socket_path)

    process = _start_sidecar(environment, socket_path)
    try:
        database.write_bytes(issued_database)
        with pytest.raises(SchemeDraftAuthorityError, match="verification failed"):
            PersistentSchemeDraftAuthority(
                database,
                key,
                authority_ref=DRAFT_AUTHORITY_REF,
                monotonic_checkpoint=client,
                checkpoint_store_ref=STORE_REF,
            )
    finally:
        _stop_sidecar(process, socket_path)


def test_unix_scheme_draft_checkpoint_client_rejects_missing_or_non_socket(
    checkpoint_paths: tuple[Path, Path, Path],
) -> None:
    _database, _key_path, socket_path = checkpoint_paths
    client = UnixSchemeDraftCheckpointClient(
        UnixSchemeDraftCheckpointClientSettings(socket_path, AUTHORITY_REF)
    )
    with pytest.raises(SchemeDraftCheckpointSidecarError, match="unavailable"):
        client.verify(SchemeDraftAuthorityStoreTail.empty(STORE_REF))
    socket_path.write_text("not-a-socket", encoding="utf-8")
    os.chmod(socket_path, 0o600)
    with pytest.raises(SchemeDraftCheckpointSidecarError, match="boundary is invalid"):
        client.verify(SchemeDraftAuthorityStoreTail.empty(STORE_REF))


def _payload(tail: SchemeDraftAuthorityStoreTail) -> dict[str, object]:
    return {
        "chain_mac": tail.chain_mac,
        "last_seen_at": tail.last_seen_at,
        "sequence": tail.sequence,
        "store_ref": tail.store_ref,
    }


def _environment(database: Path, key_path: Path, socket_path: Path) -> dict[str, str]:
    return {
        **os.environ,
        "FORTIPAM_MCP_V4_SCHEME_DRAFT_CHECKPOINT_DATABASE": str(database),
        "FORTIPAM_MCP_V4_SCHEME_DRAFT_CHECKPOINT_HMAC_KEY_FILE": str(key_path),
        "FORTIPAM_MCP_V4_SCHEME_DRAFT_CHECKPOINT_AUTHORITY_REF": AUTHORITY_REF,
        "FORTIPAM_MCP_V4_SCHEME_DRAFT_CHECKPOINT_SOCKET": str(socket_path),
        "PYTHONPATH": "src:.",
    }


def _start_sidecar(
    environment: dict[str, str],
    socket_path: Path,
) -> subprocess.Popen[bytes]:
    process = subprocess.Popen(
        (sys.executable, "-m", "fortipam_mcp.scheme_draft_checkpoint_sidecar"),
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
            raise AssertionError(f"Scheme Draft checkpoint stopped before ready: {stderr!r}")
        time.sleep(0.02)
    _stop_sidecar(process, socket_path)
    raise AssertionError("Scheme Draft checkpoint did not create its Unix socket")


def _stop_sidecar(process: subprocess.Popen[bytes], socket_path: Path) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5.0)
    if socket_path.exists() or socket_path.is_symlink():
        socket_path.unlink()
