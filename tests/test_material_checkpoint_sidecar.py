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

import fortipam_mcp.material_checkpoint_sidecar as sidecar_module
from fortipam_mcp.material_checkpoint_sidecar import (
    MaterialCheckpointSidecarError,
    UnixMaterialCheckpointClient,
    UnixMaterialCheckpointClientSettings,
    create_material_checkpoint_sidecar_app,
    material_checkpoint_settings_from_environment,
)
from v4_planning import (
    MaterialUseStoreTail,
    PersistentMaterialUseCheckpointAuthority,
    PersistentMaterialUseStateStore,
    PersistentMaterialUseStateStoreError,
)


AUTHORITY_REF = "v4-material-checkpoint-sidecar-test"
STORE_REF = "v4-material-store-sidecar-test"


@pytest.fixture
def socket_path() -> Iterator[Path]:
    scratch = Path(__file__).resolve().parents[1] / ".codex_tmp"
    scratch.mkdir(mode=0o700, exist_ok=True)
    socket_dir = Path(tempfile.mkdtemp(prefix="fmcp-", dir=scratch))
    os.chmod(socket_dir, 0o700)
    path = socket_dir / "checkpoint.sock"
    yield path
    if path.exists() or path.is_symlink():
        path.unlink()
    socket_dir.rmdir()


def _owner_file(path: Path, value: bytes) -> Path:
    path.write_bytes(value)
    os.chmod(path, 0o600)
    return path


def test_material_checkpoint_app_exposes_only_verify_and_advance(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    os.chmod(state, 0o700)
    authority = PersistentMaterialUseCheckpointAuthority(
        state / "checkpoint.sqlite3",
        _owner_file(state / "checkpoint.hmac", b"k" * 32),
        authority_ref=AUTHORITY_REF,
    )
    empty = MaterialUseStoreTail.empty(STORE_REF)
    first = MaterialUseStoreTail(STORE_REF, 1, "a" * 64)
    empty_payload = {
        "chain_hmac": empty.chain_hmac,
        "sequence": empty.sequence,
        "store_ref": empty.store_ref,
    }
    first_payload = {
        "chain_hmac": first.chain_hmac,
        "sequence": first.sequence,
        "store_ref": first.store_ref,
    }
    with TestClient(create_material_checkpoint_sidecar_app(authority)) as client:
        verified = client.post(
            "/v1/material-checkpoints/verify",
            json={"authority_ref": AUTHORITY_REF, "tail": empty_payload},
        )
        advanced = client.post(
            "/v1/material-checkpoints/advance",
            json={
                "authority_ref": AUTHORITY_REF,
                "current": first_payload,
                "previous": empty_payload,
            },
        )
        extension = client.post(
            "/v1/material-checkpoints/verify",
            json={
                "authority_ref": AUTHORITY_REF,
                "tail": empty_payload,
                "private-marker": "must-not-reflect",
            },
        )
        stale = client.post(
            "/v1/material-checkpoints/verify",
            json={"authority_ref": AUTHORITY_REF, "tail": empty_payload},
        )
        unknown = client.get("/v1/material-checkpoints/verify")

    assert verified.status_code == 204 and not verified.content
    assert advanced.status_code == 204 and not advanced.content
    assert extension.status_code == 409
    assert extension.json() == {"status": "rejected"}
    assert "must-not-reflect" not in extension.text
    assert stale.status_code == 409
    assert unknown.status_code == 405


def test_material_checkpoint_environment_requires_complete_distinct_paths(
    tmp_path: Path,
    socket_path: Path,
) -> None:
    environment = {
        sidecar_module.MATERIAL_CHECKPOINT_DATABASE_ENV: str(
            tmp_path / "checkpoint.sqlite3"
        ),
        sidecar_module.MATERIAL_CHECKPOINT_HMAC_KEY_FILE_ENV: str(
            tmp_path / "checkpoint.hmac"
        ),
        sidecar_module.MATERIAL_CHECKPOINT_AUTHORITY_REF_ENV: AUTHORITY_REF,
        sidecar_module.MATERIAL_CHECKPOINT_SOCKET_ENV: str(socket_path),
    }
    settings = material_checkpoint_settings_from_environment(environment)
    assert settings.socket_path == socket_path
    del environment[sidecar_module.MATERIAL_CHECKPOINT_AUTHORITY_REF_ENV]
    with pytest.raises(MaterialCheckpointSidecarError, match="incomplete"):
        material_checkpoint_settings_from_environment(environment)


def test_unix_checkpoint_survives_restart_and_rejects_material_store_rollback(
    tmp_path: Path,
    socket_path: Path,
) -> None:
    checkpoint_state = tmp_path / "checkpoint-state"
    checkpoint_state.mkdir(mode=0o700)
    os.chmod(checkpoint_state, 0o700)
    checkpoint_key = _owner_file(checkpoint_state / "checkpoint.hmac", b"k" * 32)
    checkpoint_database = checkpoint_state / "checkpoint.sqlite3"
    environment = {
        **os.environ,
        sidecar_module.MATERIAL_CHECKPOINT_DATABASE_ENV: str(checkpoint_database),
        sidecar_module.MATERIAL_CHECKPOINT_HMAC_KEY_FILE_ENV: str(checkpoint_key),
        sidecar_module.MATERIAL_CHECKPOINT_AUTHORITY_REF_ENV: AUTHORITY_REF,
        sidecar_module.MATERIAL_CHECKPOINT_SOCKET_ENV: str(socket_path),
        "PYTHONPATH": "src:.",
    }
    process = _start_sidecar(environment, socket_path)
    try:
        checkpoint = UnixMaterialCheckpointClient(
            UnixMaterialCheckpointClientSettings(socket_path, AUTHORITY_REF)
        )
        checkpoint.verify_ready()
        material_state = tmp_path / "material-state"
        material_state.mkdir(mode=0o700)
        os.chmod(material_state, 0o700)
        material_key = _owner_file(material_state / "material.hmac", b"m" * 32)
        material_database = material_state / "material.sqlite3"
        store = PersistentMaterialUseStateStore(
            material_database,
            material_key,
            monotonic_checkpoint=checkpoint,
            checkpoint_store_ref=STORE_REF,
        )
        empty_database = material_database.read_bytes()
        store.claim(request_digest="1" * 64, authorization_digest="2" * 64)

        _stop_sidecar(process, socket_path)
        process = _start_sidecar(environment, socket_path)
        restarted_checkpoint = UnixMaterialCheckpointClient(
            UnixMaterialCheckpointClientSettings(socket_path, AUTHORITY_REF)
        )
        restarted = PersistentMaterialUseStateStore(
            material_database,
            material_key,
            monotonic_checkpoint=restarted_checkpoint,
            checkpoint_store_ref=STORE_REF,
        )
        assert restarted.monotonic_checkpoint_protocol_bound is True
        assert restarted_checkpoint.uses_key_material(b"k" * 32) is False

        material_database.write_bytes(empty_database)
        with pytest.raises(
            PersistentMaterialUseStateStoreError,
            match="checkpoint verification failed",
        ):
            PersistentMaterialUseStateStore(
                material_database,
                material_key,
                monotonic_checkpoint=restarted_checkpoint,
                checkpoint_store_ref=STORE_REF,
            )

        wrong = UnixMaterialCheckpointClient(
            UnixMaterialCheckpointClientSettings(
                socket_path,
                "v4-wrong-material-checkpoint",
            )
        )
        with pytest.raises(MaterialCheckpointSidecarError, match="rejected"):
            wrong.verify(MaterialUseStoreTail.empty(STORE_REF))
    finally:
        _stop_sidecar(process, socket_path)


def test_unix_material_checkpoint_rejects_missing_or_non_socket(
    tmp_path: Path,
) -> None:
    socket_path = tmp_path / "checkpoint.sock"
    client = UnixMaterialCheckpointClient(
        UnixMaterialCheckpointClientSettings(socket_path, AUTHORITY_REF)
    )
    with pytest.raises(MaterialCheckpointSidecarError, match="unavailable"):
        client.verify_ready()
    socket_path.write_text("not-a-socket", encoding="utf-8")
    os.chmod(socket_path, 0o600)
    with pytest.raises(MaterialCheckpointSidecarError, match="boundary is invalid"):
        client.verify_ready()


def _start_sidecar(
    environment: dict[str, str],
    socket_path: Path,
) -> subprocess.Popen[bytes]:
    process = subprocess.Popen(
        (sys.executable, "-m", "fortipam_mcp.material_checkpoint_sidecar"),
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
            raise AssertionError(f"checkpoint sidecar stopped before ready: {stderr!r}")
        time.sleep(0.02)
    _stop_sidecar(process, socket_path)
    raise AssertionError("checkpoint sidecar did not create its Unix socket")


def _stop_sidecar(process: subprocess.Popen[bytes], socket_path: Path) -> None:
    if process.poll() is None:
        process.terminate()
        process.wait(timeout=5)
    if socket_path.exists() or socket_path.is_symlink():
        socket_path.unlink()
