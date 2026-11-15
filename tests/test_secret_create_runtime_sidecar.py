from __future__ import annotations

from collections.abc import Iterator
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from typing import cast

import pytest
from starlette.testclient import TestClient

import fortipam_mcp.secret_create_runtime_sidecar as sidecar_module
import fortipam_mcp.material_checkpoint_sidecar as checkpoint_module
from fortipam_mcp.material_checkpoint_sidecar import (
    UnixMaterialCheckpointClient,
    UnixMaterialCheckpointClientSettings,
)
from fortipam_mcp.secret_create_runtime_sidecar import (
    SECRET_CREATE_RUNTIME_REF,
    SecretCreateRuntimeSidecarError,
    UnixSecretCreateRuntimeClient,
    UnixSecretCreateRuntimeClientSettings,
    UnixSecretCreateRuntimeReadinessProbe,
    create_secret_create_runtime_sidecar_app,
    secret_create_runtime_sidecar_settings_from_environment,
)
from v4_planning import (
    C3MaterialBinding,
    InMemoryMaterialUseStateStore,
    MaterialBindingStatus,
    MaterialLease,
    MaterialLeaseCompletion,
    MaterialLeaseRequest,
    MaterialProvider,
    MaterialProviderClass,
    MaterialPurpose,
    MaterialRevocationReason,
    PackagedDenyAllSecretCreateMaterialRuntime,
    PersistentMaterialUseStateStore,
    PersistentMaterialUseStateStoreError,
    SecretCreateAdapterOutcome,
    SecretCreateMaterialRuntime,
    SecretCreatePrivateAdapter,
)


@pytest.fixture
def socket_path() -> Iterator[Path]:
    scratch = Path(__file__).resolve().parents[1] / ".codex_tmp"
    scratch.mkdir(mode=0o700, exist_ok=True)
    socket_dir = Path(tempfile.mkdtemp(prefix="fscr-", dir=scratch))
    os.chmod(socket_dir, 0o700)
    path = socket_dir / "runtime.sock"
    yield path
    if path.exists() or path.is_symlink():
        path.unlink()
    socket_dir.rmdir()


def _request(**changes: object) -> MaterialLeaseRequest:
    values: dict[str, object] = {
        "action_id": "secret-create-from-reference",
        "action_version": "1.0.0",
        "plan_digest": "1" * 64,
        "policy_decision_digest": "2" * 64,
        "authorization_digest": "3" * 64,
        "scope_digest": "4" * 64,
        "audience_digest": "5" * 64,
        "provider_class": MaterialProviderClass.EXTERNAL_VAULT_LEASE,
        "purpose": MaterialPurpose.INITIAL_ONBOARDING,
        "requested_at": 1_000,
        "expires_at": 1_120,
    }
    values.update(changes)
    return MaterialLeaseRequest(**values)  # type: ignore[arg-type]


def _payload(request: MaterialLeaseRequest) -> dict[str, object]:
    return {
        "lease_request": {
            "action_id": request.action_id,
            "action_version": request.action_version,
            "audience_digest": request.audience_digest,
            "authorization_digest": request.authorization_digest,
            "expires_at": request.expires_at,
            "plan_digest": request.plan_digest,
            "policy_decision_digest": request.policy_decision_digest,
            "provider_class": request.provider_class.value,
            "purpose": request.purpose.value,
            "requested_at": request.requested_at,
            "scope_digest": request.scope_digest,
        },
        "now_epoch": 1_001,
        "runtime_ref": SECRET_CREATE_RUNTIME_REF,
    }


class _Provider:
    def validate_binding(
        self,
        binding: C3MaterialBinding,
        request: MaterialLeaseRequest,
    ) -> MaterialBindingStatus:
        assert isinstance(binding, C3MaterialBinding)
        assert request.action_id == "secret-create-from-reference"
        return MaterialBindingStatus.AVAILABLE

    def acquire_lease(
        self,
        binding: C3MaterialBinding,
        request: MaterialLeaseRequest,
    ) -> MaterialLease:
        del binding, request
        return MaterialLease()

    def release_lease(self, lease: MaterialLease) -> MaterialLeaseCompletion:
        assert isinstance(lease, MaterialLease)
        return MaterialLeaseCompletion.RELEASED

    def revoke_lease(
        self,
        lease: MaterialLease,
        *,
        reason: MaterialRevocationReason,
    ) -> MaterialLeaseCompletion:
        del lease, reason
        return MaterialLeaseCompletion.REVOKED


class _Adapter:
    def dispatch_create(
        self,
        lease: MaterialLease,
        request: MaterialLeaseRequest,
    ) -> SecretCreateAdapterOutcome:
        assert isinstance(lease, MaterialLease)
        assert request.action_id == "secret-create-from-reference"
        return SecretCreateAdapterOutcome.VERIFIED_CREATED


class _ReplayOnlyProvider(_Provider):
    def acquire_lease(
        self,
        binding: C3MaterialBinding,
        request: MaterialLeaseRequest,
    ) -> MaterialLease:
        del binding, request
        raise AssertionError("a terminal replay must not reacquire material")


def test_sidecar_app_returns_only_categorical_outcome_and_rejects_extensions() -> None:
    runtime = SecretCreateMaterialRuntime(
        cast(MaterialProvider, _Provider()),
        InMemoryMaterialUseStateStore(),
        cast(SecretCreatePrivateAdapter, _Adapter()),
    )
    request = _payload(_request())
    with TestClient(
        create_secret_create_runtime_sidecar_app(runtime, C3MaterialBinding())
    ) as client:
        ready = client.post(
            "/v1/secret-create-runtime/ready",
            json={"runtime_ref": SECRET_CREATE_RUNTIME_REF},
        )
        result = client.post("/v1/secret-create-runtime/execute", json=request)
        extended = client.post(
            "/v1/secret-create-runtime/execute",
            json={**request, "private-marker": "must-not-reflect"},
        )
        altered = client.post(
            "/v1/secret-create-runtime/execute",
            json={
                **request,
                "lease_request": {
                    **cast(dict[str, object], request["lease_request"]),
                    "action_id": "secret-update-metadata",
                },
            },
        )
        unknown = client.get("/v1/secret-create-runtime/execute")

    assert ready.status_code == 204 and not ready.content
    assert result.status_code == 200
    assert result.json() == {
        "outcome": "verified_and_released",
        "runtime_ref": SECRET_CREATE_RUNTIME_REF,
    }
    assert extended.status_code == 409
    assert extended.json() == {"status": "rejected"}
    assert "must-not-reflect" not in extended.text
    assert altered.status_code == 409
    assert unknown.status_code == 405


def test_packaged_sidecar_is_deny_all_without_material_or_product_access() -> None:
    app = create_secret_create_runtime_sidecar_app(
        PackagedDenyAllSecretCreateMaterialRuntime(),
        C3MaterialBinding(),
    )
    with TestClient(app) as client:
        response = client.post(
            "/v1/secret-create-runtime/execute",
            json=_payload(_request()),
        )

    assert response.status_code == 503
    assert response.json() == {"status": "unavailable"}


def test_environment_requires_one_absolute_socket_path(
    socket_path: Path,
) -> None:
    environment = {
        sidecar_module.SECRET_CREATE_RUNTIME_SOCKET_ENV: str(socket_path),
        sidecar_module.SECRET_CREATE_MATERIAL_DATABASE_ENV: str(
            socket_path.parent / "material.sqlite3"
        ),
        sidecar_module.SECRET_CREATE_MATERIAL_HMAC_KEY_FILE_ENV: str(
            socket_path.parent / "material.hmac"
        ),
        sidecar_module.SECRET_CREATE_MATERIAL_CHECKPOINT_SOCKET_ENV: str(
            socket_path.parent / "checkpoint.sock"
        ),
        sidecar_module.SECRET_CREATE_MATERIAL_CHECKPOINT_AUTHORITY_REF_ENV: (
            "v4-secret-material-checkpoint"
        ),
        sidecar_module.SECRET_CREATE_MATERIAL_CHECKPOINT_STORE_REF_ENV: (
            "v4-secret-material-store"
        ),
    }
    settings = secret_create_runtime_sidecar_settings_from_environment(environment)
    assert settings.socket_path == socket_path
    assert settings.material_checkpoint_store_ref == "v4-secret-material-store"
    with pytest.raises(SecretCreateRuntimeSidecarError, match="incomplete"):
        secret_create_runtime_sidecar_settings_from_environment({})
    environment[sidecar_module.SECRET_CREATE_MATERIAL_DATABASE_ENV] = str(socket_path)
    with pytest.raises(SecretCreateRuntimeSidecarError, match="invalid"):
        secret_create_runtime_sidecar_settings_from_environment(environment)
    with pytest.raises(SecretCreateRuntimeSidecarError, match="invalid"):
        UnixSecretCreateRuntimeClientSettings(Path("relative.sock"))


def test_unix_client_survives_restart_and_packaged_runtime_remains_unavailable(
    socket_path: Path,
    tmp_path: Path,
) -> None:
    os.chmod(tmp_path, 0o700)
    checkpoint_state = tmp_path / "checkpoint-state"
    checkpoint_state.mkdir(mode=0o700)
    os.chmod(checkpoint_state, 0o700)
    checkpoint_key = _owner_file(checkpoint_state / "checkpoint.hmac", b"c" * 32)
    checkpoint_socket = socket_path.parent / "checkpoint.sock"
    checkpoint_environment = {
        **os.environ,
        checkpoint_module.MATERIAL_CHECKPOINT_DATABASE_ENV: str(
            checkpoint_state / "checkpoint.sqlite3"
        ),
        checkpoint_module.MATERIAL_CHECKPOINT_HMAC_KEY_FILE_ENV: str(checkpoint_key),
        checkpoint_module.MATERIAL_CHECKPOINT_AUTHORITY_REF_ENV: (
            "v4-secret-material-checkpoint"
        ),
        checkpoint_module.MATERIAL_CHECKPOINT_SOCKET_ENV: str(checkpoint_socket),
        "PYTHONPATH": "src:.",
    }
    checkpoint_process = _start_checkpoint_sidecar(
        checkpoint_environment,
        checkpoint_socket,
    )
    material_state = tmp_path / "material-state"
    material_state.mkdir(mode=0o700)
    os.chmod(material_state, 0o700)
    material_key = _owner_file(material_state / "material.hmac", b"m" * 32)
    environment = {
        **os.environ,
        sidecar_module.SECRET_CREATE_RUNTIME_SOCKET_ENV: str(socket_path),
        sidecar_module.SECRET_CREATE_MATERIAL_DATABASE_ENV: str(
            material_state / "material.sqlite3"
        ),
        sidecar_module.SECRET_CREATE_MATERIAL_HMAC_KEY_FILE_ENV: str(material_key),
        sidecar_module.SECRET_CREATE_MATERIAL_CHECKPOINT_SOCKET_ENV: str(
            checkpoint_socket
        ),
        sidecar_module.SECRET_CREATE_MATERIAL_CHECKPOINT_AUTHORITY_REF_ENV: (
            "v4-secret-material-checkpoint"
        ),
        sidecar_module.SECRET_CREATE_MATERIAL_CHECKPOINT_STORE_REF_ENV: (
            "v4-secret-material-store"
        ),
        "PYTHONPATH": "src:.",
    }
    process = _start_sidecar(environment, socket_path)
    try:
        readiness_probe = UnixSecretCreateRuntimeReadinessProbe(
            UnixSecretCreateRuntimeClientSettings(socket_path)
        )
        assert readiness_probe.is_available() is True
        assert not hasattr(readiness_probe, "execute_once")
        client = UnixSecretCreateRuntimeClient(
            UnixSecretCreateRuntimeClientSettings(socket_path)
        )
        client.verify_ready()
        with pytest.raises(SecretCreateRuntimeSidecarError, match="unavailable"):
            client.execute_once(_request(), now_epoch=1_001)

        _stop_sidecar(process, socket_path)
        assert readiness_probe.is_available() is False
        process = _start_sidecar(environment, socket_path)
        assert readiness_probe.is_available() is True
        restarted = UnixSecretCreateRuntimeClient(
            UnixSecretCreateRuntimeClientSettings(socket_path)
        )
        restarted.verify_ready()
        with pytest.raises(SecretCreateRuntimeSidecarError, match="unavailable"):
            restarted.execute_once(_request(), now_epoch=1_001)

        _stop_sidecar(process, socket_path)
        material_database = material_state / "material.sqlite3"
        empty_database = material_database.read_bytes()
        checkpoint = UnixMaterialCheckpointClient(
            UnixMaterialCheckpointClientSettings(
                checkpoint_socket,
                "v4-secret-material-checkpoint",
            )
        )
        store = PersistentMaterialUseStateStore(
            material_database,
            material_key,
            monotonic_checkpoint=checkpoint,
            checkpoint_store_ref="v4-secret-material-store",
        )
        store.claim(request_digest="1" * 64, authorization_digest="2" * 64)
        material_database.write_bytes(empty_database)
        with pytest.raises(AssertionError, match="checkpoint verification failed"):
            _start_sidecar(environment, socket_path)
    finally:
        _stop_sidecar(process, socket_path)
        _stop_sidecar(checkpoint_process, checkpoint_socket)


def test_persistent_private_runtime_replays_after_restart_and_rejects_rollback(
    socket_path: Path,
    tmp_path: Path,
) -> None:
    os.chmod(tmp_path, 0o700)
    checkpoint_state = tmp_path / "runtime-checkpoint"
    checkpoint_state.mkdir(mode=0o700)
    os.chmod(checkpoint_state, 0o700)
    checkpoint_key = _owner_file(checkpoint_state / "checkpoint.hmac", b"c" * 32)
    checkpoint_socket = socket_path.parent / "checkpoint.sock"
    authority_ref = "v4-secret-runtime-checkpoint"
    store_ref = "v4-secret-runtime-material-store"
    checkpoint_environment = {
        **os.environ,
        checkpoint_module.MATERIAL_CHECKPOINT_DATABASE_ENV: str(
            checkpoint_state / "checkpoint.sqlite3"
        ),
        checkpoint_module.MATERIAL_CHECKPOINT_HMAC_KEY_FILE_ENV: str(checkpoint_key),
        checkpoint_module.MATERIAL_CHECKPOINT_AUTHORITY_REF_ENV: authority_ref,
        checkpoint_module.MATERIAL_CHECKPOINT_SOCKET_ENV: str(checkpoint_socket),
        "PYTHONPATH": "src:.",
    }
    checkpoint_process = _start_checkpoint_sidecar(
        checkpoint_environment,
        checkpoint_socket,
    )
    try:
        checkpoint = UnixMaterialCheckpointClient(
            UnixMaterialCheckpointClientSettings(checkpoint_socket, authority_ref)
        )
        material_state = tmp_path / "runtime-material"
        material_state.mkdir(mode=0o700)
        os.chmod(material_state, 0o700)
        material_key = _owner_file(material_state / "material.hmac", b"m" * 32)
        material_database = material_state / "material.sqlite3"
        store = PersistentMaterialUseStateStore(
            material_database,
            material_key,
            monotonic_checkpoint=checkpoint,
            checkpoint_store_ref=store_ref,
        )
        empty_database = material_database.read_bytes()
        request = _request()
        first_runtime = SecretCreateMaterialRuntime(
            cast(MaterialProvider, _Provider()),
            store,
            cast(SecretCreatePrivateAdapter, _Adapter()),
        )
        with TestClient(
            create_secret_create_runtime_sidecar_app(
                first_runtime,
                C3MaterialBinding(),
            )
        ) as client:
            first = client.post(
                "/v1/secret-create-runtime/execute",
                json=_payload(request),
            )
        assert first.status_code == 200
        assert first.json()["outcome"] == "verified_and_released"

        restarted_store = PersistentMaterialUseStateStore(
            material_database,
            material_key,
            monotonic_checkpoint=checkpoint,
            checkpoint_store_ref=store_ref,
        )
        restarted_runtime = SecretCreateMaterialRuntime(
            cast(MaterialProvider, _ReplayOnlyProvider()),
            restarted_store,
            cast(SecretCreatePrivateAdapter, _Adapter()),
        )
        with TestClient(
            create_secret_create_runtime_sidecar_app(
                restarted_runtime,
                C3MaterialBinding(),
            )
        ) as client:
            ready = client.post(
                "/v1/secret-create-runtime/ready",
                json={"runtime_ref": SECRET_CREATE_RUNTIME_REF},
            )
            replay = client.post(
                "/v1/secret-create-runtime/execute",
                json=_payload(request),
            )
        assert ready.status_code == 204
        assert replay.status_code == 200
        assert replay.json()["outcome"] == "verified_and_released"

        material_database.write_bytes(empty_database)
        with pytest.raises(
            PersistentMaterialUseStateStoreError,
            match="checkpoint verification failed",
        ):
            PersistentMaterialUseStateStore(
                material_database,
                material_key,
                monotonic_checkpoint=checkpoint,
                checkpoint_store_ref=store_ref,
            )
    finally:
        _stop_sidecar(checkpoint_process, checkpoint_socket)


def test_unix_client_rejects_missing_or_non_socket(tmp_path: Path) -> None:
    socket_path = tmp_path / "runtime.sock"
    readiness_probe = UnixSecretCreateRuntimeReadinessProbe(
        UnixSecretCreateRuntimeClientSettings(socket_path)
    )
    assert readiness_probe.is_available() is False
    client = UnixSecretCreateRuntimeClient(
        UnixSecretCreateRuntimeClientSettings(socket_path)
    )
    with pytest.raises(SecretCreateRuntimeSidecarError, match="unavailable"):
        client.verify_ready()
    socket_path.write_text("not-a-socket", encoding="utf-8")
    os.chmod(socket_path, 0o600)
    with pytest.raises(SecretCreateRuntimeSidecarError, match="boundary is invalid"):
        client.verify_ready()


def _start_sidecar(
    environment: dict[str, str],
    socket_path: Path,
) -> subprocess.Popen[bytes]:
    process = subprocess.Popen(
        (sys.executable, "-m", "fortipam_mcp.secret_create_runtime_sidecar"),
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
            raise AssertionError(f"runtime sidecar stopped before ready: {stderr!r}")
        time.sleep(0.02)
    _stop_sidecar(process, socket_path)
    raise AssertionError("runtime sidecar did not create its Unix socket")


def _start_checkpoint_sidecar(
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
            raise AssertionError(
                f"checkpoint sidecar stopped before ready: {stderr!r}"
            )
        time.sleep(0.02)
    _stop_sidecar(process, socket_path)
    raise AssertionError("checkpoint sidecar did not create its Unix socket")


def _owner_file(path: Path, value: bytes) -> Path:
    path.write_bytes(value)
    os.chmod(path, 0o600)
    return path


def _stop_sidecar(process: subprocess.Popen[bytes], socket_path: Path) -> None:
    if process.poll() is None:
        process.terminate()
        process.wait(timeout=5)
    if socket_path.exists() or socket_path.is_symlink():
        socket_path.unlink()
