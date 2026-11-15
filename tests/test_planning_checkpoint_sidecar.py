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

from fortipam_mcp.planning_checkpoint_sidecar import (
    PlanningCheckpointSidecarError,
    UnixPlanningCheckpointClient,
    UnixPlanningCheckpointClientSettings,
    create_checkpoint_sidecar_app,
    sidecar_settings_from_environment,
)
from fortipam_mcp.local_oauth import (
    LocalOAuthProvider,
    LocalOAuthSettings,
    hash_local_password,
)
from fortipam_mcp.v4_confirmation_http import V4ConfirmationSettings
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from fortipam_mcp.v4_runtime_host import (
    V4RuntimeHostError,
    V4SyntheticHostSettings,
    V4UnixPlanningCheckpointSettings,
    V4_SYNTHETIC_SCHEME_REF,
    synthetic_host_settings_from_environment,
    synthetic_v4_plan_host_factory,
)
from v4_planning import (
    AuthenticatedRequester,
    PersistentPlanningCheckpointAuthority,
    PlanningStoreTail,
)


AUTHORITY_REF = "v4-planning-checkpoint-sidecar-test"
STORE_REF = "v4-sidecar-planning-store-test"


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
    socket_dir = Path(tempfile.mkdtemp(prefix="fcp-", dir=scratch))
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


def _tail(sequence: int, chain_hmac: str) -> PlanningStoreTail:
    return PlanningStoreTail(STORE_REF, sequence, chain_hmac)


def test_checkpoint_sidecar_app_exposes_only_exact_cas_operations(
    checkpoint_paths: tuple[Path, Path, Path],
) -> None:
    database, key_path, _socket_path = checkpoint_paths
    authority = PersistentPlanningCheckpointAuthority(
        database,
        key_path,
        authority_ref=AUTHORITY_REF,
    )
    empty = _tail(0, "chain-root")
    first = _tail(1, "a" * 64)

    with TestClient(create_checkpoint_sidecar_app(authority)) as client:
        verified = client.post(
            "/v1/checkpoints/verify",
            json={"authority_ref": AUTHORITY_REF, "tail": _payload(empty)},
        )
        advanced = client.post(
            "/v1/checkpoints/advance",
            json={
                "authority_ref": AUTHORITY_REF,
                "previous": _payload(empty),
                "current": _payload(first),
            },
        )
        stale = client.post(
            "/v1/checkpoints/advance",
            json={
                "authority_ref": AUTHORITY_REF,
                "previous": _payload(empty),
                "current": _payload(first),
            },
        )
        unknown = client.get("/v1/checkpoints/verify")
        extension = client.post(
            "/v1/checkpoints/verify",
            json={
                "authority_ref": AUTHORITY_REF,
                "tail": _payload(first),
                "extra": "rejected-marker",
            },
        )
        wrong_authority = client.post(
            "/v1/checkpoints/verify",
            json={"authority_ref": "wrong-authority-ref", "tail": _payload(first)},
        )

    assert verified.status_code == 204 and not verified.content
    assert advanced.status_code == 204 and not advanced.content
    assert stale.status_code == 409 and stale.json() == {"status": "rejected"}
    assert unknown.status_code == 405
    assert extension.status_code == 409
    assert "rejected-marker" not in extension.text
    assert wrong_authority.status_code == 409


def test_checkpoint_sidecar_environment_is_complete_and_path_bounded(
    checkpoint_paths: tuple[Path, Path, Path],
) -> None:
    database, key_path, socket_path = checkpoint_paths
    environment = {
        "FORTIPAM_MCP_V4_CHECKPOINT_DATABASE": str(database),
        "FORTIPAM_MCP_V4_CHECKPOINT_HMAC_KEY_FILE": str(key_path),
        "FORTIPAM_MCP_V4_CHECKPOINT_AUTHORITY_REF": AUTHORITY_REF,
        "FORTIPAM_MCP_V4_CHECKPOINT_SOCKET": str(socket_path),
    }
    settings = sidecar_settings_from_environment(environment)
    assert settings.database_path == database
    assert settings.socket_path == socket_path

    del environment["FORTIPAM_MCP_V4_CHECKPOINT_SOCKET"]
    with pytest.raises(PlanningCheckpointSidecarError, match="incomplete"):
        sidecar_settings_from_environment(environment)


def test_unix_checkpoint_client_runs_across_process_restart(
    checkpoint_paths: tuple[Path, Path, Path],
) -> None:
    database, key_path, socket_path = checkpoint_paths
    environment = dict(os.environ)
    environment.update(
        {
            "FORTIPAM_MCP_V4_CHECKPOINT_DATABASE": str(database),
            "FORTIPAM_MCP_V4_CHECKPOINT_HMAC_KEY_FILE": str(key_path),
            "FORTIPAM_MCP_V4_CHECKPOINT_AUTHORITY_REF": AUTHORITY_REF,
            "FORTIPAM_MCP_V4_CHECKPOINT_SOCKET": str(socket_path),
            "PYTHONPATH": "src:.",
        }
    )
    empty = _tail(0, "chain-root")
    first = _tail(1, "a" * 64)
    second = _tail(2, "b" * 64)
    client = UnixPlanningCheckpointClient(
        UnixPlanningCheckpointClientSettings(socket_path, AUTHORITY_REF)
    )

    process = _start_sidecar(environment, socket_path)
    try:
        client.verify(empty)
        client.advance(empty, first)
        client.verify(first)
    finally:
        _stop_sidecar(process, socket_path)

    restarted = _start_sidecar(environment, socket_path)
    try:
        client.verify(first)
        client.advance(first, second)
        client.verify(second)
        with pytest.raises(PlanningCheckpointSidecarError, match="rejected"):
            client.verify(first)
    finally:
        _stop_sidecar(restarted, socket_path)


def test_unix_checkpoint_client_rejects_non_socket_and_unsafe_socket(
    checkpoint_paths: tuple[Path, Path, Path],
) -> None:
    _database, _key_path, socket_path = checkpoint_paths
    client = UnixPlanningCheckpointClient(
        UnixPlanningCheckpointClientSettings(socket_path, AUTHORITY_REF)
    )
    with pytest.raises(PlanningCheckpointSidecarError, match="unavailable"):
        client.verify(_tail(0, "chain-root"))

    socket_path.write_text("not-a-socket", encoding="utf-8")
    os.chmod(socket_path, 0o600)
    with pytest.raises(PlanningCheckpointSidecarError, match="boundary is invalid"):
        client.verify(_tail(0, "chain-root"))


def test_synthetic_host_uses_only_sidecar_client_and_detects_rollback(
    checkpoint_paths: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    checkpoint_database, checkpoint_key, socket_path = checkpoint_paths
    state = tmp_path / "host-state"
    state.mkdir(mode=0o700)
    oauth = tmp_path / "oauth"
    oauth.mkdir(mode=0o700)
    planning_key = _owner_file(state / "planning.hmac", b"p" * 32)
    confirmation_key = _owner_file(state / "confirmation.hmac", b"c" * 32)
    receipt_key = _owner_file(state / "receipt.hmac", b"r" * 32)
    planning_database = state / "planning.sqlite3"
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
    settings = V4SyntheticHostSettings(
        planning_database,
        planning_key,
        planning_checkpoint_sidecar=V4UnixPlanningCheckpointSettings(
            socket_path,
            AUTHORITY_REF,
            STORE_REF,
        ),
    )
    host_environment = {
        "FORTIPAM_MCP_V4_PLAN_HOST_MODE": "synthetic",
        "FORTIPAM_MCP_V4_PLAN_STORE_DB": str(planning_database),
        "FORTIPAM_MCP_V4_PLAN_STORE_HMAC_KEY_FILE": str(planning_key),
        "FORTIPAM_MCP_V4_PLAN_CHECKPOINT_STORE_REF": STORE_REF,
        "FORTIPAM_MCP_V4_PLAN_CHECKPOINT_SIDECAR_SOCKET": str(socket_path),
        "FORTIPAM_MCP_V4_PLAN_CHECKPOINT_SIDECAR_AUTHORITY_REF": AUTHORITY_REF,
    }
    assert synthetic_host_settings_from_environment(host_environment) == settings
    del host_environment[
        "FORTIPAM_MCP_V4_PLAN_CHECKPOINT_SIDECAR_AUTHORITY_REF"
    ]
    with pytest.raises(V4RuntimeHostError, match="sidecar requires complete"):
        synthetic_host_settings_from_environment(host_environment)
    confirmation_settings = V4ConfirmationSettings(
        state / "confirmation.sqlite3",
        confirmation_key,
        receipt_key,
    )
    factory = synthetic_v4_plan_host_factory(settings, clock=lambda: 1_950_000_000)
    environment = dict(os.environ)
    environment.update(
        {
            "FORTIPAM_MCP_V4_CHECKPOINT_DATABASE": str(checkpoint_database),
            "FORTIPAM_MCP_V4_CHECKPOINT_HMAC_KEY_FILE": str(checkpoint_key),
            "FORTIPAM_MCP_V4_CHECKPOINT_AUTHORITY_REF": AUTHORITY_REF,
            "FORTIPAM_MCP_V4_CHECKPOINT_SOCKET": str(socket_path),
            "PYTHONPATH": "src:.",
        }
    )

    process = _start_sidecar(environment, socket_path)
    try:
        components = factory(provider, confirmation_settings)
        assert components.planning_checkpoint_authority is None
        assert isinstance(
            components.planning_checkpoint_client,
            UnixPlanningCheckpointClient,
        )
        empty_database = planning_database.read_bytes()
        components.plan_services.preview(
            V4_SYNTHETIC_SCHEME_REF,
            V4PlanningPrincipal(
                AuthenticatedRequester("a" * 64, "operator"),
                "b" * 64,
            ),
        )
    finally:
        _stop_sidecar(process, socket_path)

    restarted = _start_sidecar(environment, socket_path)
    try:
        assert factory(provider, confirmation_settings).plan_services.status()[
            "monotonic_checkpoint_protocol_bound"
        ] is True
        planning_database.write_bytes(empty_database)
        with pytest.raises(V4RuntimeHostError, match="initialization failed closed"):
            factory(provider, confirmation_settings)
    finally:
        _stop_sidecar(restarted, socket_path)

def _payload(tail: PlanningStoreTail) -> dict[str, object]:
    return {
        "store_ref": tail.store_ref,
        "sequence": tail.sequence,
        "chain_hmac": tail.chain_hmac,
    }


def _start_sidecar(
    environment: dict[str, str],
    socket_path: Path,
) -> subprocess.Popen[bytes]:
    process = subprocess.Popen(
        (sys.executable, "-m", "fortipam_mcp.planning_checkpoint_sidecar"),
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
