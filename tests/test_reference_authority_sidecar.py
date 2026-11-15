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

import fortipam_mcp.reference_authority_sidecar as sidecar_module
from fortipam_mcp.local_oauth import (
    LocalOAuthProvider,
    LocalOAuthSettings,
    hash_local_password,
)
from fortipam_mcp.reference_authority_sidecar import (
    ReferenceAuthoritySidecarError,
    UnixReferenceAuthorityClient,
    UnixReferenceAuthorityClientSettings,
    create_reference_authority_sidecar_app,
    reference_sidecar_settings_from_environment,
)
from fortipam_mcp.reference_checkpoint_sidecar import (
    UnixReferenceCheckpointClient,
    UnixReferenceCheckpointClientSettings,
)
from fortipam_mcp.v4_confirmation_http import V4ConfirmationSettings
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from fortipam_mcp.v4_runtime_host import (
    V4RuntimeHostError,
    V4SyntheticHostSettings,
    V4UnixReferenceAuthoritySettings,
    V4_SYNTHETIC_SCHEME_REF,
    issue_synthetic_reference_grants,
    synthetic_host_settings_from_environment,
    synthetic_v4_plan_host_factory,
)
from v4_planning import (
    AuthenticatedRequester,
    PersistentReferenceAuthority,
    canonical_digest,
)


NOW = 1_950_000_000
AUTHORITY_REF = "v4-reference-authority-test"
CHECKPOINT_AUTHORITY_REF = "v4-reference-checkpoint-test"
CHECKPOINT_STORE_REF = "v4-reference-store-test"
REFERENCE = "folder-object-ref0001"
REFERENCE_KIND = "object_public_folder"
REQUESTER_DIGEST = "a" * 64
ENVIRONMENT_REF = "laboratory-environment-ref01"
SCOPE_REF = "laboratory-scope-ref0001"


class MutableClock:
    def __init__(self, value: int) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


@pytest.fixture
def socket_path() -> Iterator[Path]:
    scratch = Path(__file__).resolve().parents[1] / ".codex_tmp"
    scratch.mkdir(mode=0o700, exist_ok=True)
    socket_dir = Path(tempfile.mkdtemp(prefix="fra-", dir=scratch))
    os.chmod(socket_dir, 0o700)
    path = socket_dir / "reference.sock"
    yield path
    if path.exists() or path.is_symlink():
        path.unlink()
    socket_dir.rmdir()


def _owner_file(path: Path, value: bytes) -> Path:
    path.write_bytes(value)
    os.chmod(path, 0o600)
    return path


def _authority(
    root: Path,
    *,
    clock: MutableClock | None = None,
) -> tuple[PersistentReferenceAuthority, Path, Path]:
    os.chmod(root, 0o700)
    database = root / "reference.sqlite3"
    key = _owner_file(root / "reference.hmac", b"r" * 32)
    return (
        PersistentReferenceAuthority(
            database,
            key,
            authority_ref=AUTHORITY_REF,
            clock=clock,
        ),
        database,
        key,
    )


def _issue(authority: PersistentReferenceAuthority) -> None:
    authority.issue(
        REFERENCE,
        reference_kind=REFERENCE_KIND,
        requester_digest=REQUESTER_DIGEST,
        environment_ref=ENVIRONMENT_REF,
        scope_ref=SCOPE_REF,
        expires_at=NOW + 600,
        now_epoch=NOW,
    )


def _request() -> dict[str, object]:
    return {
        "authority_ref": AUTHORITY_REF,
        "environment_ref": ENVIRONMENT_REF,
        "now_epoch": NOW + 1,
        "reference": REFERENCE,
        "reference_kind": REFERENCE_KIND,
        "requester_digest": REQUESTER_DIGEST,
        "scope_ref": SCOPE_REF,
    }


def test_reference_sidecar_app_exposes_only_ready_and_exact_authorize(
    tmp_path: Path,
) -> None:
    authority, _database, _key = _authority(tmp_path)
    _issue(authority)
    with TestClient(create_reference_authority_sidecar_app(authority)) as client:
        ready = client.post(
            "/v1/reference-authority/ready",
            json={"authority_ref": AUTHORITY_REF},
        )
        authorized = client.post(
            "/v1/reference-authority/authorize",
            json=_request(),
        )
        extension = client.post(
            "/v1/reference-authority/authorize",
            json={**_request(), "private-marker": "must-not-reflect"},
        )
        mismatch = client.post(
            "/v1/reference-authority/authorize",
            json={**_request(), "requester_digest": "b" * 64},
        )
        unknown = client.get("/v1/reference-authority/authorize")

    assert ready.status_code == 204 and not ready.content
    assert authorized.status_code == 200
    assert authorized.json() == {
        "authority_ref": AUTHORITY_REF,
        "decision": {
            "reference_digest": canonical_digest(REFERENCE),
            "reference_kind": REFERENCE_KIND,
            "authority_ref": AUTHORITY_REF,
            "requester_digest": REQUESTER_DIGEST,
            "environment_digest": canonical_digest(ENVIRONMENT_REF),
            "scope_digest": canonical_digest(SCOPE_REF),
            "authorized": True,
            "checked_at": NOW + 1,
            "expires_at": NOW + 61,
        },
    }
    assert extension.status_code == 409
    assert extension.json() == {"status": "rejected"}
    assert "must-not-reflect" not in extension.text
    assert mismatch.status_code == 200
    assert mismatch.json()["decision"]["authorized"] is False
    assert unknown.status_code == 405


def test_reference_sidecar_environment_and_host_binding_are_complete(
    tmp_path: Path,
    socket_path: Path,
) -> None:
    service_environment = {
        sidecar_module.REFERENCE_AUTHORITY_DATABASE_ENV: str(
            tmp_path / "reference.sqlite3"
        ),
        sidecar_module.REFERENCE_AUTHORITY_HMAC_KEY_FILE_ENV: str(
            tmp_path / "reference.hmac"
        ),
        sidecar_module.REFERENCE_AUTHORITY_REF_ENV: AUTHORITY_REF,
        sidecar_module.REFERENCE_AUTHORITY_SOCKET_ENV: str(socket_path),
        sidecar_module.REFERENCE_AUTHORITY_CHECKPOINT_SOCKET_ENV: str(
            socket_path.parent / "checkpoint.sock"
        ),
        sidecar_module.REFERENCE_AUTHORITY_CHECKPOINT_REF_ENV: (
            CHECKPOINT_AUTHORITY_REF
        ),
        sidecar_module.REFERENCE_AUTHORITY_CHECKPOINT_STORE_REF_ENV: (
            CHECKPOINT_STORE_REF
        ),
    }
    assert reference_sidecar_settings_from_environment(
        service_environment
    ).socket_path == socket_path
    del service_environment[sidecar_module.REFERENCE_AUTHORITY_SOCKET_ENV]
    with pytest.raises(ReferenceAuthoritySidecarError, match="incomplete"):
        reference_sidecar_settings_from_environment(service_environment)

    host_environment = {
        "FORTIPAM_MCP_V4_PLAN_HOST_MODE": "synthetic",
        "FORTIPAM_MCP_V4_PLAN_STORE_DB": str(tmp_path / "planning.sqlite3"),
        "FORTIPAM_MCP_V4_PLAN_STORE_HMAC_KEY_FILE": str(
            tmp_path / "planning.hmac"
        ),
        "FORTIPAM_MCP_V4_PLAN_REFERENCE_SIDECAR_SOCKET": str(socket_path),
        "FORTIPAM_MCP_V4_PLAN_REFERENCE_SIDECAR_AUTHORITY_REF": AUTHORITY_REF,
    }
    settings = synthetic_host_settings_from_environment(host_environment)
    assert settings is not None
    assert settings.reference_sidecar == V4UnixReferenceAuthoritySettings(
        socket_path,
        AUTHORITY_REF,
    )
    with pytest.raises(V4RuntimeHostError, match="exactly one binding"):
        synthetic_host_settings_from_environment(
            {
                **host_environment,
                "FORTIPAM_MCP_V4_PLAN_REFERENCE_AUTHORITY_DB": str(
                    tmp_path / "reference.sqlite3"
                ),
                "FORTIPAM_MCP_V4_PLAN_REFERENCE_AUTHORITY_HMAC_KEY_FILE": str(
                    tmp_path / "reference.hmac"
                ),
            }
        )
    del host_environment[
        "FORTIPAM_MCP_V4_PLAN_REFERENCE_SIDECAR_AUTHORITY_REF"
    ]
    with pytest.raises(V4RuntimeHostError, match="complete socket and Authority"):
        synthetic_host_settings_from_environment(host_environment)


def test_unix_reference_client_survives_restart_and_binds_host(
    tmp_path: Path,
    socket_path: Path,
) -> None:
    clock = MutableClock(NOW)
    _unbound_authority, database, key_path = _authority(tmp_path, clock=clock)
    checkpoint_state = tmp_path / "checkpoint"
    checkpoint_state.mkdir(mode=0o700)
    os.chmod(checkpoint_state, 0o700)
    checkpoint_key = _owner_file(checkpoint_state / "checkpoint.hmac", b"k" * 32)
    checkpoint_socket = socket_path.parent / "checkpoint.sock"
    checkpoint_environment = {
        **os.environ,
        "FORTIPAM_MCP_V4_REFERENCE_CHECKPOINT_DATABASE": str(
            checkpoint_state / "checkpoint.sqlite3"
        ),
        "FORTIPAM_MCP_V4_REFERENCE_CHECKPOINT_HMAC_KEY_FILE": str(checkpoint_key),
        "FORTIPAM_MCP_V4_REFERENCE_CHECKPOINT_AUTHORITY_REF": (
            CHECKPOINT_AUTHORITY_REF
        ),
        "FORTIPAM_MCP_V4_REFERENCE_CHECKPOINT_SOCKET": str(checkpoint_socket),
        "PYTHONPATH": "src:.",
    }
    checkpoint_process = _start_sidecar(
        checkpoint_environment,
        checkpoint_socket,
        module="fortipam_mcp.reference_checkpoint_sidecar",
    )
    checkpoint_client = UnixReferenceCheckpointClient(
        UnixReferenceCheckpointClientSettings(
            checkpoint_socket,
            CHECKPOINT_AUTHORITY_REF,
        )
    )
    authority = PersistentReferenceAuthority(
        database,
        key_path,
        authority_ref=AUTHORITY_REF,
        monotonic_checkpoint=checkpoint_client,
        checkpoint_store_ref=CHECKPOINT_STORE_REF,
        clock=clock,
    )
    requester = AuthenticatedRequester(REQUESTER_DIGEST, "operator")
    grant_refs = issue_synthetic_reference_grants(
        authority,
        requester_digest=requester.digest,
        expires_at=NOW + 600,
        now_epoch=NOW,
    )
    assert grant_refs
    environment = {
        **os.environ,
        sidecar_module.REFERENCE_AUTHORITY_DATABASE_ENV: str(database),
        sidecar_module.REFERENCE_AUTHORITY_HMAC_KEY_FILE_ENV: str(key_path),
        sidecar_module.REFERENCE_AUTHORITY_REF_ENV: AUTHORITY_REF,
        sidecar_module.REFERENCE_AUTHORITY_SOCKET_ENV: str(socket_path),
        sidecar_module.REFERENCE_AUTHORITY_CHECKPOINT_SOCKET_ENV: str(
            checkpoint_socket
        ),
        sidecar_module.REFERENCE_AUTHORITY_CHECKPOINT_REF_ENV: (
            CHECKPOINT_AUTHORITY_REF
        ),
        sidecar_module.REFERENCE_AUTHORITY_CHECKPOINT_STORE_REF_ENV: (
            CHECKPOINT_STORE_REF
        ),
        "PYTHONPATH": "src:.",
    }
    process = _start_sidecar(environment, socket_path)
    try:
        client = UnixReferenceAuthorityClient(
            UnixReferenceAuthorityClientSettings(socket_path, AUTHORITY_REF)
        )
        assert client.monotonic_checkpoint_protocol_bound is True
        client.verify_ready()

        host_state = tmp_path / "host"
        host_state.mkdir(mode=0o700)
        os.chmod(host_state, 0o700)
        planning_key = _owner_file(host_state / "planning.hmac", b"p" * 32)
        confirmation_key = _owner_file(host_state / "confirmation.hmac", b"c" * 32)
        browser_key = _owner_file(host_state / "browser.hmac", b"b" * 32)
        oauth_state = tmp_path / "oauth"
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
        settings = V4SyntheticHostSettings(
            host_state / "planning.sqlite3",
            planning_key,
            reference_sidecar=V4UnixReferenceAuthoritySettings(
                socket_path,
                AUTHORITY_REF,
            ),
        )
        confirmation = V4ConfirmationSettings(
            host_state / "confirmation.sqlite3",
            confirmation_key,
            browser_key,
        )
        components = synthetic_v4_plan_host_factory(settings, clock=clock)(
            provider,
            confirmation,
        )
        principal = V4PlanningPrincipal(requester, "b" * 64)
        preview = components.plan_services.preview(V4_SYNTHETIC_SCHEME_REF, principal)
        assert preview["reference_authority_ref"] == AUTHORITY_REF
        assert preview["reference_authorization_expires_at"] == NOW + 60
        assert components.reference_authority is None
        assert isinstance(components.reference_client, UnixReferenceAuthorityClient)
        assert components.plan_services.status()[
            "reference_authorization_protocol_bound"
        ] is True
        assert components.plan_services.status()[
            "reference_authority_checkpoint_protocol_bound"
        ] is True

        _stop_sidecar(process, socket_path)
        process = _start_sidecar(environment, socket_path)
        restarted = synthetic_v4_plan_host_factory(settings, clock=clock)(
            provider,
            confirmation,
        )
        assert isinstance(restarted.reference_client, UnixReferenceAuthorityClient)
        restarted.reference_client.verify_ready()
    finally:
        _stop_sidecar(process, socket_path)
        _stop_sidecar(checkpoint_process, checkpoint_socket)


def test_unix_reference_client_rejects_missing_or_non_socket(
    tmp_path: Path,
) -> None:
    socket_path = tmp_path / "reference.sock"
    client = UnixReferenceAuthorityClient(
        UnixReferenceAuthorityClientSettings(socket_path, AUTHORITY_REF)
    )
    with pytest.raises(ReferenceAuthoritySidecarError, match="unavailable"):
        client.verify_ready()
    socket_path.write_text("not-a-socket", encoding="utf-8")
    os.chmod(socket_path, 0o600)
    with pytest.raises(ReferenceAuthoritySidecarError, match="boundary is invalid"):
        client.verify_ready()


def _start_sidecar(
    environment: dict[str, str],
    socket_path: Path,
    *,
    module: str = "fortipam_mcp.reference_authority_sidecar",
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
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5.0)
    if socket_path.exists() or socket_path.is_symlink():
        socket_path.unlink()
