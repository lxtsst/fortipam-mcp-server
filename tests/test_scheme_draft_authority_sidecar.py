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

import fortipam_mcp.scheme_draft_authority_sidecar as sidecar_module
from fortipam_mcp.local_oauth import (
    LocalOAuthProvider,
    LocalOAuthSettings,
    hash_local_password,
)
from fortipam_mcp.scheme_draft_authority_sidecar import (
    SchemeDraftAuthoritySidecarError,
    UnixSchemeDraftAuthorityClient,
    UnixSchemeDraftAuthorityClientSettings,
    create_scheme_draft_authority_sidecar_app,
    scheme_draft_sidecar_settings_from_environment,
)
from fortipam_mcp.scheme_draft_checkpoint_sidecar import (
    UnixSchemeDraftCheckpointClient,
    UnixSchemeDraftCheckpointClientSettings,
)
from fortipam_mcp.v4_confirmation_http import V4ConfirmationSettings
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from fortipam_mcp.v4_runtime_host import (
    V4RuntimeHostError,
    V4SyntheticHostSettings,
    V4UnixSchemeDraftAuthoritySettings,
    issue_synthetic_scheme_draft,
    synthetic_host_settings_from_environment,
    synthetic_v4_plan_host_factory,
)
from test_v4_draft_authority import MutableClock, NOW, _authority, _draft
from v4_planning import AuthenticatedRequester, PersistentSchemeDraftAuthority


AUTHORITY_REF = "v4-scheme-draft-authority-test"
CHECKPOINT_AUTHORITY_REF = "v4-scheme-draft-checkpoint-test"
CHECKPOINT_STORE_REF = "v4-scheme-draft-store-test"


@pytest.fixture
def socket_path() -> Iterator[Path]:
    scratch = Path(__file__).resolve().parents[1] / ".codex_tmp"
    scratch.mkdir(mode=0o700, exist_ok=True)
    socket_dir = Path(tempfile.mkdtemp(prefix="fsd-", dir=scratch))
    os.chmod(socket_dir, 0o700)
    path = socket_dir / "draft.sock"
    yield path
    if path.exists() or path.is_symlink():
        path.unlink()
    socket_dir.rmdir()


@pytest.fixture
def checkpoint_socket_path() -> Iterator[Path]:
    scratch = Path(__file__).resolve().parents[1] / ".codex_tmp"
    scratch.mkdir(mode=0o700, exist_ok=True)
    socket_dir = Path(tempfile.mkdtemp(prefix="fsdc-", dir=scratch))
    os.chmod(socket_dir, 0o700)
    path = socket_dir / "c.sock"
    yield path
    if path.exists() or path.is_symlink():
        path.unlink()
    socket_dir.rmdir()


def _owner_file(path: Path, value: bytes) -> Path:
    path.write_bytes(value)
    os.chmod(path, 0o600)
    return path


def test_scheme_draft_sidecar_app_exposes_only_ready_and_exact_resolve(
    tmp_path: Path,
) -> None:
    clock = MutableClock(NOW)
    authority, _database, _key = _authority(tmp_path, clock)
    requester = AuthenticatedRequester("a" * 64, "operator")
    draft_ref = authority.issue(
        _draft(), requester, expires_at=NOW + 600, now_epoch=NOW
    )
    request = {
        "authority_ref": AUTHORITY_REF,
        "now_epoch": NOW,
        "requester": sidecar_module._requester_payload(requester),
        "scheme_draft_ref": draft_ref,
    }
    with TestClient(create_scheme_draft_authority_sidecar_app(authority)) as client:
        ready = client.post(
            "/v1/scheme-draft/ready",
            json={"authority_ref": AUTHORITY_REF},
        )
        resolved = client.post("/v1/scheme-draft/resolve", json=request)
        extension = client.post(
            "/v1/scheme-draft/resolve",
            json={**request, "private-marker": "must-not-reflect"},
        )
        wrong_requester = client.post(
            "/v1/scheme-draft/resolve",
            json={
                **request,
                "requester": sidecar_module._requester_payload(
                    AuthenticatedRequester("b" * 64, "operator")
                ),
            },
        )
        unknown = client.get("/v1/scheme-draft/resolve")

    assert ready.status_code == 204 and not ready.content
    assert resolved.status_code == 200
    assert resolved.json() == {
        "authority_ref": AUTHORITY_REF,
        "draft": sidecar_module.scheme_draft_as_mapping(_draft()),
    }
    assert extension.status_code == 409
    assert extension.json() == {"status": "rejected"}
    assert "must-not-reflect" not in extension.text
    assert wrong_requester.status_code == 409
    assert unknown.status_code == 405


def test_scheme_draft_sidecar_environment_and_host_binding_are_complete(
    tmp_path: Path,
    socket_path: Path,
) -> None:
    service_environment = {
        sidecar_module.SCHEME_DRAFT_AUTHORITY_DATABASE_ENV: str(
            tmp_path / "draft.sqlite3"
        ),
        sidecar_module.SCHEME_DRAFT_AUTHORITY_HMAC_KEY_FILE_ENV: str(
            tmp_path / "draft.hmac"
        ),
        sidecar_module.SCHEME_DRAFT_AUTHORITY_REF_ENV: AUTHORITY_REF,
        sidecar_module.SCHEME_DRAFT_AUTHORITY_SOCKET_ENV: str(socket_path),
        sidecar_module.SCHEME_DRAFT_AUTHORITY_CHECKPOINT_SOCKET_ENV: str(
            tmp_path / "checkpoint.sock"
        ),
        sidecar_module.SCHEME_DRAFT_AUTHORITY_CHECKPOINT_REF_ENV: (
            CHECKPOINT_AUTHORITY_REF
        ),
        sidecar_module.SCHEME_DRAFT_AUTHORITY_CHECKPOINT_STORE_REF_ENV: (
            CHECKPOINT_STORE_REF
        ),
    }
    assert scheme_draft_sidecar_settings_from_environment(
        service_environment
    ).socket_path == socket_path
    del service_environment[sidecar_module.SCHEME_DRAFT_AUTHORITY_SOCKET_ENV]
    with pytest.raises(SchemeDraftAuthoritySidecarError, match="incomplete"):
        scheme_draft_sidecar_settings_from_environment(service_environment)

    host_environment = {
        "FORTIPAM_MCP_V4_PLAN_HOST_MODE": "synthetic",
        "FORTIPAM_MCP_V4_PLAN_STORE_DB": str(tmp_path / "planning.sqlite3"),
        "FORTIPAM_MCP_V4_PLAN_STORE_HMAC_KEY_FILE": str(
            tmp_path / "planning.hmac"
        ),
        "FORTIPAM_MCP_V4_PLAN_SCHEME_DRAFT_SIDECAR_SOCKET": str(socket_path),
        "FORTIPAM_MCP_V4_PLAN_SCHEME_DRAFT_SIDECAR_AUTHORITY_REF": AUTHORITY_REF,
    }
    settings = synthetic_host_settings_from_environment(host_environment)
    assert settings is not None
    assert settings.scheme_draft_sidecar == V4UnixSchemeDraftAuthoritySettings(
        socket_path,
        AUTHORITY_REF,
    )
    with pytest.raises(V4RuntimeHostError, match="exactly one binding"):
        synthetic_host_settings_from_environment(
            {
                **host_environment,
                "FORTIPAM_MCP_V4_PLAN_SCHEME_DRAFT_AUTHORITY_DB": str(
                    tmp_path / "draft.sqlite3"
                ),
                "FORTIPAM_MCP_V4_PLAN_SCHEME_DRAFT_AUTHORITY_HMAC_KEY_FILE": str(
                    tmp_path / "draft.hmac"
                ),
            }
        )
    del host_environment[
        "FORTIPAM_MCP_V4_PLAN_SCHEME_DRAFT_SIDECAR_AUTHORITY_REF"
    ]
    with pytest.raises(V4RuntimeHostError, match="complete socket and Authority"):
        synthetic_host_settings_from_environment(host_environment)


def test_unix_scheme_draft_client_survives_restart_and_binds_host(
    tmp_path: Path,
    socket_path: Path,
    checkpoint_socket_path: Path,
) -> None:
    clock = MutableClock(NOW)
    _unbound, database, key_path = _authority(tmp_path, clock)
    checkpoint_state = tmp_path / "draft-checkpoint-state"
    checkpoint_state.mkdir(mode=0o700)
    os.chmod(checkpoint_state, 0o700)
    checkpoint_key = _owner_file(checkpoint_state / "checkpoint.hmac", b"k" * 32)
    checkpoint_environment = {
        **os.environ,
        "FORTIPAM_MCP_V4_SCHEME_DRAFT_CHECKPOINT_DATABASE": str(
            checkpoint_state / "checkpoint.sqlite3"
        ),
        "FORTIPAM_MCP_V4_SCHEME_DRAFT_CHECKPOINT_HMAC_KEY_FILE": str(
            checkpoint_key
        ),
        "FORTIPAM_MCP_V4_SCHEME_DRAFT_CHECKPOINT_AUTHORITY_REF": (
            CHECKPOINT_AUTHORITY_REF
        ),
        "FORTIPAM_MCP_V4_SCHEME_DRAFT_CHECKPOINT_SOCKET": str(
            checkpoint_socket_path
        ),
        "PYTHONPATH": "src:.",
    }
    checkpoint_process = _start_sidecar(
        checkpoint_environment,
        checkpoint_socket_path,
        module="fortipam_mcp.scheme_draft_checkpoint_sidecar",
    )
    checkpoint = UnixSchemeDraftCheckpointClient(
        UnixSchemeDraftCheckpointClientSettings(
            checkpoint_socket_path,
            CHECKPOINT_AUTHORITY_REF,
        )
    )
    authority = PersistentSchemeDraftAuthority(
        database,
        key_path,
        authority_ref=AUTHORITY_REF,
        monotonic_checkpoint=checkpoint,
        checkpoint_store_ref=CHECKPOINT_STORE_REF,
        clock=clock,
    )
    requester = AuthenticatedRequester("a" * 64, "operator")
    draft_ref = authority.issue(
        _draft(), requester, expires_at=NOW + 600, now_epoch=NOW
    )
    synthetic_draft_ref = issue_synthetic_scheme_draft(
        authority,
        requester,
        expires_at=NOW + 600,
        now_epoch=NOW,
    )
    environment = {
        **os.environ,
        sidecar_module.SCHEME_DRAFT_AUTHORITY_DATABASE_ENV: str(database),
        sidecar_module.SCHEME_DRAFT_AUTHORITY_HMAC_KEY_FILE_ENV: str(key_path),
        sidecar_module.SCHEME_DRAFT_AUTHORITY_REF_ENV: AUTHORITY_REF,
        sidecar_module.SCHEME_DRAFT_AUTHORITY_SOCKET_ENV: str(socket_path),
        sidecar_module.SCHEME_DRAFT_AUTHORITY_CHECKPOINT_SOCKET_ENV: str(
            checkpoint_socket_path
        ),
        sidecar_module.SCHEME_DRAFT_AUTHORITY_CHECKPOINT_REF_ENV: (
            CHECKPOINT_AUTHORITY_REF
        ),
        sidecar_module.SCHEME_DRAFT_AUTHORITY_CHECKPOINT_STORE_REF_ENV: (
            CHECKPOINT_STORE_REF
        ),
        "PYTHONPATH": "src:.",
    }
    process = _start_sidecar(environment, socket_path)
    try:
        client = UnixSchemeDraftAuthorityClient(
            UnixSchemeDraftAuthorityClientSettings(socket_path, AUTHORITY_REF),
            clock=clock,
        )
        assert client.monotonic_checkpoint_protocol_bound is True
        client.verify_ready()
        assert client.resolve(draft_ref, requester) == _draft()

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
            scheme_draft_sidecar=V4UnixSchemeDraftAuthoritySettings(
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
        preview = components.plan_services.preview(synthetic_draft_ref, principal)
        assert preview["confirmation_state"] == "awaiting_human_reauthentication"
        assert components.scheme_draft_authority is None
        assert isinstance(
            components.scheme_draft_client,
            UnixSchemeDraftAuthorityClient,
        )
        assert components.plan_services.status()[
            "scheme_draft_issuance_protocol_bound"
        ] is True
        assert components.plan_services.status()[
            "scheme_draft_authority_checkpoint_protocol_bound"
        ] is True

        _stop_sidecar(process, socket_path)
        process = _start_sidecar(environment, socket_path)
        restarted = synthetic_v4_plan_host_factory(settings, clock=clock)(
            provider,
            confirmation,
        )
        assert isinstance(
            restarted.scheme_draft_client,
            UnixSchemeDraftAuthorityClient,
        )
        assert restarted.scheme_draft_client.resolve(draft_ref, requester) == _draft()
    finally:
        _stop_sidecar(process, socket_path)
        _stop_sidecar(checkpoint_process, checkpoint_socket_path)


def test_unix_scheme_draft_client_rejects_missing_or_non_socket(
    tmp_path: Path,
) -> None:
    socket_path = tmp_path / "draft.sock"
    client = UnixSchemeDraftAuthorityClient(
        UnixSchemeDraftAuthorityClientSettings(socket_path, AUTHORITY_REF)
    )
    with pytest.raises(SchemeDraftAuthoritySidecarError, match="unavailable"):
        client.verify_ready()
    socket_path.write_text("not-a-socket", encoding="utf-8")
    os.chmod(socket_path, 0o600)
    with pytest.raises(SchemeDraftAuthoritySidecarError, match="boundary is invalid"):
        client.verify_ready()


def _start_sidecar(
    environment: dict[str, str],
    socket_path: Path,
    *,
    module: str = "fortipam_mcp.scheme_draft_authority_sidecar",
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
            raise AssertionError(f"draft sidecar stopped before ready: {stderr!r}")
        time.sleep(0.02)
    _stop_sidecar(process, socket_path)
    raise AssertionError("draft sidecar did not create its Unix socket")


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
