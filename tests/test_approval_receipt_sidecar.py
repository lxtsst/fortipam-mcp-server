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

import fortipam_mcp.approval_receipt_sidecar as sidecar_module
from fortipam_mcp.approval_receipt_sidecar import (
    ApprovalReceiptSidecarError,
    UnixApprovalReceiptAuthenticator,
    UnixApprovalReceiptAuthenticatorSettings,
    approval_receipt_sidecar_settings_from_environment,
    create_approval_receipt_sidecar_app,
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
from v4_planning import ApprovalReceipt, ApprovalReceiptAuthenticator, canonical_digest


@pytest.fixture
def socket_path() -> Iterator[Path]:
    # A repository-root scratch path can exceed the Unix-socket pathname limit
    # in isolated release stages. Keep this test-only private directory short.
    socket_dir = Path(tempfile.mkdtemp(prefix="far-", dir="/tmp"))
    os.chmod(socket_dir, 0o700)
    path = socket_dir / "receipt.sock"
    yield path
    if path.exists() or path.is_symlink():
        path.unlink()
    socket_dir.rmdir()


def _owner_file(path: Path, value: bytes) -> Path:
    path.write_bytes(value)
    os.chmod(path, 0o600)
    return path


def _receipt(authenticator: ApprovalReceiptAuthenticator) -> ApprovalReceipt:
    content = {
        "approver_digest": "a" * 64,
        "authenticator_ref": authenticator.authority_ref,
        "decision_digest": "b" * 64,
        "decision_ref": "decision-ref",
        "execution_authorized": False,
        "expires_at": 200,
        "issued_at": 100,
        "one_time": True,
        "plan_digest": "c" * 64,
        "plan_ref": "plan-ref",
        "receipt_ref": "receipt-ref",
        "requester_digest": "d" * 64,
    }
    digest = canonical_digest(content)
    return ApprovalReceipt(
        receipt_ref="receipt-ref",
        decision_ref="decision-ref",
        decision_digest="b" * 64,
        plan_ref="plan-ref",
        plan_digest="c" * 64,
        requester_digest="d" * 64,
        approver_digest="a" * 64,
        issued_at=100,
        expires_at=200,
        one_time=True,
        execution_authorized=False,
        receipt_digest=digest,
        authenticator_ref=authenticator.authority_ref,
        receipt_mac=authenticator.mac(digest),
    )


def test_receipt_sidecar_app_exposes_only_ready_and_exact_mac() -> None:
    authenticator = ApprovalReceiptAuthenticator(b"r" * 32)
    digest = "d" * 64
    request = {
        "authenticator_ref": authenticator.authority_ref,
        "receipt_digest": digest,
    }
    with TestClient(create_approval_receipt_sidecar_app(authenticator)) as client:
        ready = client.post(
            "/v1/approval-receipt/ready",
            json={"authenticator_ref": authenticator.authority_ref},
        )
        signed = client.post("/v1/approval-receipt/mac", json=request)
        extension = client.post(
            "/v1/approval-receipt/mac",
            json={**request, "private-marker": "must-not-reflect"},
        )
        altered = client.post(
            "/v1/approval-receipt/mac",
            json={**request, "receipt_digest": "invalid"},
        )
        unknown = client.get("/v1/approval-receipt/mac")

    assert ready.status_code == 204 and not ready.content
    assert signed.status_code == 200
    assert signed.json() == {
        "authenticator_ref": authenticator.authority_ref,
        "receipt_mac": authenticator.mac(digest),
    }
    assert extension.status_code == 409
    assert extension.json() == {"status": "rejected"}
    assert "must-not-reflect" not in extension.text
    assert altered.status_code == 409
    assert unknown.status_code == 405


def test_receipt_sidecar_environment_requires_complete_absolute_paths(
    tmp_path: Path,
    socket_path: Path,
) -> None:
    environment = {
        sidecar_module.APPROVAL_RECEIPT_SIDECAR_HMAC_KEY_FILE_ENV: str(
            tmp_path / "receipt.hmac"
        ),
        sidecar_module.APPROVAL_RECEIPT_SIDECAR_SOCKET_ENV: str(socket_path),
    }
    settings = approval_receipt_sidecar_settings_from_environment(environment)
    assert settings.socket_path == socket_path

    del environment[sidecar_module.APPROVAL_RECEIPT_SIDECAR_SOCKET_ENV]
    with pytest.raises(ApprovalReceiptSidecarError, match="incomplete"):
        approval_receipt_sidecar_settings_from_environment(environment)


def test_unix_receipt_authenticator_survives_restart_and_binds_host(
    tmp_path: Path,
    socket_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    os.chmod(state, 0o700)
    key_path = _owner_file(state / "receipt.hmac", b"r" * 32)
    environment = {
        **os.environ,
        sidecar_module.APPROVAL_RECEIPT_SIDECAR_HMAC_KEY_FILE_ENV: str(key_path),
        sidecar_module.APPROVAL_RECEIPT_SIDECAR_SOCKET_ENV: str(socket_path),
        "PYTHONPATH": "src:.",
    }
    process = _start_sidecar(environment, socket_path)
    try:
        client = UnixApprovalReceiptAuthenticator(
            UnixApprovalReceiptAuthenticatorSettings(socket_path)
        )
        client.verify_ready()
        local_authenticator = ApprovalReceiptAuthenticator(b"r" * 32)
        receipt = _receipt(local_authenticator)
        assert client.verify(receipt) is True
        assert client.uses_key_material(b"r" * 32) is False

        planning_key = _owner_file(state / "planning.hmac", b"p" * 32)
        confirmation_key = _owner_file(state / "confirmation.hmac", b"c" * 32)
        browser_key = _owner_file(state / "browser.hmac", b"b" * 32)
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
        components = synthetic_v4_plan_host_factory(
            V4SyntheticHostSettings(state / "planning.sqlite3", planning_key),
            approval_receipt_authenticator=client,
        )(
            provider,
            V4ConfirmationSettings(
                state / "confirmation.sqlite3",
                confirmation_key,
                browser_key,
            ),
        )
        workflow = components.plan_services._facade._workflow  # noqa: SLF001
        assert workflow._approval_gate._receipt_authenticator is client  # noqa: SLF001
        assert workflow._store._approval_receipt_authenticator is client  # noqa: SLF001
        assert components.plan_services.status()[
            "approval_receipt_authenticator_protocol_bound"
        ] is True

        _stop_sidecar(process, socket_path)
        process = _start_sidecar(environment, socket_path)
        restarted = UnixApprovalReceiptAuthenticator(
            UnixApprovalReceiptAuthenticatorSettings(socket_path)
        )
        restarted.verify_ready()
        assert restarted.verify(receipt) is True
    finally:
        _stop_sidecar(process, socket_path)


def test_unix_receipt_authenticator_rejects_missing_or_non_socket(
    tmp_path: Path,
) -> None:
    socket_path = tmp_path / "receipt.sock"
    client = UnixApprovalReceiptAuthenticator(
        UnixApprovalReceiptAuthenticatorSettings(socket_path)
    )
    with pytest.raises(ApprovalReceiptSidecarError, match="unavailable"):
        client.verify_ready()
    socket_path.write_text("not-a-socket", encoding="utf-8")
    os.chmod(socket_path, 0o600)
    with pytest.raises(ApprovalReceiptSidecarError, match="boundary is invalid"):
        client.verify_ready()


def _start_sidecar(
    environment: dict[str, str],
    socket_path: Path,
) -> subprocess.Popen[bytes]:
    process = subprocess.Popen(
        (sys.executable, "-m", "fortipam_mcp.approval_receipt_sidecar"),
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
            raise AssertionError(f"receipt sidecar stopped before ready: {stderr!r}")
        time.sleep(0.02)
    _stop_sidecar(process, socket_path)
    raise AssertionError("receipt sidecar did not create its Unix socket")


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
