from __future__ import annotations

from collections.abc import Iterator
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time

import pytest

from fortipam_mcp.approver_checkpoint_sidecar import (
    UnixApproverCheckpointClient,
    UnixApproverCheckpointClientSettings,
)
from fortipam_mcp.approver_delegation_bootstrap import (
    ApproverDelegationBootstrapError,
    ApproverDelegationBootstrapSettings,
    bootstrap_approver_delegation,
    bootstrap_settings_from_environment,
)
from v4_planning import PersistentApproverAuthorizationAuthority


APPROVER_AUTHORITY_REF = "v4-approver-bootstrap-authority-test"
CHECKPOINT_AUTHORITY_REF = "v4-approver-bootstrap-checkpoint-test"
CHECKPOINT_STORE_REF = "v4-approver-bootstrap-store-test"
NOW = 1_950_000_000


def _owner_directory(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True)
    os.chmod(path, 0o700)
    return path


def _owner_file(path: Path, value: bytes) -> Path:
    path.write_bytes(value)
    os.chmod(path, 0o600)
    return path


@pytest.fixture
def socket_path() -> Iterator[Path]:
    scratch = Path(__file__).resolve().parents[1] / ".codex_tmp"
    scratch.mkdir(mode=0o700, exist_ok=True)
    socket_dir = Path(tempfile.mkdtemp(prefix="fab-", dir=scratch))
    os.chmod(socket_dir, 0o700)
    path = socket_dir / "checkpoint.sock"
    yield path
    if path.exists() or path.is_symlink():
        path.unlink()
    socket_dir.rmdir()


def _settings(
    tmp_path: Path,
    socket_path: Path,
    *,
    input_mode: int = 0o600,
    expires_at: int = NOW + 600,
) -> tuple[ApproverDelegationBootstrapSettings, dict[str, str]]:
    approver_state = _owner_directory(tmp_path / "approver-state")
    checkpoint_state = _owner_directory(tmp_path / "checkpoint-state")
    private = _owner_directory(tmp_path / "private")
    approver_key = _owner_file(approver_state / "approver.hmac", b"a" * 32)
    checkpoint_key = _owner_file(checkpoint_state / "checkpoint.hmac", b"k" * 32)
    input_path = private / "approver-input.json"
    input_path.write_text(
        json.dumps(
            {
                "action_bindings": [
                    {"action_id": "folder-create", "action_version": "1.0.0"}
                ],
                "approver": {
                    "identity_authority_ref": "bootstrap-identity-authority",
                    "subject_namespace": "bootstrap-subject-namespace",
                    "subject_ref": "bootstrap-approver-subject",
                },
                "environment_ref": "bootstrap-environment",
                "expires_at": expires_at,
                "policy_version": "1.0.0",
                "scope_ref": "bootstrap-scope",
            }
        ),
        encoding="utf-8",
    )
    os.chmod(input_path, input_mode)
    settings = ApproverDelegationBootstrapSettings(
        approver_state / "approver.sqlite3",
        approver_key,
        APPROVER_AUTHORITY_REF,
        socket_path,
        CHECKPOINT_AUTHORITY_REF,
        CHECKPOINT_STORE_REF,
        input_path,
        private / "approver-output.json",
    )
    sidecar_environment = {
        **os.environ,
        "FORTIPAM_MCP_V4_APPROVER_CHECKPOINT_DATABASE": str(
            checkpoint_state / "checkpoint.sqlite3"
        ),
        "FORTIPAM_MCP_V4_APPROVER_CHECKPOINT_HMAC_KEY_FILE": str(checkpoint_key),
        "FORTIPAM_MCP_V4_APPROVER_CHECKPOINT_AUTHORITY_REF": (
            CHECKPOINT_AUTHORITY_REF
        ),
        "FORTIPAM_MCP_V4_APPROVER_CHECKPOINT_SOCKET": str(socket_path),
        "PYTHONPATH": "src:.",
    }
    return settings, sidecar_environment


def test_approver_bootstrap_writes_private_handle_and_checkpointed_state(
    tmp_path: Path,
    socket_path: Path,
) -> None:
    settings, sidecar_environment = _settings(tmp_path, socket_path)
    process = _start_sidecar(sidecar_environment, socket_path)
    try:
        bootstrap_approver_delegation(settings, now_epoch=NOW)
        output = json.loads(settings.output_path.read_text(encoding="utf-8"))
        delegation_ref = output["delegation_ref"]
        assert set(output) == {"delegation_ref"}
        assert delegation_ref.startswith("approver-delegation-")
        assert stat.S_IMODE(settings.output_path.stat().st_mode) == 0o600
        assert delegation_ref.encode("utf-8") not in settings.database_path.read_bytes()

        checkpoint = UnixApproverCheckpointClient(
            UnixApproverCheckpointClientSettings(
                socket_path,
                CHECKPOINT_AUTHORITY_REF,
            )
        )
        authority = PersistentApproverAuthorizationAuthority(
            settings.database_path,
            settings.hmac_key_path,
            authority_ref=APPROVER_AUTHORITY_REF,
            monotonic_checkpoint=checkpoint,
            checkpoint_store_ref=CHECKPOINT_STORE_REF,
            clock=lambda: NOW + 1,
        )
        authority.revoke(delegation_ref, now_epoch=NOW + 1)
    finally:
        _stop_sidecar(process, socket_path)


def test_approver_bootstrap_environment_and_cli_do_not_print_values(
    tmp_path: Path,
    socket_path: Path,
) -> None:
    settings, sidecar_environment = _settings(
        tmp_path,
        socket_path,
        expires_at=int(time.time()) + 600,
    )
    environment = {
        **sidecar_environment,
        "FORTIPAM_MCP_V4_APPROVER_BOOTSTRAP_DATABASE": str(settings.database_path),
        "FORTIPAM_MCP_V4_APPROVER_BOOTSTRAP_HMAC_KEY_FILE": str(
            settings.hmac_key_path
        ),
        "FORTIPAM_MCP_V4_APPROVER_BOOTSTRAP_AUTHORITY_REF": APPROVER_AUTHORITY_REF,
        "FORTIPAM_MCP_V4_APPROVER_BOOTSTRAP_CHECKPOINT_SOCKET": str(socket_path),
        "FORTIPAM_MCP_V4_APPROVER_BOOTSTRAP_CHECKPOINT_AUTHORITY_REF": (
            CHECKPOINT_AUTHORITY_REF
        ),
        "FORTIPAM_MCP_V4_APPROVER_BOOTSTRAP_CHECKPOINT_STORE_REF": (
            CHECKPOINT_STORE_REF
        ),
        "FORTIPAM_MCP_V4_APPROVER_BOOTSTRAP_INPUT": str(settings.input_path),
        "FORTIPAM_MCP_V4_APPROVER_BOOTSTRAP_OUTPUT": str(settings.output_path),
    }
    assert bootstrap_settings_from_environment(environment) == settings

    process = _start_sidecar(sidecar_environment, socket_path)
    try:
        result = subprocess.run(
            (sys.executable, "-m", "fortipam_mcp.approver_delegation_bootstrap"),
            cwd=Path(__file__).resolve().parents[1],
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        _stop_sidecar(process, socket_path)

    delegation_ref = json.loads(settings.output_path.read_text(encoding="utf-8"))[
        "delegation_ref"
    ]
    assert result.returncode == 0
    assert result.stdout == '{"status":"issued"}\n'
    assert result.stderr == ""
    assert delegation_ref not in result.stdout
    assert "bootstrap-approver-subject" not in result.stdout + result.stderr


def test_approver_bootstrap_rejects_unsafe_extension_and_existing_output(
    tmp_path: Path,
    socket_path: Path,
) -> None:
    unsafe, _environment = _settings(
        tmp_path / "unsafe",
        socket_path,
        input_mode=0o644,
    )
    with pytest.raises(ApproverDelegationBootstrapError, match="owner-only"):
        bootstrap_approver_delegation(unsafe, now_epoch=NOW)
    assert not unsafe.database_path.exists()
    assert not unsafe.output_path.exists()

    extension, _environment = _settings(tmp_path / "extension", socket_path)
    payload = json.loads(extension.input_path.read_text(encoding="utf-8"))
    payload["private-marker"] = "must-not-reflect"
    extension.input_path.write_text(json.dumps(payload), encoding="utf-8")
    os.chmod(extension.input_path, 0o600)
    with pytest.raises(ApproverDelegationBootstrapError, match="input is invalid") as exc:
        bootstrap_approver_delegation(extension, now_epoch=NOW)
    assert "must-not-reflect" not in str(exc.value)
    assert not extension.database_path.exists()

    existing, _environment = _settings(tmp_path / "existing", socket_path)
    _owner_file(existing.output_path, b"do-not-overwrite")
    with pytest.raises(ApproverDelegationBootstrapError, match="output is unavailable"):
        bootstrap_approver_delegation(existing, now_epoch=NOW)
    assert existing.output_path.read_bytes() == b"do-not-overwrite"
    assert not existing.database_path.exists()


def test_approver_bootstrap_fails_closed_without_checkpoint_sidecar(
    tmp_path: Path,
    socket_path: Path,
) -> None:
    settings, _environment = _settings(tmp_path, socket_path)
    with pytest.raises(ApproverDelegationBootstrapError, match="input was rejected"):
        bootstrap_approver_delegation(settings, now_epoch=NOW)
    assert not settings.output_path.exists()


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
