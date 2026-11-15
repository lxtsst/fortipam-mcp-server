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

from fortipam_mcp.reference_checkpoint_sidecar import (
    UnixReferenceCheckpointClient,
    UnixReferenceCheckpointClientSettings,
)
from fortipam_mcp.reference_grant_bootstrap import (
    ReferenceGrantBootstrapError,
    ReferenceGrantBootstrapSettings,
    bootstrap_reference_grants,
    bootstrap_settings_from_environment,
)
from v4_planning import PersistentReferenceAuthority


AUTHORITY_REF = "v4-reference-bootstrap-test"
CHECKPOINT_AUTHORITY_REF = "v4-reference-bootstrap-checkpoint-test"
CHECKPOINT_STORE_REF = "v4-reference-bootstrap-store-test"
REQUESTER_DIGEST = "a" * 64
ENVIRONMENT_REF = "reference-bootstrap-environment"
SCOPE_REF = "reference-bootstrap-scope"
REFERENCES = (
    ("reference-bootstrap-folder", "object_public_folder"),
    ("reference-bootstrap-owner", "field_owner_ref"),
)


def _owner_directory(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True)
    os.chmod(path, 0o700)
    return path


def _owner_file(path: Path, value: bytes) -> Path:
    path.write_bytes(value)
    os.chmod(path, 0o600)
    return path


@pytest.fixture
def checkpoint_socket_path() -> Iterator[Path]:
    scratch = Path(__file__).resolve().parents[1] / ".codex_tmp"
    scratch.mkdir(mode=0o700, exist_ok=True)
    socket_dir = Path(tempfile.mkdtemp(prefix="frgb-", dir=scratch))
    os.chmod(socket_dir, 0o700)
    socket_path = socket_dir / "checkpoint.sock"
    yield socket_path
    if socket_path.exists() or socket_path.is_symlink():
        socket_path.unlink()
    socket_dir.rmdir()


def _settings(
    tmp_path: Path,
    *,
    input_mode: int = 0o600,
    expires_at: int = 1_950_000_600,
) -> ReferenceGrantBootstrapSettings:
    state = _owner_directory(tmp_path / "state")
    private = _owner_directory(tmp_path / "private")
    key_path = _owner_file(state / "reference.hmac", b"r" * 32)
    input_path = private / "reference-input.json"
    input_path.write_text(
        json.dumps(
            {
                "environment_ref": ENVIRONMENT_REF,
                "expires_at": expires_at,
                "references": [
                    {"reference": reference, "reference_kind": kind}
                    for reference, kind in REFERENCES
                ],
                "requester_digest": REQUESTER_DIGEST,
                "scope_ref": SCOPE_REF,
            }
        ),
        encoding="utf-8",
    )
    os.chmod(input_path, input_mode)
    return ReferenceGrantBootstrapSettings(
        state / "reference.sqlite3",
        key_path,
        AUTHORITY_REF,
        input_path,
        private / "reference-output.json",
    )


def test_reference_bootstrap_writes_private_handles_and_authorizes(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    bootstrap_reference_grants(settings, now_epoch=1_950_000_000)

    output = json.loads(settings.output_path.read_text(encoding="utf-8"))
    grant_refs = tuple(output["grant_refs"])
    assert set(output) == {"grant_refs"}
    assert len(grant_refs) == len(REFERENCES)
    assert all(value.startswith("reference-grant-") for value in grant_refs)
    assert stat.S_IMODE(settings.output_path.stat().st_mode) == 0o600
    authority = PersistentReferenceAuthority(
        settings.database_path,
        settings.hmac_key_path,
        authority_ref=AUTHORITY_REF,
        clock=lambda: 1_950_000_000,
    )
    for reference, kind in REFERENCES:
        assert authority.authorize(
            reference,
            reference_kind=kind,
            requester_digest=REQUESTER_DIGEST,
            environment_ref=ENVIRONMENT_REF,
            scope_ref=SCOPE_REF,
            now_epoch=1_950_000_000,
        ).authorized
    stored = settings.database_path.read_bytes()
    assert all(value.encode("utf-8") not in stored for value in grant_refs)


def test_reference_bootstrap_advances_process_separated_checkpoint(
    tmp_path: Path,
    checkpoint_socket_path: Path,
) -> None:
    settings = _settings(tmp_path)
    checkpoint_state = _owner_directory(tmp_path / "checkpoint-state")
    checkpoint_key = _owner_file(checkpoint_state / "checkpoint.hmac", b"k" * 32)
    checkpointed = ReferenceGrantBootstrapSettings(
        settings.database_path,
        settings.hmac_key_path,
        settings.authority_ref,
        settings.input_path,
        settings.output_path,
        checkpoint_socket_path,
        CHECKPOINT_AUTHORITY_REF,
        CHECKPOINT_STORE_REF,
    )
    environment = {
        **os.environ,
        "FORTIPAM_MCP_V4_REFERENCE_CHECKPOINT_DATABASE": str(
            checkpoint_state / "checkpoint.sqlite3"
        ),
        "FORTIPAM_MCP_V4_REFERENCE_CHECKPOINT_HMAC_KEY_FILE": str(checkpoint_key),
        "FORTIPAM_MCP_V4_REFERENCE_CHECKPOINT_AUTHORITY_REF": (
            CHECKPOINT_AUTHORITY_REF
        ),
        "FORTIPAM_MCP_V4_REFERENCE_CHECKPOINT_SOCKET": str(checkpoint_socket_path),
        "PYTHONPATH": "src:.",
    }
    process = _start_checkpoint_sidecar(environment, checkpoint_socket_path)
    try:
        bootstrap_reference_grants(checkpointed, now_epoch=1_950_000_000)
        checkpoint = UnixReferenceCheckpointClient(
            UnixReferenceCheckpointClientSettings(
                checkpoint_socket_path,
                CHECKPOINT_AUTHORITY_REF,
            )
        )
        authority = PersistentReferenceAuthority(
            settings.database_path,
            settings.hmac_key_path,
            authority_ref=AUTHORITY_REF,
            monotonic_checkpoint=checkpoint,
            checkpoint_store_ref=CHECKPOINT_STORE_REF,
            clock=lambda: 1_950_000_001,
        )
        authority.verify_ready()
    finally:
        _stop_checkpoint_sidecar(process, checkpoint_socket_path)


def test_reference_bootstrap_environment_and_cli_do_not_print_values(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path, expires_at=int(time.time()) + 600)
    environment = {
        **os.environ,
        "FORTIPAM_MCP_V4_REFERENCE_BOOTSTRAP_DATABASE": str(settings.database_path),
        "FORTIPAM_MCP_V4_REFERENCE_BOOTSTRAP_HMAC_KEY_FILE": str(
            settings.hmac_key_path
        ),
        "FORTIPAM_MCP_V4_REFERENCE_BOOTSTRAP_AUTHORITY_REF": AUTHORITY_REF,
        "FORTIPAM_MCP_V4_REFERENCE_BOOTSTRAP_INPUT": str(settings.input_path),
        "FORTIPAM_MCP_V4_REFERENCE_BOOTSTRAP_OUTPUT": str(settings.output_path),
        "PYTHONPATH": "src:.",
    }
    assert bootstrap_settings_from_environment(environment) == settings

    result = subprocess.run(
        (sys.executable, "-m", "fortipam_mcp.reference_grant_bootstrap"),
        cwd=Path(__file__).resolve().parents[1],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    grant_refs = json.loads(settings.output_path.read_text(encoding="utf-8"))[
        "grant_refs"
    ]
    assert result.returncode == 0
    assert result.stdout == '{"status":"issued"}\n'
    assert result.stderr == ""
    assert all(value not in result.stdout for value in grant_refs)
    assert all(reference not in result.stdout for reference, _kind in REFERENCES)

    partial_environment = dict(environment)
    partial_environment[
        "FORTIPAM_MCP_V4_REFERENCE_BOOTSTRAP_CHECKPOINT_SOCKET"
    ] = "/private/tmp/reference-checkpoint.sock"
    with pytest.raises(ReferenceGrantBootstrapError, match="incomplete"):
        bootstrap_settings_from_environment(partial_environment)


def test_reference_bootstrap_rejects_unsafe_extension_and_existing_output(
    tmp_path: Path,
) -> None:
    unsafe = _settings(tmp_path / "unsafe", input_mode=0o644)
    with pytest.raises(ReferenceGrantBootstrapError, match="owner-only"):
        bootstrap_reference_grants(unsafe, now_epoch=1_950_000_000)
    assert not unsafe.database_path.exists()
    assert not unsafe.output_path.exists()

    extension = _settings(tmp_path / "extension")
    payload = json.loads(extension.input_path.read_text(encoding="utf-8"))
    payload["private-marker"] = "must-not-reflect"
    extension.input_path.write_text(json.dumps(payload), encoding="utf-8")
    os.chmod(extension.input_path, 0o600)
    with pytest.raises(ReferenceGrantBootstrapError, match="input is invalid") as exc:
        bootstrap_reference_grants(extension, now_epoch=1_950_000_000)
    assert "must-not-reflect" not in str(exc.value)
    assert not extension.database_path.exists()

    existing = _settings(tmp_path / "existing")
    _owner_file(existing.output_path, b"do-not-overwrite")
    with pytest.raises(ReferenceGrantBootstrapError, match="output is unavailable"):
        bootstrap_reference_grants(existing, now_epoch=1_950_000_000)
    assert existing.output_path.read_bytes() == b"do-not-overwrite"
    assert not existing.database_path.exists()


def test_reference_bootstrap_rejects_duplicate_or_invalid_binding(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    payload = json.loads(settings.input_path.read_text(encoding="utf-8"))
    payload["references"].append(payload["references"][0])
    settings.input_path.write_text(json.dumps(payload), encoding="utf-8")
    os.chmod(settings.input_path, 0o600)

    with pytest.raises(ReferenceGrantBootstrapError, match="input was rejected"):
        bootstrap_reference_grants(settings, now_epoch=1_950_000_000)
    assert not settings.output_path.exists()


def _start_checkpoint_sidecar(
    environment: dict[str, str],
    socket_path: Path,
) -> subprocess.Popen[bytes]:
    process = subprocess.Popen(
        (sys.executable, "-m", "fortipam_mcp.reference_checkpoint_sidecar"),
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
            raise AssertionError(f"reference checkpoint stopped before ready: {stderr!r}")
        time.sleep(0.02)
    _stop_checkpoint_sidecar(process, socket_path)
    raise AssertionError("reference checkpoint did not create its Unix socket")


def _stop_checkpoint_sidecar(
    process: subprocess.Popen[bytes],
    socket_path: Path,
) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5.0)
    if socket_path.exists() or socket_path.is_symlink():
        socket_path.unlink()
