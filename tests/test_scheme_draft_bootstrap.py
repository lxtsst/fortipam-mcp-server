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

from fortipam_mcp.scheme_draft_checkpoint_sidecar import (
    UnixSchemeDraftCheckpointClient,
    UnixSchemeDraftCheckpointClientSettings,
)
from fortipam_mcp.scheme_draft_bootstrap import (
    SchemeDraftBootstrapError,
    SchemeDraftBootstrapSettings,
    bootstrap_scheme_draft,
    bootstrap_settings_from_environment,
)
from v4_planning import (
    AuthenticatedRequester,
    DesiredObject,
    ObjectClass,
    PersistentSchemeDraftAuthority,
    SchemeDraft,
    SchemeId,
    scheme_draft_as_mapping,
    scheme_draft_from_mapping,
)


AUTHORITY_REF = "v4-scheme-draft-bootstrap-test"
CHECKPOINT_AUTHORITY_REF = "v4-scheme-draft-bootstrap-checkpoint-test"
CHECKPOINT_STORE_REF = "v4-scheme-draft-bootstrap-store-test"
REQUESTER = AuthenticatedRequester("bootstrap-test-subject", "operator")


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
    socket_dir = Path(tempfile.mkdtemp(prefix="fsdb-", dir=scratch))
    os.chmod(socket_dir, 0o700)
    path = socket_dir / "c.sock"
    yield path
    if path.exists() or path.is_symlink():
        path.unlink()
    socket_dir.rmdir()


def _draft() -> SchemeDraft:
    return SchemeDraft(
        scheme_id=SchemeId.ACCESS_DOMAIN,
        scheme_version="1.0.0",
        registry_schema_version="1.1.0",
        blueprint_ref="FPA-BP-004",
        environment_ref="bootstrap-test-environment",
        scope_ref="bootstrap-test-scope",
        owner_ref="bootstrap-test-owner",
        audience_ref="bootstrap-test-audience",
        outcome_code="establish_access_domain",
        desired_objects=(
            DesiredObject(
                object_ref="bootstrap-test-folder",
                object_class=ObjectClass.PUBLIC_FOLDER,
                desired_exists=True,
                desired_fields=(
                    ("enabled", True),
                    ("owner_ref", "bootstrap-test-owner"),
                ),
            ),
        ),
        approval_class="independent_approval",
        separation_required=True,
        risk_class="high",
        external_effects=("access_scope_change",),
        assumption_codes=("fixed_fixture_only",),
        excluded_scope_codes=("credential_material",),
        verification_codes=("relation_readback",),
        stop_codes=("current_state_drift",),
        evidence_policy="redacted_contract_evidence",
        maintenance_class="none",
        reversibility_class="compensating_action_required",
        evidence_refs=("bootstrap-test-evidence",),
        unresolved_gap_codes=(),
        reconciliation_strategy="reconcile_or_manual",
        summary_ttl_seconds=300,
    )


def _settings(tmp_path: Path, *, input_mode: int = 0o600) -> SchemeDraftBootstrapSettings:
    state = _owner_directory(tmp_path / "state")
    private = _owner_directory(tmp_path / "private")
    key_path = _owner_file(state / "draft.hmac", b"d" * 32)
    input_path = private / "draft-input.json"
    input_path.write_text(
        json.dumps(
            {
                "draft": scheme_draft_as_mapping(_draft()),
                "expires_at": 1_950_000_600,
                "requester_digest": REQUESTER.digest,
            }
        ),
        encoding="utf-8",
    )
    os.chmod(input_path, input_mode)
    return SchemeDraftBootstrapSettings(
        state / "draft.sqlite3",
        key_path,
        AUTHORITY_REF,
        input_path,
        private / "draft-output.json",
    )


def test_scheme_draft_mapping_round_trip_is_exact() -> None:
    assert scheme_draft_from_mapping(scheme_draft_as_mapping(_draft())) == _draft()


def test_private_bootstrap_writes_only_owner_only_opaque_ref(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    bootstrap_scheme_draft(settings, now_epoch=1_950_000_000)

    output = json.loads(settings.output_path.read_text(encoding="utf-8"))
    draft_ref = output["scheme_draft_ref"]
    assert set(output) == {"scheme_draft_ref"}
    assert draft_ref.startswith("scheme-draft-")
    assert stat.S_IMODE(settings.output_path.stat().st_mode) == 0o600
    authority = PersistentSchemeDraftAuthority(
        settings.database_path,
        settings.hmac_key_path,
        authority_ref=AUTHORITY_REF,
        clock=lambda: 1_950_000_000,
    )
    assert authority.resolve(
        draft_ref,
        REQUESTER,
    ) == _draft()


def test_private_bootstrap_advances_process_separated_checkpoint(
    tmp_path: Path,
    checkpoint_socket_path: Path,
) -> None:
    settings = _settings(tmp_path)
    checkpoint_state = _owner_directory(tmp_path / "checkpoint-state")
    checkpoint_key = _owner_file(checkpoint_state / "checkpoint.hmac", b"k" * 32)
    checkpointed = SchemeDraftBootstrapSettings(
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
    process = _start_checkpoint_sidecar(environment, checkpoint_socket_path)
    try:
        bootstrap_scheme_draft(checkpointed, now_epoch=1_950_000_000)
        checkpoint = UnixSchemeDraftCheckpointClient(
            UnixSchemeDraftCheckpointClientSettings(
                checkpoint_socket_path,
                CHECKPOINT_AUTHORITY_REF,
            )
        )
        authority = PersistentSchemeDraftAuthority(
            settings.database_path,
            settings.hmac_key_path,
            authority_ref=AUTHORITY_REF,
            monotonic_checkpoint=checkpoint,
            checkpoint_store_ref=CHECKPOINT_STORE_REF,
            clock=lambda: 1_950_000_000,
        )
        authority.verify_ready()
    finally:
        _stop_checkpoint_sidecar(process, checkpoint_socket_path)


def test_bootstrap_environment_and_cli_never_print_ref_or_input(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    now = int(time.time())
    payload = json.loads(settings.input_path.read_text(encoding="utf-8"))
    payload["expires_at"] = now + 600
    settings.input_path.write_text(json.dumps(payload), encoding="utf-8")
    os.chmod(settings.input_path, 0o600)
    environment = dict(os.environ)
    environment.update(
        {
            "FORTIPAM_MCP_V4_DRAFT_BOOTSTRAP_DATABASE": str(
                settings.database_path
            ),
            "FORTIPAM_MCP_V4_DRAFT_BOOTSTRAP_HMAC_KEY_FILE": str(
                settings.hmac_key_path
            ),
            "FORTIPAM_MCP_V4_DRAFT_BOOTSTRAP_AUTHORITY_REF": AUTHORITY_REF,
            "FORTIPAM_MCP_V4_DRAFT_BOOTSTRAP_INPUT": str(settings.input_path),
            "FORTIPAM_MCP_V4_DRAFT_BOOTSTRAP_OUTPUT": str(settings.output_path),
            "PYTHONPATH": "src:.",
        }
    )
    assert bootstrap_settings_from_environment(environment) == settings

    result = subprocess.run(
        (sys.executable, "-m", "fortipam_mcp.scheme_draft_bootstrap"),
        cwd=Path(__file__).resolve().parents[1],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    draft_ref = json.loads(settings.output_path.read_text(encoding="utf-8"))[
        "scheme_draft_ref"
    ]
    assert result.returncode == 0
    assert result.stdout == '{"status":"issued"}\n'
    assert result.stderr == ""
    assert draft_ref not in result.stdout
    assert "bootstrap-test-folder" not in result.stdout + result.stderr

    partial_environment = dict(environment)
    partial_environment[
        "FORTIPAM_MCP_V4_DRAFT_BOOTSTRAP_CHECKPOINT_SOCKET"
    ] = "/private/tmp/scheme-draft-checkpoint.sock"
    with pytest.raises(SchemeDraftBootstrapError, match="incomplete"):
        bootstrap_settings_from_environment(partial_environment)


def test_bootstrap_rejects_unsafe_extension_and_existing_output(
    tmp_path: Path,
) -> None:
    unsafe = _settings(tmp_path / "unsafe", input_mode=0o644)
    with pytest.raises(SchemeDraftBootstrapError, match="owner-only"):
        bootstrap_scheme_draft(unsafe, now_epoch=1_950_000_000)
    assert not unsafe.database_path.exists()
    assert not unsafe.output_path.exists()

    extension = _settings(tmp_path / "extension")
    payload = json.loads(extension.input_path.read_text(encoding="utf-8"))
    payload["private-marker"] = "must-not-reflect"
    extension.input_path.write_text(json.dumps(payload), encoding="utf-8")
    os.chmod(extension.input_path, 0o600)
    with pytest.raises(SchemeDraftBootstrapError, match="input is invalid") as exc:
        bootstrap_scheme_draft(extension, now_epoch=1_950_000_000)
    assert "must-not-reflect" not in str(exc.value)
    assert not extension.database_path.exists()
    failed = subprocess.run(
        (sys.executable, "-m", "fortipam_mcp.scheme_draft_bootstrap"),
        cwd=Path(__file__).resolve().parents[1],
        env={
            **os.environ,
            "FORTIPAM_MCP_V4_DRAFT_BOOTSTRAP_DATABASE": str(
                extension.database_path
            ),
            "FORTIPAM_MCP_V4_DRAFT_BOOTSTRAP_HMAC_KEY_FILE": str(
                extension.hmac_key_path
            ),
            "FORTIPAM_MCP_V4_DRAFT_BOOTSTRAP_AUTHORITY_REF": AUTHORITY_REF,
            "FORTIPAM_MCP_V4_DRAFT_BOOTSTRAP_INPUT": str(extension.input_path),
            "FORTIPAM_MCP_V4_DRAFT_BOOTSTRAP_OUTPUT": str(extension.output_path),
            "PYTHONPATH": "src:.",
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert failed.returncode == 1
    assert failed.stdout == ""
    assert failed.stderr == '{"status":"failed"}\n'
    assert "must-not-reflect" not in failed.stderr

    existing = _settings(tmp_path / "existing")
    _owner_file(existing.output_path, b"do-not-overwrite")
    with pytest.raises(SchemeDraftBootstrapError, match="output is unavailable"):
        bootstrap_scheme_draft(existing, now_epoch=1_950_000_000)
    assert existing.output_path.read_bytes() == b"do-not-overwrite"
    assert not existing.database_path.exists()


def _start_checkpoint_sidecar(
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
    _stop_checkpoint_sidecar(process, socket_path)
    raise AssertionError("Scheme Draft checkpoint did not create its Unix socket")


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
