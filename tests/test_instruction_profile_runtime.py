"""Owner startup joins real sealed creation records to independent phase stores."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any

import pytest

from fortipam_mcp import instruction_profile_runtime as runtime
from fortipam_mcp.instruction_profile_http_transport import FortiPamInstructionProfileHttpTransport
from fortipam_mcp.secret_metadata_http_transport import ENV_PREFIX

from test_instruction_profile_http_transport import Fixture, fixture as fixture, run


def setup(tmp_path: Path, fixture: Fixture) -> tuple[dict[str, str], dict[str, Any], Path]:
    tmp_path.chmod(0o700)
    state, peer, _ = fixture
    paths = {"state_directory": str(state), "execution_database_file": str(tmp_path / "create.sqlite")}
    for name, content in (("authority", b"a"), ("execution", b"e")):
        path = tmp_path / (name + ".key")
        path.write_bytes(content * 32)
        path.chmod(0o600)
        paths[name + "_hmac_key_file"] = str(path)
    manifest: dict[str, Any] = {"contract": runtime.CONTRACT, "phase": "create",
        "binding": {"name": peer.binding._name, "brief": peer.brief, "text": peer.text, "nonce": "a" * 64},
        "identity": {"environment_ref": "synthetic-environment", "scope_ref": "synthetic-scope",
            "audience_ref": "synthetic-audience", "allowed_requester_digest": "1" * 64,
            "allowed_transport_digest": "2" * 64, "serial_digest": peer.serial_digest, "schema_digest": peer.schema_digest},
        "paths": paths}
    path = tmp_path / "startup.json"
    path.write_text(json.dumps(manifest))
    path.chmod(0o600)
    return {runtime.PREFIX + "ENABLED": "true", runtime.PREFIX + "STARTUP_MANIFEST_FILE": str(path),
        ENV_PREFIX + "ENABLED": "true", ENV_PREFIX + "BASE_URL": "https://pam.example",
        ENV_PREFIX + "API_TOKEN": "synthetic-token"}, manifest, path


def delete_manifest(manifest: dict[str, Any], root: Path) -> dict[str, Any]:
    result = copy.deepcopy(manifest)
    result["phase"] = "delete"
    result["paths"]["execution_database_file"] = str(root / "delete.sqlite")
    for name, content in (("authority", b"r"), ("execution", b"s")):
        path = root / ("delete-" + name + ".key")
        path.write_bytes(content * 32)
        path.chmod(0o600)
        result["paths"][name + "_hmac_key_file"] = str(path)
    return result


def test_disabled_startup_does_not_read_material(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runtime, "_read", lambda *args: pytest.fail("Disabled startup read a file"))
    assert runtime.build_instruction_profile_candidate({}) is None


@pytest.mark.parametrize("flags", [{"ENABLED": "TRUE"}, {"EXECUTION_ENABLED": "true"},
    {"ENABLED": True}, {"ENABLED": "true", "EXECUTION_ENABLED": "yes"}])
def test_invalid_flags_refuse(flags: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        runtime.build_instruction_profile_candidate({runtime.PREFIX + key: value for key, value in flags.items()})


def test_startup_preserves_original_records_and_opens_no_device_connection(
    tmp_path: Path, fixture: Fixture, monkeypatch: pytest.MonkeyPatch,
) -> None:
    env, manifest, _ = setup(tmp_path, fixture)
    state = fixture[0]
    original = {p.name: p.read_bytes() for p in state.iterdir()}
    monkeypatch.setattr(FortiPamInstructionProfileHttpTransport, "_request",
                        lambda *args, **kwargs: pytest.fail("Startup contacted the device"))
    for enabled in (False, True):
        env[runtime.PREFIX + "EXECUTION_ENABLED"] = str(enabled).lower()
        action = runtime.build_instruction_profile_candidate(env)
        assert action is not None and action.phase == "create" and action._enabled is enabled
        assert action._workflow._enabled is enabled
    assert all((state / name).read_bytes() == value for name, value in original.items())
    assert Path(manifest["paths"]["execution_database_file"]).is_file()
    pins = [state / runtime._COMMON_MARKER, state / runtime._phase_marker("create")]
    rendered = "".join(path.read_text() for path in pins)
    for value in (*manifest["binding"].values(), "synthetic-token"):
        assert value not in rendered


@pytest.mark.parametrize("fault", ["extra", "password", "phase", "nested", "mode", "hardlink", "symlink",
    "key_reuse", "key_length", "state_collision", "sidecar_collision", "relative_path", "binding", "identity", "url_userinfo"])
def test_invalid_startup_cannot_create_execution_ledger(tmp_path: Path, fixture: Fixture, fault: str) -> None:
    env, manifest, path = setup(tmp_path, fixture)
    original_database = Path(manifest["paths"]["execution_database_file"])
    if fault == "extra": manifest["unknown"] = "denied"
    elif fault == "password": manifest["binding"]["password"] = "synthetic-forbidden"
    elif fault == "phase": manifest["phase"] = "update"
    elif fault == "nested": manifest["binding"]["nonce"] = {"value": "invalid"}
    elif fault == "mode": path.chmod(0o644)
    elif fault == "hardlink": os.link(path, tmp_path / "alias.json")
    elif fault == "symlink":
        path.rename(tmp_path / "original.json")
        path.symlink_to(tmp_path / "original.json")
    elif fault == "key_reuse": Path(manifest["paths"]["execution_hmac_key_file"]).write_bytes(b"a" * 32)
    elif fault == "key_length": Path(manifest["paths"]["authority_hmac_key_file"]).write_bytes(b"a" * 33)
    elif fault == "state_collision": manifest["paths"]["execution_database_file"] = str(fixture[0] / "ledger")
    elif fault == "sidecar_collision": manifest["paths"]["execution_database_file"] = str(path).removesuffix(".json")
    elif fault == "relative_path": manifest["paths"]["execution_hmac_key_file"] = "relative.key"
    elif fault == "binding": manifest["binding"]["nonce"] = "invalid"
    elif fault == "identity": manifest["identity"]["allowed_requester_digest"] = "invalid"
    else: env[ENV_PREFIX + "BASE_URL"] = "https://user:private@pam.example"
    if fault == "sidecar_collision":
        manifest["paths"]["authority_hmac_key_file"] = manifest["paths"]["execution_database_file"] + "-wal"
        key = Path(manifest["paths"]["authority_hmac_key_file"])
        key.write_bytes(b"a" * 32)
        key.chmod(0o600)
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="^FortiPAM Instruction Profile startup is unavailable.$"):
        runtime.build_instruction_profile_candidate(env)
    assert not original_database.exists()
    assert fixture[1].writes == []


@pytest.mark.parametrize("fault", ["duplicate", "escaped_duplicate", "invalid_escape", "invalid_utf8", "non_string"])
def test_invalid_manifest_is_refused_before_decoding(
    tmp_path: Path, fixture: Fixture, monkeypatch: pytest.MonkeyPatch, fault: str,
) -> None:
    env, manifest, path = setup(tmp_path, fixture)
    raw = json.dumps(manifest).encode()
    value = json.dumps(manifest["identity"]["scope_ref"]).encode()
    if fault == "duplicate": raw = raw.replace(b'"scope_ref": ' + value, b'"scope_ref": ' + value + b', "scope_ref": ' + value)
    elif fault == "escaped_duplicate": raw = raw.replace(b'"scope_ref": ' + value, b'"scope_ref": ' + value + b', "scope_\\u0072ef": ' + value)
    elif fault == "invalid_escape": raw = raw.replace(value, b'"synthetic-\\q"')
    elif fault == "invalid_utf8": raw = raw.replace(value, b'"synthetic-\xff"')
    else: raw = raw.replace(value, b'null')
    path.write_bytes(raw)
    monkeypatch.setattr(runtime, "_decode", lambda *args: pytest.fail("Forbidden manifest decoded"))
    with pytest.raises(ValueError): runtime.build_instruction_profile_candidate(env)


@pytest.mark.parametrize("fault", ["binding", "identity", "database", "key", "api_identity"])
def test_restart_namespace_cannot_be_rebound(tmp_path: Path, fixture: Fixture, fault: str) -> None:
    env, manifest, path = setup(tmp_path, fixture)
    assert runtime.build_instruction_profile_candidate(env) is not None
    if fault == "binding": manifest["binding"]["nonce"] = "9" * 64
    elif fault == "identity": manifest["identity"]["allowed_requester_digest"] = "9" * 64
    elif fault == "database": manifest["paths"]["execution_database_file"] = str(tmp_path / "new.sqlite")
    elif fault == "key": Path(manifest["paths"]["execution_hmac_key_file"]).write_bytes(b"z" * 32)
    else: env[ENV_PREFIX + "API_TOKEN"] = "changed-synthetic-identity"
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError): runtime.build_instruction_profile_candidate(env)
    assert not (tmp_path / "new.sqlite").exists()


@pytest.mark.parametrize("shared", [None, "database", "sidecar", "authority_key", "execution_key", "key_path"])
def test_phase_startup_requires_independent_keys_and_database_family(tmp_path: Path, fixture: Fixture, shared: str | None) -> None:
    env, manifest, path = setup(tmp_path, fixture)
    action = runtime.build_instruction_profile_candidate(env)
    assert action is not None
    run(fixture, "create")
    original_common = (fixture[0] / runtime._COMMON_MARKER).read_bytes()
    restore = delete_manifest(manifest, tmp_path)
    if shared in {"database", "sidecar"}:
        restore["paths"]["execution_database_file"] = manifest["paths"]["execution_database_file"] + ("-wal" if shared == "sidecar" else "")
    elif shared == "key_path":
        restore["paths"]["authority_hmac_key_file"] = manifest["paths"]["authority_hmac_key_file"]
        Path(restore["paths"]["authority_hmac_key_file"]).write_bytes(b"r" * 32)
    elif shared:
        field = "authority_hmac_key_file" if shared == "authority_key" else "execution_hmac_key_file"
        Path(restore["paths"][field]).write_bytes(Path(manifest["paths"][field]).read_bytes())
    path.write_text(json.dumps(restore))
    if shared:
        with pytest.raises(ValueError): runtime.build_instruction_profile_candidate(env)
    else:
        restored = runtime.build_instruction_profile_candidate(env)
        assert restored is not None and restored.phase == "delete"
        assert restored._workflow._execution_store is not action._workflow._execution_store
    assert (fixture[0] / runtime._COMMON_MARKER).read_bytes() == original_common


@pytest.mark.parametrize("missing", ["ledger", "common_pin", "phase_pin"])
def test_missing_pinned_state_is_not_recreated(tmp_path: Path, fixture: Fixture, missing: str) -> None:
    env, manifest, _ = setup(tmp_path, fixture)
    action = runtime.build_instruction_profile_candidate(env)
    assert action is not None
    target = (Path(manifest["paths"]["execution_database_file"]) if missing == "ledger" else
              fixture[0] / (runtime._COMMON_MARKER if missing == "common_pin" else runtime._phase_marker("create")))
    target.unlink()
    with pytest.raises(ValueError): runtime.build_instruction_profile_candidate(env)
    assert not target.exists() and not (fixture[0] / "create.claim.json").exists()


def test_original_ownership_and_unconsumed_phase_are_required(tmp_path: Path, fixture: Fixture) -> None:
    env, _, _ = setup(tmp_path, fixture)
    run(fixture, "create")
    with pytest.raises(ValueError): runtime.build_instruction_profile_candidate(env)
    assert not (fixture[0] / runtime._COMMON_MARKER).exists()
