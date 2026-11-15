"""Protected metadata-only startup and persistent LDAP phase namespaces."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any

import pytest

from fortipam_mcp import ldap_server_update_runtime as runtime
from fortipam_mcp.ldap_server_http_transport import FortiPamLdapServerHttpTransport
from fortipam_mcp.ldap_server_update_live_workflow import LdapServerUpdateLiveWorkflow
from fortipam_mcp.secret_metadata_http_transport import ENV_PREFIX

from test_ldap_server_http_transport import binding
from test_ldap_server_projection import SERIAL


def _setup(tmp_path: Path) -> tuple[dict[str, str], dict[str, Any], Path, dict[str, Path]]:
    tmp_path.chmod(0o700)
    creation = tmp_path / "creation"
    creation.mkdir(mode=0o700)
    state = creation.with_name(creation.name + ".ldap-update")
    state.mkdir(mode=0o700)
    paths = {"creation_state_directory": creation, "state_directory": state,
        "execution_database_file": tmp_path / "update.sqlite",
        "execution_hmac_key_file": tmp_path / "update-execution.key",
        "authority_hmac_key_file": tmp_path / "update-authority.key"}
    for name, value in (("authority", b"a"), ("execution", b"e")):
        paths[name + "_hmac_key_file"].write_bytes(value * 32)
        paths[name + "_hmac_key_file"].chmod(0o600)
    selected = binding()
    manifest: dict[str, Any] = {"contract": runtime.CONTRACT, "phase": "update",
        "binding": {name: getattr(selected, name) for name in runtime._SCHEMA["binding"]},
        "identity": {"environment_ref": "synthetic-environment", "scope_ref": "synthetic-lab-scope",
            "audience_ref": "synthetic-lab-audience", "allowed_requester_digest": "1" * 64,
            "allowed_transport_digest": "2" * 64, "expected_serial": SERIAL},
        "paths": {name: str(value) for name, value in paths.items()}}
    path = tmp_path / "startup.json"
    path.write_text(json.dumps(manifest))
    path.chmod(0o600)
    environment = {runtime.PREFIX + "ENABLED": "true", runtime.PREFIX + "STARTUP_MANIFEST_FILE": str(path),
        ENV_PREFIX + "ENABLED": "true", ENV_PREFIX + "BASE_URL": "https://pam.example",
        ENV_PREFIX + "API_TOKEN": "synthetic-api-token"}
    return environment, manifest, path, paths


@pytest.fixture
def composed(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    phases: dict[int, str] = {}

    def init(self: LdapServerUpdateLiveWorkflow, *args: Any, **kwargs: Any) -> None:
        calls.append(kwargs)
        phases[id(self)] = str(kwargs["phase"])

    monkeypatch.setattr(LdapServerUpdateLiveWorkflow, "__init__", init)
    monkeypatch.setattr(LdapServerUpdateLiveWorkflow, "phase", property(lambda self: phases[id(self)]))
    return calls


def _restore_manifest(manifest: dict[str, Any], tmp_path: Path) -> dict[str, Any]:
    restored = copy.deepcopy(manifest)
    restored["phase"] = "restore"
    restored["identity"]["allowed_requester_digest"] = "3" * 64
    restored["paths"]["execution_database_file"] = str(tmp_path / "restore.sqlite")
    for name, value in (("authority", b"r"), ("execution", b"s")):
        path = tmp_path / f"restore-{name}.key"
        path.write_bytes(value * 32)
        path.chmod(0o600)
        restored["paths"][name + "_hmac_key_file"] = str(path)
    return restored


def test_default_reads_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runtime, "_read", lambda *args: pytest.fail("Disabled source read"))
    assert runtime.build_ldap_server_update_candidate({}) is None


@pytest.mark.parametrize("values", [{"ENABLED": "TRUE"}, {"ENABLED": "1"},
    {"EXECUTION_ENABLED": "true"}, {"EXECUTION_ENABLED": "yes"}, {"ENABLED": True}])
def test_invalid_flags_fail_closed(values: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="^FortiPAM LDAP server update startup is unavailable.$"):
        runtime.build_ldap_server_update_candidate({runtime.PREFIX + name: value for name, value in values.items()})


def test_startup_pins_only_metadata_and_preserves_creation_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, composed: list[dict[str, Any]],
) -> None:
    environment, _, _, paths = _setup(tmp_path)
    creation_marker = paths["creation_state_directory"] / "created.json"
    creation_marker.write_text("synthetic-original-creation-state")
    creation_marker.chmod(0o600)
    monkeypatch.setattr(FortiPamLdapServerHttpTransport, "_exchange",
        lambda *args, **kwargs: pytest.fail("Startup opened a device connection"))
    from fortipam_mcp import ldap_server_runtime
    monkeypatch.setattr(ldap_server_runtime._CentralLdapLoader, "__init__",
        lambda *args, **kwargs: pytest.fail("Update composed a bind-material loader"))
    for gate in (False, True):
        environment[runtime.PREFIX + "EXECUTION_ENABLED"] = str(gate).lower()
        action = runtime.build_ldap_server_update_candidate(environment)
        assert action is not None and action.phase == "update"
        assert composed[-1]["execution_enabled"] is gate
        assert composed[-1]["creation_state_directory"] == paths["creation_state_directory"]
    assert creation_marker.read_text() == "synthetic-original-creation-state"
    assert paths["execution_database_file"].exists()
    assert set(item.name for item in paths["state_directory"].iterdir()) == {
        "operation.lock", runtime._COMMON_MARKER, runtime._phase_marker("update")}
    rendered = "".join(item.read_text() for item in paths["state_directory"].glob("*.json"))
    for value in (binding().username, binding().dn, binding().server, "synthetic-api-token"):
        assert value not in rendered
    assert "loader" not in composed[-1] and "material_store" not in composed[-1]


@pytest.mark.parametrize("fault", ["extra", "material", "password", "phase", "version", "nested",
    "manifest_mode", "parent_mode", "symlink", "hardlink", "key_reuse", "key_length",
    "path_collision", "sidecar_collision", "state_collision", "other_state", "relative_path",
    "binding", "requester", "transport", "scope", "serial", "url_userinfo"])
def test_invalid_manifest_refuses_before_execution_ledger(
    tmp_path: Path, fault: str, composed: list[dict[str, Any]],
) -> None:
    environment, manifest, path, paths = _setup(tmp_path)
    if fault == "extra": manifest["unknown"] = "denied"
    elif fault == "material": manifest["material"] = {"credential_binding_id": "denied"}
    elif fault == "password": manifest["binding"]["password"] = "synthetic-forbidden"
    elif fault == "phase": manifest["phase"] = "create"
    elif fault == "version": manifest["contract"] += "-v2"
    elif fault == "nested": manifest["binding"]["username"] = {"password": "synthetic-forbidden"}
    elif fault == "manifest_mode": path.chmod(0o644)
    elif fault == "parent_mode": tmp_path.chmod(0o755)
    elif fault == "symlink":
        original = paths["authority_hmac_key_file"]
        renamed = tmp_path / "renamed.key"
        original.rename(renamed)
        original.symlink_to(renamed)
    elif fault == "hardlink": os.link(paths["authority_hmac_key_file"], tmp_path / "alias.key")
    elif fault == "key_reuse": paths["execution_hmac_key_file"].write_bytes(b"a" * 32)
    elif fault == "key_length": paths["authority_hmac_key_file"].write_bytes(b"a" * 33)
    elif fault == "path_collision": manifest["paths"]["execution_database_file"] = str(path)
    elif fault == "sidecar_collision": manifest["paths"]["execution_database_file"] = str(path).removesuffix(".json")
    elif fault == "state_collision": manifest["paths"]["execution_database_file"] = str(paths["state_directory"] / "ledger")
    elif fault == "other_state":
        other = tmp_path / "fresh-state"
        other.mkdir(mode=0o700)
        manifest["paths"]["state_directory"] = str(other)
    elif fault == "relative_path": manifest["paths"]["execution_hmac_key_file"] = "execution.key"
    elif fault == "binding": manifest["binding"]["server"] = "outside.invalid"
    elif fault == "requester": manifest["identity"]["allowed_requester_digest"] = "invalid"
    elif fault == "transport": manifest["identity"]["allowed_transport_digest"] = "invalid"
    elif fault == "scope": manifest["identity"]["scope_ref"] = "invalid ref"
    elif fault == "serial": manifest["identity"]["expected_serial"] = "invalid serial"
    elif fault == "url_userinfo": environment[ENV_PREFIX + "BASE_URL"] = "https://username:forbidden@pam.example"
    if fault == "sidecar_collision":
        manifest["paths"]["authority_hmac_key_file"] = manifest["paths"]["execution_database_file"] + "-wal"
        alias = Path(manifest["paths"]["authority_hmac_key_file"])
        alias.write_bytes(b"a" * 32)
        alias.chmod(0o600)
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="^FortiPAM LDAP server update startup is unavailable.$"):
        runtime.build_ldap_server_update_candidate(environment)
    assert not paths["execution_database_file"].exists()
    assert composed == []


@pytest.mark.parametrize("fault", ["password", "duplicate", "escaped_duplicate", "invalid_escape", "invalid_utf8", "non_string"])
def test_invalid_schema_never_decodes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str,
) -> None:
    environment, manifest, path, paths = _setup(tmp_path)
    if fault == "password": manifest["binding"]["password"] = "synthetic-forbidden"
    raw = json.dumps(manifest).encode()
    field = json.dumps(manifest["identity"]["scope_ref"]).encode()
    if fault == "duplicate":
        raw = raw.replace(b'"scope_ref": ' + field, b'"scope_ref": ' + field + b', "scope_ref": ' + field)
    elif fault == "escaped_duplicate":
        raw = raw.replace(b'"scope_ref": ' + field, b'"scope_ref": ' + field + b', "scope_\\u0072ef": ' + field)
    elif fault == "invalid_escape": raw = raw.replace(field, b'"synthetic-\\q-scope"')
    elif fault == "invalid_utf8": raw = raw.replace(field, b'"synthetic-\xff-scope"')
    elif fault == "non_string": raw = raw.replace(field, b'null')
    path.write_bytes(raw)
    monkeypatch.setattr(runtime, "_decode", lambda *args: pytest.fail("Decoded forbidden schema"))
    with pytest.raises(ValueError):
        runtime.build_ldap_server_update_candidate(environment)
    assert not paths["execution_database_file"].exists()


@pytest.mark.parametrize("changed", ["binding", "identity", "database", "key", "api_identity"])
def test_restart_cannot_rebind_namespace(
    tmp_path: Path, changed: str, composed: list[dict[str, Any]],
) -> None:
    environment, manifest, path, paths = _setup(tmp_path)
    assert runtime.build_ldap_server_update_candidate(environment) is not None
    if changed == "binding": manifest["binding"]["private_nonce"] = "9" * 64
    elif changed == "identity": manifest["identity"]["allowed_requester_digest"] = "9" * 64
    elif changed == "database": manifest["paths"]["execution_database_file"] = str(tmp_path / "new.sqlite")
    elif changed == "key": paths["execution_hmac_key_file"].write_bytes(b"z" * 32)
    elif changed == "api_identity": environment[ENV_PREFIX + "API_TOKEN"] = "another-synthetic-identity"
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        runtime.build_ldap_server_update_candidate(environment)
    assert len(composed) == 1 and not (tmp_path / "new.sqlite").exists()


def test_phase_switch_keeps_claim_and_common_pin_with_independent_stores(
    tmp_path: Path, composed: list[dict[str, Any]],
) -> None:
    environment, manifest, path, paths = _setup(tmp_path)
    assert runtime.build_ldap_server_update_candidate(environment) is not None
    claim = paths["state_directory"] / "update.claim.json"
    claim.write_text("{}")
    claim.chmod(0o600)
    common = (paths["state_directory"] / runtime._COMMON_MARKER).read_bytes()
    restore = _restore_manifest(manifest, tmp_path)
    path.write_text(json.dumps(restore))
    action = runtime.build_ldap_server_update_candidate(environment)
    assert action is not None and action.phase == "restore"
    assert claim.read_text() == "{}"
    assert (paths["state_directory"] / runtime._COMMON_MARKER).read_bytes() == common
    assert Path(restore["paths"]["execution_database_file"]).exists()
    assert composed[0]["execution_store"] is not composed[1]["execution_store"]
    path.write_text(json.dumps(manifest))
    assert runtime.build_ldap_server_update_candidate(environment) is not None
    assert claim.read_text() == "{}"


@pytest.mark.parametrize("shared", ["database", "sidecar", "authority_key", "execution_key", "key_path"])
def test_phase_switch_rejects_shared_database_family_and_keys(
    tmp_path: Path, shared: str, composed: list[dict[str, Any]],
) -> None:
    environment, manifest, path, paths = _setup(tmp_path)
    assert runtime.build_ldap_server_update_candidate(environment) is not None
    restore = _restore_manifest(manifest, tmp_path)
    if shared in {"database", "sidecar"}:
        restore["paths"]["execution_database_file"] = str(paths["execution_database_file"]) + ("-wal" if shared == "sidecar" else "")
    elif shared == "key_path":
        restore["paths"]["authority_hmac_key_file"] = str(paths["authority_hmac_key_file"])
        paths["authority_hmac_key_file"].write_bytes(b"r" * 32)
    else:
        key = shared.removesuffix("_key")
        Path(restore["paths"][key + "_hmac_key_file"]).write_bytes(paths[key + "_hmac_key_file"].read_bytes())
    path.write_text(json.dumps(restore))
    with pytest.raises(ValueError):
        runtime.build_ldap_server_update_candidate(environment)
    assert len(composed) == 1
    assert not (paths["state_directory"] / runtime._phase_marker("restore")).exists()


@pytest.mark.parametrize("marker", ["update.plan.json", "update.claim.json", "restore-ack.json", "restore-verified.json"])
def test_missing_common_pin_cannot_adopt_prior_state(tmp_path: Path, marker: str) -> None:
    environment, _, _, paths = _setup(tmp_path)
    old = paths["state_directory"] / marker
    old.write_text("{}")
    old.chmod(0o600)
    with pytest.raises(ValueError):
        runtime.build_ldap_server_update_candidate(environment)
    assert not paths["execution_database_file"].exists()
    assert not (paths["state_directory"] / runtime._COMMON_MARKER).exists()


def test_existing_unpinned_database_cannot_be_shared(tmp_path: Path) -> None:
    environment, _, _, paths = _setup(tmp_path)
    paths["execution_database_file"].write_bytes(b"synthetic-other-ledger")
    paths["execution_database_file"].chmod(0o600)
    with pytest.raises(ValueError):
        runtime.build_ldap_server_update_candidate(environment)
    assert paths["execution_database_file"].read_bytes() == b"synthetic-other-ledger"
    assert not (paths["state_directory"] / runtime._phase_marker("update")).exists()


def test_existing_phase_pin_rejects_missing_ledger_without_http_claim(
    tmp_path: Path, composed: list[dict[str, Any]],
) -> None:
    environment, _, _, paths = _setup(tmp_path)
    assert runtime.build_ldap_server_update_candidate(environment) is not None
    phase_marker = paths["state_directory"] / runtime._phase_marker("update")
    original_pin = phase_marker.read_bytes()
    assert not any((paths["state_directory"] / name).exists() for name in runtime._phase_state("update"))
    paths["execution_database_file"].unlink()
    with pytest.raises(ValueError, match="^FortiPAM LDAP server update startup is unavailable.$"):
        runtime.build_ldap_server_update_candidate(environment)
    assert not paths["execution_database_file"].exists()
    assert phase_marker.read_bytes() == original_pin
    assert len(composed) == 1
