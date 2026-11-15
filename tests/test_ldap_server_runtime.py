"""Synthetic protected startup sources; no device or real credential access."""
from __future__ import annotations

import json
import os
import http.client
from pathlib import Path
from typing import Any

import pytest

from fortipam_mcp import ldap_server_runtime as runtime
from fortipam_mcp.ldap_server_http_transport import FortiPamLdapServerHttpTransport
from fortipam_mcp.secret_create_central_lab_provider import OwnerOnlyCentralLabSecretCreateEnvFileLoader
from fortipam_mcp.secret_metadata_http_transport import ENV_PREFIX
from v4_planning.material_provider import MaterialAccessDenied, MaterialBindingStatus
from v4_planning import AuthenticatedRequester
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from test_ldap_server_http_transport import PASSWORD, Peer, binding
from test_ldap_server_projection import SERIAL


def _setup(tmp_path: Path) -> tuple[dict[str, str], dict[str, Any], Path, dict[str, Path]]:
    tmp_path.chmod(0o700)
    state = tmp_path / "http-state"
    state.mkdir(mode=0o700)
    paths = {"state_directory": state,
        "execution_database_file": tmp_path / "execution.sqlite",
        "material_database_file": tmp_path / "material.sqlite",
        "execution_hmac_key_file": tmp_path / "execution.key",
        "material_hmac_key_file": tmp_path / "material.key",
        "authority_hmac_key_file": tmp_path / "authority.key",
        "credential_bindings_file": tmp_path / "central-binding.json",
        "secret_env_file": tmp_path / "central.env"}
    for name, value in (("authority", b"a"), ("execution", b"e"), ("material", b"m")):
        paths[name + "_hmac_key_file"].write_bytes(value * 32)
        paths[name + "_hmac_key_file"].chmod(0o600)
    paths["credential_bindings_file"].write_text(json.dumps({"schema_version": "credential-bindings-v1",
        "bindings": [{"id": "ldap-test-bind", "provider": "env-file", "variables":
            {"username": "TEST_LDAP_USERNAME", "password": "TEST_LDAP_PASSWORD"}}]}))
    selected = binding()
    paths["secret_env_file"].write_text(
        "TEST_LDAP_USERNAME=" + selected.username + "\nTEST_LDAP_PASSWORD=" + PASSWORD.decode() + "\n")
    for name in ("credential_bindings_file", "secret_env_file"):
        paths[name].chmod(0o600)
    manifest: dict[str, Any] = {"contract": runtime.CONTRACT,
        "binding": {name: getattr(selected, name) for name in runtime._SCHEMA["binding"]},
        "identity": {"environment_ref": "synthetic-environment", "scope_ref": "synthetic-lab-scope",
            "audience_ref": "synthetic-lab-audience", "allowed_requester_digest": "1" * 64,
            "allowed_transport_digest": "2" * 64, "expected_serial": SERIAL},
        "paths": {name: str(value) for name, value in paths.items()},
        "material": {"credential_binding_id": "ldap-test-bind"}}
    path = tmp_path / "startup.json"
    path.write_text(json.dumps(manifest))
    path.chmod(0o600)
    environment = {runtime.PREFIX + "ENABLED": "true", runtime.PREFIX + "STARTUP_MANIFEST_FILE": str(path),
        ENV_PREFIX + "ENABLED": "true", ENV_PREFIX + "BASE_URL": "https://pam.example",
        ENV_PREFIX + "API_TOKEN": "synthetic-api-token"}
    return environment, manifest, path, paths


def test_default_reads_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runtime, "_read", lambda *args: pytest.fail("Disabled source read"))
    assert runtime.build_ldap_server_candidate({}) is None


@pytest.mark.parametrize("values", [{"ENABLED": "TRUE"}, {"ENABLED": "1"},
    {"EXECUTION_ENABLED": "true"}, {"EXECUTION_ENABLED": "yes"}, {"ENABLED": True}])
def test_invalid_flags_fail_closed(values: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="^FortiPAM LDAP server startup is unavailable.$"):
        runtime.build_ldap_server_candidate({runtime.PREFIX + name: value for name, value in values.items()})


def test_startup_and_restart_never_extract_bind_material_or_connect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment, _, _, paths = _setup(tmp_path)
    monkeypatch.setattr(OwnerOnlyCentralLabSecretCreateEnvFileLoader, "load_secret_create_material_once",
        lambda *args: pytest.fail("Startup extracted bind material"))
    monkeypatch.setattr(FortiPamLdapServerHttpTransport, "_exchange",
        lambda *args, **kwargs: pytest.fail("Startup opened a device connection"))
    first = runtime.build_ldap_server_candidate(environment)
    assert first is not None
    assert runtime.build_ldap_server_candidate(environment) is not None
    environment[runtime.PREFIX + "EXECUTION_ENABLED"] = "true"
    assert runtime.build_ldap_server_candidate(environment) is not None
    assert paths["execution_database_file"].exists()
    assert paths["material_database_file"].exists()
    namespace = (paths["state_directory"] / "runtime.namespace.json").read_text()
    assert PASSWORD.decode() not in namespace and binding().username not in namespace


@pytest.mark.parametrize("fault", ["extra", "duplicate", "password", "nested", "version",
    "manifest_mode", "parent_mode", "symlink", "hardlink", "key_reuse", "key_length", "path_collision",
    "sidecar_collision", "state_collision", "binding", "requester", "transport", "scope", "serial",
    "missing_central", "central_mode", "url_userinfo", "relative_path"])
def test_invalid_startup_refuses_before_ledger_creation(tmp_path: Path, fault: str) -> None:
    environment, manifest, path, paths = _setup(tmp_path)
    raw = None
    if fault == "extra": manifest["unknown"] = "denied"
    elif fault == "duplicate": raw = json.dumps(manifest)[:-1] + ',"contract":"duplicate"}'
    elif fault == "password": manifest["binding"]["password"] = "synthetic-forbidden"
    elif fault == "nested": manifest["binding"]["username"] = {"password": "synthetic-forbidden"}
    elif fault == "version": manifest["contract"] += "-v2"
    elif fault == "manifest_mode": path.chmod(0o644)
    elif fault == "parent_mode": tmp_path.chmod(0o755)
    elif fault == "symlink":
        moved = tmp_path / "moved.key"
        paths["authority_hmac_key_file"].rename(moved)
        paths["authority_hmac_key_file"].symlink_to(moved)
    elif fault == "hardlink": os.link(paths["authority_hmac_key_file"], tmp_path / "alias.key")
    elif fault == "key_reuse": paths["material_hmac_key_file"].write_bytes(b"a" * 32)
    elif fault == "key_length": paths["authority_hmac_key_file"].write_bytes(b"a" * 33)
    elif fault == "path_collision": manifest["paths"]["execution_database_file"] = str(paths["authority_hmac_key_file"])
    elif fault == "sidecar_collision": manifest["paths"]["material_database_file"] = str(paths["execution_database_file"]) + "-wal"
    elif fault == "state_collision": manifest["paths"]["execution_database_file"] = str(paths["state_directory"] / "create.claim.json")
    elif fault == "binding": manifest["binding"]["server"] = "outside.invalid"
    elif fault == "requester": manifest["identity"]["allowed_requester_digest"] = "invalid"
    elif fault == "transport": manifest["identity"]["allowed_transport_digest"] = "invalid"
    elif fault == "scope": manifest["identity"]["scope_ref"] = "invalid ref"
    elif fault == "serial": manifest["identity"]["expected_serial"] = "invalid serial"
    elif fault == "missing_central": manifest["material"]["credential_binding_id"] = "absent"
    elif fault == "central_mode": paths["secret_env_file"].chmod(0o644)
    elif fault == "url_userinfo": environment[ENV_PREFIX + "BASE_URL"] = "https://username:forbidden@pam.example"
    elif fault == "relative_path": manifest["paths"]["secret_env_file"] = "central.env"
    path.write_text(raw if raw is not None else json.dumps(manifest))
    with pytest.raises(ValueError, match="^FortiPAM LDAP server startup is unavailable.$"):
        runtime.build_ldap_server_candidate(environment)
    assert not paths["execution_database_file"].exists()
    assert not paths["material_database_file"].exists()


def test_unknown_material_rejected_before_decode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    environment, manifest, path, _ = _setup(tmp_path)
    manifest["binding"]["password"] = "synthetic-forbidden"
    path.write_text(json.dumps(manifest))
    monkeypatch.setattr(runtime, "_decode", lambda *args: pytest.fail("Decoded forbidden input"))
    with pytest.raises(ValueError):
        runtime.build_ldap_server_candidate(environment)


@pytest.mark.parametrize("fault", ["duplicate", "escaped_duplicate", "invalid_escape", "invalid_utf8", "non_string"])
def test_invalid_manifest_values_rejected_before_decode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str,
) -> None:
    environment, manifest, path, paths = _setup(tmp_path)
    raw = json.dumps(manifest).encode()
    field = json.dumps(manifest["identity"]["scope_ref"]).encode()
    if fault == "duplicate":
        raw = raw.replace(b'"scope_ref": ' + field, b'"scope_ref": ' + field + b', "scope_ref": ' + field)
    elif fault == "escaped_duplicate":
        raw = raw.replace(b'"scope_ref": ' + field, b'"scope_ref": ' + field + b', "scope_\\u0072ef": ' + field)
    elif fault == "invalid_escape":
        raw = raw.replace(field, b'"synthetic-\\q-scope"')
    elif fault == "invalid_utf8":
        raw = raw.replace(field, b'"synthetic-\xff-scope"')
    else:
        raw = raw.replace(field, b'null')
    path.write_bytes(raw)
    monkeypatch.setattr(runtime, "_decode", lambda *args: pytest.fail("Decoded invalid manifest values"))
    with pytest.raises(ValueError, match="^FortiPAM LDAP server startup is unavailable.$"):
        runtime.build_ldap_server_candidate(environment)
    assert not paths["execution_database_file"].exists()
    assert not paths["material_database_file"].exists()


@pytest.mark.parametrize("changed", ["binding", "identity", "database", "key", "api_identity"])
def test_restart_cannot_rebind_fixed_namespace(tmp_path: Path, changed: str) -> None:
    environment, manifest, path, paths = _setup(tmp_path)
    assert runtime.build_ldap_server_candidate(environment) is not None
    if changed == "binding": manifest["binding"]["private_nonce"] = "9" * 64
    elif changed == "identity": manifest["identity"]["allowed_requester_digest"] = "9" * 64
    elif changed == "database": manifest["paths"]["execution_database_file"] = str(tmp_path / "new.sqlite")
    elif changed == "key": paths["execution_hmac_key_file"].write_bytes(b"z" * 32)
    elif changed == "api_identity": environment[ENV_PREFIX + "API_TOKEN"] = "another-synthetic-identity"
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        runtime.build_ldap_server_candidate(environment)
    assert not (tmp_path / "new.sqlite").exists()


def test_missing_namespace_cannot_adopt_old_claim(tmp_path: Path) -> None:
    environment, _, _, paths = _setup(tmp_path)
    (paths["state_directory"] / "create.claim.json").write_text("{}")
    (paths["state_directory"] / "create.claim.json").chmod(0o600)
    with pytest.raises(ValueError):
        runtime.build_ldap_server_candidate(environment)
    assert not (paths["state_directory"] / "runtime.namespace.json").exists()


def test_central_loader_pins_metadata_and_clears_output(tmp_path: Path) -> None:
    _, _, _, paths = _setup(tmp_path)
    loader = runtime._CentralLdapLoader(paths["credential_bindings_file"], paths["secret_env_file"], "ldap-test-bind")
    assert loader.validate_prebound() is MaterialBindingStatus.AVAILABLE
    username, password = loader.load_secret_create_material_once()
    try:
        assert username == binding().username.encode() and password == PASSWORD
    finally:
        username[:] = b"\0" * len(username)
        password[:] = b"\0" * len(password)
    paths["credential_bindings_file"].write_text(paths["credential_bindings_file"].read_text() + "\n")
    assert loader.validate_prebound() is MaterialBindingStatus.UNAVAILABLE
    with pytest.raises(MaterialAccessDenied):
        loader.load_secret_create_material_once()


def test_real_startup_action_authority_m4_material_and_http_join(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment, manifest, path, _ = _setup(tmp_path)
    principal = V4PlanningPrincipal(AuthenticatedRequester(
        subject_ref="synthetic-operator", principal_class="operator",
        identity_authority_ref="synthetic-identity-authority", subject_namespace="3" * 64), "2" * 64)
    manifest["identity"]["allowed_requester_digest"] = principal.requester.digest
    path.write_text(json.dumps(manifest))
    environment[runtime.PREFIX + "EXECUTION_ENABLED"] = "true"
    peer = Peer()
    monkeypatch.setattr(http.client, "HTTPSConnection", peer.connection)
    buffers: list[tuple[bytearray, bytearray]] = []
    load = OwnerOnlyCentralLabSecretCreateEnvFileLoader.load_secret_create_material_once

    def tracked_load(self: OwnerOnlyCentralLabSecretCreateEnvFileLoader) -> tuple[bytearray, bytearray]:
        result = load(self)
        buffers.append(result)
        return result

    monkeypatch.setattr(OwnerOnlyCentralLabSecretCreateEnvFileLoader, "load_secret_create_material_once", tracked_load)
    action = runtime.build_ldap_server_candidate(environment)
    assert action is not None and buffers == [] and peer.connections == []
    preview = action.preview(principal)
    authorization = action.authorize(str(preview["preview_ref"]), principal)
    assert buffers == [] and peer.binds == peer.posts == 0
    result = action.execute(str(authorization["authorization_ref"]), principal)
    assert result["outcome"] == "succeeded" and peer.binds == peer.posts == 1
    assert len(buffers) == 1 and not any(any(part) for part in buffers[0])
    assert peer.row is not None
    rendered = json.dumps([preview, authorization, result])
    for value in (binding().username, binding().dn, binding().server, PASSWORD.decode(), "synthetic-api-token"):
        assert value not in rendered
    calls = len(peer.connections)
    replay = action.execute(str(authorization["authorization_ref"]), principal)
    assert replay["idempotent_replay"] is True and len(peer.connections) == calls and len(buffers) == 1
    restarted = runtime.build_ldap_server_candidate(environment)
    assert restarted is not None
    with pytest.raises(RuntimeError):
        restarted.preview(principal)
    with pytest.raises(RuntimeError):
        restarted.execute(str(authorization["authorization_ref"]), principal)
    assert len(peer.connections) == calls and len(buffers) == 1 and peer.posts == 1
