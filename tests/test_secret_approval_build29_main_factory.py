from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import fortipam_mcp.secret_approval_build29_main_factory as module
from fortipam_mcp.approval_and_observe_execution_mcp_action import ProtectedApprovalAndObserveMcpAction
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.secret_approval_build29_main_factory import (
    PREFIX, RUNTIME_CONTRACT, RUNTIME_KEYS, RUNTIME_VERSION,
    SecretApprovalBuild29MainFactoryError, build_secret_approval_build29_main_context,
)
from fortipam_mcp.secret_approval_build29_metadata_reader import (
    SecretApprovalBuild29ProfileReader, SecretApprovalBuild29ProjectionReader,
)
from fortipam_mcp.secret_approval_build29_projection_source import (
    SOURCE_CONTRACT, SOURCE_VERSION, FortiPamSecretApprovalBuild29ProjectionSource,
)
from fortipam_mcp.secret_approval_build29_runtime_provider import OwnerOnlySecretApprovalBuild29UsernameSource
from fortipam_mcp.v4_runtime_host import V4PlanHostComponents
from test_secret_approval_build29_projection_source import _BINDING, _REQUESTER, _draft
from v4_planning import M4AdapterDenied
from v4_planning.approval import ApprovalReceiptAuthenticator


def _write(path: Path, raw: bytes) -> None:
    path.write_bytes(raw)
    path.chmod(0o600)


def _fixture(tmp_path: Path) -> dict[str, Any]:
    root = tmp_path.resolve()
    runtime, binding, credentials = root / "runtime.json", root / "binding.json", root / "central.env"
    payload = {
        "contract": SOURCE_CONTRACT, "version": SOURCE_VERSION,
        "requester_digest": _REQUESTER.digest, "environment_ref": _draft().environment_ref,
        "scope_ref": _draft().scope_ref, "approval_profile_object_ref": _BINDING.approval_profile_object_ref,
        "approval_profile_ref": _BINDING.approval_profile_ref, "approval_profile_name": _BINDING.approval_profile_name,
        "secret_approval_object_ref": _BINDING.secret_approval_object_ref,
        "folder_path": _BINDING.folder_path, "secret_name": _BINDING.secret_name, "secret_id": _BINDING.secret_id,
    }
    settings = {
        "contract": RUNTIME_CONTRACT, "version": RUNTIME_VERSION,
        "source_plan_ref": "unit-source-plan-ref01", "approval_receipt_ref": "unit-receipt-ref01",
        "authorization_ref": "unit-authorization-ref01", "environment_ref": payload["environment_ref"],
        "scope_ref": payload["scope_ref"], "requester_digest": payload["requester_digest"],
        "folder_id": 17, "serial": "FPAVUNIT01", "owner_name": "unit-owner", "web_url": "https://unit-web.example.test/",
        "username_file": str(root / "account.username"), "claim_directory": str(root / "claims"),
        "witness_key_file": str(root / "witness.key"), "known_hosts_file": str(root / "known_hosts"), "ssh_port": 22,
        "qualification_file": str(root / "qualification.json"), "qualification_authority_ref": "unit-source-authority-ref01",
        "qualification_key_file": str(root / "qualification.key"), "evidence_digest": "e" * 64,
        "execution_db": str(root / "execution.sqlite3"), "execution_key_file": str(root / "execution.key"),
        "secret_env_file": str(credentials), "owner_username_variable": "UNIT_OWNER_NAME",
        "owner_password_variable": "UNIT_OWNER_PASSWORD", "api_token_variable": "UNIT_API_TOKEN",
        "base_url": "https://unit.example.test", "ca_file": None,
        "approval_receipt_key_file": str(root / "receipt.key"),
        "approver_authority_socket": str(root / "approver.sock"),
        "approver_authority_ref": "unit-approver-authority-ref01",
    }
    assert set(settings) == RUNTIME_KEYS
    _write(runtime, json.dumps(settings).encode())
    _write(binding, json.dumps(payload).encode())
    _write(credentials, b"UNIT_API_TOKEN=unit-api-token\nUNIT_OWNER_NAME=unit-owner\nUNIT_OWNER_PASSWORD=unit-owner-password\n")
    _write(Path(settings["approval_receipt_key_file"]), b"i" * 32)
    return {"runtime": runtime, "binding": binding, "settings": settings, "payload": payload,
            "environment": {PREFIX + "RUNTIME_FILE": str(runtime)}}


def _build(fixture: dict[str, Any], *, enabled: bool = False) -> Any:
    return build_secret_approval_build29_main_context(fixture["environment"], fixture["binding"], execution_enabled=enabled)


def _components(context: Any, *, authenticator: Any = None) -> V4PlanHostComponents:
    source = FortiPamSecretApprovalBuild29ProjectionSource(
        context.secret_transport, context.approval_profile_transport, context.binding_resolver, contract_registered=True,
    )
    pair = context.planning_authorities() if context._enabled else (ApprovalReceiptAuthenticator(b"i" * 32), None)
    selected_authenticator = authenticator or pair[0]
    gate = SimpleNamespace(_receipt_authenticator=selected_authenticator, _approver_authorizer=pair[1])
    return V4PlanHostComponents(
        plan_services=SimpleNamespace(_workflow=SimpleNamespace(_approval_gate=gate)),
        confirmation_service=object(), approval_and_observe_projection_source=source,
        _secret_approval_planning_reader=object(),
        _secret_approval_receipt_authenticator=selected_authenticator,
        _secret_approval_approver_authority_ref="unit-approver-authority-ref01", _clock=lambda: 1000,
    )


def test_readonly_context_has_typed_getters_and_reads_only_the_selected_api_pair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    buffers: list[bytearray] = []
    variable_pairs: list[tuple[bytes, bytes]] = []
    parse = module._parse_prebound_secret_env
    def selected(content: bytearray, first: bytes, second: bytes, *, extract_values: bool) -> Any:
        buffers.append(content)
        variable_pairs.append((first, second))
        pair = parse(content, first, second, extract_values=extract_values)
        buffers.extend(pair)
        return pair
    monkeypatch.setattr(module, "_parse_prebound_secret_env", selected)
    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("Unexpected readonly dependency read")
    monkeypatch.setattr(module, "SecretApprovalBuild29PrivateSources", forbidden)
    monkeypatch.setattr(module, "TargetSshTransportConfig", forbidden)
    monkeypatch.setattr(module, "PersistentM4ExecutionStateStore", forbidden)
    monkeypatch.setattr(module.OwnerOnlySecretApprovalBuild29UsernameSource, "read_span", forbidden)
    monkeypatch.setattr(module.OwnerSessionMetadataTransport, "authenticated", forbidden)
    context = _build(fixture)
    assert type(context.secret_transport) is SecretApprovalBuild29ProjectionReader
    assert type(context.approval_profile_transport) is SecretApprovalBuild29ProfileReader
    assert context.binding_resolver.resolve(_draft(), _REQUESTER) == _BINDING
    assert variable_pairs == [(b"UNIT_API_TOKEN", b"UNIT_OWNER_NAME")]
    assert buffers and all(not any(raw) for raw in buffers)
    assert not Path(fixture["settings"]["execution_db"]).exists()
    for value in ("unit-api-token", "unit-owner-password", _BINDING.secret_name):
        assert value not in repr(context)
    with pytest.raises(SecretApprovalBuild29MainFactoryError):
        context.execution_factory(_components(context))


@pytest.mark.parametrize("change", ["unknown", "missing", "bool_id", "string_port", "relative", "duplicate_path", "variable_alias", "wrong_contract", "wrong_version"])
def test_runtime_contract_rejects_unknown_missing_malformed_and_aliased_members(
    tmp_path: Path, change: str,
) -> None:
    fixture = _fixture(tmp_path)
    settings = fixture["settings"]
    if change == "unknown":
        settings["password"] = "private-unit-sentinel"
    elif change == "missing":
        del settings["qualification_file"]
    elif change == "bool_id":
        settings["folder_id"] = True
    elif change == "string_port":
        settings["ssh_port"] = "22"
    elif change == "relative":
        settings["username_file"] = "relative.username"
    elif change == "duplicate_path":
        settings["execution_key_file"] = settings["qualification_key_file"]
    elif change == "variable_alias":
        settings["api_token_variable"] = settings["owner_username_variable"]
    else:
        settings["contract" if change == "wrong_contract" else "version"] = "wrong-unit-version"
    _write(fixture["runtime"], json.dumps(settings).encode())
    with pytest.raises(SecretApprovalBuild29MainFactoryError) as failure:
        _build(fixture)
    assert "private-unit-sentinel" not in str(failure.value) and failure.value.__cause__ is None


@pytest.mark.parametrize("change", ["duplicate", "permissions", "symlink", "parent_symlink"])
def test_runtime_file_is_exact_unique_owner_600_and_nofollow(tmp_path: Path, change: str) -> None:
    fixture = _fixture(tmp_path)
    if change == "duplicate":
        content = fixture["runtime"].read_bytes()
        _write(fixture["runtime"], b'{"contract":' + json.dumps(RUNTIME_CONTRACT).encode() + b"," + content[1:])
    elif change == "permissions":
        fixture["runtime"].chmod(0o644)
    elif change == "symlink":
        alias = tmp_path / "alias.json"
        alias.symlink_to(fixture["runtime"])
        fixture["environment"][PREFIX + "RUNTIME_FILE"] = str(alias)
    else:
        alias = tmp_path / "alias-directory"
        alias.symlink_to(tmp_path, target_is_directory=True)
        fixture["environment"][PREFIX + "RUNTIME_FILE"] = str(alias / "runtime.json")
    with pytest.raises(SecretApprovalBuild29MainFactoryError):
        _build(fixture)


@pytest.mark.parametrize("field", ["requester_digest", "environment_ref", "scope_ref", "contract", "version"])
def test_runtime_and_binding_must_match_actor_scope_and_new_source(tmp_path: Path, field: str) -> None:
    fixture = _fixture(tmp_path)
    fixture["payload"][field] = "f" * 64 if field == "requester_digest" else "other-unit-reference"
    _write(fixture["binding"], json.dumps(fixture["payload"]).encode())
    with pytest.raises(SecretApprovalBuild29MainFactoryError):
        _build(fixture)


def test_owner_name_mismatch_erases_selected_credentials(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = _fixture(tmp_path)
    fixture["settings"]["owner_name"] = "another-unit-owner"
    _write(fixture["runtime"], json.dumps(fixture["settings"]).encode())
    captured: list[bytearray] = []
    original = module._parse_prebound_secret_env
    def selected(*args: Any, **kwargs: Any) -> Any:
        pair = original(*args, **kwargs)
        captured.extend(pair)
        return pair
    monkeypatch.setattr(module, "_parse_prebound_secret_env", selected)
    with pytest.raises(SecretApprovalBuild29MainFactoryError):
        _build(fixture)
    assert captured and all(not any(raw) for raw in captured)


def _private_dependencies(fixture: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    settings = fixture["settings"]
    for name, value in (("known_hosts_file", b"unit-known-host-entry\n"), ("witness_key_file", b"w" * 32),
                        ("qualification_key_file", b"q" * 32), ("execution_key_file", b"x" * 32)):
        _write(Path(settings[name]), value)
    calls: dict[str, Any] = {"sources": 0, "producer": 0, "produce": 0, "closed": 0}
    class Sources:
        def __init__(self, owner: Any, ssh: Any, **kwargs: Any) -> None:
            calls["sources"] += 1
            calls["owner"], calls["ssh"], calls["source_kwargs"] = owner, ssh, kwargs
            self.key = bytearray(kwargs["witness_key"])
        def close(self) -> None:
            calls["closed"] += 1
    class Producer:
        def __init__(self, owner: Any, sources: Any, **kwargs: Any) -> None:
            calls["producer"] += 1
            calls["producer_kwargs"] = kwargs
        def produce(self, binding: Any) -> Any:
            calls["produce"] += 1
            raise AssertionError("No material production during factory construction")
    monkeypatch.setattr(module, "SecretApprovalBuild29PrivateSources", Sources)
    monkeypatch.setattr(module, "SecretApprovalBuild29RuntimeProducer", Producer)
    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("No account material or network in main factory")
    monkeypatch.setattr(OwnerOnlySecretApprovalBuild29UsernameSource, "read_span", forbidden)
    monkeypatch.setattr(module.OwnerSessionMetadataTransport, "authenticated", forbidden)
    return calls


def test_execution_factory_composes_real_fixed_dependencies_without_producing_material(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    context = _build(fixture, enabled=True)
    calls = _private_dependencies(fixture, monkeypatch)
    components = _components(context)
    action = context.execution_factory(components)
    assert type(action) is ProtectedApprovalAndObserveMcpAction
    assert context.execution_factory(components) is action
    assert calls["sources"] == calls["producer"] == 1 and calls["produce"] == 0
    assert calls["ssh"].host == "unit.example.test" and calls["ssh"].username == "unit-owner"
    assert calls["source_kwargs"]["expected_secret_id"] == _BINDING.secret_id
    assert calls["producer_kwargs"]["binding"] == _BINDING
    assert type(calls["producer_kwargs"]["username_source"]) is OwnerOnlySecretApprovalBuild29UsernameSource
    factory = action._coordinator._resolver._runner_factory
    assert factory._planning is components._secret_approval_planning_reader
    assert factory._authority_ref == "unit-approver-authority-ref01"
    assert type(factory._store) is PersistentM4ExecutionStateStore
    assert factory._store._key == b"x" * 32
    factory._store.verify_ready()
    # No manifest is issued, opened or interpreted by construction.
    assert not Path(fixture["settings"]["qualification_file"]).exists()
    with pytest.raises(M4AdapterDenied):
        factory._qualifier.verify(binding_digest="b" * 64, plan_digest="c" * 64, now_epoch=1000)
    with pytest.raises(SecretApprovalBuild29MainFactoryError):
        context.execution_factory(_components(context))


@pytest.mark.parametrize("missing", ["source", "old_source", "planning", "authenticator", "authority", "foreign_getter"])
def test_factory_requires_exact_build29_components_before_private_dependencies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, missing: str,
) -> None:
    fixture = _fixture(tmp_path)
    context = _build(fixture, enabled=True)
    calls = _private_dependencies(fixture, monkeypatch)
    components = _components(context)
    if missing in {"source", "old_source"}:
        object.__setattr__(components, "approval_and_observe_projection_source", None if missing == "source" else object())
    elif missing == "foreign_getter":
        components.approval_and_observe_projection_source._secret_transport = object()
    else:
        field = {"planning": "_secret_approval_planning_reader", "authenticator": "_secret_approval_receipt_authenticator",
                 "authority": "_secret_approval_approver_authority_ref"}[missing]
        object.__setattr__(components, field, None)
    with pytest.raises(SecretApprovalBuild29MainFactoryError):
        context.execution_factory(components)
    assert calls["sources"] == calls["producer"] == calls["produce"] == 0


@pytest.mark.parametrize("shared", ["intent", "witness", "execution"])
def test_qualification_key_must_be_independent_of_intent_and_private_source_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shared: str,
) -> None:
    fixture = _fixture(tmp_path)
    context = _build(fixture, enabled=True)
    calls = _private_dependencies(fixture, monkeypatch)
    _write(Path(fixture["settings"]["qualification_key_file"]), {"intent": b"i", "witness": b"w", "execution": b"x"}[shared] * 32)
    with pytest.raises(SecretApprovalBuild29MainFactoryError):
        context.execution_factory(_components(context))
    assert calls["sources"] == calls["producer"] == calls["produce"] == 0


def test_remote_authenticator_without_key_independence_proof_is_not_qualified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    context = _build(fixture, enabled=True)
    calls = _private_dependencies(fixture, monkeypatch)
    class RemoteAuthenticator:
        authority_ref = "unit-remote-authority-ref01"
        def uses_key_material(self, _key: bytes) -> bool:
            return False
    with pytest.raises(SecretApprovalBuild29MainFactoryError):
        context.execution_factory(_components(context, authenticator=RemoteAuthenticator()))
    assert calls["sources"] == calls["producer"] == 0


def test_main_restart_reuses_and_validates_its_existing_ledger_without_reset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    calls = _private_dependencies(fixture, monkeypatch)
    first = _build(fixture, enabled=True)
    first_action = first.execution_factory(_components(first))
    store = first_action._coordinator._resolver._runner_factory._store
    store.claim(plan_ref="unit-plan-ref01", requester_digest="a" * 64, idempotency_digest="b" * 64,
                context_digest="c" * 64, authorization_digest="d" * 64)
    second = _build(fixture, enabled=True)
    second_store = second.execution_factory(_components(second))._coordinator._resolver._runner_factory._store
    claim = second_store.claim(plan_ref="unit-plan-ref01", requester_digest="a" * 64, idempotency_digest="b" * 64,
                               context_digest="c" * 64, authorization_digest="d" * 64)
    assert claim.state.value == "in_progress"
    assert calls["produce"] == 0


def test_planning_authorities_are_deferred_cached_and_erase_binary_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    key_path = Path(fixture["settings"]["approval_receipt_key_file"])
    raw = bytearray(range(32))
    _write(key_path, bytes(raw))
    original = module._read_private_buffer
    reads: list[bytearray] = []
    def selected(path: Path, limit: int) -> bytearray:
        result = original(path, limit)
        if path == key_path:
            reads.append(result)
        return result
    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("No UDS connection during authority construction")
    monkeypatch.setattr(module, "_read_private_buffer", selected)
    monkeypatch.setattr(module.UnixApproverAuthorizationClient, "_post", forbidden)
    readonly = _build(fixture)
    with pytest.raises(SecretApprovalBuild29MainFactoryError):
        readonly.planning_authorities()
    assert not reads
    context = _build(fixture, enabled=True)
    assert not reads
    pair = context.planning_authorities()
    assert type(pair[0]) is ApprovalReceiptAuthenticator
    assert type(pair[1]) is module.UnixApproverAuthorizationClient
    assert pair[0].uses_key_material(bytes(raw))
    assert pair[1].authority_ref == fixture["settings"]["approver_authority_ref"]
    assert context.planning_authorities() is pair
    assert len(reads) == 1 and not any(reads[0])
    assert bytes(raw).decode("latin1") not in repr(context)


@pytest.mark.parametrize("change", ["missing", "short", "permissions", "symlink"])
def test_planning_authority_key_failure_is_closed_single_attempt_and_erases_buffer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str,
) -> None:
    fixture = _fixture(tmp_path)
    context = _build(fixture, enabled=True)
    key_path = Path(fixture["settings"]["approval_receipt_key_file"])
    if change == "missing":
        key_path.unlink()
    elif change == "short":
        _write(key_path, b"private-key-sentinel")
    elif change == "permissions":
        key_path.chmod(0o644)
    else:
        replacement = tmp_path / "replacement.key"
        _write(replacement, b"i" * 32)
        key_path.unlink()
        key_path.symlink_to(replacement)
    original = module._read_private_buffer
    reads: list[bytearray] = []
    attempts: list[Path] = []
    def selected(path: Path, limit: int) -> bytearray:
        attempts.append(path)
        result = original(path, limit)
        reads.append(result)
        return result
    monkeypatch.setattr(module, "_read_private_buffer", selected)
    for _ in range(2):
        with pytest.raises(SecretApprovalBuild29MainFactoryError) as failure:
            context.planning_authorities()
        assert "private-key-sentinel" not in str(failure.value)
        assert failure.value.__cause__ is None
    assert attempts == [key_path]
    assert all(not any(raw) for raw in reads)


@pytest.mark.parametrize("field", ["approval_receipt_key_file", "approver_authority_socket", "approver_authority_ref"])
def test_new_planning_authority_settings_are_required(tmp_path: Path, field: str) -> None:
    fixture = _fixture(tmp_path)
    del fixture["settings"][field]
    _write(fixture["runtime"], json.dumps(fixture["settings"]).encode())
    with pytest.raises(SecretApprovalBuild29MainFactoryError):
        _build(fixture)


@pytest.mark.parametrize("injection", ["uncached", "receipt", "client", "gate_receipt", "authority_ref"])
def test_execution_rejects_foreign_or_uncached_authority_pair_before_private_dependencies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, injection: str,
) -> None:
    fixture = _fixture(tmp_path)
    context = _build(fixture, enabled=True)
    calls = _private_dependencies(fixture, monkeypatch)
    components = _components(context)
    gate = components.plan_services._workflow._approval_gate
    if injection == "uncached":
        object.__setattr__(context, "_planning_authorities", None)
    elif injection == "receipt":
        object.__setattr__(components, "_secret_approval_receipt_authenticator", ApprovalReceiptAuthenticator(b"i" * 32))
    elif injection == "client":
        gate._approver_authorizer = module.UnixApproverAuthorizationClient(
            module.UnixApproverAuthorizationClientSettings(
                Path(fixture["settings"]["approver_authority_socket"]), fixture["settings"]["approver_authority_ref"],
            )
        )
    elif injection == "gate_receipt":
        gate._receipt_authenticator = ApprovalReceiptAuthenticator(b"i" * 32)
    else:
        object.__setattr__(components, "_secret_approval_approver_authority_ref", "foreign-approver-authority-ref01")
    with pytest.raises(SecretApprovalBuild29MainFactoryError):
        context.execution_factory(components)
    assert calls["sources"] == calls["producer"] == calls["produce"] == 0


def _linux_fixture(tmp_path: Path) -> dict[str, Any]:
    fixture = _fixture(tmp_path)
    settings = fixture["settings"]
    settings["contract"] = module.LINUX_RUNTIME_CONTRACT
    settings["version"] = module.LINUX_RUNTIME_VERSION
    settings["owner_api_env_file"] = settings.pop("secret_env_file")
    settings.pop("web_url")
    settings.pop("username_file")
    settings.update(expected_folder_acl_digest="a" * 64, linux_target_name="unit-linux-target", linux_target_ipv4_address="192.0.2.8",
                    linux_username_env_file=str(tmp_path.resolve() / "original-linux.env"),
                    linux_username_variable="UNIT_LINUX_USERNAME", ssh_host="original-ssh.example.test")
    assert set(settings) == module.LINUX_RUNTIME_KEYS
    _write(fixture["runtime"], json.dumps(settings).encode())
    return fixture


def test_linux_main_has_explicit_target_and_independent_env_without_material_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _linux_fixture(tmp_path)
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("No Linux username read during composition")
    monkeypatch.setattr(module.OwnerOnlySecretApprovalBuild29EnvUsernameSource, "read_span", forbidden)
    context = _build(fixture, enabled=True)
    assert context.secret_transport._transport._linux_target_name == "unit-linux-target"
    calls = _private_dependencies(fixture, monkeypatch)
    action = context.execution_factory(_components(context))
    assert calls["ssh"].host == "original-ssh.example.test"
    assert calls["ssh"].known_hosts_file == Path(fixture["settings"]["known_hosts_file"])
    assert calls["source_kwargs"]["web_url"] is None
    assert calls["source_kwargs"]["linux_target_name"] == "unit-linux-target"
    assert calls["source_kwargs"]["expected_ssh_host"] == "original-ssh.example.test"
    assert calls["producer_kwargs"]["linux_target_name"] == "unit-linux-target"
    assert calls["producer_kwargs"]["linux_target_ipv4_address"] == "192.0.2.8"
    assert calls["producer_kwargs"]["expected_folder_acl_digest"] == "a" * 64
    assert type(calls["producer_kwargs"]["username_source"]) is module.OwnerOnlySecretApprovalBuild29EnvUsernameSource
    qualifier = action._coordinator._resolver._runner_factory._qualifier
    assert type(qualifier) is module.OwnerOnlySecretApprovalBuild29LinuxQualificationVerifier
    assert not Path(fixture["settings"]["linux_username_env_file"]).exists()
    assert not Path(fixture["settings"]["qualification_file"]).exists()


@pytest.mark.parametrize("change", ["old_contract", "web_url", "username_file", "missing_target", "missing_ip",
                                     "bad_ip", "bad_target", "bad_ssh", "same_env", "bad_variable"])
def test_linux_main_rejects_mixed_scope_missing_binding_and_aliased_sources(tmp_path: Path, change: str) -> None:
    fixture = _linux_fixture(tmp_path)
    settings = fixture["settings"]
    if change == "old_contract":
        settings["contract"] = RUNTIME_CONTRACT
    elif change in {"web_url", "username_file"}:
        settings[change] = "unaccepted-value"
    elif change == "missing_target":
        del settings["linux_target_name"]
    elif change == "missing_ip":
        del settings["linux_target_ipv4_address"]
    elif change == "bad_ip":
        settings["linux_target_ipv4_address"] = "not-an-ip"
    elif change == "bad_target":
        settings["linux_target_name"] = "target/other"
    elif change == "bad_ssh":
        settings["ssh_host"] = "host/endpoint"
    elif change == "same_env":
        settings["linux_username_env_file"] = settings["owner_api_env_file"]
    else:
        settings["linux_username_variable"] = "USER;OTHER"
    _write(fixture["runtime"], json.dumps(settings).encode())
    with pytest.raises(SecretApprovalBuild29MainFactoryError):
        _build(fixture)


def test_remote_linux_main_selects_fixed_reference_source_without_read_or_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _linux_fixture(tmp_path)
    settings = fixture["settings"]
    settings["contract"] = module.LINUX_REMOTE_RUNTIME_CONTRACT
    del settings["linux_username_env_file"], settings["linux_username_variable"]
    settings["linux_username_reference_file"] = str(tmp_path.resolve() / "unread-reference.json")
    assert set(settings) == module.LINUX_REMOTE_RUNTIME_KEYS
    _write(fixture["runtime"], json.dumps(settings).encode())
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("Remote source is deferred to private field dispatch")
    monkeypatch.setattr(module.OwnerOnlySecretApprovalBuild29RemoteUsernameSource, "read_span", forbidden)
    context = _build(fixture, enabled=True)
    calls = _private_dependencies(fixture, monkeypatch)
    context.execution_factory(_components(context))
    assert type(calls["producer_kwargs"]["username_source"]) is module.OwnerOnlySecretApprovalBuild29RemoteUsernameSource
    assert not Path(settings["linux_username_reference_file"]).exists()
    assert calls["producer_kwargs"]["linux_target_name"] == settings["linux_target_name"]


@pytest.mark.parametrize("value", [None, "not-a-digest", True])
def test_linux_runtime_requires_protected_full_acl_digest(tmp_path: Path, value: Any) -> None:
    fixture = _linux_fixture(tmp_path)
    if value is None:
        del fixture["settings"]["expected_folder_acl_digest"]
    else:
        fixture["settings"]["expected_folder_acl_digest"] = value
    _write(fixture["runtime"], json.dumps(fixture["settings"]).encode())
    with pytest.raises(SecretApprovalBuild29MainFactoryError):
        _build(fixture)
