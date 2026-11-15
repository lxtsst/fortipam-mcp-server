"""Real producer assembly with pure scoped sources and synthetic GET responses."""

from dataclasses import replace
import json
from pathlib import Path
from typing import Any, cast

import pytest

import fortipam_mcp.secret_approval_build29_private_sources as source_module
import fortipam_mcp.secret_approval_build29_runtime_provider as module
from fortipam_mcp.approval_and_observe_projection_source import ApprovalAndObserveBinding
from fortipam_mcp.secret_approval_build29_runtime_provider import (
    OwnerOnlySecretApprovalBuild29UsernameSource,
    SecretApprovalBuild29RuntimeProducer,
    SecretApprovalBuild29RuntimeProviderError,
)
from test_secret_approval_build29_http_transport import (
    _FOLDER, _NAME, _SERIAL, _Owner, _Response, _mutable_owner, _mutation_schema,
)
from test_secret_approval_build29_metadata_reader import _PROFILE, _profile_payload


_BINDING = ApprovalAndObserveBinding(
    "approval-profile-object-unit01", "approval-profile-ref-unit01", _PROFILE,
    "secret-approval-object-unit01", _FOLDER, _NAME, 24,
)


class _Client:
    def __init__(self, secret: bytes) -> None:
        self.secret = secret
        self.calls: list[tuple[str, str]] = []

    def stream(self, method: str, path: str, **kwargs: Any) -> _Response:
        assert method == "GET"
        self.calls.append((method, path))
        if path == "/api/v2/cmdb/secret/database/24":
            return _Response(self.secret)
        assert path == "/api/v2/cmdb/secret/approval-profile/" + _PROFILE
        return _Response(json.dumps(_profile_payload()).encode())


class _Sources:
    def __init__(self, owner: _Owner) -> None:
        self._owner = owner
        self._serial = _SERIAL
        self._linux_target_name: str | None = None
        self._identity: dict[str, Any] = {"id": 24, "name": _NAME, "folder": 17}
        self._folder = _FOLDER
        self._path = "/api/v2/cmdb/secret/database/24"
        self.schema_calls = self.native_calls = 0
        self._closed = False

    def _check_binding(self) -> None:
        assert not self._closed
        assert self._owner._bound_secret_name == self._identity["name"]

    def approval_schema(self) -> dict[str, object]:
        self.schema_calls += 1
        assert self._owner._client is not None
        return _mutation_schema()

    def native_preservation_digest(self, values: tuple[str, str, str, str]) -> str:
        self.native_calls += 1
        assert self._owner._client is not None
        assert len(values) == 4
        return "b" * 64

    def close(self) -> None:
        self._closed = True


class _ScopeOwner(_Owner):
    def __init__(self, payload: dict[str, object]) -> None:
        super().__init__(payload)
        self.acl_permitted = True
        self.acl_calls = 0

    def _verify_collector_folder_acl(self, folder_id: int, owner_name: str) -> bool:
        self.acl_calls += 1
        assert self._client is not None
        assert folder_id == 17 and owner_name == self._owner_name
        return self.acl_permitted


def _context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, bypass: str = "disable", enabled: bool = True,
) -> tuple[SecretApprovalBuild29RuntimeProducer, _ScopeOwner, _Sources, _Client]:
    monkeypatch.setattr(source_module, "SecretApprovalBuild29PrivateSources", _Sources)
    owner = _ScopeOwner(json.loads(_mutable_owner(bypass=bypass).client.response.raw))
    client = _Client(owner.client.response.raw)
    owner.client = cast(Any, client)
    sources = _Sources(owner)
    claims = tmp_path / "claims"
    claims.mkdir(mode=0o700)
    producer = SecretApprovalBuild29RuntimeProducer(
        owner, cast(Any, sources), binding=_BINDING, expected_folder_id=17, expected_serial=_SERIAL,
        web_url="https://unit.example.test/", claim_directory=claims,
        username_source=OwnerOnlySecretApprovalBuild29UsernameSource(tmp_path / "unread-username.bin"),
        execution_enabled=enabled,
    )
    return producer, owner, sources, client


def test_constructor_and_default_disabled_production_do_no_private_io(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    producer, owner, sources, client = _context(tmp_path, monkeypatch, enabled=False)
    assert owner.authentications == sources.schema_calls == sources.native_calls == 0
    assert not client.calls
    with pytest.raises(SecretApprovalBuild29RuntimeProviderError):
        producer.produce(_BINDING)
    assert owner.authentications == sources.schema_calls == sources.native_calls == 0
    assert not client.calls


def test_real_transition_assembly_is_once_logged_out_and_does_not_read_username(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: object, **kwargs: object) -> object:
        raise AssertionError("Username material is not a production input read.")

    monkeypatch.setattr(OwnerOnlySecretApprovalBuild29UsernameSource, "read_span", forbidden)
    producer, owner, sources, client = _context(tmp_path, monkeypatch)
    transition = producer.produce(_BINDING)
    assert transition.baseline.approval_values == ("disable", "disable", "disable", "")
    assert transition.expected_private_state.approval_values == ("enable", "disable", "disable", _PROFILE)
    assert len(transition.expected_binding_digest) == 64
    assert transition.baseline.native_digest == transition.expected_private_state.native_digest
    assert (sources.schema_calls, sources.native_calls, owner.authentications) == (1, 1, 2)
    assert owner.acl_calls == 2
    assert owner._client is None and owner.logout_verified
    assert [method for method, _ in client.calls] == ["GET", "GET"]
    assert not tuple((tmp_path / "claims").iterdir())
    with pytest.raises(SecretApprovalBuild29RuntimeProviderError):
        producer.produce(_BINDING)
    assert (sources.schema_calls, sources.native_calls, owner.authentications) == (1, 1, 2)
    transition.transport.close()
    sources.close()
    assert transition.transport._closed and sources._closed


def test_wrong_approval_binding_before_io_does_not_consume_the_right_subject(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    producer, owner, sources, client = _context(tmp_path, monkeypatch)
    with pytest.raises(SecretApprovalBuild29RuntimeProviderError):
        producer.produce(replace(_BINDING, secret_id=25))
    assert owner.authentications == sources.schema_calls == sources.native_calls == 0
    assert not client.calls
    transition = producer.produce(_BINDING)
    transition.transport.close()


@pytest.mark.parametrize("attribute", ["_owner", "_serial", "_identity", "_folder", "_path"])
def test_foreign_source_association_rejected_by_constructor_and_before_produce_io(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, attribute: str,
) -> None:
    producer, owner, sources, client = _context(tmp_path, monkeypatch)
    foreign: dict[str, Any] = {
        "_owner": _mutable_owner(), "_serial": "FPAVOTHER0001",
        "_identity": {"id": 25, "name": _NAME, "folder": 17},
        "_folder": "Public/other", "_path": "/api/v2/cmdb/secret/database/25",
    }
    setattr(sources, attribute, foreign[attribute])
    with pytest.raises(SecretApprovalBuild29RuntimeProviderError):
        SecretApprovalBuild29RuntimeProducer(
            owner, cast(Any, sources), binding=_BINDING, expected_folder_id=17, expected_serial=_SERIAL,
            web_url="https://unit.example.test/", claim_directory=tmp_path / "claims",
            username_source=OwnerOnlySecretApprovalBuild29UsernameSource(tmp_path / "unread-username.bin"),
            execution_enabled=True,
        )
    with pytest.raises(SecretApprovalBuild29RuntimeProviderError):
        producer.produce(_BINDING)
    assert owner.authentications == sources.schema_calls == sources.native_calls == 0
    assert not client.calls


def test_source_drift_after_production_is_refused_before_native_callback_io(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    producer, owner, sources, _ = _context(tmp_path, monkeypatch)
    transition = producer.produce(_BINDING)
    assert transition.transport._mutation is not None
    sources._serial = "FPAVOTHER0001"
    with pytest.raises(ValueError):
        transition.transport._mutation.native_preservation_digest(transition.baseline.approval_values)
    assert sources.native_calls == 1 and owner.authentications == 2
    transition.transport.close()


def test_nonqualified_baseline_closes_transport_and_production_cannot_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    producer, owner, sources, _ = _context(tmp_path, monkeypatch, bypass="enable")
    closed: list[Any] = []
    original = module.FortiPamSecretApprovalBuild29HttpTransport.close

    def close(transport: Any) -> None:
        original(transport)
        closed.append(transport)

    monkeypatch.setattr(module.FortiPamSecretApprovalBuild29HttpTransport, "close", close)
    with pytest.raises(SecretApprovalBuild29RuntimeProviderError):
        producer.produce(_BINDING)
    assert len(closed) == 1 and closed[0]._closed
    assert owner.logout_verified and owner._client is None
    assert (sources.schema_calls, sources.native_calls, owner.authentications) == (1, 1, 2)
    with pytest.raises(SecretApprovalBuild29RuntimeProviderError):
        producer.produce(_BINDING)
    assert owner.authentications == 2


def test_schema_session_logout_failure_never_builds_native_state_and_is_consumed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    producer, owner, sources, client = _context(tmp_path, monkeypatch)
    owner.logout_result = False
    with pytest.raises(SecretApprovalBuild29RuntimeProviderError):
        producer.produce(_BINDING)
    assert owner._client is None
    assert (sources.schema_calls, sources.native_calls, owner.authentications) == (1, 0, 1)
    assert not client.calls
    with pytest.raises(SecretApprovalBuild29RuntimeProviderError):
        producer.produce(_BINDING)
    assert owner.authentications == 1


def test_current_owner_acl_denial_is_before_schema_or_native_source_io(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    producer, owner, sources, client = _context(tmp_path, monkeypatch)
    owner.acl_permitted = False
    with pytest.raises(SecretApprovalBuild29RuntimeProviderError):
        producer.produce(_BINDING)
    assert owner.acl_calls == 1 and owner.authentications == 1
    assert sources.schema_calls == sources.native_calls == 0
    assert not client.calls and owner.logout_verified and owner._client is None


def test_current_owner_acl_is_rechecked_after_production_before_native_source_io(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    producer, owner, sources, _ = _context(tmp_path, monkeypatch)
    transition = producer.produce(_BINDING)
    assert transition.transport._mutation is not None
    owner.acl_permitted = False
    with owner.authenticated():
        with pytest.raises(ValueError):
            transition.transport._mutation.native_preservation_digest(transition.baseline.approval_values)
    assert owner.acl_calls == 3 and sources.native_calls == 1
    assert owner.logout_verified and owner._client is None
    transition.transport.close()


def test_linux_producer_passes_explicit_scope_without_reading_original_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from test_secret_approval_build29_http_transport import _LINUX_TARGET, _linux_payload
    monkeypatch.setattr(source_module, "SecretApprovalBuild29PrivateSources", _Sources)
    owner = _ScopeOwner(_linux_payload())
    client = _Client(owner.client.response.raw)
    owner.client = cast(Any, client)
    sources = _Sources(owner)
    sources._linux_target_name = _LINUX_TARGET
    from test_secret_approval_build29_runtime_provider import _linux_folder_acl, _linux_acl_digest
    acl = _linux_folder_acl()
    acl_reads: list[str] = []
    def folder_acl(method: str, path: str, body: object, *, query: str) -> tuple[int, object]:
        assert owner._client is not None
        assert method == "GET" and path == "/api/v2/cmdb/secret/folder/17" and body is None
        assert query == "format=id%7Cinherit-permission%7Cuser-permission%7Cgroup-permission"
        acl_reads.append(path)
        return 200, {"results": [acl]}
    monkeypatch.setattr(owner, "_request", folder_acl)
    (tmp_path / "claims").mkdir(mode=0o700)
    producer = SecretApprovalBuild29RuntimeProducer(
        owner, cast(Any, sources), binding=_BINDING, expected_folder_id=17, expected_serial=_SERIAL,
        linux_target_name=_LINUX_TARGET, linux_target_ipv4_address="192.0.2.10",
        expected_folder_acl_digest=_linux_acl_digest(acl),
        username_source=module.OwnerOnlySecretApprovalBuild29EnvUsernameSource(
            tmp_path / "unread-original.env", username_variable="UNIT_LINUX_USERNAME",
        ), claim_directory=tmp_path / "claims", execution_enabled=True,
    )
    transition = producer.produce(_BINDING)
    transport = transition.transport
    assert transport._linux_target_name == _LINUX_TARGET
    assert transport._mutation is not None and transport._mutation.web_fields is None
    assert transport._mutation.linux_fields is not None
    assert transport._mutation.linux_fields.target_ipv4_address == "192.0.2.10"
    assert not (tmp_path / "unread-original.env").exists()
    assert transition.baseline.approval_values == ("disable", "disable", "disable", "")
    assert len(acl_reads) == 2 and owner.acl_calls == 0
    pinned_acl_digest = producer._folder_acl_digest
    producer._folder_acl_digest = "f" * 64
    with owner.authenticated():
        with pytest.raises(ValueError):
            transport._mutation.native_preservation_digest(("disable", "disable", "disable", ""))
    assert len(acl_reads) == 2
    producer._folder_acl_digest = pinned_acl_digest
    acl["group-permission"][0]["folder-permission"] = "edit"
    with owner.authenticated():
        with pytest.raises(ValueError):
            producer._native_digest(("disable", "disable", "disable", ""))
    assert sources.native_calls == 1 and len(acl_reads) == 3
    sources._linux_target_name = "changed-target"
    with pytest.raises(ValueError):
        producer._native_digest(("disable", "disable", "disable", ""))
    assert sources.native_calls == 1
    transport.close()
