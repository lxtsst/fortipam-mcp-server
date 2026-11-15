from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import fortipam_mcp.secret_approval_build29_http_transport as module
from fortipam_mcp.owner_session_metadata import OwnerSessionMetadataTransport
from fortipam_mcp.secret_approval_build29_http_transport import (
    FortiPamSecretApprovalBuild29HttpTransport,
    SecretApprovalBuild29HttpTransportError,
    SecretApprovalBuild29MutationBinding,
    SecretApprovalBuild29WebFieldsBinding,
)
from fortipam_mcp.secret_approval_build29_contract import APPROVAL_FIELDS
from fortipam_mcp.secret_metadata_http_transport import (
    FortiPamSecretMetadataHttpTransport, SecretMetadataHttpTransportConfig,
)


_NAME = "mcp-v4-bp008-approval-unit01"
_FOLDER = "Public/mcp-v4-folder-unit01"
_SERIAL = "FPAVUNIT0001"
_REMOVE = object()


def _payload() -> dict[str, object]:
    return {
        "version": "v7.0.0", "build": 29, "http_method": "GET", "http_status": 200,
        "status": "OK", "path": "secret", "name": "database", "serial": _SERIAL, "vdom": "root",
        "results": [{
            "id": 24, "name": _NAME, "folder": 17, "q_origin_key": "24",
            "need-approval": "disable", "need-approval-job": "disable",
            "bypass-approval": "disable", "approval-profile": "",
            "description": "Unit-test metadata.",
            "permissions": {"approval_status": "none", "user": 4},
            "field": [{"value": "unit-password", "keyinfo": "unit-keyinfo"}],
            "keyinfo": "unit-keyinfo",
        }],
    }


class _Response:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.status_code = 200
        self.headers = {"content-type": "application/json"}

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *args: object) -> None:
        pass

    def iter_bytes(self) -> Iterator[bytes]:
        for offset in range(0, len(self.raw), 37):
            yield self.raw[offset:offset + 37]


class _Client:
    def __init__(self, response: _Response) -> None:
        self.response = response
        self.calls: list[tuple[str, str]] = []

    def stream(self, method: str, path: str, **kwargs: object) -> _Response:
        self.calls.append((method, path))
        return self.response


class _Owner(OwnerSessionMetadataTransport):
    def __init__(self, payload: dict[str, object]) -> None:
        config = SecretMetadataHttpTransportConfig("https://fpa.example.test", "unit-token", 15, None)
        super().__init__(
            config, owner_name="mcp-v4-owner-unit01", credentials=lambda: ("unit-owner", "unit-password"),
            folder_path=_FOLDER, secret_name=_NAME, target_name="mcp-v4-target-unit01",
            witness=FortiPamSecretMetadataHttpTransport(config), clock=lambda: 1.0,
        )
        self.client = _Client(_Response(json.dumps(payload).encode()))
        self.logout_result = True
        self.authentications = 0
        self.folder_result = 17
        self.secret_result = 24

    @contextmanager
    def authenticated(self) -> Iterator[OwnerSessionMetadataTransport]:
        self.authentications += 1
        self._client = self.client
        self._expires_at = 300
        try:
            yield self
        finally:
            self._client = None
            self.logout_verified = self.logout_result

    def resolve_folder_id(self, folder_path: str) -> int:
        assert folder_path == _FOLDER
        return self.folder_result

    def _lookup_id(self, kind: str, path: str) -> int:
        assert (kind, path) == ("secret", _FOLDER + "/" + _NAME)
        return self.secret_result


def _transport(owner: _Owner) -> FortiPamSecretApprovalBuild29HttpTransport:
    return FortiPamSecretApprovalBuild29HttpTransport(
        owner, expected_secret_id=24, expected_secret_name=_NAME,
        expected_folder_id=17, folder_path=_FOLDER, expected_serial=_SERIAL,
    )


def test_fixed_read_normalizes_only_private_identity_and_approval_fields() -> None:
    owner = _Owner(_payload())
    projection, digest = _transport(owner)._read_private_projection()
    assert set(projection) == {"version", "build", "results"}
    row = projection["results"]
    assert isinstance(row, dict)
    assert set(row) == {"id", "name", "folder", "need-approval", "need-approval-job", "bypass-approval", "approval-profile"}
    assert "unit-password" not in repr(projection) and "unit-keyinfo" not in repr(projection)
    assert len(digest) == 64
    assert owner.client.calls == [("GET", "/api/v2/cmdb/secret/database/24")]
    assert owner.logout_verified is True and owner._client is None


def test_inspection_contains_only_flags_and_redacted_metadata_digest() -> None:
    result = _transport(_Owner(_payload())).inspect()
    assert not result.interactive_approval_required
    assert not result.job_approval_required
    assert not result.owner_bypass_allowed
    assert not result.approval_profile_attached
    assert result.logout_verified
    assert _NAME not in repr(result) and _SERIAL not in repr(result)


def test_material_never_reaches_generic_json_decoding(monkeypatch: pytest.MonkeyPatch) -> None:
    owner = _Owner(_payload())
    original = json.loads
    def guarded(raw: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(raw, (bytes, bytearray)):
            assert b"unit-password" not in raw and b"unit-keyinfo" not in raw
        return original(raw, *args, **kwargs)
    monkeypatch.setattr(module.json, "loads", guarded)
    _transport(owner).inspect()


def test_totp_shared_key_is_redacted_before_decode_and_rotation_does_not_change_metadata_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _payload()
    rows = payload["results"]
    assert isinstance(rows, list)
    rows[0].update({
        "shared-key": "ENC unit-totp-top-old",
        "totp-setting": {"period": 30, "shared-key": "ENC unit-totp-nested-old"},
    })
    owner = _Owner(payload)
    original = json.loads
    def guarded(raw: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(raw, (bytes, bytearray)):
            assert b"unit-totp-" not in raw
        return original(raw, *args, **kwargs)
    monkeypatch.setattr(module.json, "loads", guarded)
    transport = _transport(owner)
    private_projection, private_digest = transport._read_private_projection()
    public_before = transport.inspect().redacted_metadata_digest
    assert "shared-key" not in repr(private_projection)
    owner.client.response.raw = owner.client.response.raw.replace(b"unit-totp-top-old", b"unit-totp-top-new").replace(
        b"unit-totp-nested-old", b"unit-totp-nested-new",
    )
    rotated_projection, rotated_digest = transport._read_private_projection()
    assert private_projection == rotated_projection
    assert private_digest == rotated_digest == public_before == transport.inspect().redacted_metadata_digest


@pytest.mark.parametrize("material", ["", "x"])
def test_short_material_values_are_null_before_generic_decoding(
    monkeypatch: pytest.MonkeyPatch, material: str,
) -> None:
    payload = _payload()
    rows = payload["results"]
    assert isinstance(rows, list)
    rows[0].update({"field": material, "keyinfo": material, "shared-key": material,
                    "totp-setting": {"shared-key": material, "nested": [{"keyinfo": material, "field": material}]}})
    owner = _Owner(payload)
    original = json.loads
    def guarded(raw: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(raw, (bytes, bytearray)) and raw.lstrip().startswith(b"{"):
            assert all(raw.count(b'"' + key + b'": null') == 2 for key in (b"shared-key", b"keyinfo", b"field"))
        return original(raw, *args, **kwargs)
    monkeypatch.setattr(module.json, "loads", guarded)
    _transport(owner).inspect()


def test_material_redactor_covers_repeated_and_nested_members_after_front_resize() -> None:
    raw = bytearray(b'{"shared-key":"","shared-key":"x","nested":[{"keyinfo":"","field":"x","shared-key":"z"}],"field":""}')
    module._redact_material_members(raw)
    assert raw == b'{"shared-key":null,"shared-key":null,"nested":[{"keyinfo":null,"field":null,"shared-key":null}],"field":null}'


@pytest.mark.parametrize(
    ("key", "value"),
    [("version", "v1.9.1"), ("build", 30), ("build", True), ("http_status", True),
     ("http_method", "PUT"), ("status", "success"), ("path", "other"),
     ("name", "other"), ("serial", "FOREIGN0001"), ("vdom", "other"), ("extra", True)],
)
def test_native_envelope_drift_fails_closed(key: str, value: object) -> None:
    payload = _payload()
    payload[key] = value
    owner = _Owner(payload)
    with pytest.raises(SecretApprovalBuild29HttpTransportError, match="unavailable"):
        _transport(owner).inspect()
    assert owner.logout_verified


@pytest.mark.parametrize(
    ("key", "value"),
    [("id", 25), ("id", True), ("name", "other"), ("folder", 18),
     ("q_origin_key", "25"), ("need-approval", _REMOVE), ("need-approval-job", "unknown"),
     ("bypass-approval", None), ("approval-profile", _REMOVE), ("approval-profile", False)],
)
def test_native_record_identity_or_approval_drift_fails_closed(key: str, value: object) -> None:
    payload = _payload()
    rows = payload["results"]
    assert isinstance(rows, list)
    if value is _REMOVE:
        rows[0].pop(key)
    else:
        rows[0][key] = value
    with pytest.raises(SecretApprovalBuild29HttpTransportError):
        _transport(_Owner(payload)).inspect()


@pytest.mark.parametrize("kind", ["folder", "secret", "logout", "status", "size", "duplicate"])
def test_lookup_response_bounds_and_logout_fail_closed(kind: str) -> None:
    owner = _Owner(_payload())
    if kind == "folder":
        owner.folder_result = 18
    elif kind == "secret":
        owner.secret_result = 25
    elif kind == "logout":
        owner.logout_result = False
    elif kind == "status":
        owner.client.response.status_code = 403
    elif kind == "size":
        owner.client.response.raw = b" " * (module.MAX_RESPONSE_BYTES + 1)
    else:
        owner.client.response.raw = owner.client.response.raw.replace(b'"need-approval": "disable"', b'"need-approval": "disable", "need-approval": "enable"')
    with pytest.raises(SecretApprovalBuild29HttpTransportError):
        _transport(owner).inspect()
    if kind in ("folder", "secret"):
        assert owner.client.calls == []


def test_digest_changes_for_metadata_but_excludes_approval_and_material() -> None:
    owner = _Owner(_payload())
    before = _transport(owner).inspect().redacted_metadata_digest
    payload = _payload()
    rows = payload["results"]
    assert isinstance(rows, list)
    rows[0].update({"need-approval": "enable", "approval-profile": "mcp-v4-approval-profile-unit01", "field": [{"value": "different-material"}]})
    assert _transport(_Owner(payload)).inspect().redacted_metadata_digest == before
    rows[0]["description"] = "Changed metadata."
    assert _transport(_Owner(payload)).inspect().redacted_metadata_digest != before


def test_one_identical_raw_nonselected_duplicate_normalizes_without_digest_change() -> None:
    owner = _Owner(_payload())
    expected = _transport(owner).inspect().redacted_metadata_digest
    member = b'"description": "Unit-test metadata."'
    owner.client.response.raw = owner.client.response.raw.replace(member, member + b", " + member)
    assert _transport(owner).inspect().redacted_metadata_digest == expected


@pytest.mark.parametrize("kind", ["decoded_equal", "conflict", "two", "field", "keyinfo", "envelope", "nested"])
def test_duplicate_exception_rejects_unqualified_or_protected_members(kind: str) -> None:
    owner = _Owner(_payload())
    raw = owner.client.response.raw
    member = b'"description": "Unit-test metadata."'
    if kind == "decoded_equal":
        replacement = member + b', "description": "Unit\\u002dtest metadata."'
    elif kind == "conflict":
        replacement = member + b', "description": "different"'
    elif kind == "two":
        replacement = member + b", " + member + b", " + member
    elif kind in ("field", "keyinfo"):
        replacement = member + b', "' + kind.encode() + b'": null'
    elif kind == "envelope":
        member = b'"build": 29'
        replacement = member + b", " + member
    else:
        replacement = member + b', "extra": {"x": 1, "x": 1}'
    owner.client.response.raw = raw.replace(member, replacement)
    with pytest.raises(SecretApprovalBuild29HttpTransportError):
        _transport(owner).inspect()


def _mutation_schema() -> dict[str, object]:
    selected: dict[str, dict[str, object]] = {}
    for name in APPROVAL_FIELDS:
        member: dict[str, object] = {
            "name": name, "category": "unitary", "multiple_values": False,
            "default": "" if name == "approval-profile" else "disable", "help": "Unit-test source.",
            "type": "string" if name == "approval-profile" else "option",
        }
        if name != "bypass-approval":
            member["required"] = True
        if name == "approval-profile":
            member.update(size=79, datasource=["secret.approval-profile.name"])
        else:
            member["options"] = [{"name": value, "help": "Unit-test enum."} for value in ("enable", "disable")]
        selected[name] = member
    return {"version": "v7.0.0", "build": 29, "selected_schema": selected}


class _MutationClient(_Client):
    def __init__(self, response: _Response) -> None:
        super().__init__(response)
        self.bodies: list[dict[str, object]] = []
        self.uncertain = False
        self.change_other_metadata = False
        self.apply_body = True
        self.reject_ack = False

    def build_request(self, method: str, path: str) -> Any:
        return SimpleNamespace(headers={"cookie": "ccsrftoken=unit-csrf"})

    def stream(self, method: str, path: str, **kwargs: object) -> _Response:
        if method == "GET":
            return super().stream(method, path, **kwargs)
        self.calls.append((method, path))
        assert (method, path) == ("PUT", "/api/v2/cmdb/secret/database/24")
        encoded = kwargs["content"]
        assert isinstance(encoded, bytes)
        body = json.loads(encoded)
        assert set(body) == APPROVAL_FIELDS | {"id", "name", "folder", "template", "field"}
        assert {key: body[key] for key in ("id", "name", "folder", "template")} == {
            "id": 24, "name": _NAME, "folder": 17, "template": "Web Account",
        }
        assert body["field"] == [
            {"id": 1, "name": "Password", "value": "unit-password"},
            {"id": 3, "name": "URL", "value": "https://unit.example.test/"},
            {"id": 2, "name": "Username", "value": "unit-account"},
        ]
        self.bodies.append(body)
        if self.uncertain:
            raise OSError("Unit-test dispatch ambiguity.")
        payload = json.loads(self.response.raw)
        if self.apply_body:
            row = payload["results"][0]
            row.update({key: body[key] for key in APPROVAL_FIELDS})
            enabled = body["need-approval"] == "enable"
            row["permissions"]["approval_status"] = "required" if enabled else "none"
            if enabled:
                row["num-approval-tiers"] = 1
            else:
                row.pop("num-approval-tiers", None)
        if self.change_other_metadata:
            payload["results"][0]["description"] = "Unexpected metadata drift."
        self.response.raw = json.dumps(payload).encode()
        # This is solely a unit ACK, not an inferred native response contract.
        return _Response(b'{"unit_ack": false}' if self.reject_ack else b'{"unit_ack": true}')


def _mutable_owner(*, bypass: str = "disable") -> _Owner:
    payload = _payload()
    rows = payload["results"]
    assert isinstance(rows, list)
    rows[0]["bypass-approval"] = bypass
    rows[0].update({"template": "Web Account", "target": "", "field": [
        {"id": identifier, "name": name, "value": value, "desc": "", "type": name.lower(), "q_origin_key": identifier}
        for identifier, name, value in (
            (3, "URL", "https://unit.example.test/"), (2, "Username", "unit-account"), (1, "Password", "unit-password"),
        )
    ]})
    owner = _Owner(payload)
    owner.client = _MutationClient(owner.client.response)
    return owner


def _mutation_transport(
    owner: _Owner, directory: Path, *, enabled: bool = True,
    ack: bool = True, profile: Any = None, native: Any = None,
    web_fields: bool = True, username: Any = None,
) -> FortiPamSecretApprovalBuild29HttpTransport:
    directory.mkdir(mode=0o700, exist_ok=True)
    binding = SecretApprovalBuild29MutationBinding(
        schema=_mutation_schema(), approval_profile_name="mcp-v4-approval-profile-unit01",
        profile_digest=profile or (lambda: "a" * 64),
        native_preservation_digest=native or (lambda _values: "b" * 64),
        claim_directory=directory,
        ack_verifier=(lambda status, raw: status == 200 and json.loads(raw) == {"unit_ack": True}) if ack else None,
        web_fields=SecretApprovalBuild29WebFieldsBinding(
            "https://unit.example.test/", username or (lambda: memoryview(bytearray(b"unit-account"))),
        ) if web_fields else None,
    )
    return FortiPamSecretApprovalBuild29HttpTransport(
        owner, expected_secret_id=24, expected_secret_name=_NAME,
        expected_folder_id=17, folder_path=_FOLDER, expected_serial=_SERIAL,
        mutation=binding, execution_enabled=enabled,
    )


@pytest.mark.parametrize("bypass", ["disable", "enable"])
def test_once_enable_and_owned_restore_use_fixed_web_body_and_preserve_baseline(tmp_path: Path, bypass: str) -> None:
    owner = _mutable_owner(bypass=bypass)
    transport = _mutation_transport(owner, tmp_path)
    baseline = transport.inspect_transition()
    result = transport.enable_and_readback(baseline, expires_at=30, clock=lambda: 1.0)
    assert result.verified
    assert "digest" not in repr(result) and _NAME not in repr(result)
    applied = transport.inspect_transition()
    assert transport.restore_and_readback(applied, expires_at=30, clock=lambda: 1.0).verified
    assert transport.inspect_transition() == baseline
    assert isinstance(owner.client, _MutationClient)
    assert [{key: body[key] for key in APPROVAL_FIELDS} for body in owner.client.bodies] == [
        {"need-approval": "enable", "need-approval-job": "disable", "bypass-approval": bypass, "approval-profile": "mcp-v4-approval-profile-unit01"},
        {"need-approval": "disable", "need-approval-job": "disable", "bypass-approval": bypass, "approval-profile": ""},
    ]
    assert len(list(tmp_path.glob("*.claim"))) == 2
    for file in tmp_path.glob("*.claim"):
        record = json.loads(file.read_text())
        assert record["replay_permitted"] is False and _NAME not in file.read_text()
    logins = owner.authentications
    with pytest.raises(SecretApprovalBuild29HttpTransportError):
        transport.enable_and_readback(baseline, expires_at=30, clock=lambda: 1.0)
    with pytest.raises(SecretApprovalBuild29HttpTransportError):
        transport.restore_and_readback(applied, expires_at=30, clock=lambda: 1.0)
    assert owner.authentications == logins


@pytest.mark.parametrize("condition", ["closed_gate", "missing_ack", "missing_web_fields", "no_ownership", "expired"])
def test_mutation_denials_happen_before_login_or_claim(tmp_path: Path, condition: str) -> None:
    owner = _mutable_owner()
    transport = _mutation_transport(owner, tmp_path, enabled=condition != "closed_gate", ack=condition != "missing_ack",
                                    web_fields=condition != "missing_web_fields")
    expected = transport.inspect_transition()
    logins = owner.authentications
    method = transport.restore_and_readback if condition == "no_ownership" else transport.enable_and_readback
    with pytest.raises(SecretApprovalBuild29HttpTransportError):
        method(expected, expires_at=0 if condition == "expired" else 30, clock=lambda: 1.0)
    assert owner.authentications == logins and list(tmp_path.glob("*.claim")) == []


@pytest.mark.parametrize("phase", ["profile", "native", "final_read"])
def test_witness_or_final_drift_causes_zero_put_and_no_claim(tmp_path: Path, phase: str) -> None:
    owner = _mutable_owner()
    calls = 0
    def witness() -> str:
        nonlocal calls
        calls += 1
        return "c" * 64 if calls >= (3 if phase == "final_read" else 2) else "a" * 64
    transport = _mutation_transport(
        owner, tmp_path, profile=witness if phase != "native" else None,
        native=(lambda _values: witness()) if phase == "native" else None,
    )
    expected = transport.inspect_transition()
    with pytest.raises(SecretApprovalBuild29HttpTransportError):
        transport.enable_and_readback(expected, expires_at=30, clock=lambda: 1.0)
    assert isinstance(owner.client, _MutationClient)
    assert owner.client.bodies == [] and list(tmp_path.glob("*.claim")) == []


@pytest.mark.parametrize("failure", ["uncertain", "ack", "metadata", "native", "unapplied", "logout"])
def test_post_claim_failure_never_replays_or_grants_restore(tmp_path: Path, failure: str) -> None:
    owner = _mutable_owner()
    def native(_values: tuple[str, str, str, str]) -> str:
        assert isinstance(owner.client, _MutationClient)
        return "c" * 64 if failure == "native" and owner.client.bodies else "b" * 64
    transport = _mutation_transport(owner, tmp_path, native=native)
    before = transport.inspect_transition()
    assert isinstance(owner.client, _MutationClient)
    owner.client.uncertain = failure == "uncertain"
    owner.client.reject_ack = failure == "ack"
    owner.client.change_other_metadata = failure == "metadata"
    owner.client.apply_body = failure != "unapplied"
    owner.logout_result = failure != "logout"
    with pytest.raises(SecretApprovalBuild29HttpTransportError):
        transport.enable_and_readback(before, expires_at=30, clock=lambda: 1.0)
    assert len(owner.client.bodies) == 1 and len(list(tmp_path.glob("*.claim"))) == 1
    logins = owner.authentications
    with pytest.raises(SecretApprovalBuild29HttpTransportError):
        transport.enable_and_readback(before, expires_at=30, clock=lambda: 1.0)
    with pytest.raises(SecretApprovalBuild29HttpTransportError):
        transport.restore_and_readback(before, expires_at=30, clock=lambda: 1.0)
    assert owner.authentications == logins
    replacement = _mutation_transport(_mutable_owner(), tmp_path)
    with pytest.raises(SecretApprovalBuild29HttpTransportError):
        replacement.enable_and_readback(before, expires_at=30, clock=lambda: 1.0)


@pytest.mark.parametrize("stage", ["current_drift", "csrf_check", "final_drift"])
def test_prewrite_exception_stage_distinguishes_drift_csrf_and_final_read_without_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stage: str,
) -> None:
    owner = _mutable_owner()
    calls = 0
    def profile() -> str:
        nonlocal calls
        calls += 1
        return "c" * 64 if calls >= (3 if stage == "final_drift" else 2) and stage != "csrf_check" else "a" * 64
    transport = _mutation_transport(owner, tmp_path, profile=profile)
    before = transport.inspect_transition()
    if stage == "csrf_check":
        def denied_csrf() -> str:
            raise ValueError("Unit-test private failure text.")
        monkeypatch.setattr(transport, "_csrf", denied_csrf)
    with pytest.raises(SecretApprovalBuild29HttpTransportError) as caught:
        transport.enable_and_readback(before, expires_at=30, clock=lambda: 1.0)
    assert caught.value.stage == stage
    assert str(caught.value) == module._UNAVAILABLE
    assert _NAME not in repr(caught.value) and "private failure" not in repr(caught.value)
    assert isinstance(owner.client, _MutationClient)
    assert owner.client.bodies == [] and list(tmp_path.glob("*.claim")) == []
    assert owner.logout_verified and owner._client is None


def test_private_username_lifecycle_and_redacted_decode_on_enable_and_restore(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    owner = _mutable_owner()
    buffers: list[bytearray] = []
    views: list[memoryview] = []

    def username() -> memoryview:
        backing = bytearray(b"padunit-accountpad")
        view = memoryview(backing)[3:-3]
        buffers.append(backing)
        views.append(view)
        return view

    transport = _mutation_transport(owner, tmp_path, username=username)
    original_loads = json.loads

    def guarded_loads(raw: Any, **kwargs: Any) -> Any:
        if isinstance(raw, (bytes, bytearray)):
            assert b"unit-password" not in raw and b"unit-account" not in raw and b"unit-keyinfo" not in raw
        return original_loads(raw, **kwargs)

    monkeypatch.setattr(module, "json", SimpleNamespace(loads=guarded_loads, dumps=json.dumps, dump=json.dump))
    before = transport.inspect_transition()
    assert not buffers
    assert transport.enable_and_readback(before, expires_at=30, clock=lambda: 1.0).verified
    applied = transport.inspect_transition()
    assert transport.restore_and_readback(applied, expires_at=30, clock=lambda: 1.0).verified
    assert len(buffers) == 2 and buffers[0] is not buffers[1]
    assert all(not any(backing) for backing in buffers)
    for view in views:
        with pytest.raises(ValueError):
            _ = view.obj
    assert transport._mutation is not None and transport._mutation.web_fields is not None
    assert "unit-account" not in repr(transport._mutation.web_fields)


@pytest.mark.parametrize("change", ["serial", "build", "identity", "metadata", "username", "slot", "final_drift"])
def test_fixed_field_read_and_final_drift_deny_before_claim(tmp_path: Path, change: str, monkeypatch: pytest.MonkeyPatch) -> None:
    owner = _mutable_owner()
    buffers: list[bytearray] = []

    def username() -> memoryview:
        backing = bytearray(b"unit-account")
        buffers.append(backing)
        return memoryview(backing)

    transport = _mutation_transport(owner, tmp_path, username=username)
    before = transport.inspect_transition()
    original_stream = owner.client.stream
    reads = 0

    def changed_stream(method: str, path: str, **kwargs: object) -> _Response:
        nonlocal reads
        response = original_stream(method, path, **kwargs)
        if method == "GET":
            reads += 1
            if reads == (3 if change == "final_drift" else 2):
                payload = json.loads(response.raw)
                row = payload["results"][0]
                if change in {"serial", "build"}:
                    payload[change] = "DIFFERENT" if change == "serial" else 30
                elif change == "identity":
                    row["id"] = 25
                elif change in {"metadata", "final_drift"}:
                    row["description"] = "Changed metadata."
                elif change == "username":
                    row["field"][1]["value"] = "different-account"
                else:
                    row["field"][0]["q_origin_key"] = "3"
                return _Response(json.dumps(payload).encode())
        return response

    monkeypatch.setattr(owner.client, "stream", changed_stream)
    with pytest.raises(SecretApprovalBuild29HttpTransportError):
        transport.enable_and_readback(before, expires_at=30, clock=lambda: 1.0)
    assert isinstance(owner.client, _MutationClient) and not owner.client.bodies
    assert not list(tmp_path.glob("*.claim")) and transport._ownership is None
    assert all(not any(backing) for backing in buffers)
    assert bool(buffers) == (change in {"username", "slot", "final_drift"})
    assert owner.logout_verified


@pytest.mark.parametrize("kind", ["readonly", "wrong_account", "close"])
def test_private_username_refusal_and_close_preserve_default_denial(tmp_path: Path, kind: str) -> None:
    owner = _mutable_owner()
    backing = bytearray(b"wrong-account" if kind == "wrong_account" else b"unit-account")
    view = memoryview(backing).toreadonly() if kind == "readonly" else memoryview(backing)
    transport = _mutation_transport(owner, tmp_path, username=lambda: view)
    before = transport.inspect_transition()
    if kind == "close":
        transport.close()
    with pytest.raises(SecretApprovalBuild29HttpTransportError):
        transport.enable_and_readback(before, expires_at=30, clock=lambda: 1.0)
    assert isinstance(owner.client, _MutationClient) and not owner.client.bodies
    assert not list(tmp_path.glob("*.claim")) and transport._ownership is None
    if kind == "close":
        view.release()
    else:
        assert not any(backing)
        with pytest.raises(ValueError):
            _ = view.obj


def test_shared_digest_normalizes_only_exact_computed_paths_without_input_mutation() -> None:
    before = {"description": "preserved", "permissions": {
        "approval_status": "none", "user": 4, "nested": {"approval_status": "preserved"},
    }, "nested": {"num-approval-tiers": 7}}
    after = deepcopy(before)
    after["num-approval-tiers"] = 1
    after["permissions"]["approval_status"] = "required"
    saved = deepcopy((before, after))
    digest = module._preserved_metadata_digest(before)
    assert module._preserved_metadata_digest(after) == digest
    assert (before, after) == saved
    for path in ("other_permission", "nested_permission", "nested_tiers", "other_config"):
        changed = deepcopy(after)
        if path == "other_permission":
            changed["permissions"]["user"] = 3
        elif path == "nested_permission":
            changed["permissions"]["nested"]["approval_status"] = "changed"
        elif path == "nested_tiers":
            changed["nested"]["num-approval-tiers"] = 8
        else:
            changed["description"] = "changed"
        assert module._preserved_metadata_digest(changed) != digest


@pytest.mark.parametrize("annotation,value", [
    ("num-approval-tiers", None), ("num-approval-tiers", 0), ("num-approval-tiers", 2),
    ("num-approval-tiers", True), ("num-approval-tiers", 1.0), ("num-approval-tiers", "1"),
    ("approval_status", "other"), ("approval_status", None), ("approval_status", 1),
    ("permissions", []), ("permissions", {}),
])
def test_unqualified_computed_annotations_fail_closed(annotation: str, value: object) -> None:
    row = {"permissions": {"approval_status": "none", "user": 4}}
    if annotation == "approval_status":
        row["permissions"][annotation] = value
    else:
        row[annotation] = value
    with pytest.raises(ValueError):
        module._preserved_metadata_digest(row)


def test_request_field_empty_annotation_normalizes_only_root_and_preserves_nested() -> None:
    before = {"permissions": {"approval_status": "none", "user": 4},
              "nested": {"request-field": []}, "description": "preserved"}
    after = {**deepcopy(before), "request-field": []}
    saved = deepcopy((before, after))
    digest = module._preserved_metadata_digest(before)
    assert module._preserved_metadata_digest(after) == digest and (before, after) == saved
    after["nested"]["request-field"].append("synthetic")
    assert module._preserved_metadata_digest(after) != digest
    del after["nested"]["request-field"]
    assert module._preserved_metadata_digest(after) != digest


@pytest.mark.parametrize("value", [None, {}, "", 0, False, (), [{}], ["synthetic"]])
def test_request_field_unqualified_container_refuses(value: object) -> None:
    with pytest.raises(ValueError):
        module._preserved_metadata_digest({"request-field": value})


def test_request_field_identical_root_duplicate_remains_protected() -> None:
    payload = _payload()
    payload["results"][0]["request-field"] = []
    owner = _Owner(payload)
    member = b'"request-field": []'
    owner.client.response.raw = owner.client.response.raw.replace(member, member + b", " + member)
    with pytest.raises(SecretApprovalBuild29HttpTransportError):
        _transport(owner).inspect()


def _native_put_ack() -> bytearray:
    return bytearray(json.dumps({"version": "v7.0.0", "build": 29, "http_method": "PUT",
        "http_status": 200, "path": "secret", "name": "database", "serial": _SERIAL,
        "vdom": "root", "status": "success", "mkey": 24,
    }, separators=(",", ":")).encode()[:-1] + b',"results":{"x":1,"x":2,"value":"unit-password"}}')


def test_pure_ack_checks_only_authoritative_root_without_decoding_results_or_mutating_buffer(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _native_put_ack()
    original = bytearray(raw)
    original_loads = json.loads

    def guarded_loads(value: Any, **kwargs: Any) -> Any:
        assert isinstance(value, (bytes, bytearray))
        assert b"unit-password" not in value and b'"x"' not in value
        return original_loads(value, **kwargs)

    monkeypatch.setattr(module, "json", SimpleNamespace(loads=guarded_loads, dumps=json.dumps))
    assert module.qualify_secret_approval_build29_put_ack(200, raw, expected_serial=_SERIAL, expected_secret_id=24)
    assert raw == original


@pytest.mark.parametrize("before,after", [
    (b'"version":"v7.0.0"', b'"version":"v1.9.1"'),
    (b'"build":29', b'"build":30'), (b'"http_method":"PUT"', b'"http_method":"GET"'),
    (b'"http_status":200', b'"http_status":400'), (b'"path":"secret"', b'"path":"other"'),
    (b'"name":"database"', b'"name":"other"'), (b'"serial":"FPAVUNIT0001"', b'"serial":"OTHER"'),
    (b'"vdom":"root"', b'"vdom":"other"'), (b'"status":"success"', b'"status":"OK"'),
    (b'"mkey":24', b'"mkey":"24"'), (b'"mkey":24', b'"mkey":25'), (b'"mkey":24', b'"mkey":24.0'),
    (b'"mkey":24', b'"mkey":true'), (b'"mkey":24,', b''),
    (b'"mkey":24', b'"mkey":24,"error":0'), (b'"mkey":24', b'"mkey":24,"schema_errors":[]'),
    (b'"mkey":24', b'"mkey":24,"mkey":24'), (b'"build":29', b'"build":29,"build":29'),
    (b'"x":1', b'"x":01'), (b'"x":1', b'"x":NaN'), (b'"x":1', b'"x":truefalse'),
    (b'"unit-password"', b'"bad\\xescape"'), (b'"unit-password"', b'"bad\\uZZZZ"'),
    (b'"unit-password"', b'"bad\xffutf8"'), (b'"unit-password"', b'"bad\x01control"'),
    (b'"unit-password"', b'[1,]'), (b'"unit-password"', b'{"x":1,}'),
    (b'"unit-password"', b'{"x" 1}'), (b'"unit-password"', b'[1 2]'),
])
def test_fixed_ack_rejects_marker_drift_and_malformed_non_authoritative_results(before: bytes, after: bytes) -> None:
    raw = _native_put_ack()
    assert before in raw
    raw = raw.replace(before, after, 1)
    original = bytearray(raw)
    assert not module.qualify_secret_approval_build29_put_ack(200, raw, expected_serial=_SERIAL, expected_secret_id=24)
    assert raw == original


@pytest.mark.parametrize("kind", ["http_status", "bound_id", "bound_serial", "trailing", "root_array", "empty"])
def test_ack_requires_bound_transport_and_complete_root(kind: str) -> None:
    raw = _native_put_ack()
    if kind == "trailing":
        raw.extend(b" null")
    elif kind == "root_array":
        raw = bytearray(b"[") + raw + b"]"
    elif kind == "empty":
        raw.clear()
    assert not module.qualify_secret_approval_build29_put_ack(
        400 if kind == "http_status" else 200, raw,
        expected_serial="OTHER" if kind == "bound_serial" else _SERIAL,
        expected_secret_id=25 if kind == "bound_id" else 24,
    )


_LINUX_TARGET = "mcp-v4-target-unit01"


def _linux_payload() -> dict[str, Any]:
    payload = cast(dict[str, Any], _payload())
    payload["results"][0].update({
        "template": "Unix Account (SSH Password)", "target": _LINUX_TARGET,
        "totp-setting": {"status": "disable", "shared-key": ""},
        "field": [
            {"id": index, "name": name, "type": kind, "value": value}
            for index, (name, kind, value) in enumerate((
                ("Host", "target-address", "192.0.2.10"),
                ("Username", "username", "unit-account"),
                ("Password", "password", "unit-password"),
            ), 1)
        ],
    })
    return payload


class _LinuxMutationClient(_Client):
    def __init__(self, response: _Response) -> None:
        super().__init__(response)
        self.bodies: list[dict[str, Any]] = []

    def build_request(self, method: str, path: str) -> Any:
        return SimpleNamespace(headers={"cookie": "ccsrftoken=unit-csrf"})

    def stream(self, method: str, path: str, **kwargs: Any) -> _Response:
        if method != "PUT":
            return super().stream(method, path, **kwargs)
        self.calls.append((method, path))
        body = json.loads(kwargs["content"])
        assert set(body) == APPROVAL_FIELDS | {"id", "name", "folder", "template", "target", "field"}
        assert body["template"] == "Unix Account (SSH Password)" and body["target"] == _LINUX_TARGET
        assert body["field"] == [{key: slot[key] for key in ("id", "name", "value")}
                                 for slot in _linux_payload()["results"][0]["field"]]
        self.bodies.append(body)
        payload = json.loads(self.response.raw)
        payload["results"][0].update({key: body[key] for key in APPROVAL_FIELDS})
        self.response.raw = json.dumps(payload).encode()
        return _Response(b'{"unit_ack": true}')


def _linux_transport(owner: _Owner, directory: Path, **changes: Any) -> FortiPamSecretApprovalBuild29HttpTransport:
    directory.mkdir(mode=0o700, exist_ok=True)
    binding = module.SecretApprovalBuild29LinuxFieldsBinding(
        _LINUX_TARGET, "192.0.2.10", changes.pop("username", lambda: memoryview(bytearray(b"unit-account"))),
    )
    mutation = SecretApprovalBuild29MutationBinding(
        _mutation_schema(), "mcp-v4-approval-profile-unit01", lambda: "a" * 64,
        lambda _: "b" * 64, directory, lambda status, raw: status == 200 and json.loads(raw) == {"unit_ack": True},
        linux_fields=binding, web_fields=changes.pop("web_fields", None),
        expected_folder_acl_digest=changes.pop("expected_folder_acl_digest", "c" * 64),
    )
    arguments: dict[str, Any] = dict(owner=owner, expected_secret_id=24, expected_secret_name=_NAME,
        expected_folder_id=17, folder_path=_FOLDER, expected_serial=_SERIAL,
        mutation=mutation, execution_enabled=True, linux_target_name=_LINUX_TARGET)
    arguments.update(changes)
    return FortiPamSecretApprovalBuild29HttpTransport(**arguments)


def test_linux_enable_restore_fixed_routing_and_material_lifecycle(tmp_path: Path) -> None:
    owner = _Owner(_linux_payload())
    owner.client = _LinuxMutationClient(owner.client.response)
    buffers: list[bytearray] = []
    def username() -> memoryview:
        material = bytearray(b"unit-account")
        buffers.append(material)
        return memoryview(material)
    transport = _linux_transport(owner, tmp_path, username=username)
    baseline = transport.inspect_transition()
    assert transport.enable_and_readback(baseline, expires_at=30, clock=lambda: 1).verified
    applied = transport.inspect_transition()
    assert transport.restore_and_readback(applied, expires_at=30, clock=lambda: 1).verified
    assert transport.inspect_transition() == baseline
    assert len(owner.client.bodies) == 2 and len(list(tmp_path.glob("*.claim"))) == 2
    assert len(buffers) == 2 and all(not any(material) for material in buffers)
    with pytest.raises(SecretApprovalBuild29HttpTransportError):
        transport.enable_and_readback(baseline, expires_at=30, clock=lambda: 1)


@pytest.mark.parametrize("key,value", [
    ("template", "Web Account"), ("target", "other-target"),
    ("totp-setting", {"status": "enable"}), ("field", []),
    ("bypass-approval", "enable"),
])
def test_linux_drift_or_unqualified_baseline_never_claims(tmp_path: Path, key: str, value: Any) -> None:
    owner = _Owner(_linux_payload())
    transport = _linux_transport(owner, tmp_path)
    baseline = transport.inspect_transition()
    payload = _linux_payload()
    payload["results"][0][key] = value
    owner.client.response.raw = json.dumps(payload).encode()
    with pytest.raises(SecretApprovalBuild29HttpTransportError):
        transport.enable_and_readback(baseline, expires_at=30, clock=lambda: 1)
    assert not list(tmp_path.iterdir()) and all(method == "GET" for method, _ in owner.client.calls)
    assert owner.logout_verified


@pytest.mark.parametrize("kind", ["implicit", "mismatch", "dual", "closed"])
def test_linux_binding_requires_explicit_matching_exclusive_scope(tmp_path: Path, kind: str) -> None:
    owner = _Owner(_linux_payload())
    if kind == "closed":
        transport = _linux_transport(owner, tmp_path, execution_enabled=False)
        baseline = transport.inspect_transition()
        with pytest.raises(SecretApprovalBuild29HttpTransportError):
            transport.enable_and_readback(baseline, expires_at=30, clock=lambda: 1)
    else:
        changes: dict[str, Any] = {"linux_target_name": None if kind == "implicit" else "other-target"}
        if kind == "dual":
            changes = {"web_fields": SecretApprovalBuild29WebFieldsBinding(
                "https://unit.example.test/", lambda: memoryview(bytearray(b"unit-account")))}
        with pytest.raises(SecretApprovalBuild29HttpTransportError):
            _linux_transport(owner, tmp_path, **changes)
        assert owner.authentications == 0
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("kind", ["username", "host", "baseline"])
def test_linux_bound_material_and_baseline_refusals_before_claim(tmp_path: Path, kind: str) -> None:
    payload = _linux_payload()
    if kind == "host":
        payload["results"][0]["field"][0]["value"] = "192.0.2.11"
    if kind == "baseline":
        payload["results"][0]["bypass-approval"] = "enable"
    owner = _Owner(payload)
    owner.client = _LinuxMutationClient(owner.client.response)
    backing = bytearray(b"wrong-account" if kind == "username" else b"unit-account")
    transport = _linux_transport(owner, tmp_path, username=lambda: memoryview(backing))
    baseline = transport.inspect_transition()
    with pytest.raises(SecretApprovalBuild29HttpTransportError):
        transport.enable_and_readback(baseline, expires_at=30, clock=lambda: 1)
    assert not list(tmp_path.iterdir()) and all(method == "GET" for method, _ in owner.client.calls)
    if kind != "baseline":
        assert not any(backing)


@pytest.mark.parametrize("digest", [None, "", "short", "G" * 64, "a" * 63])
def test_linux_mutation_requires_exact_folder_acl_digest(tmp_path, digest):
    with pytest.raises(module.SecretApprovalBuild29HttpTransportError):
        _linux_transport(_Owner(_linux_payload()), tmp_path, expected_folder_acl_digest=digest)
