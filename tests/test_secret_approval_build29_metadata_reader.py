"""Fixed actual getter contracts exercised through synthetic scoped Owners."""

from copy import deepcopy
from dataclasses import asdict
import json
from typing import Any, cast

import pytest

import fortipam_mcp.secret_approval_build29_metadata_reader as module
from fortipam_mcp.secret_approval_build29_metadata_reader import (
    SecretApprovalBuild29MetadataReaderError,
    SecretApprovalBuild29ProfileReader,
    SecretApprovalBuild29ProjectionReader,
)
from test_secret_approval_build29_http_transport import (
    _FOLDER, _NAME, _SERIAL, _Owner, _Response, _payload, _transport,
)


_PROFILE = "mcp-v4-approval-profile-unit01"


def _profile_payload() -> dict[str, Any]:
    return {
        "version": "v7.0.0", "build": 29, "http_method": "GET", "http_status": 200,
        "status": "success", "path": "secret", "name": "approval-profile", "vdom": "root",
        "serial": _SERIAL, "mkey": _PROFILE, "revision": "synthetic-revision-01",
        "results": [{"name": _PROFILE, "q_origin_key": _PROFILE, "type": "single",
                     "first-num": 1, "first-user": [{"name": "admin", "q_origin_key": "admin"}],
                     "first-group": [], "second-user": [], "second-group": [], "third-user": [], "third-group": [],
                     "self-approval": "disable", "auto-approval-schedule": "", "max-allowed-duration": 0,
                     "remote-group-email": "disable", "email-template": "", "approver-perm-req": "none",
                     "field": [], "description": "Synthetic unrelated description."}],
    }


def _profile_reader(payload: dict[str, Any] | None = None) -> tuple[SecretApprovalBuild29ProfileReader, _Owner]:
    owner = _Owner(_profile_payload() if payload is None else payload)
    return SecretApprovalBuild29ProfileReader(owner, expected_serial=_SERIAL, profile_name=_PROFILE), owner


def _secret_payload() -> dict[str, Any]:
    payload = cast(dict[str, Any], deepcopy(_payload()))
    payload["results"][0].update({"template": "Web Account", "target": "",
                                   "totp-setting": {"status": "disable", "shared-key": "ENC UNIT-TOTP-CIPHERTEXT"}})
    return payload


def _secret_reader(payload: dict[str, Any] | None = None) -> tuple[SecretApprovalBuild29ProjectionReader, _Owner]:
    owner = _Owner(_secret_payload() if payload is None else payload)
    transport = _transport(owner)
    return SecretApprovalBuild29ProjectionReader(transport, approval_profile_name=_PROFILE), owner


def _read_secret(reader: SecretApprovalBuild29ProjectionReader, **changes: Any) -> Any:
    arguments: dict[str, Any] = {"folder_path": _FOLDER, "secret_name": _NAME,
                 "approval_profile_name": _PROFILE, "expected_secret_id": 24}
    arguments.update(changes)
    return reader.inspect_approval_projection(**arguments)


def test_profile_actual_contract_has_only_proven_flags_and_fixed_get() -> None:
    reader, owner = _profile_reader()
    result = reader.readback(_PROFILE)
    assert result.verified and set(asdict(result).values()) == {True}
    assert "description" not in asdict(result) and "email_approval_link_expiry_default" not in asdict(result)
    assert _PROFILE not in repr(result)
    assert owner.client.calls == [("GET", "/api/v2/cmdb/secret/approval-profile/" + _PROFILE)]
    assert owner.logout_verified and owner._client is None


def test_profile_digest_uses_active_session_full_config_and_excludes_revision() -> None:
    reader, owner = _profile_reader()
    with pytest.raises(SecretApprovalBuild29MetadataReaderError):
        reader.current_configuration_digest()
    assert owner.authentications == 0 and not owner.client.calls
    with owner.authenticated():
        first = reader.current_configuration_digest()
        payload = _profile_payload()
        payload["revision"] = "synthetic-revision-02"
        owner.client.response = _Response(json.dumps(payload).encode())
        assert reader.current_configuration_digest() == first
        payload["results"][0]["description"] = "Changed synthetic configuration."
        owner.client.response = _Response(json.dumps(payload).encode())
        assert reader.current_configuration_digest() != first
    assert owner.authentications == 1 and owner.logout_verified


@pytest.mark.parametrize("name,value", [
    ("status", "OK"), ("build", True), ("version", "v7.0.1"), ("http_method", "POST"),
    ("http_status", 201), ("serial", "FPAVOTHER0001"), ("mkey", "mcp-v4-other-profile"),
    ("name", "database"), ("path", "other"), ("vdom", "other"), ("unknown", "extra"),
])
def test_profile_envelope_denial_and_logout(name: str, value: object) -> None:
    payload = _profile_payload()
    payload[name] = value
    reader, owner = _profile_reader(payload)
    with pytest.raises(SecretApprovalBuild29MetadataReaderError):
        reader.readback(_PROFILE)
    assert owner.logout_verified and owner._client is None


@pytest.mark.parametrize("name,value", [
    ("field", None), ("field", [{"value": "synthetic-material"}]),
    ("first-num", True), ("first-user", [{"name": "other"}]), ("second-user", [{"name": "other"}]),
    ("self-approval", "enable"), ("auto-approval-schedule", "future"), ("max-allowed-duration", False),
    ("remote-group-email", "enable"), ("email-template", "future"), ("approver-perm-req", "read"),
    ("name", "mcp-v4-other-profile"), ("q_origin_key", "mcp-v4-other-profile"),
])
def test_profile_exact_empty_custom_fields_and_semantics(name: str, value: object) -> None:
    payload = _profile_payload()
    payload["results"][0][name] = value
    reader, owner = _profile_reader(payload)
    with pytest.raises(SecretApprovalBuild29MetadataReaderError):
        reader.readback(_PROFILE)
    assert owner.logout_verified


def test_profile_unique_raw_empty_field_and_required_members() -> None:
    reader, owner = _profile_reader()
    owner.client.response.raw = owner.client.response.raw.replace(b'"field": []', b'"field": [], "field": []')
    with pytest.raises(SecretApprovalBuild29MetadataReaderError):
        reader.readback(_PROFILE)
    payload = _profile_payload()
    del payload["results"][0]["first-group"]
    owner.client.response.raw = json.dumps(payload).encode()
    with pytest.raises(SecretApprovalBuild29MetadataReaderError):
        reader.readback(_PROFILE)


def test_fixed_profile_selector_and_logout_are_required() -> None:
    reader, owner = _profile_reader()
    with pytest.raises(SecretApprovalBuild29MetadataReaderError):
        reader.readback("mcp-v4-other-profile")
    assert owner.authentications == 0
    owner.logout_result = False
    with pytest.raises(SecretApprovalBuild29MetadataReaderError):
        reader.readback(_PROFILE)


def test_secret_fixed_categorical_getter_never_calls_material_or_transition_producers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader, owner = _secret_reader()

    def forbidden(*args: object, **kwargs: object) -> object:
        raise AssertionError("No transition or material producers are available.")

    monkeypatch.setattr(reader._transport, "inspect_transition", forbidden)
    monkeypatch.setattr(reader._transport, "_read_transition", forbidden)
    result = _read_secret(reader)
    assert asdict(result) == {"secret_exists": True, "interactive_approval_required": False,
                              "job_approval_required": False, "owner_bypass_allowed": False,
                              "approval_profile_matches": False, "approval_profile_unset": True,
                              "field_values_attached": True}
    assert owner.client.calls == [("GET", "/api/v2/cmdb/secret/database/24")]
    assert owner.logout_verified and owner._client is None
    assert _NAME not in repr(result) and "CIPHERTEXT" not in repr(result)


def test_all_known_material_is_wiped_before_metadata_json_decoding(monkeypatch: pytest.MonkeyPatch) -> None:
    original = json.loads
    watched: list[bytearray] = []
    original_wipe = module._zeroize_mutable

    def guarded(raw: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(raw, (bytes, bytearray)):
            assert b"unit-password" not in raw and b"unit-keyinfo" not in raw
            assert b"UNIT-TOTP-CIPHERTEXT" not in raw
        return original(raw, *args, **kwargs)

    def wipe(raw: bytearray) -> None:
        watched.append(raw)
        original_wipe(raw)

    monkeypatch.setattr(module.json, "loads", guarded)
    monkeypatch.setattr(module, "_zeroize_mutable", wipe)
    reader, owner = _secret_reader()
    _read_secret(reader)
    profile, _ = _profile_reader()
    profile.readback(_PROFILE)
    assert watched and all(not raw for raw in watched)
    assert owner.logout_verified


@pytest.mark.parametrize("changes", [
    {"folder_path": "Public/other"}, {"secret_name": "mcp-v4-other"},
    {"approval_profile_name": "mcp-v4-approval-profile-other"}, {"expected_secret_id": 25},
    {"expected_secret_id": True},
])
def test_secret_selector_denial_is_before_login(changes: dict[str, object]) -> None:
    reader, owner = _secret_reader()
    with pytest.raises(SecretApprovalBuild29MetadataReaderError):
        _read_secret(reader, **changes)
    assert owner.authentications == 0 and not owner.client.calls


@pytest.mark.parametrize("name,value", [
    ("template", "Windows Machine"), ("target", "mcp-v4-target-other"),
    ("totp-setting", {"status": "enable", "shared-key": "ENC UNIT-TOTP-CIPHERTEXT"}),
    ("totp-setting", {"status": False}), ("approval-profile", "mcp-v4-approval-profile-other"),
    ("need-approval", "unknown"), ("id", 25), ("field", None),
])
def test_secret_compatible_metadata_and_bound_profile_required(name: str, value: object) -> None:
    payload = _secret_payload()
    payload["results"][0][name] = value
    reader, owner = _secret_reader(payload)
    with pytest.raises(SecretApprovalBuild29MetadataReaderError):
        _read_secret(reader)
    assert owner.logout_verified and owner._client is None


def test_secret_transport_envelope_and_logout_are_not_bypassed() -> None:
    payload = _secret_payload()
    payload["serial"] = "FPAVOTHER0001"
    reader, owner = _secret_reader(payload)
    with pytest.raises(SecretApprovalBuild29MetadataReaderError):
        _read_secret(reader)
    assert owner.logout_verified
    reader, owner = _secret_reader()
    owner.logout_result = False
    with pytest.raises(SecretApprovalBuild29MetadataReaderError):
        _read_secret(reader)


def test_bound_profile_matches_is_a_categorical_read_not_material_qualification() -> None:
    payload = _secret_payload()
    payload["results"][0].update({"approval-profile": _PROFILE, "need-approval": "enable"})
    reader, _ = _secret_reader(payload)
    result = _read_secret(reader)
    assert result.approval_profile_matches and result.interactive_approval_required
    assert not result.approval_profile_unset


def test_profile_http_type_size_and_active_deadline_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    reader, owner = _profile_reader()
    owner.client.response.headers["content-type"] = "text/json"
    with pytest.raises(SecretApprovalBuild29MetadataReaderError):
        reader.readback(_PROFILE)
    reader, owner = _profile_reader()
    monkeypatch.setattr(module, "MAX_RESPONSE_BYTES", 8)
    with pytest.raises(SecretApprovalBuild29MetadataReaderError):
        reader.readback(_PROFILE)
    reader, owner = _profile_reader()
    with owner.authenticated():
        owner._expires_at = 1.0
        with pytest.raises(SecretApprovalBuild29MetadataReaderError):
            reader.current_configuration_digest()
    assert not owner.client.calls


@pytest.mark.parametrize("enabled", [False, True])
def test_explicit_linux_projection_uses_bound_metadata_observer(tmp_path: Any, enabled: bool) -> None:
    from test_secret_approval_build29_http_transport import _linux_payload, _linux_transport
    payload = _linux_payload()
    if enabled:
        payload["results"][0].update({"need-approval": "enable", "approval-profile": _PROFILE})
    owner = _Owner(payload)
    reader = SecretApprovalBuild29ProjectionReader(_linux_transport(owner, tmp_path))
    result = _read_secret(reader)
    assert result.interactive_approval_required is enabled
    assert owner.logout_verified
    default_reader, _ = _secret_reader(payload)
    with pytest.raises(SecretApprovalBuild29MetadataReaderError):
        _read_secret(default_reader)
