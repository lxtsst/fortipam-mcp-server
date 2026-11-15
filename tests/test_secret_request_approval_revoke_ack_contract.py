"""Synthetic offline checks for the exact qualified native withdrawal ACK."""

from dataclasses import FrozenInstanceError, replace
import json

import pytest

from fortipam_mcp.secret_metadata_http_transport import MAX_RESPONSE_BYTES
from fortipam_mcp.secret_request_approval_revoke_ack_contract import (
    SecretRequestApprovalRevokeAckContractError,
    qualify_secret_request_approval_revoke_ack,
)
from fortipam_mcp.secret_request_approval_revoke_detail_contract import (
    SecretRequestApprovalRevokeDetailBinding,
)

_BINDING = SecretRequestApprovalRevokeDetailBinding(
    19, 7, "synthetic-requester", "synthetic-profile", "synthetic-reviewer", "SYNTHETIC29",
)
_ACK = {
    "status": "OK", "http_status": 200, "msg": "Successfully deleted approval entry",
    "http_method": "DELETE", "vdom": "", "path": "secret", "name": "request-approval",
}


def _qualify(raw: object = None, **kwargs: object):
    options = {"http_status": 200, "binding": _BINDING,
               "authenticated_reviewer": "synthetic-reviewer", **kwargs}
    return qualify_secret_request_approval_revoke_ack(
        json.dumps(_ACK).encode() if raw is None else raw, **options,
    )


def test_exact_ack_is_private_immutable_and_binds_original_identity() -> None:
    witness = _qualify()
    assert len(witness.private_binding_digest) == len(witness.private_native_ack_digest) == 64
    assert "synthetic" not in repr(witness) and _ACK["msg"] not in repr(witness)
    assert not hasattr(witness, "msg") and not hasattr(witness, "dispatch_allowed")
    with pytest.raises(FrozenInstanceError):
        witness.private_native_ack_digest = "changed"
    altered = _qualify(binding=replace(_BINDING, request_id=20))
    assert altered.private_binding_digest != witness.private_binding_digest
    assert altered.private_native_ack_digest == witness.private_native_ack_digest
    raw = bytearray(json.dumps(_ACK).encode())
    before = bytes(raw)
    assert _qualify(raw) == witness and bytes(raw) == before


@pytest.mark.parametrize("key,value", [
    ("status", "success"), ("status", True), ("http_status", 201),
    ("http_status", "200"), ("http_status", 200.0), ("http_status", True),
    ("http_method", "POST"), ("http_method", "delete"), ("path", "system"),
    ("name", "request"), ("vdom", "root"), ("vdom", None),
    ("msg", "SYNTHETIC_PRIVATE_UNKNOWN"), ("msg", ""), ("msg", None),
    ("msg", {"value": "SYNTHETIC_PRIVATE_UNKNOWN"}),
])
def test_envelope_drift_is_refused_without_response_text(key: str, value: object) -> None:
    raw = json.dumps({**_ACK, key: value}).encode()
    with pytest.raises(SecretRequestApprovalRevokeAckContractError) as error:
        _qualify(raw)
    assert str(error.value) == "The fixed Launcher Request withdrawal acknowledgement is unavailable."
    assert "SYNTHETIC_PRIVATE_UNKNOWN" not in repr(error.value)


@pytest.mark.parametrize("key", list(_ACK))
def test_each_missing_or_duplicate_member_is_refused(key: str) -> None:
    with pytest.raises(SecretRequestApprovalRevokeAckContractError):
        _qualify(json.dumps({k: v for k, v in _ACK.items() if k != key}).encode())
    duplicate = json.dumps(_ACK)[:-1] + "," + json.dumps(key) + ":" + json.dumps(_ACK[key]) + "}"
    with pytest.raises(SecretRequestApprovalRevokeAckContractError):
        _qualify(duplicate.encode())


@pytest.mark.parametrize("kwargs", [
    {"http_status": 201}, {"http_status": 403}, {"http_status": True},
    {"http_status": 200.0}, {"http_status": "200"}, {"binding": {}},
    {"authenticated_reviewer": "synthetic-requester"}, {"authenticated_reviewer": True},
])
def test_transport_status_and_identity_are_exact(kwargs: dict) -> None:
    with pytest.raises(SecretRequestApprovalRevokeAckContractError):
        _qualify(**kwargs)


@pytest.mark.parametrize("raw", [
    b"", b"[]", b"null", b"{} trailing", b'{"msg":NaN}', b'{"msg":"\xff"}',
    b"{" + b" " * MAX_RESPONSE_BYTES, b'{"status":"OK",}',
    json.dumps({**_ACK, "unknown": "SYNTHETIC_PRIVATE_UNKNOWN"}).encode(),
    json.dumps(_ACK).encode()[:-1] + b',"\\u0073tatus":"OK"}',
    json.dumps(_ACK),
])
def test_unsafe_json_unknown_keys_and_escaped_duplicates_fail_closed(raw: object) -> None:
    with pytest.raises(SecretRequestApprovalRevokeAckContractError):
        _qualify(raw)


def test_unknown_nested_material_never_reaches_value_decoder(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = json.dumps({**_ACK, "field": [{"value": "SYNTHETIC_PRIVATE_UNKNOWN"}]}).encode()
    loads = json.loads

    def safe_loads(value, *args, **kwargs):
        assert "SYNTHETIC_PRIVATE_UNKNOWN" not in str(value)
        return loads(value, *args, **kwargs)

    monkeypatch.setattr(json, "loads", safe_loads)
    with pytest.raises(SecretRequestApprovalRevokeAckContractError):
        _qualify(raw)
