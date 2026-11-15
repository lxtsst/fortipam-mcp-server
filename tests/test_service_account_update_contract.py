"""Fixed native update-check body is not a service operation or permission."""
import json

import pytest

from fortipam_mcp import service_account_update_contract as contract


def test_update_check_is_fixed_and_does_not_decode_or_return_binding_values(monkeypatch):
    binding = contract.ServiceAccountUpdateBinding(123456, 7, "a" * 64)
    def forbidden(*args, **kwargs):
        raise AssertionError("No decoder or command executor may be used.")
    monkeypatch.setattr(json, "loads", forbidden)
    body = contract.compile_native_service_account_update(binding)
    try:
        assert body == b'{"secret-id":123456,"dep-id":7,"action":3}'
        assert type(body) is bytearray
        assert "123456" not in repr(binding) and "redacted" in repr(binding)
        summary = contract.service_account_update_source_boundary()
        assert "123456" not in json.dumps(summary)
        assert summary["check_is_metadata_only"] is False
        assert summary["request_contains_credential_fields"] is False
        assert summary["server_side_material_use_qualified"] is False
        assert summary["execution_authorized"] is summary["runtime_registered"] is False
    finally:
        body[:] = b"\0" * len(body)


@pytest.mark.parametrize("field,value", [(name, value)
    for name in ("secret_id", "dependency_id")
    for value in (True, False, 0, -1, 2_147_483_648, "1", 1.0, None)])
def test_identifier_types_and_bounds_fail_with_value_free_error(field, value):
    fields = dict(secret_id=1, dependency_id=1, dependency_context_digest="b" * 64)
    fields[field] = value
    with pytest.raises(contract.ServiceAccountUpdateContractError) as caught:
        contract.ServiceAccountUpdateBinding(**fields)
    assert str(caught.value) == "The private service-account update request is unavailable."


@pytest.mark.parametrize("digest", [None, "", "A" * 64, "a" * 63, "a" * 65, "g" * 64])
def test_unbound_or_noncanonical_context_is_rejected(digest):
    with pytest.raises(contract.ServiceAccountUpdateContractError):
        contract.ServiceAccountUpdateBinding(1, 1, digest)


def test_maximum_native_ids_and_object_tamper_or_action_injection():
    binding = contract.ServiceAccountUpdateBinding(2_147_483_647, 64, "c" * 64)
    assert contract.compile_native_service_account_update(binding) == b'{"secret-id":2147483647,"dep-id":64,"action":3}'
    with pytest.raises(contract.ServiceAccountUpdateContractError):
        contract.ServiceAccountUpdateBinding(1, 65, "c" * 64)
    with pytest.raises(TypeError):
        contract.compile_native_service_account_update(binding, action=6)
    object.__setattr__(binding, "dependency_id", True)
    with pytest.raises(contract.ServiceAccountUpdateContractError):
        contract.compile_native_service_account_update(binding)
    with pytest.raises(contract.ServiceAccountUpdateContractError):
        contract.compile_native_service_account_update({"secret-id": 1, "dep-id": 1, "action": 6})
