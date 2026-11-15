"""Independent protected invocation joins; no live device or credentials."""
from dataclasses import replace

import pytest

from fortipam_mcp.secret_request_approval_revoke_continuity import (
    SecretRequestApprovalRevokeContinuityError,
    qualify_secret_request_approval_revoke_with_invocation,
)
from fortipam_mcp.secret_request_create_invocation_witness import SecretRequestCreateInvocationWitness
from test_secret_request_approval_revoke_continuity import _fixture, _signed, _KEY


def _invocation(payload, expected):
    return SecretRequestCreateInvocationWitness(
        intent_ref="synthetic-original-intent",
        requester_digest=expected.requester_digest,
        transport_digest=expected.transport_digest,
        fortipam_requester=expected.binding.requester,
        environment_ref=expected.environment_ref,
        scope_ref=expected.scope_ref,
        created_record=expected.created_record,
        create_started_at=payload["create_started_at"],
        create_finished_at=payload["create_finished_at"],
        create_claim_digest="e" * 64,
    )


def test_original_invocation_and_signed_continuity_join():
    payload, expected = _fixture()
    result = qualify_secret_request_approval_revoke_with_invocation(
        _signed(payload), verification_key=_KEY, expected=expected,
        invocation=_invocation(payload, expected),
    )
    assert result.private_continuity_digest
    assert not hasattr(result, "authorized")


@pytest.mark.parametrize("field,value", [
    ("requester_digest", "c" * 64), ("transport_digest", "d" * 64),
    ("fortipam_requester", "other-requester"), ("environment_ref", "other-environment"),
    ("scope_ref", "other-scope"), ("create_started_at", None), ("create_finished_at", None),
])
def test_validly_signed_continuity_cannot_replace_independent_invocation(field, value):
    payload, expected = _fixture()
    original = _invocation(payload, expected)
    if value is None:
        value = getattr(original, field) + 0.25
    invocation = replace(original, **{field: value})
    with pytest.raises(SecretRequestApprovalRevokeContinuityError):
        qualify_secret_request_approval_revoke_with_invocation(
            _signed(payload), verification_key=_KEY, expected=expected, invocation=invocation,
        )


def test_different_created_result_is_not_same_invocation():
    payload, expected = _fixture()
    invocation = replace(_invocation(payload, expected), created_record=replace(expected.created_record, request_id=20))
    with pytest.raises(SecretRequestApprovalRevokeContinuityError):
        qualify_secret_request_approval_revoke_with_invocation(
            _signed(payload), verification_key=_KEY, expected=expected, invocation=invocation,
        )


def test_independently_signed_store_survives_restart_and_binds_continuity(tmp_path):
    from fortipam_mcp.secret_request_create_invocation_witness import (
        OwnerOnlySecretRequestCreateInvocationWitnessStore,
        SecretRequestCreateInvocationWitnessError,
    )
    tmp_path.chmod(0o700)
    payload, expected = _fixture()
    path = tmp_path / "original-invocation.json"
    witness_key = b"i" * 32
    assert witness_key != _KEY
    OwnerOnlySecretRequestCreateInvocationWitnessStore(path, witness_key).publish(_invocation(payload, expected))
    loaded = OwnerOnlySecretRequestCreateInvocationWitnessStore(path, witness_key).load()
    qualified = qualify_secret_request_approval_revoke_with_invocation(
        _signed(payload), verification_key=_KEY, expected=expected, invocation=loaded,
    )
    assert qualified.private_continuity_digest
    with pytest.raises(SecretRequestCreateInvocationWitnessError):
        OwnerOnlySecretRequestCreateInvocationWitnessStore(path, _KEY).load()
