"""Independent cleanup of synthetic private frames and temporary projections."""
import hashlib
import json

import pytest

from fortipam_mcp import local_user_reset_projection as user
from fortipam_mcp import policy_assignment_preservation as policy
from fortipam_mcp import secret_instruction_build29_api_preservation as instruction


def case(kind, valid):
    if kind == 'user':
        from test_local_user_reset_projection import _case, _body, NAME
        schema, record = _case()
        raw = _body(record) if valid else bytearray(b'SYNTHETIC_UNPARSED_PRIVATE_USER_FRAME')
        return user, raw, lambda: user.project_local_user_reset_detail(raw, schema, expected_username=NAME)
    if kind == 'policy':
        import test_policy_assignment_preservation as fixture
        raw = bytearray(json.dumps(fixture.source()).encode()) if valid else bytearray(b'SYNTHETIC_UNPARSED_PRIVATE_SECRET_FRAME')
        kwargs = dict(identity=fixture.IDENTITY, serial_digest=fixture.SERIAL_DIGEST,
            expected_policy_name='synthetic-policy-a', credential_before=fixture.credential(),
            credential_after=fixture.credential(), totp_before=fixture.totp(), totp_after=fixture.totp(), witness_key=fixture.KEY)
        return policy, raw, lambda: policy.consume_policy_assignment_preservation(raw, **kwargs)
    import test_secret_instruction_build29_api_preservation as fixture
    raw = fixture._raw(fixture._source()) if valid else bytearray(b'SYNTHETIC_UNPARSED_PRIVATE_SECRET_FRAME')
    kwargs = dict(identity=fixture.IDENTITY, serial_digest=hashlib.sha256(fixture.SERIAL.encode()).hexdigest(),
        instruction_profile_name='', credential_before=fixture._credential(), credential_after=fixture._credential(),
        totp_before=fixture._totp(), totp_after=fixture._totp(), witness_key=fixture.KEY)
    return instruction, raw, lambda: instruction.consume_secret_instruction_build29_api_preservation(raw, **kwargs)


@pytest.mark.parametrize('kind', ['policy', 'instruction', 'user'])
@pytest.mark.parametrize('valid', [False, True])
@pytest.mark.parametrize('error_type', [MemoryError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_first_cleanup_failure_still_erases_owned_input_and_never_publishes(monkeypatch, kind, valid, error_type):
    module, raw, consume = case(kind, valid)
    erase = module._zeroize_mutable
    retained = []
    def fail_first(buffer):
        retained.append(buffer)
        erase(buffer)
        if len(retained) == 1: raise error_type('Synthetic first-cleanup failure')
    monkeypatch.setattr(module, '_zeroize_mutable', fail_first)
    try:
        with pytest.raises(error_type): consume()
        assert len(retained) == 2 and retained[-1] is raw
        assert not any(raw) and all(not any(buffer) for buffer in retained)
    finally:
        # Keep a failing regression from retaining even synthetic test inputs.
        erase(raw)


@pytest.mark.parametrize('kind', ['policy', 'instruction', 'user'])
def test_secondary_cleanup_failure_also_leaves_both_owned_buffers_erased(monkeypatch, kind):
    module, raw, consume = case(kind, True)
    erase = module._zeroize_mutable
    retained = []
    def fail_second(buffer):
        retained.append(buffer); erase(buffer)
        if len(retained) == 2: raise KeyboardInterrupt('Synthetic secondary cleanup interruption')
    monkeypatch.setattr(module, '_zeroize_mutable', fail_second)
    with pytest.raises(KeyboardInterrupt): consume()
    assert len(retained) == 2 and not any(raw) and all(not any(buffer) for buffer in retained)
