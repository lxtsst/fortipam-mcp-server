"""Full strict local MFA state comparisons, without native qualification."""
from dataclasses import replace
import json

import pytest

from fortipam_mcp.fortitoken_user_contract import FortitokenUserPlan, expected_fortitoken_user_state
from test_fortitoken_user_contract import TOKEN
from test_fortitoken_user_source import Peer


def apply(peer,body):
    values = json.loads(body)
    for name,value in values.items():
        if name == '$originalName': continue
        if name == 'webauthn': peer.user[name].update(value)
        else: peer.user[name] = value


def compile_and_apply(peer,source,plan):
    with memoryview(TOKEN) as token: body = source.compile_body(plan,token_reference_digest='a'*64,token=token)
    try: apply(peer,body)
    finally: body[:] = b'\0'*len(body)


def test_presence_and_complete_nonmaterial_equality_cannot_replace_a_private_token_match():
    peer = Peer(); source = peer.reader(); plan = FortitokenUserPlan(source.read().state,'assign')
    compile_and_apply(peer,source,plan); observed = source.read()
    assert observed.state.digest == expected_fortitoken_user_state(plan).digest and not observed.token_reference_matched
    with pytest.raises(ValueError,match='unavailable'): source.verify_postcondition(plan,observed)
    with memoryview(TOKEN) as token: matched = source.read_matching_token(token_reference_digest='a'*64,token=token)
    assert matched.token_reference_matched
    source.verify_postcondition(plan,matched)
    assert source.preview('revoke')['complete_postcondition_qualified'] is False


@pytest.mark.parametrize('fault', ['foreign-observation','cloned-plan','expired'])
def test_postcondition_requires_the_actual_compilation_and_current_source_observation(fault):
    peer = Peer('revoke'); source = peer.reader(); plan = FortitokenUserPlan(source.read().state,'revoke')
    compile_and_apply(peer,source,plan); observed = source.read()
    if fault == 'foreign-observation': observed = peer.reader().read()
    elif fault == 'cloned-plan': plan = replace(plan)
    else: peer.clock.value = 1010
    with pytest.raises(ValueError,match='unavailable'): source.verify_postcondition(plan,observed)


@pytest.mark.parametrize('field,value', [('two-factor-authentication','email'),('email-to','changed'),
    ('two-factor-notification','sms'),('gui-ignore-release-overview-version','changed')])
def test_revoke_does_not_ignore_omitted_authentication_or_unsubmitted_field_drift(field,value):
    peer = Peer('revoke'); source = peer.reader(); plan = FortitokenUserPlan(source.read().state,'revoke')
    compile_and_apply(peer,source,plan); peer.user[field] = value
    with pytest.raises(ValueError,match='unavailable'): source.verify_postcondition(plan,source.read())


@pytest.mark.parametrize('fault', ['reference','value'])
def test_private_matching_refuses_wrong_context_or_selector_without_publishing(fault):
    peer = Peer('revoke'); source = peer.reader(); original = source.read(); calls = len(peer.calls)
    with memoryview(TOKEN if fault == 'reference' else b'SYNTHETIC_OTHER_TOKEN') as token:
        with pytest.raises(ValueError,match='unavailable'):
            source.read_matching_token(token_reference_digest='f'*64 if fault == 'reference' else 'a'*64,token=token)
    assert source._latest is original and len(peer.calls)-calls == (0 if fault == 'reference' else 2)
    assert all(not any(raw) for raw in peer.buffers)


def test_strict_local_inverse_matches_full_original_only_when_cached_authentication_is_preserved():
    for initial_authentication in ('fortitoken','email'):
        peer = Peer(); peer.user['two-factor-authentication'] = initial_authentication
        source = peer.reader(); original = source.read().state; plan = FortitokenUserPlan(original,'assign')
        compile_and_apply(peer,source,plan)
        with memoryview(TOKEN) as token: assigned = source.read_matching_token(token_reference_digest='a'*64,token=token)
        source.verify_postcondition(plan,assigned)
        inverse = FortitokenUserPlan(assigned.state,'revoke'); compile_and_apply(peer,source,inverse)
        restored = source.read(); source.verify_postcondition(inverse,restored)
        assert (restored.state.digest == original.digest) is (initial_authentication == 'fortitoken')
        if initial_authentication == 'fortitoken': source.verify_original_nonmaterial_state(plan,restored)
        else:
            with pytest.raises(ValueError,match='unavailable'): source.verify_original_nonmaterial_state(plan,restored)
        assert not restored.token_reference_matched and not restored.state.token_present


def test_original_populated_selector_requires_a_fresh_private_match_after_rebinding():
    peer = Peer('revoke'); source = peer.reader(); original = FortitokenUserPlan(source.read().state,'revoke')
    compile_and_apply(peer,source,original); empty = source.read()
    inverse = FortitokenUserPlan(empty.state,'assign'); compile_and_apply(peer,source,inverse)
    ordinary = source.read()
    assert ordinary.state.digest == original.current.digest
    with pytest.raises(ValueError,match='unavailable'): source.verify_original_nonmaterial_state(original,ordinary)
    with memoryview(TOKEN) as token: matched = source.read_matching_token(token_reference_digest='a'*64,token=token)
    source.verify_original_nonmaterial_state(original,matched)
    assert source.preview('revoke')['independent_recovery_verified'] is False
