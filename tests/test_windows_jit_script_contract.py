"""Fixed definition-only JIT contracts with synthetic API envelopes."""
from copy import deepcopy
import json

import pytest

from fortipam_mcp.windows_jit_script_contract import (compile_windows_jit_script_pair,
    preview_windows_jit_script_pair, windows_jit_script_pair_matches)
from test_checkout_script_contract import DEFAULT, envelope


def test_fixed_pair_reuses_native_api_fields_without_mutating_default_or_accepting_commands():
    before = deepcopy(DEFAULT); grant,revoke = compile_windows_jit_script_pair(DEFAULT,nonce='01234567')
    assert set(grant) == set(revoke) == set(DEFAULT['results']) and 'comment' not in grant
    assert grant['type'] == revoke['type'] == 'powershell' and grant['log-trigger'] == revoke['log-trigger'] == 'any'
    assert grant['script'] == 'Add-LocalGroupMember -Group Administrators -Member $USER'
    assert revoke['script'] == 'Remove-LocalGroupMember -Group Administrators -Member $USER'
    assert windows_jit_script_pair_matches(DEFAULT,envelope(grant),envelope([revoke]),nonce='01234567')
    assert DEFAULT == before
    grant['script'] = 'SYNTHETIC_UNAPPROVED_COMMAND'
    assert compile_windows_jit_script_pair(DEFAULT,nonce='01234567')[0]['script'] != grant['script']


@pytest.mark.parametrize('nonce', ['', '0123456','012345678','DEADBEEF','01234567;whoami',None,123])
def test_only_one_fixed_disposable_pair_name_domain_is_accepted(nonce):
    with pytest.raises(ValueError,match='^The private Windows JIT Script pair is unavailable.$'):
        compile_windows_jit_script_pair(DEFAULT,nonce=nonce)


@pytest.mark.parametrize('fault', ['version','build','method','status','nonblank','type','singular-comment','extra-field'])
def test_foreign_or_changed_native_default_does_not_create_a_candidate(fault):
    default = deepcopy(DEFAULT)
    if fault == 'version': default['version'] = 'v1.9.1'
    elif fault == 'build': default['build'] = True
    elif fault == 'method': default['http_method'] = 'POST'
    elif fault == 'status': default['status'] = 'OK'
    elif fault == 'nonblank': default['results']['script'] = 'SYNTHETIC_UNAPPROVED_COMMAND'
    elif fault == 'type': default['results']['type'] = 'ssh-script'
    elif fault == 'singular-comment': default['results']['comment'] = default['results'].pop('comments')
    else: default['results']['secret'] = 'SYNTHETIC_FORBIDDEN_MATERIAL'
    with pytest.raises(ValueError,match='unavailable'): compile_windows_jit_script_pair(default,nonce='01234567')


@pytest.mark.parametrize('field,value', [('name','MCPV4JitGrant89abcdef'),('type','ssh-script'),('comments','changed'),
    ('script','Add-ADGroupMember -Identity "Domain Admins" -Members $USER'),('expect-type','failure'),
    ('expect-string','SYNTHETIC_MARKER'),('log-trigger','failure'),('comment','')])
def test_drifted_definition_or_domain_scope_never_matches_the_fixed_pair(field,value):
    grant,revoke = compile_windows_jit_script_pair(DEFAULT,nonce='01234567'); grant[field] = value
    assert not windows_jit_script_pair_matches(DEFAULT,envelope(grant),envelope(revoke),nonce='01234567')


def test_swapped_duplicate_or_missing_definition_cannot_prove_pair_readback():
    grant,revoke = compile_windows_jit_script_pair(DEFAULT,nonce='01234567')
    for left,right in ((envelope(revoke),envelope(grant)),(envelope([grant,grant]),envelope(revoke)),
        (envelope(grant),envelope([])),(envelope(grant),envelope(grant))):
        assert not windows_jit_script_pair_matches(DEFAULT,left,right,nonce='01234567')


def test_preview_has_no_selectors_commands_or_effect_authority_from_successful_definition_match():
    grant,revoke = compile_windows_jit_script_pair(DEFAULT,nonce='01234567')
    assert windows_jit_script_pair_matches(DEFAULT,envelope(grant),envelope(revoke),nonce='01234567')
    public = preview_windows_jit_script_pair(DEFAULT,nonce='01234567'); text = json.dumps(public)
    assert all(value not in text for value in (grant['name'],revoke['name'],'01234567','$USER','Add-LocalGroupMember'))
    assert not public['execution_authorized'] and not public['native_backend_qualified']
    assert not public['configuration_ready'] and not public['secret_jit_policy_configured']
    assert not public['script_result_qualified'] and not public['jit_privilege_effect_verified']
    assert public['Security Changes']['scripts_define_administrator_membership_mutations']
    assert not public['Security Changes']['script_failure_blocks_checkout']
    assert not public['Security Changes']['existing_logon_privilege_removed_by_group_removal']
