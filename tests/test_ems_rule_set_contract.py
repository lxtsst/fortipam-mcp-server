"""Synthetic fixed request profiles, not Rule Set native or response qualification."""
import copy
from dataclasses import replace
import json
import pickle

import pytest

from fortipam_mcp.ems_rule_set_contract import (DisabledProcessRuleSetRequest,SingleRuleSetDeleteRequest,
    rule_set_detail_path,rule_set_request_boundary)
from fortipam_mcp.ems_tag_contract import DisabledLinuxProcessTag
from v4_planning.material_provider import MaterialAccessDenied

NONCE='12'*16


def test_disabled_create_preserves_qualified_process_profile_without_tag_create_fields():
    draft=DisabledLinuxProcessTag(NONCE); request=DisabledProcessRuleSetRequest(42,draft); raw=request._compile()
    try:
        body=json.loads(raw)
        assert set(body)=={'status','tag','rules','use_custom_logic','comments'}
        assert body['status'] is body['use_custom_logic'] is False and body['tag']==42
        assert body['rules']==draft._body['rules'] and 'match_type_id' not in body['rules'][0]
        assert body['comments']==draft._body['comments']
    finally: raw[:]=b'\0'*len(raw)
    assert request.parameters_digest!=replace(request,_tag_id=43).parameters_digest
    assert request.parameters_digest!=replace(request,_draft=DisabledLinuxProcessTag('34'*16)).parameters_digest


def test_delete_has_one_exact_rule_set_id_and_no_tag_recovery_route_or_body():
    request=SingleRuleSetDeleteRequest(42); raw=request._compile()
    try: assert json.loads(raw)=={'ids':[42]}
    finally: raw[:]=b'\0'*len(raw)
    assert request.parameters_digest!=replace(request,_rule_set_id=43).parameters_digest
    assert request.parameters_digest!=DisabledProcessRuleSetRequest(42,DisabledLinuxProcessTag(NONCE)).parameters_digest


@pytest.mark.parametrize('identifier',[0,-1,True,False,1.0,'42','1/get?offset=0',[],{},None,2147483648])
def test_untrusted_selectors_cannot_become_paths_or_request_ids(identifier):
    for build in (rule_set_detail_path,SingleRuleSetDeleteRequest,lambda value:DisabledProcessRuleSetRequest(value,DisabledLinuxProcessTag(NONCE))):
        with pytest.raises(ValueError) as error: build(identifier)
        assert str(identifier) not in str(error.value)


@pytest.mark.parametrize('value',[None,{},'SYNTHETIC_PRIVATE_INPUT'])
def test_create_rejects_a_caller_defined_rule_or_draft(value):
    with pytest.raises(ValueError) as error: DisabledProcessRuleSetRequest(42,value)
    assert 'SYNTHETIC_PRIVATE_INPUT' not in str(error.value)


def test_compile_returns_fresh_owned_bytes_and_revalidates_frozen_selector():
    request=SingleRuleSetDeleteRequest(42); first=request._compile(); digest=request.parameters_digest
    first[:]=b'X'*len(first)
    second=request._compile()
    try: assert json.loads(second)=={'ids':[42]} and request.parameters_digest==digest
    finally: first[:]=b'\0'*len(first); second[:]=b'\0'*len(second)
    object.__setattr__(request,'_rule_set_id',True)
    with pytest.raises(ValueError): request._compile()
    with pytest.raises(ValueError): request.parameters_digest


def test_request_factories_cannot_supply_authority_response_or_ownership():
    boundary=rule_set_request_boundary()
    assert boundary['create_requires_empty_original_owned_tag_linkage'] and boundary['delete_requires_original_birth_and_fresh_no_usage']
    assert boundary['tag_association_or_rule_evaluation_may_change'] and boundary['disabled_does_not_prove_no_access_effect']
    for key in ('execution_authorized','device_contacted','response_contract_verified','native_rule_set_behavior_verified',
            'source_or_request_grants_authority','implicit_cascade_cleanup_verified','old_tag_post_recovery_reinterpreted'):
        assert boundary[key] is False
    assert NONCE not in json.dumps(boundary) and '/api/' not in json.dumps(boundary)


@pytest.mark.parametrize('candidate',[SingleRuleSetDeleteRequest(42),DisabledProcessRuleSetRequest(42,DisabledLinuxProcessTag(NONCE))])
def test_private_requests_never_offer_copy_or_pickle_material_surfaces(candidate):
    assert NONCE not in str(candidate) and '42' not in repr(candidate)
    for operation in (copy.copy,copy.deepcopy,pickle.dumps):
        with pytest.raises(MaterialAccessDenied): operation(candidate)
