"""Explicit Folder drafts never inherit the accepted inherited Folder authority."""
from dataclasses import replace
import hashlib
import json

import pytest

from fortipam_mcp.folder_http_transport import _isolated_child_body
from fortipam_mcp.windows_execution_folder_contract import (
    WindowsExecutionFolderBinding, WindowsExecutionFolderError, compile_windows_execution_folder,
    consume_windows_execution_folder_state, consume_windows_execution_policy_link,
    consume_windows_execution_folder_ack,
)
from fortipam_mcp.windows_execution_policy_contract import CANONICAL_PROFILE, compile_windows_execution_policy, consume_windows_policy_state
from test_windows_execution_policy_contract import (
    BINDING as POLICY, sources as policy_sources, envelope as policy_envelope, backend_normalized_state,
)

OWNER = 'synthetic-owner'
NAME = 'mcp-v4-winexec-explicit-20261022-r1'


def binding():
    policy = compile_windows_execution_policy(*policy_sources(native=True), binding=POLICY, profile=CANONICAL_PROFILE)
    state = consume_windows_policy_state(backend_normalized_state(), request=policy)
    return WindowsExecutionFolderBinding(NAME, 17, OWNER, 'a'*64, policy, 'b'*64, state, 'c'*64)


def defaults():
    return {'id':0, 'name':'', 'parent-folder':0, 'folder-type':'public', 'inherit-policy':'enable',
        'secret-policy':'', 'inherit-permission':'enable', 'inherit-folder-ztna':'enable',
        'ztna-tags-match-logic':'or', 'ztna-ems-tag':[], 'user-permission':[], 'group-permission':[]}


def sources():
    values = defaults()
    def field(kind):return {'type':kind}
    def table(key, children):return {'mkey':key, 'children':children}
    fields = {key:field('integer' if key in ('id', 'parent-folder')
        else 'string' if key in ('name', 'secret-policy') else 'option') for key in values}
    for key, principal in (('user-permission', 'user-name'), ('group-permission', 'group-name')):
        fields[key] = table('id', {'id':field('integer'), principal:table('name', {'name':field('string')}),
            'folder-permission':field('option'), 'secret-permission':field('option'), 'allowed-launcher-type':field('option')})
    fields['ztna-ems-tag'] = table('name', {'name':field('string')})
    return (policy_envelope([{'children':fields}], name='folder', action='schema'),
        policy_envelope([values], name='folder', action='default'))


def request():
    return compile_windows_execution_folder(*sources(), binding=binding())


def native_state(**changes):
    # Independent native row: assigned IDs, explicit relation and effective ACL
    # metadata are not copied from the compiler's request or expected digest.
    row = {'id':41, 'name':NAME, 'parent-folder':17, 'folder-type':'public',
        'inherit-policy':'disable', 'secret-policy':POLICY.name, 'inherit-permission':'disable',
        'inherit-folder-ztna':'enable', 'ztna-tags-match-logic':'or', 'ztna-ems-tag':[],
        'user-permission':[{'id':3, 'user-name':[{'name':OWNER, 'q_origin_key':OWNER}],
            'folder-permission':'owner', 'secret-permission':'owner', 'allowed-launcher-type':'all', 'q_origin_key':3}],
        'group-permission':[], 'q_origin_key':41, 'permissions':{'user':'owner'}}
    row.update(changes)
    return policy_envelope([row], name='folder', status='OK', mkey=41)


def test_native_eleven_field_request_and_fourteen_field_state_are_distinct_from_inherited_action():
    schema, raw = sources()
    value = compile_windows_execution_folder(schema, raw, binding=binding())
    assert not any(schema) and not any(raw)
    wire = json.loads(value.body_json)
    assert len(wire) == 11 and 'folder-type' not in wire
    assert wire['inherit-policy'] == wire['inherit-permission'] == 'disable'
    assert wire['secret-policy'] == POLICY.name and wire['user-permission'][0]['allowed-launcher-type'] == 'all'
    old = _isolated_child_body(NAME, 17, OWNER, empty_inactive_policy=True)
    assert old['inherit-policy'] == 'enable' and old['secret-policy'] == ''
    raw = native_state()
    first = consume_windows_execution_folder_state(raw, request=value, native_folder_id=41)
    assert len(first) == 64 and not any(raw)
    assert consume_windows_execution_folder_state(native_state(), request=value, native_folder_id=41) == first
    allocated = json.loads(native_state())
    allocated['results'][0]['user-permission'][0].update(id=4, q_origin_key=4)
    assert consume_windows_execution_folder_state(bytearray(json.dumps(allocated).encode()),
        request=value, native_folder_id=41) != first
    assert not hasattr(value, 'ownership') and not hasattr(value, 'execute')


@pytest.mark.parametrize('failure', ['extra', 'missing', 'table-type', 'table-key', 'nested-key',
    'nested-readonly', 'scalar-type', 'default-selector', 'default-owner', 'default-id', 'default-bool', 'schema-error'])
def test_changed_native_sources_refuse_and_erase_without_guessing(failure):
    schema, raw = (json.loads(content) for content in sources())
    fields = schema['results'][0]['children']
    if failure == 'extra':fields['future-control'] = {'type':'option'}
    if failure == 'missing':del fields['folder-type']
    if failure == 'table-type':fields['user-permission']['type'] = 'table'
    if failure == 'table-key':fields['user-permission']['mkey'] = 'name'
    if failure == 'nested-key':fields['user-permission']['children']['user-name']['mkey'] = 'id'
    if failure == 'nested-readonly':fields['user-permission']['children']['secret-permission']['read_only'] = True
    if failure == 'scalar-type':fields['secret-policy']['type'] = 'option'
    if failure == 'default-selector':raw['results'][0]['secret-policy'] = POLICY.name
    if failure == 'default-owner':raw['results'][0]['user-permission'] = [{'id':1}]
    if failure == 'default-id':raw['results'][0]['id'] = 1
    if failure == 'default-bool':raw['results'][0]['parent-folder'] = False
    if failure == 'schema-error':schema['schema_errors'] = []
    first, second = (bytearray(json.dumps(content).encode()) for content in (schema, raw))
    with pytest.raises(WindowsExecutionFolderError):compile_windows_execution_folder(first, second, binding=binding())
    assert not any(first) and not any(second)


@pytest.mark.parametrize('changes', [{'inherit-policy':'enable'}, {'secret-policy':'other-policy'},
    {'inherit-permission':'enable'}, {'group-permission':[{'id':1}]}, {'folder-type':'personal'},
    {'parent-folder':18}, {'permissions':{'user':'read'}}, {'q_origin_key':True}, {'q_ref':0},
    {'user-permission':[]}, {'ztna-ems-tag':[{'name':'other-tag'}]}])
def test_complete_state_rejects_policy_acl_parent_origin_or_unqualified_metadata(changes):
    raw = native_state(**changes)
    with pytest.raises(WindowsExecutionFolderError):
        consume_windows_execution_folder_state(raw, request=request(), native_folder_id=41)
    assert not any(raw)


@pytest.mark.parametrize('failure', ['relation-id', 'relation-origin', 'principal-origin', 'launcher', 'second-owner', 'acl-extra'])
def test_complete_owner_relation_is_qualified_and_full_allocation_is_fingerprinted(failure):
    value = json.loads(native_state());relation = value['results'][0]['user-permission'][0]
    if failure == 'relation-id':relation['id'] = 0
    if failure == 'relation-origin':relation['q_origin_key'] = 4
    if failure == 'principal-origin':relation['user-name'][0]['q_origin_key'] = 'other'
    if failure == 'launcher':relation['allowed-launcher-type'] = 'ssh'
    if failure == 'second-owner':value['results'][0]['user-permission'].append(dict(relation))
    if failure == 'acl-extra':relation['future-control'] = 'enable'
    with pytest.raises(WindowsExecutionFolderError):
        consume_windows_execution_folder_state(bytearray(json.dumps(value).encode()), request=request(), native_folder_id=41)


@pytest.mark.parametrize('changes', [{'status':'success'}, {'mkey':True}, {'serial':'OTHER'}, {'next_idx':1},
    {'limit_reached':True}, {'size':True}, {'matched_count':2}, {'schema_errors':[]}, {'action':'set'}])
def test_folder_specific_detail_envelope_cannot_fall_back_to_policy_shape(changes):
    value = json.loads(native_state());value.update(changes)
    with pytest.raises(WindowsExecutionFolderError):
        consume_windows_execution_folder_state(bytearray(json.dumps(value).encode()), request=request(), native_folder_id=41)


def test_bound_policy_allows_only_exact_original_zero_or_one_reference_delta():
    profile = binding()
    before = consume_windows_execution_policy_link(backend_normalized_state(), binding=profile, expected_references=0)
    row = json.loads(backend_normalized_state());row['results'][0]['q_ref'] = 1
    raw = bytearray(json.dumps(row).encode())
    after = consume_windows_execution_policy_link(raw, binding=profile, expected_references=1)
    assert before != after and not any(raw)
    row['results'][0]['q_type'] = 99
    with pytest.raises(WindowsExecutionFolderError):
        consume_windows_execution_policy_link(bytearray(json.dumps(row).encode()), binding=profile, expected_references=1)
    with pytest.raises(WindowsExecutionFolderError):
        consume_windows_execution_policy_link(backend_normalized_state(), binding=profile, expected_references=1)
    with pytest.raises(WindowsExecutionFolderError):
        consume_windows_execution_policy_link(backend_normalized_state(), binding=profile, expected_references=True)
    with pytest.raises(WindowsExecutionFolderError):
        consume_windows_execution_policy_link(backend_normalized_state(), binding=replace(profile, policy_state_digest='d'*64), expected_references=0)


def test_profile_and_native_defaults_cannot_be_replaced_under_original_request_digest():
    profile = request()
    with pytest.raises(WindowsExecutionFolderError):replace(profile, binding=replace(profile.binding, parent_folder_id=18)).validate()
    body = json.loads(profile.body_json);body['inherit-policy'] = 'enable'
    encoded = json.dumps(body, sort_keys=True, separators=(',', ':'))
    with pytest.raises(WindowsExecutionFolderError):
        replace(profile, body_json=encoded, body_digest=hashlib.sha256(encoded.encode()).hexdigest()).validate()
    defaults_value = json.loads(profile.defaults_json);defaults_value['ztna-tags-match-logic'] = 'and'
    with pytest.raises(WindowsExecutionFolderError):
        replace(profile, defaults_json=json.dumps(defaults_value, separators=(',', ':'))).validate()


@pytest.mark.parametrize('phase',['create','delete'])
@pytest.mark.parametrize('status',['OK','success'])
def test_private_original_source_ack_records_exact_numeric_id_and_native_status(phase,status):
    raw=policy_envelope([],name='folder',http_method='POST' if phase=='create' else 'DELETE',
        status=status,mkey=41,error=0)
    digest=hashlib.sha256(raw).hexdigest()
    ack=consume_windows_execution_folder_ack(raw,request=request(),phase=phase,http_status=200,
        native_folder_id=41 if phase=='delete' else None)
    assert (ack.native_folder_id,ack.native_status,ack.response_digest)==(41,status,digest)
    assert not any(raw) and '41' not in repr(ack)


@pytest.mark.parametrize('changes',[{'name':'policy'},{'serial':'OTHER'},{'mkey':True},{'mkey':'41'},
    {'mkey':0},{'status':'error'},{'build':True},{'error':None},{'error':True},{'action':'set'},
    {'schema_errors':[]},{'http_method':'GET'}])
def test_original_source_ack_refuses_unqualified_wire_shapes_and_erases(changes):
    value=dict(name='folder',http_method='POST',status='OK',mkey=41,error=0);value.update(changes)
    raw=policy_envelope([],**value)
    with pytest.raises(WindowsExecutionFolderError):
        consume_windows_execution_folder_ack(raw,request=request(),phase='create',http_status=200)
    assert not any(raw)
