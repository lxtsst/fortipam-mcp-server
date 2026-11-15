"""Synthetic original provenance tests; no files, credentials or device I/O."""
from copy import deepcopy
from dataclasses import asdict, replace
from datetime import datetime, timezone
import hashlib
import hmac
import json
from typing import Any

import pytest

from fortipam_mcp.secret_request_approval_revoke_continuity import (
    SecretRequestApprovalRevokeContinuityError,
    SecretRequestApprovalRevokeContinuityExpected,
    qualify_secret_request_approval_revoke_continuity,
)
from fortipam_mcp.secret_request_collection_http_transport import SecretRequestCollectionRecord
from fortipam_mcp.secret_request_approval_revoke_detail_contract import (
    qualify_secret_request_approval_revoke_secret_profile_relation,
)
from test_secret_request_approval_revoke_detail_contract import _BINDING, _relation_payloads

_KEY = b'synthetic-verification-key-only!'


def _encode(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _signed(payload: object) -> bytes:
    return _encode({'payload': payload, 'hmac_sha256': hmac.new(_KEY, _encode(payload), hashlib.sha256).hexdigest()})


def _fixture() -> tuple[dict[str, Any], SecretRequestApprovalRevokeContinuityExpected]:
    secret, profile = _relation_payloads()
    secret['results'][0].update(name='synthetic-secret', folder=3,
        template='Unix Account (SSH Password)', target='synthetic-target', **{'need-approval-job': 'disable'})
    created = SecretRequestCollectionRecord(19, 7, 'launcher', '2026-10-08 12:00:00')
    scope = dict(secret_id=7, secret_name='synthetic-secret', folder_path='synthetic-folder',
                 scope_ref='synthetic-scope', environment_ref='synthetic-environment')
    linux = dict(folder_id=3, template_name='Unix Account (SSH Password)', target_name='synthetic-target')
    parent_binding = dict(**scope, requester_digest='a'*64, approval_profile_name=_BINDING.approval_profile_name)
    expected = SecretRequestApprovalRevokeContinuityExpected(_BINDING, created, _encode(parent_binding),
        'a'*64, 'b'*64, scope['environment_ref'], scope['scope_ref'], scope['secret_name'],
        scope['folder_path'], **linux)
    observed = int(datetime(2026, 10, 8, 12, tzinfo=timezone.utc).timestamp())
    role = dict(version='v7.0.0', build=29, http_method='GET', http_status=200,
                status='success', serial=_BINDING.source_serial, path='system', name='admin', vdom='root', mkey=_BINDING.original_reviewer, revision='synthetic-revision',
                results=[dict(name=_BINDING.original_reviewer, q_origin_key=_BINDING.original_reviewer, accprofile='super_admin', status='enable',
                              **{'remote-auth': 'disable', 'wildcard': 'disable'})])
    relation = qualify_secret_request_approval_revoke_secret_profile_relation(
        _encode(secret), _encode(profile), binding=_BINDING, authenticated_reviewer=_BINDING.original_reviewer)
    payload = dict(contract='bp008-same-invocation-original-request-relation-v1', binding=asdict(_BINDING),
        created_record=asdict(created), parent_binding=parent_binding, authenticated_requester_digest='a'*64,
        authenticated_transport_digest='b'*64, relation_witness=asdict(relation), linux_parent_binding=linux,
        create_started_at=observed+1, create_finished_at=observed+2,
        precreate_parent=dict(observed_at=observed,
            selected=dict(**scope, **linux, requester=_BINDING.requester,
                          original_reviewer=_BINDING.original_reviewer, source_serial=_BINDING.source_serial,
                          approval_profile_name=_BINDING.approval_profile_name),
            sources=dict(role=role, secret=secret, profile=profile),
            device_dates=dict(role='2026-10-08T12:00:00+00:00', secret=None, profile='2026-10-08T12:00:00+00:00')))
    return payload, expected


def test_original_signed_record_is_private_immutable_and_never_dispatch_authority() -> None:
    payload, expected = _fixture()
    before = deepcopy(payload)
    result = qualify_secret_request_approval_revoke_continuity(_signed(payload), verification_key=_KEY, expected=expected)
    assert payload == before
    assert result.private_continuity_digest == hashlib.sha256(_encode(payload)).hexdigest()
    assert asdict(result.relation) == payload['relation_witness']
    assert 'synthetic' not in repr(result) and result.private_continuity_digest not in repr(result)
    assert not hasattr(result, 'authorized') and not hasattr(result, 'execute')
    assert 'synthetic' not in repr(expected)


@pytest.mark.parametrize('path', [
    'contract', 'binding.request_id', 'binding.secret_id', 'binding.requester',
    'binding.original_reviewer', 'binding.approval_profile_name', 'binding.source_serial',
    'created_record.request_id', 'created_record.secret_id', 'created_record.creation_time',
    'created_record.request_type', 'authenticated_requester_digest', 'authenticated_transport_digest',
    'parent_binding.scope_ref', 'parent_binding.environment_ref', 'parent_binding.requester_digest',
    'precreate_parent.selected.secret_id', 'precreate_parent.selected.secret_name',
    'precreate_parent.selected.folder_path', 'precreate_parent.selected.requester',
    'precreate_parent.selected.approval_profile_name', 'precreate_parent.selected.original_reviewer',
    'precreate_parent.selected.source_serial', 'precreate_parent.selected.scope_ref',
    'precreate_parent.selected.environment_ref', 'precreate_parent.selected.folder_id',
    'precreate_parent.selected.template_name', 'precreate_parent.selected.target_name',
    'linux_parent_binding.folder_id', 'linux_parent_binding.template_name', 'linux_parent_binding.target_name',
    'relation_witness.private_binding_digest', 'relation_witness.private_secret_metadata_digest',
    'relation_witness.private_profile_metadata_digest', 'precreate_parent.sources.role.serial',
    'precreate_parent.sources.profile.serial', 'precreate_parent.sources.secret.serial',
])
def test_resigned_cross_scope_join_refuses(path: str) -> None:
    payload, expected = _fixture()
    row = payload
    parts = path.split('.')
    for part in parts[:-1]:
        row = row[part]
    row[parts[-1]] = 999 if type(row[parts[-1]]) is int else 'different-synthetic-value'
    with pytest.raises(SecretRequestApprovalRevokeContinuityError, match='^Original Request creation continuity is unavailable.$'):
        qualify_secret_request_approval_revoke_continuity(_signed(payload), verification_key=_KEY, expected=expected)


@pytest.mark.parametrize('failure', ['signature', 'key', 'missing', 'extra', 'duplicate', 'bool',
    'reordered_times', 'late', 'before_parent', 'nonfinite', 'naive_date', 'old_date', 'no_role_date',
    'role', 'secret_folder', 'current_profile', 'wrong_expected_transport', 'wrong_expected_parent'])
def test_malformed_or_substituted_original_sources_fail_closed(failure: str) -> None:
    payload, expected = _fixture()
    key = _KEY
    parent = payload['precreate_parent']
    if failure == 'signature':
        raw = _signed(payload)
        raw = raw.replace(b'synthetic-scope', b'different-scope')
    else:
        if failure == 'key': key = b'x' * 32
        elif failure == 'missing': del payload['linux_parent_binding']
        elif failure == 'extra': payload['extra'] = True
        elif failure == 'bool': payload['binding']['secret_id'] = True
        elif failure == 'reordered_times': payload['create_started_at'] = payload['create_finished_at'] + 1
        elif failure == 'late': payload['create_finished_at'] = parent['observed_at'] + 61
        elif failure == 'before_parent': payload['create_started_at'] = parent['observed_at'] - 1
        elif failure == 'naive_date': parent['device_dates']['profile'] = '2026-10-08T12:00:00'
        elif failure == 'old_date': parent['device_dates']['profile'] = '2020-10-08T12:00:00+00:00'
        elif failure == 'no_role_date': parent['device_dates']['role'] = None
        elif failure == 'role': parent['sources']['role']['results'][0]['accprofile'] = 'read_only'
        elif failure == 'secret_folder': parent['sources']['secret']['results'][0]['folder'] = 9
        elif failure == 'current_profile':
            parent['sources']['profile']['results'][0]['first-user'][0]['name'] = 'current-owner'
        elif failure == 'wrong_expected_transport': expected = replace(expected, transport_digest='c'*64)
        elif failure == 'wrong_expected_parent': expected = replace(expected, parent_binding_json=b'{}')
        raw = _signed(payload)
        if failure == 'duplicate': raw = raw.replace(b'"payload":', b'"payload":{},"payload":', 1)
        elif failure == 'nonfinite': raw = raw.replace(str(payload['create_started_at']).encode(), b'NaN')
    with pytest.raises(SecretRequestApprovalRevokeContinuityError) as caught:
        qualify_secret_request_approval_revoke_continuity(raw, verification_key=key, expected=expected)
    assert 'synthetic' not in str(caught.value)
    assert caught.value.__suppress_context__


def test_original_historical_evidence_is_not_rejected_or_relabelled_by_wall_clock() -> None:
    payload, expected = _fixture()
    # No now() input or current freshness promise: dates belong to creation only.
    result = qualify_secret_request_approval_revoke_continuity(_signed(payload), verification_key=_KEY, expected=expected)
    assert not hasattr(result, 'fresh')


@pytest.mark.parametrize('member,value', [('field', [{'value': 'synthetic-MATERIAL-SENTINEL'}]),
    ('keyinfo', {'key': 'synthetic-MATERIAL-SENTINEL'}), ('shared-key', 'synthetic-MATERIAL-SENTINEL')])
def test_material_is_rejected_before_generic_value_decode(member: str, value: object,
                                                          monkeypatch: pytest.MonkeyPatch) -> None:
    payload, expected = _fixture()
    payload['precreate_parent']['sources']['secret']['results'][0][member] = value
    raw = _signed(payload)
    original_loads = json.loads

    def guarded_loads(raw_value: Any, *args: Any, **kwargs: Any) -> Any:
        # Raw validators may decode field names, never the protected values.
        if isinstance(raw_value, (bytes, bytearray)):
            assert b'synthetic-MATERIAL-SENTINEL' not in raw_value
        elif isinstance(raw_value, str):
            assert 'synthetic-MATERIAL-SENTINEL' not in raw_value
        return original_loads(raw_value, *args, **kwargs)

    monkeypatch.setattr(json, 'loads', guarded_loads)
    with pytest.raises(SecretRequestApprovalRevokeContinuityError):
        qualify_secret_request_approval_revoke_continuity(raw, verification_key=_KEY, expected=expected)


@pytest.mark.parametrize('failure', ['dict_rows', 'extra_row', 'extra_envelope', 'origin', 'mkey',
                                     'vdom', 'bool_build', 'missing_revision'])
def test_original_role_exact_source_shape(failure: str) -> None:
    payload, expected = _fixture()
    role = payload['precreate_parent']['sources']['role']
    if failure == 'dict_rows': role['results'] = role['results'][0]
    elif failure == 'extra_row': role['results'][0]['extra'] = 'unsupported'
    elif failure == 'extra_envelope': role['extra'] = 'unsupported'
    elif failure == 'origin': role['results'][0]['q_origin_key'] = 'other-reviewer'
    elif failure == 'mkey': role['mkey'] = 'other-reviewer'
    elif failure == 'vdom': role['vdom'] = 'other-vdom'
    elif failure == 'bool_build': role['build'] = True
    elif failure == 'missing_revision': del role['revision']
    with pytest.raises(SecretRequestApprovalRevokeContinuityError):
        qualify_secret_request_approval_revoke_continuity(_signed(payload), verification_key=_KEY, expected=expected)


def test_pre_redacted_null_material_and_empty_fields_are_accepted() -> None:
    payload, expected = _fixture()
    sources = payload['precreate_parent']['sources']
    sources['secret']['results'][0].update(field=None, keyinfo=None, **{'shared-key': None})
    relation = qualify_secret_request_approval_revoke_secret_profile_relation(
        _encode(sources['secret']), _encode(sources['profile']), binding=_BINDING,
        authenticated_reviewer=_BINDING.original_reviewer)
    payload['relation_witness'] = asdict(relation)
    assert qualify_secret_request_approval_revoke_continuity(
        _signed(payload), verification_key=_KEY, expected=expected).relation == relation
