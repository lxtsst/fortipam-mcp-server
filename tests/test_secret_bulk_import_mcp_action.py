"""Synthetic Text workflow behind the real fixed MCP/OAuth boundary."""

import copy
from dataclasses import replace
import json
import pickle

import pytest
from starlette.testclient import TestClient

from fortipam_mcp import secret_bulk_import_mcp_action as boundary
from fortipam_mcp.http_server import HttpConfigurationError, create_http_app
from fortipam_mcp.runtime_profile import RuntimeProfile
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from v4_planning.material_provider import MaterialAccessDenied
from v4_planning.models import AuthenticatedRequester
from test_ldap_server_mcp_action import _call, _login, _settings

_PREVIEW = 'preview_v4_secret_bulk_import_text_700'
_AUTHORIZE = 'authorize_v4_secret_bulk_import_text_700'
_EXECUTE = 'execute_v4_secret_bulk_import_text_700'
_NAMES = {_PREVIEW, _AUTHORIZE, _EXECUTE}
_ERROR = 'FortiPAM Text import action is unavailable.'
_PRIVATE = 'synthetic-private-material-marker'


def _synthetic_workflow(monkeypatch):
    calls = []
    kind = boundary._OriginalTextBatchOwner
    workflow = object.__new__(kind)

    def preview(self, **identity):
        assert self is workflow
        calls.append(('preview', None, identity))
        return {'preview_ref': 'synthetic-preview'}

    def authorize(self, reference, **identity):
        assert self is workflow and reference == 'synthetic-preview'
        calls.append(('authorize', reference, identity))
        return {'authorization_ref': 'synthetic-authorization'}

    def execute(self, reference, **identity):
        assert self is workflow and reference == 'synthetic-authorization'
        calls.append(('execute', reference, identity))
        return {'completed': True, 'verified_lines': 2, 'total_lines': 2}

    monkeypatch.setattr(kind, 'preview', preview)
    monkeypatch.setattr(kind, 'authorize', authorize)
    monkeypatch.setattr(kind, 'execute_once', execute)
    return workflow, calls


def _tools(client, headers):
    response = client.post('/fpamcp', headers=headers, json={
        'jsonrpc': '2.0', 'id': 'list', 'method': 'tools/list', 'params': {},
    })
    assert response.status_code == 200
    return {tool['name']: tool for tool in response.json()['result']['tools']}


def test_exact_wrapper_maps_identity_and_hides_workflow_failures(monkeypatch):
    workflow, calls = _synthetic_workflow(monkeypatch)
    action = boundary.SecretBulkImportMcpAction(workflow)
    principal = V4PlanningPrincipal(AuthenticatedRequester('synthetic-operator', 'operator'), 'a' * 64)
    identity = {'requester_digest': principal.requester.digest, 'transport_digest': 'a' * 64}
    assert action.call('preview', principal) == {'preview_ref': 'synthetic-preview'}
    assert action.call('authorize', principal, 'synthetic-preview') == {'authorization_ref': 'synthetic-authorization'}
    assert action.call('execute', principal, 'synthetic-authorization')['verified_lines'] == 2
    assert calls == [('preview', None, identity), ('authorize', 'synthetic-preview', identity),
                     ('execute', 'synthetic-authorization', identity)]
    assert 'redacted' in repr(action)
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(MaterialAccessDenied):
            operation(action)
    with pytest.raises(ValueError, match=_ERROR):
        boundary.SecretBulkImportMcpAction(object())
    for operation, selected, reference in (
        ('preview', object(), None), ('preview', principal, _PRIVATE),
        ('authorize', principal, None), ('execute', principal, True), (_PRIVATE, principal, None),
    ):
        with pytest.raises(RuntimeError) as error:
            action.call(operation, selected, reference)
        assert str(error.value) == _ERROR and error.value.__suppress_context__
    assert len(calls) == 3

    def fail(*args, **kwargs):
        raise ValueError(_PRIVATE)

    for method, operation, reference in (
        ('preview', 'preview', None), ('authorize', 'authorize', 'synthetic-preview'),
        ('execute_once', 'execute', 'synthetic-authorization'),
    ):
        monkeypatch.setattr(boundary._OriginalTextBatchOwner, method, fail)
        with pytest.raises(RuntimeError) as error:
            action.call(operation, principal, reference)
        assert str(error.value) == _ERROR and error.value.__cause__ is None
        assert error.value.__suppress_context__ and _PRIVATE not in str(error.value)


def test_real_oauth_tools_use_fixed_schemas_and_distinct_planning_operation_scopes(tmp_path, monkeypatch):
    workflow, calls = _synthetic_workflow(monkeypatch)
    app = create_http_app(_settings(tmp_path), secret_bulk_import_action=boundary.SecretBulkImportMcpAction(workflow))
    with TestClient(app, base_url='https://mcp.example.com') as client:
        read = _login(client, 'fortipam:read')
        tools = _tools(client, read)
        assert _NAMES <= tools.keys()
        for name, fields in ((_PREVIEW, set()), (_AUTHORIZE, {'preview_ref'}), (_EXECUTE, {'authorization_ref'})):
            schema = tools[name]['inputSchema']
            assert set(schema['properties']) == fields and set(schema.get('required', ())) == fields
            assert all(value['type'] == 'string' for value in schema['properties'].values())
        assert _call(client, read, _PREVIEW, {})['isError'] and not calls
        planning = _login(client, 'fortipam:read fortipam:plan')
        assert not _call(client, planning, _PREVIEW, {})['isError']
        assert _call(client, planning, _AUTHORIZE, {'preview_ref': 'synthetic-preview'})['isError']
        assert _call(client, planning, _EXECUTE, {'authorization_ref': 'synthetic-authorization'})['isError']
        assert [call[0] for call in calls] == ['preview']
        operator = _login(client, 'fortipam:read fortipam:plan fortipam:operate')
        for name, arguments in ((_PREVIEW, {}), (_AUTHORIZE, {'preview_ref': 'synthetic-preview'}),
                                (_EXECUTE, {'authorization_ref': 'synthetic-authorization'})):
            assert not _call(client, operator, name, arguments)['isError']
        assert [call[0] for call in calls[-3:]] == ['preview', 'authorize', 'execute']
        identity = calls[-1][2]
        assert set(identity) == {'requester_digest', 'transport_digest'}
        assert all(len(value) == 64 for value in identity.values())
        assert all(call[2] == identity for call in calls[-3:])
        before = len(calls)
        for name, arguments in (
            (_PREVIEW, {'path': _PRIVATE}),
            (_AUTHORIZE, {'preview_ref': 'synthetic-preview', 'password': _PRIVATE}),
            (_EXECUTE, {'authorization_ref': 'synthetic-authorization', 'body': _PRIVATE}),
        ):
            result = _call(client, operator, name, arguments)
            assert result['isError'] and _PRIVATE not in json.dumps(result)
        assert len(calls) == before

        def fail(*args, **kwargs):
            raise ValueError(_PRIVATE)

        monkeypatch.setattr(boundary._OriginalTextBatchOwner, 'preview', fail)
        result = _call(client, operator, _PREVIEW, {})
        assert result['isError'] and _PRIVATE not in json.dumps(result)
        assert _ERROR in json.dumps(result)


def test_http_host_defaults_closed_and_rejects_unqualified_injection(tmp_path, monkeypatch):
    settings = _settings(tmp_path)
    workflow, calls = _synthetic_workflow(monkeypatch)
    action = boundary.SecretBulkImportMcpAction(workflow)
    app = create_http_app(settings)
    with TestClient(app, base_url='https://mcp.example.com') as client:
        names = _tools(client, _login(client, 'fortipam:read fortipam:plan'))
        assert not _NAMES.intersection(names)
        assert 'get_v4_secret_bulk_import_apply_requirements' in names
    for invalid, candidate in (
        (replace(settings, runtime_profile=RuntimeProfile.READONLY), action),
        (replace(settings, runtime_profile=RuntimeProfile.V4_PLAN_ONLY), action),
        (replace(settings, auth_mode='bearer', bearer_token='synthetic-token'), action),
        (replace(settings, local_oauth=None), action),
        (replace(settings, v4_planning_authorization=None), action),
        (settings, object()),
    ):
        with pytest.raises(HttpConfigurationError):
            create_http_app(invalid, secret_bulk_import_action=candidate)
    assert calls == []
