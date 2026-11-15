"""Real OAuth/ASGI identity metadata; no product, material or M4 operation."""
from dataclasses import replace
import json

import pytest
from starlette.testclient import TestClient
from v4_planning import AuthenticatedRequester

from fortipam_mcp.ems_tag_principal_binding import EmsTagPrincipalBinding
from fortipam_mcp.http_server import create_http_app, HttpConfigurationError, HttpServerSettings
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from test_ems_tag_mcp_oauth import headers, rpc, data
from test_http_server import _v4_controlled_environment, _bearer_environment, V4_FOLDER_ACTION_FEATURE_ENV

TOOL = 'bind_v4_ems_original_account_requester_748'
SCOPE = dict(environment_ref='ems-disposable-lab', scope_ref='original-account-sdk-test', audience_ref='private-ems-client')


def binding(root, *, enabled=True, now=None):
    root.mkdir(mode=0o700)
    directory = root/'binding';directory.mkdir(mode=0o700)
    key = root/'binding.key';key.write_bytes(b'p'*32);key.chmod(0o600)
    value = EmsTagPrincipalBinding(directory,key,capture_enabled=enabled,clock=None if now is None else lambda:now[0],**SCOPE)
    return value


def settings(root):
    environment = _v4_controlled_environment(root);environment[V4_FOLDER_ACTION_FEATURE_ENV] = 'false'
    return HttpServerSettings.from_environment(environment)


def capture(client, token, **arguments):
    return rpc(client,token,'tools/call',dict(name=TOOL,arguments=arguments))


def test_explicit_sdk_binding_is_write_once_and_has_no_device_authority(tmp_path):
    cfg = settings(tmp_path);value = binding(tmp_path/'identity')
    with TestClient(create_http_app(cfg),base_url='https://mcp.example.com') as client:
        operator = headers(client,'fortipam:read fortipam:plan fortipam:operate')
        assert all(tool['name']!=TOOL for tool in rpc(client,operator,'tools/list')['tools'])
    with TestClient(create_http_app(cfg,v4_ems_tag_principal_binding=value),base_url='https://mcp.example.com') as client:
        plan = headers(client,'fortipam:read fortipam:plan')
        operator = headers(client,'fortipam:read fortipam:plan fortipam:operate')
        entry = next(tool for tool in rpc(client,operator,'tools/list')['tools'] if tool['name']==TOOL)
        assert entry['inputSchema']['additionalProperties'] is False and not entry['inputSchema'].get('properties')
        assert capture(client,plan)['isError']
        assert capture(client,operator,requester_digest='a'*64)['isError']
        assert not list(value._directory.iterdir())
        result = data(capture(client,operator))
        assert result==dict(identity_binding_recorded=True,execution_authorized=False,device_write_executed=False)
        packet = (value._directory/'sdk-requester-binding.json').read_bytes()
        original = value.load()
        assert data(capture(client,operator))==result
        assert value.load()==original and (value._directory/'sdk-requester-binding.json').read_bytes()==packet
        # A second client namespace cannot overwrite the first record.
        another = headers(client,'fortipam:read fortipam:plan fortipam:operate')
        assert capture(client,another)['isError']
        assert (value._directory/'sdk-requester-binding.json').read_bytes()==packet
        body = json.loads(packet)['body']
        assert set(body)=={'contract','scope','directory','directory_identity','requester_digest',
            'transport_namespace_digest','observed_at','expires_at'}
        assert not any(name in body for name in ('token','subject','username','password','client_id'))
    reader = EmsTagPrincipalBinding(value._directory,value._key_file,**SCOPE)
    assert reader.load()==original
    fake = V4PlanningPrincipal(AuthenticatedRequester(subject_ref='synthetic-foreign-operator',principal_class='operator'), 'f'*64)
    with pytest.raises(ValueError):reader.require_requester(fake)
    value.close();reader.close()


def test_default_disabled_and_non_sdk_calls_cannot_record_a_requester(tmp_path):
    cfg = settings(tmp_path);value = binding(tmp_path/'identity',enabled=False)
    fake = V4PlanningPrincipal(AuthenticatedRequester(subject_ref='synthetic-operator',principal_class='operator'), 'e'*64)
    with pytest.raises(RuntimeError):value.capture_from_sdk(lambda:fake)
    with TestClient(create_http_app(cfg,v4_ems_tag_principal_binding=value),base_url='https://mcp.example.com') as client:
        operator = headers(client,'fortipam:read fortipam:plan fortipam:operate')
        assert capture(client,operator)['isError']
    assert not list(value._directory.iterdir());value.close()
    enabled = binding(tmp_path/'enabled')
    with pytest.raises(RuntimeError):enabled.capture_from_sdk(lambda:fake)
    assert not list(enabled._directory.iterdir());enabled.close()


def test_expired_or_modified_binding_never_renews_or_becomes_execution_permission(tmp_path):
    cfg = settings(tmp_path);now = [1000];value = binding(tmp_path/'identity',now=now)
    with TestClient(create_http_app(cfg,v4_ems_tag_principal_binding=value),base_url='https://mcp.example.com') as client:
        operator = headers(client,'fortipam:read fortipam:plan fortipam:operate')
        data(capture(client,operator));path = value._directory/'sdk-requester-binding.json';raw = path.read_bytes()
        now[0] = 2800
        with pytest.raises(ValueError):value.load()
        assert capture(client,operator)['isError'] and path.read_bytes()==raw
    modified = json.loads(raw);modified['body']['requester_digest'] = 'a'*64
    path.write_text(json.dumps(modified))
    fresh_reader = EmsTagPrincipalBinding(value._directory,value._key_file,clock=lambda:1001,**SCOPE)
    with pytest.raises(ValueError):fresh_reader.load()
    value.close();fresh_reader.close()


def test_bootstrap_requires_controlled_https_oauth_and_a_separate_witness_key(tmp_path):
    cfg = settings(tmp_path);value = binding(tmp_path/'identity')
    with pytest.raises(HttpConfigurationError):
        create_http_app(HttpServerSettings.from_environment(_bearer_environment()),v4_ems_tag_principal_binding=value)
    with pytest.raises(HttpConfigurationError):
        create_http_app(replace(cfg,v4_planning_authorization=None),v4_ems_tag_principal_binding=value)
    value._key_file.write_bytes(cfg.v4_planning_authorization.namespace_hmac_key)
    same_key = EmsTagPrincipalBinding(value._directory,value._key_file,**SCOPE)
    with pytest.raises(HttpConfigurationError):create_http_app(cfg,v4_ems_tag_principal_binding=same_key)
