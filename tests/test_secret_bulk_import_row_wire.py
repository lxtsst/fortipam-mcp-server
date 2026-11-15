"""Synthetic complete native wire/default projection; no product dispatcher."""

import copy
import hashlib
import json
import pickle
import threading
import time

import pytest

from fortipam_mcp import secret_bulk_import_row_wire as wire
from fortipam_mcp.secret_bulk_import_intake import BulkImportIntakeError
from fortipam_mcp.secret_bulk_import_row_provider import _OriginalRowMaterialRuntime
from fortipam_mcp.secret_metadata_http_transport import _SECRET_CREATE_191_REQUIRED_DEFAULTS
from test_secret_bulk_import_row_conversion import fixture
from test_secret_bulk_import_row_provider import execute, material_store
from v4_planning import M4Verification
from v4_planning.secret_create_adapter import SecretCreateAdapterOutcome

SERIAL = hashlib.sha256(b'Synthetic wire-default device').hexdigest()


def defaults_response():
    values = {key: '' for key in wire._SCALAR_KEYS}
    integers = {'id', 'folder', 'associated-secret', 'secret-auth-duration', 'pwd-chg-sch-interval',
        'credential-expiry-after', 'reconcile-secret-id', 'heartbeat-interval', 'checkout-renew-times',
        'checkout-duration', 'force-checkout-idle-time', 'ssh-service-port', 'rdp-service-port',
        'vnc-service-port', 'display-num', 'samba-service-port', 'sftp-service-port', 'telnet-service-port'}
    values.update({key: 0 for key in integers})
    values.update({key: 'disable' for key in ('auto-association','block-clipboard','tunnel-encryption',
        'secret-auth-owner-exempt','password-changer','credential-expire-notification','pwd-chg-use-policy-default',
        'password-reconciliation','password-heartbeat','heartbeat-use-policy-default','checkout','checkin-pwd-change',
        'checkout-duration-renew','bypass-approval','ssh-auto-password','ssh-switch-account','rdp-restricted-admin-mode',
        'rdp-auto-totp','rdp-nla-kerberos','rdp-remote-app','rdp-remote-app-owner-exempt','rdp-tcp-forward','allow-viewer-launch-web')})
    values.update({key: 'down' for key in wire._SCALAR_KEYS if key.endswith('-service-status')})
    values.update(proxy='enable', recording='disable')
    values.update({'cert-expiry-log':'enable','inherit-permission':'enable','inherit-folder-ztna':'enable',
        'rdp-security-level':'best-effort','reconcile-method':'reconcile-after-fail'})
    values.update(_SECRET_CREATE_191_REQUIRED_DEFAULTS)
    values.update({key:[] for key in wire._ARRAY_KEYS})
    values['totp-setting'] = dict(status='disable', **{'shared-key':'','is-ftk':False,'fortitoken-access-code':''})
    return dict(version='v7.0.0',build=29,path='secret',name='database',http_method='GET',status='success',
        http_status=200,vdom='root',serial='Synthetic wire-default device',results=values,
        **{'unselected-private-extension':{'credential':'Synthetic forbidden default material'}})


def project(payload=None):
    raw = bytearray(json.dumps(payload or defaults_response()).encode())
    try:
        return wire._project_build29_secret_wire_defaults(raw, serial_digest=SERIAL)
    finally:
        assert raw and not any(raw)


@pytest.mark.parametrize('fault', ['missing','wrong-version','boolean-build','wrong-device','error-bool','material-field',
    'shared-key','access-code','active-totp','ftk','nested-scalar','boolean-scalar','default-drift','duplicate-key','ztna-mode'])
def test_default_projection_rejects_partial_material_or_wrong_envelopes_without_decoding_secrets(monkeypatch, fault):
    response = defaults_response()
    if fault == 'missing': del response['results']['checkout-duration']
    elif fault == 'wrong-version': response['version'] = 'v7.0.1'
    elif fault == 'boolean-build': response['build'] = True
    elif fault == 'wrong-device': response['serial'] = 'Wrong synthetic device'
    elif fault == 'error-bool': response['error'] = False
    elif fault == 'material-field': response['results']['field'] = [{'value':'Synthetic forbidden default material'}]
    elif fault == 'shared-key': response['results']['totp-setting']['shared-key'] = 'Synthetic forbidden default material'
    elif fault == 'access-code': response['results']['totp-setting']['fortitoken-access-code'] = 'Synthetic forbidden default material'
    elif fault == 'active-totp': response['results']['totp-setting']['status'] = 'enable'
    elif fault == 'ftk': response['results']['totp-setting']['is-ftk'] = True
    elif fault == 'nested-scalar': response['results']['sudo-prompt'] = {'value':'Synthetic forbidden default material'}
    elif fault == 'boolean-scalar': response['results']['checkout-duration'] = False
    elif fault == 'default-drift': response['results']['av-profile'] = 'Unqualified profile'
    elif fault == 'ztna-mode': response['results']['inherit-folder-ztna'] = 'unknown'
    original = json.loads
    def guarded(raw, *args, **kwargs):
        assert b'Synthetic forbidden default material' not in (raw.encode() if type(raw) is str else raw)
        return original(raw, *args, **kwargs)
    monkeypatch.setattr(wire.m.json, 'loads', guarded)
    raw = bytearray(json.dumps(response).encode())
    if fault == 'duplicate-key':
        raw = bytearray(raw.replace(b'"build": 29', b'"build": 29,"build": 29'))
    with pytest.raises(BulkImportIntakeError):
        wire._project_build29_secret_wire_defaults(raw, serial_digest=SERIAL)
    assert not any(raw)


@pytest.mark.parametrize('mode', ['enable','disable'])
def test_blank_default_projection_preserves_actual_ztna_mode_and_skips_unselected_material(monkeypatch, mode):
    payload = defaults_response(); payload['results']['inherit-folder-ztna'] = mode
    original = json.loads
    def guarded(raw, *args, **kwargs):
        assert b'Synthetic forbidden default material' not in (raw.encode() if type(raw) is str else raw)
        return original(raw,*args,**kwargs)
    monkeypatch.setattr(wire.m.json,'loads',guarded)
    assert dict(project(payload).scalars)['inherit-folder-ztna'] == mode


def test_native_scalar_fallbacks_do_not_invent_ztna_inheritance_or_drop_template_controls():
    payload = defaults_response()
    payload['results'].update({'inherit-folder-ztna':'disable','password-changer':'',
        'keyboard-layout':'','ssh-switch-account':'','rsa-sign-algo':'','ssh-algorithm':'',
        'rdp-remote-app-profile':'Synthetic default app','bypass-approval':'enable'})
    defaults = project(payload)
    values = wire._native_controls(defaults)
    assert values['inherit-folder-ztna'] == 'disable'
    assert values['password-changer'] == 'disable' and values['keyboard-layout'] == 'en-us'
    assert values['ssh-switch-account'] == 'enable' and values['rsa-sign-algo'] == 'ssh-rsa'
    assert values['ssh-algorithm'] == 'compatible' and values['rdp-remote-app'] == 'disable'
    assert values['rdp-remote-app-profile'] == ''
    assert values['bypass-approval'] == 'disable'


@pytest.mark.parametrize('targetless', [False, True])
def test_complete_native_wire_filters_target_fields_sorts_utf16_and_preserves_default_controls(tmp_path, monkeypatch, targetless, capfd):
    loader, session, state, reference, bridge, converter, _, _ = fixture(tmp_path, monkeypatch, targetless=targetless,
        names={'password':'😀 Password','passphrase':'\ue000 Passphrase'})
    defaults = project()
    encoder = wire._Build29OriginalRowWireEncoder(converter, defaults,
        expected_defaults_digest=defaults.digest(), expected_serial_digest=SERIAL)
    class Transport:
        body = dto = view = None
        calls = 0
        def _create_and_verify_with_original_row(self, context, columns, *, deadline):
            self.calls += 1
            with encoder._serialize_once(context, columns, deadline=deadline) as view:
                self.view, self.body, self.dto = view, view.obj, json.loads(bytes(view))
                assert view.readonly
            return SecretCreateAdapterOutcome.VERIFIED_CREATED
    transport = Transport()
    bridge._transport = transport
    runtime = _OriginalRowMaterialRuntime(bridge, material_store(tmp_path))
    try:
        with reference:
            assert execute(loader, state, runtime).verification is M4Verification.VERIFIED
            assert execute(loader, state, runtime).verification is M4Verification.VERIFIED
        dto = transport.dto
        assert set(dto) == set(wire._WIRE_KEYS) and len(dto) == 102
        names = [field['name'] for field in dto['field']]
        assert names == sorted(names, key=lambda name:name.encode('utf-16-be'))
        assert names.index('😀 Password') < names.index('\ue000 Passphrase')
        assert len(names) == (10 if targetless else 7)
        assert all(set(field) == {'name','value'} for field in dto['field'])
        assert dto['field'][names.index('😀 Password')]['value'] == ' password\r\n"\\秘密 '
        assert dto['http-service-status'] == 'up' and 'http-service-port' not in dto
        assert dto['ssh-service-port'] == 22 and dto['samba-service-port'] == 0
        assert dto['associated-secret'] == 0 and dto['inherit-permission'] == 'enable'
        assert dto['totp-setting'] == json.loads(wire._TOTP)
        assert transport.calls == 1 and not any(transport.body)
        with pytest.raises(ValueError): transport.view.tobytes()
        for obj in (defaults,encoder):
            for operation in (copy.copy,copy.deepcopy,pickle.dumps):
                with pytest.raises(RuntimeError):operation(obj)
        assert capfd.readouterr() == ('','')
    finally:
        session.close()


@pytest.mark.parametrize('fault', ['consumer','cancel','idle','interrupt'])
def test_wire_and_dto_owned_bytes_clear_together_on_uncertain_exit(tmp_path, monkeypatch, fault):
    loader, session, state, reference, bridge, converter, _, _ = fixture(tmp_path, monkeypatch)
    defaults = project()
    encoder = wire._Build29OriginalRowWireEncoder(converter,defaults,
        expected_defaults_digest=defaults.digest(),expected_serial_digest=SERIAL)
    class Transport:
        body = None
        calls = 0
        def _create_and_verify_with_original_row(self, context, columns, *, deadline):
            self.calls += 1
            if fault == 'idle':deadline = time.monotonic()+0.1
            with encoder._serialize_once(context,columns,deadline=deadline) as view:
                self.body = view.obj
                if fault == 'consumer':raise ValueError('Synthetic fixed downstream failure')
                if fault == 'cancel':session.close()
                if fault == 'interrupt':raise KeyboardInterrupt
                if fault == 'idle':
                    time.sleep(0.18)
                    assert not any(self.body)
            return SecretCreateAdapterOutcome.VERIFIED_CREATED
    transport = Transport();bridge._transport = transport
    runtime = _OriginalRowMaterialRuntime(bridge,material_store(tmp_path))
    try:
        with reference:
            if fault == 'interrupt':
                with pytest.raises(KeyboardInterrupt):execute(loader,state,runtime)
            else:assert execute(loader,state,runtime).verification is M4Verification.UNKNOWN
            assert execute(loader,state,runtime).verification is M4Verification.UNKNOWN
        assert transport.calls == 1 and not any(transport.body)
        assert all(not any(buffer) for buffer in bridge._owned._buffers)
        assert not any(thread.name == 'owner-row-conversion-disposal' and thread.is_alive() for thread in threading.enumerate())
    finally:session.close()
