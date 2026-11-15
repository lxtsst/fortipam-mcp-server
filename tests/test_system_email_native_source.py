"""Fixed private SMTP read, no credential decode or action authority."""
from dataclasses import asdict
import io
import json

import pytest

from fortipam_mcp.system_email_native_source import SystemEmailNativeSource,_PATH,_SCHEMA,_TYPES
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig


class Peer:
    def __init__(self):
        self.calls=[];self.resources=[];self.buffers=[];self.status=200;self.whitespace=False;self.raw_override=None;self.close_failure=False
        self.body=dict(http_method='GET',version='v7.0.0',build=29,http_status=200,path='system',name='email-server',
            serial='SYNTHETIC01',status='success',results=dict(type='custom',server='smtp.example.test',port=465,
                security='smtps',authenticate='disable',username='',password='',**{'source-ip':'0.0.0.0','source-ip6':'::',
                'interface-select-method':'auto','interface':'','sender':'sender@example.test','reply-to':'',
                'validate-server':'enable','ssl-min-proto-version':'tls1-2'}))
        choices={'type':['default','custom'],'security':['none','starttls','smtps'],'authenticate':['enable','disable'],
            'interface-select-method':['auto','sdwan','specify'],'validate-server':['enable','disable'],
            'ssl-min-proto-version':['default','tls1-0','tls1-1','tls1-2','tls1-3']}
        fields={name:dict(type=kind)for name,kind in _TYPES.items()}
        for name,values in choices.items():fields[name]['options']=[dict(name=value,help='Synthetic help.')for value in values]
        fields['port'].update(**{'min-value':1,'max-value':65535})
        fields['password']['default']='SYNTHETIC_C3_SENTINEL'
        self.schema={**self.body,'action':'schema','results':{'children':fields}}
    def factory(self,*args,**kwargs):
        peer=self
        class Response:
            closed=False;status=peer.status
            def __init__(self,path):
                raw=json.dumps(peer.schema).encode() if path==_SCHEMA else peer.raw_override if peer.raw_override is not None else json.dumps(peer.body).encode()
                self.stream=io.BytesIO(b' \n'+raw+b' \n' if peer.whitespace else raw)
            def getheader(self,name,default=''):return {'content-type':'application/json','content-encoding':'identity'}.get(name,default)
            def readinto(self,view):peer.buffers.append(view.obj);return self.stream.readinto(view)
            def close(self):
                self.closed=True
                if peer.close_failure:raise OSError('Synthetic close failure.')
        class Connection:
            closed=False
            def request(self,method,path,*,headers):
                assert method=='GET'and path in (_PATH,_SCHEMA);self.path=path;assert headers['Authorization']=='Bearer synthetic-token'
                peer.calls.append((method,path))
            def getresponse(self):result=Response(self.path);peer.resources.append(result);return result
            def close(self):self.closed=True
        result=Connection();peer.resources.append(result);return result
    def source(self):
        return SystemEmailNativeSource(SecretMetadataHttpTransportConfig('https://pam.example.test','synthetic-token',5,None),
            expected_serial='SYNTHETIC01',connection_factory=self.factory)


@pytest.mark.parametrize('material',['','SYNTHETIC_C3_SENTINEL'])
def test_credentials_never_reach_decoder_or_projection_and_resources_close(monkeypatch,material):
    peer=Peer();peer.whitespace=True;peer.body['results'].update(username=material,password=material)
    decode=json.loads
    def safe(raw,*args,**kwargs):
        if isinstance(raw,(bytes,bytearray,str)):assert 'SYNTHETIC_C3_SENTINEL' not in str(raw)
        return decode(raw,*args,**kwargs)
    monkeypatch.setattr(json,'loads',safe);source=peer.source();observed=source.read()
    assert observed.service_type=='custom' and observed.security_mode=='smtps'
    assert observed.username_empty is (not material) and observed.password_empty is (not material)
    assert 'SYNTHETIC_C3_SENTINEL' not in json.dumps(asdict(observed))
    assert 'smtp.example.test' not in repr(observed) and 'redacted' in repr(observed)
    assert len(peer.calls)==2 and all(r.closed for r in peer.resources)and all(not any(b)for b in peer.buffers)
    source.close()
    with pytest.raises(ValueError):source.read()
    assert len(peer.calls)==2


@pytest.mark.parametrize('fault',['serial','build','method','table','field','password-type','username-type','port-bool','port-range','security','auth'])
def test_foreign_or_incomplete_native_state_fails_closed_without_raw_error(fault):
    peer=Peer();body=peer.body;row=body['results']
    if fault=='serial':body['serial']='FOREIGN01'
    elif fault=='build':body['build']=30
    elif fault=='method':body['http_method']='PUT'
    elif fault=='table':body['name']='approval-email'
    elif fault=='field':row['unclassified']='SYNTHETIC_C3_SENTINEL'
    elif fault=='password-type':row['password']={}
    elif fault=='username-type':row['username']=[]
    elif fault=='port-bool':row['port']=True
    elif fault=='port-range':row['port']=0
    elif fault=='security':row['security']='unknown'
    elif fault=='auth':row['authenticate']='unknown'
    with pytest.raises(ValueError)as error:peer.source().read()
    assert str(error.value)=='The private outbound SMTP source is unavailable.'
    assert all(r.closed for r in peer.resources)and all(not any(b)for b in peer.buffers)


def test_duplicate_credential_field_or_failed_resource_close_cannot_qualify():
    peer=Peer();raw=json.dumps(peer.body).encode()
    peer.raw_override=raw.replace(b'"password": ""',b'"password":"SYNTHETIC_C3_SENTINEL","password":""')
    with pytest.raises(ValueError):peer.source().read()
    assert all(r.closed for r in peer.resources)and all(not any(b)for b in peer.buffers)
    peer=Peer();peer.close_failure=True
    with pytest.raises(ValueError):peer.source().read()
    assert all(r.closed for r in peer.resources)and all(not any(b)for b in peer.buffers)


@pytest.mark.parametrize('field,value',[
    ('type','default'),('server','second.example.test'),('port',587),('security','starttls'),('authenticate','enable'),
    ('source-ip','192.0.2.1'),('source-ip6','2001:db8::1'),('interface-select-method','specify'),('interface','port1'),
    ('sender','second@example.test'),('reply-to','reply@example.test'),('validate-server','disable'),('ssl-min-proto-version','tls1-3')])
def test_every_nonmaterial_native_field_changes_the_complete_fingerprint(field,value):
    peer=Peer();before=peer.source().read();peer.body['results'][field]=value;after=peer.source().read()
    assert before.nonmaterial_digest!=after.nonmaterial_digest
    assert all(r.closed for r in peer.resources)and all(not any(b)for b in peer.buffers)


@pytest.mark.parametrize('fault',['missing-schema-field','extra-schema-field','wrong-type','duplicate-option','invalid-option','ipv4-type','ipv6-type','missing-row-field'])
def test_full_schema_and_current_cannot_be_replaced_by_a_partial_projection(fault):
    peer=Peer();fields=peer.schema['results']['children'];row=peer.body['results']
    if fault=='missing-schema-field':del fields['sender']
    elif fault=='extra-schema-field':fields['unclassified']={'type':'string'}
    elif fault=='wrong-type':fields['password']['type']='string'
    elif fault=='duplicate-option':fields['type']['options'].append(dict(fields['type']['options'][0]))
    elif fault=='invalid-option':row['ssl-min-proto-version']='unclassified-option'
    elif fault=='ipv4-type':row['source-ip']='2001:db8::1'
    elif fault=='ipv6-type':row['source-ip6']='192.0.2.1'
    elif fault=='missing-row-field':del row['source-ip6']
    source=peer.source()
    with pytest.raises(ValueError):source.read()
    assert source._last_failure_stage==('complete_schema'if fault in {'missing-schema-field','extra-schema-field','wrong-type','duplicate-option'}
        else'complete_current_fields'if fault=='missing-row-field'else'schema_value_validation')
    assert all(r.closed for r in peer.resources)and all(not any(b)for b in peer.buffers)


def test_only_compiled_schema_and_current_routes_are_readable():
    peer=Peer();source=peer.source()
    with pytest.raises(ValueError):source._fetch('/api/v2/cmdb/system/admin')
    assert not peer.calls
