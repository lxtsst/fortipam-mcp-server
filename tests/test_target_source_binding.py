"""Constructor snapshot binding with actual readers/adapters and no network."""
from dataclasses import replace
import json
import ssl

import pytest

from fortipam_mcp import target_api_dependency_reader as r
from fortipam_mcp import target_creation_http_transport as creator
from fortipam_mcp import target_preservation_http_transport as coordinate
from fortipam_mcp import target_preservation_contract as c
from test_target_api_dependency_reader import Harness, COORDINATES, DIGEST
from test_target_preservation_contract import row, capture


@pytest.fixture
def sources(tmp_path, monkeypatch):
    original=ssl.create_default_context
    loaded=[]
    def context(*,cadata=None):
        loaded.append(cadata)
        return original()
    monkeypatch.setattr(ssl,'create_default_context',context)
    ca=tmp_path/'ca.pem';ca.write_text('SYNTHETIC_CA_A')
    config=r.SecretMetadataHttpTransportConfig('https://synthetic.invalid','synthetic-token',30,str(ca))
    h=Harness()
    def reader():
        return r.TargetApiDependencyReader(config,serial_digest=DIGEST,clock=lambda:h.now,client_factory=h.factory)
    def adapter(kind, **changes):
        directory=tmp_path/str(len(list(tmp_path.iterdir())));directory.mkdir(mode=0o700)
        state=capture(row())
        if 'serial_digest' in changes:
            serial=changes.pop('serial_digest')
            state_digest,preserved=c._state_digests(state.name,serial,state.field_digests,state.metadata_digests)
            state=replace(state,serial_digest=serial,state_digest=state_digest,preserved_digest=preserved)
        cfg=replace(config,**changes)
        if kind=='coordinate':
            return coordinate.TargetCoordinateHttpTransport(cfg,c.TargetCoordinateChange(
                state,replace(state.coordinates,address='192.0.2.99')),state_directory=directory)
        body={key:row()[key] for key in c.TARGET_STATE_FIELDS-creator.e._GENERATED}
        body['$originalName']=state.name
        return creator.TargetCreationHttpTransport(cfg,state,bytearray(json.dumps(body).encode()),
            state_directory=directory,provenance_key=b'k'*32)
    return h,reader,adapter,ca,loaded


@pytest.mark.parametrize('kind',['creator','coordinate'])
def test_actual_snapshot_binding_survives_path_change_without_reloading(sources,kind):
    h,make_reader,make_adapter,ca,loaded=sources
    reader=make_reader();transport=make_adapter(kind);observation=reader.observe(COORDINATES)
    reader.check_transport_source(observation,transport)
    ca.write_text('SYNTHETIC_CA_B')
    reader.check_transport_source(observation,transport)
    other=make_adapter(kind)
    with pytest.raises(r.TargetApiDependencyReadError):reader.check_transport_source(observation,other)
    ca.write_text('SYNTHETIC_CA_A')
    with pytest.raises(r.TargetApiDependencyReadError):reader.check_transport_source(observation,other)
    assert loaded==['SYNTHETIC_CA_A','SYNTHETIC_CA_A','SYNTHETIC_CA_B']
    assert len(h.requests)==8 and not transport._enabled
    if kind=='creator':assert not transport._recovery_enabled
    assert not list(ca.parent.rglob('*.claim.json'))


@pytest.mark.parametrize('kind',['creator','coordinate'])
@pytest.mark.parametrize('changes',[{'base_url':'https://other.invalid'},
    {'bearer_token':'another-synthetic-token'},{'serial_digest':'b'*64},{'ca_file':None}])
def test_source_mismatch_denied(sources,kind,changes):
    h,make_reader,make_adapter,ca,loaded=sources
    reader=make_reader();observed=reader.observe(COORDINATES)
    with pytest.raises(r.TargetApiDependencyReadError):
        reader.check_transport_source(observed,make_adapter(kind,**changes))
    assert len(h.requests)==8


@pytest.mark.parametrize('state',['foreign','copied','superseded','expired','closed','failed'])
def test_binding_requires_current_observation(sources,state):
    h,make_reader,make_adapter,ca,loaded=sources
    reader=make_reader();observed=reader.observe(COORDINATES);transport=make_adapter('creator')
    if state=='foreign':observed=make_reader().observe(COORDINATES)
    elif state=='copied':observed=replace(observed)
    elif state=='superseded':reader.observe(COORDINATES)
    elif state=='expired':h.now=40
    elif state=='closed':reader.close()
    else:
        h.fault='status'
        with pytest.raises(r.TargetApiDependencyReadError):reader.observe(COORDINATES)
    with pytest.raises(r.TargetApiDependencyReadError):reader.check_transport_source(observed,transport)


def test_digest_lookalike_is_not_a_transport(sources):
    h,make_reader,make_adapter,ca,loaded=sources
    reader=make_reader();observed=reader.observe(COORDINATES)
    class Impostor:
        _source_context_digest=observed.source_context_digest
    with pytest.raises(r.TargetApiDependencyReadError):reader.check_transport_source(observed,Impostor())
