"""Synthetic original POST evidence and complete Target anchor conservation."""
from dataclasses import replace
import json

import pytest

from fortipam_mcp import target_creation_evidence as e
from fortipam_mcp import target_preservation_contract as c
from test_target_preservation_contract import row, response, capture, SERIAL, NAME


def envelope(*, absent=False, **changes):
    return bytearray(json.dumps(dict({'version':'v7.0.0','build':29,'path':'secret','name':'target',
        'vdom':'root','serial':SERIAL,'http_method':'GET' if absent else 'POST',
        'http_status':404 if absent else 200,'status':'Not Found' if absent else 'success',
        'mkey':NAME,'error':2 if absent else 0,'results':[] if absent else {'unknown':'MATERIAL_SENTINEL'}}, **changes)).encode())


def inputs():
    actual = row(); actual.update({'id':10,'uuid':'synthetic-assigned-uuid','creation-time':1234})
    return [envelope(absent=True), envelope(), response(actual)], actual


def test_original_creation_evidence_and_complete_anchor(monkeypatch):
    buffers, actual = inputs(); proposal = capture(row())
    loads = json.loads
    def selected(raw, *args, **kwargs):
        assert b'MATERIAL_SENTINEL' not in bytes(raw)
        return loads(raw,*args,**kwargs)
    monkeypatch.setattr(e.m.json,'loads',selected)
    evidence = e.verify_target_creation_evidence(*buffers,proposal=proposal,claim_digest='a'*64)
    assert all(not any(b) for b in buffers)
    current = response(actual)
    assert e.verify_original_target_state(current,evidence=evidence,expected_claim_digest='a'*64) == evidence.created
    assert not any(current) and NAME not in repr(evidence)


@pytest.mark.parametrize('field', sorted(c.TARGET_STATE_FIELDS - e._GENERATED))
def test_any_unrequested_created_field_denied_and_all_inputs_cleared(field):
    buffers, actual = inputs(); actual[field] = 'unexpected'
    buffers[2] = response(actual)
    with pytest.raises(e.TargetCreationEvidenceError):
        e.verify_target_creation_evidence(*buffers,proposal=capture(row()),claim_digest='a'*64)
    assert all(not any(b) for b in buffers)


@pytest.mark.parametrize('index,changes', [(0,{'results':[{'name':NAME}]}),(0,{'http_status':403}),
    (0,{'status':'success'}),(0,{'serial':'other'}),(1,{'mkey':'other'}),
    (1,{'error':-1}),(1,{'error':True}),(1,{'http_method':'PUT'}),(1,{'build':30})])
def test_wrong_native_evidence_denied(index, changes):
    buffers, _ = inputs(); buffers[index] = envelope(absent=index==0,**changes)
    with pytest.raises(e.TargetCreationEvidenceError):
        e.verify_target_creation_evidence(*buffers,proposal=capture(row()),claim_digest='a'*64)
    assert all(not any(b) for b in buffers)


@pytest.mark.parametrize('fault', ['claim','evidence','id','uuid','creation-time','metadata'])
def test_anchor_cannot_adopt_another_claim_or_changed_object(fault):
    buffers, actual = inputs()
    evidence = e.verify_target_creation_evidence(*buffers,proposal=capture(row()),claim_digest='a'*64)
    if fault == 'evidence': evidence = replace(evidence,absence_digest='b'*64)
    if fault in e._GENERATED: actual[fault] = 'replacement'
    if fault == 'metadata': actual['q_ref'] = 1
    content = response(actual)
    with pytest.raises(e.TargetCreationEvidenceError):
        e.verify_original_target_state(content,evidence=evidence,expected_claim_digest='b'*64 if fault=='claim' else 'a'*64)
    assert not any(content)


@pytest.mark.parametrize('shape',['missing','null','array','object'])
def test_build29_native_not_found_empty_shapes(shape):
    value=json.loads(envelope(absent=True));value.pop('mkey')
    if shape=='missing':value.pop('results')
    else:value['results']={'null':None,'array':[],'object':{}}[shape]
    buffers,_=inputs();buffers[0]=bytearray(json.dumps(value).encode())
    assert e.verify_target_creation_evidence(*buffers,proposal=capture(row()),claim_digest='a'*64)
    assert all(not any(b) for b in buffers)


@pytest.mark.parametrize('changes',[{'status':'error'},{'status':'not found'},{'error':True},
    {'error':2.0},{'error':0},{'error':3},{'error':'MATERIAL_SENTINEL'},
    {'results':{'name':NAME}},{'results':'MATERIAL_SENTINEL'},{'results':False}])
def test_unqualified_absence_never_normalized(changes,monkeypatch):
    buffers,_=inputs();buffers[0]=envelope(absent=True,**changes)
    loads=json.loads
    def selected(raw,*args,**kwargs):
        assert b'MATERIAL_SENTINEL' not in bytes(raw)
        return loads(raw,*args,**kwargs)
    monkeypatch.setattr(e.m.json,'loads',selected)
    with pytest.raises(e.TargetCreationEvidenceError):
        e.verify_target_creation_evidence(*buffers,proposal=capture(row()),claim_digest='a'*64)
    assert all(not any(b) for b in buffers)


def test_absence_error_code_is_required():
    value=json.loads(envelope(absent=True));del value['error']
    buffers,_=inputs();buffers[0]=bytearray(json.dumps(value).encode())
    with pytest.raises(e.TargetCreationEvidenceError):
        e.verify_target_creation_evidence(*buffers,proposal=capture(row()),claim_digest='a'*64)
    assert all(not any(b) for b in buffers)
