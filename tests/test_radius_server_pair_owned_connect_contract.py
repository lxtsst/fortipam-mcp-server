"""Bounded pair observation grammar, ordinal binding and raw-buffer clearing."""
from __future__ import annotations

import copy
import json
import pickle
from typing import Any

import pytest

from fortipam_mcp.radius_server_pair_contract import RadiusServerPairError
from fortipam_mcp.radius_server_pair_owned_connect_contract import project_pair_owned_connect_observation
from v4_planning.material_provider import MaterialAccessDenied
from test_radius_server_pair_contract import binding
from test_radius_server_projection import SERIAL, envelope


def project(value: Any,ordinal: str='secondary',**changes: Any) -> Any:
    raw=bytearray(json.dumps(value).encode());args=dict(ordinal=ordinal,expected_serial=SERIAL,http_status=200)
    args.update(changes)
    try:return project_pair_owned_connect_observation(raw,binding(),**args)
    finally:assert not raw


@pytest.mark.parametrize('ordinal',['primary','secondary'])
@pytest.mark.parametrize('status',['reachable','invalid_secret','ok','SYNTHETIC_PRIVATE'])
def test_minimized_result_never_qualifies_connectivity(ordinal: str,status: str) -> None:
    b=binding();address=b.server if ordinal=='primary' else b.secondary_server
    value=envelope(http_method='POST',action='test-connect',mkey=b.name,results={'status':status,'server':address})
    observation=project(value,ordinal)
    assert observation.ordinal==ordinal and observation.negative_status==(status=='invalid_secret')
    assert observation.status_token==(None if status=='SYNTHETIC_PRIVATE' else status)
    rendered=json.dumps(observation.as_dict())
    assert not observation.as_dict()['connectivity_qualified'] and not observation.reject_only_shape
    for private in (b.name,address,SERIAL,'SYNTHETIC_PRIVATE'):assert private not in rendered
    for operation in (copy.copy,copy.deepcopy,pickle.dumps):
        with pytest.raises(MaterialAccessDenied):operation(observation)


@pytest.mark.parametrize('fault',['ordinal','server','serial','build','route','method','selector','unknown_field','oversize','malformed'])
def test_invalid_response_or_foreign_selector_is_denied_and_cleared(fault: str) -> None:
    b=binding();value=envelope(http_method='POST',action='test-connect',mkey=b.name,results={'status':'ok'})
    changes={}
    if fault=='ordinal':changes['ordinal']='tertiary'
    elif fault=='server':value['results']['server']=b.server
    elif fault=='serial':value['serial']='SYNTHETIC_OTHER'
    elif fault=='build':value['build']=30
    elif fault=='route':value['action']='another-operation'
    elif fault=='method':value['http_method']='GET'
    elif fault=='selector':value['mkey']='SYNTHETIC_OTHER'
    elif fault=='unknown_field':value['results']['unknown']='SYNTHETIC_PRIVATE'
    elif fault=='oversize':value['results']['access_message']='x'*66000
    else:value['results']=[]
    with pytest.raises(RadiusServerPairError):project(value,**changes)
