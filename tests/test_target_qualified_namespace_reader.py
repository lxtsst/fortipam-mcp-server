"""Lifecycle namespace requires stable global projection and fresh witnesses."""
from dataclasses import replace
import hashlib
import asyncio
import pytest
from fortipam_mcp import target_qualified_namespace_reader as m
from test_target_qualified_reference_reader import Peer,SERIAL,ROOT,frame

NAME='mcp-v4-target-synthetic'
WITNESSES=('Synthetic A','Synthetic B')
CONTEXT=ROOT[:-2]+b' (target) #'


@pytest.fixture
def setup(tmp_path,monkeypatch):
    pin=tmp_path/'known_hosts';pin.write_text('synthetic pin\n');pin.chmod(0o600)
    config=m.TargetSshTransportConfig('synthetic.invalid',22,'synthetic','synthetic-password',pin,10)
    peer=Peer();peer.names=WITNESSES+('Hidden Target',);peer.second=None;peer.projections=0;peer.returned=ROOT
    now=[100.0]
    async def read(process,command,prompt,deadline):
        if command!=m._NAMES:return await peer.read(process,command,prompt,deadline)
        assert prompt==CONTEXT
        peer.commands.append(command);peer.projections+=1
        names=peer.second if peer.projections==2 and peer.second is not None else peer.names
        return frame(command,[b'    edit "'+x.encode()+b'"' for x in names],prompt=CONTEXT)
    async def dynamic(process,command,prompt,deadline):
        peer.commands.append(command)
        return CONTEXT if command=='config secret target' else peer.returned
    monkeypatch.setattr(m,'FortiPamTargetReferenceSshTransport',lambda config:peer)
    monkeypatch.setattr(m,'_complete_pre_login',peer.login)
    monkeypatch.setattr(m,'_send_and_read',read)
    monkeypatch.setattr(m,'_send_and_read_dynamic_prompt',dynamic)
    reader=m.FortiPamTargetQualifiedNamespaceReader(config,serial_digest=hashlib.sha256(SERIAL).hexdigest(),clock=lambda:now[0])
    return reader,peer,now


@pytest.mark.parametrize('present',[False,True,'case'])
def test_bracketed_global_projection_covers_visible_witnesses(setup,present):
    reader,peer,now=setup
    if present:peer.names+=(NAME.upper() if present=='case' else NAME,)
    observed=reader.read_namespace(NAME,api_names=WITNESSES)
    reader.check_current(observed,candidate_name=NAME,api_names=WITNESSES)
    assert observed.candidate_absent==(not present) and observed.target_count==len(peer.names)
    assert 'Hidden Target' not in repr(observed) and NAME not in repr(observed)
    assert peer.commands==[m.r._SERIAL,m.r._VERSION,'config secret target',m._NAMES,m._NAMES,'end',m.r._SERIAL,m.r._VERSION]
    assert (peer.closed,peer.waited,peer.disconnected)==(1,1,1)


@pytest.mark.parametrize('fault',['drift','missing_witness','duplicate','oversize','escape','return','serial_after','version_after','login'])
def test_namespace_failure_never_returns_partial_absence(setup,fault):
    reader,peer,now=setup
    if fault=='drift':peer.second=tuple(reversed(peer.names))
    elif fault=='missing_witness':peer.names=('Other A','Other B')
    elif fault=='duplicate':peer.names=WITNESSES+(WITNESSES[0],)
    elif fault=='oversize':peer.names=tuple('Target '+str(i) for i in range(129))
    elif fault=='escape':peer.names=WITNESSES+('Invalid\\name',)
    elif fault=='return':peer.returned=b'WRONG #'
    elif fault=='serial_after':peer.overrides[7]=frame(m.r._SERIAL,[b'Serial-Number: OTHER'])
    elif fault=='version_after':peer.overrides[8]=frame(m.r._VERSION,[b'Version: FortiPAM v7.0.1,build0029'])
    else:peer.raise_login=True
    with pytest.raises(m.TargetQualifiedNamespaceError):reader.read_namespace(NAME,api_names=WITNESSES)
    assert reader._current is None and (peer.closed,peer.waited,peer.disconnected)==(1,1,1)


@pytest.mark.parametrize('fault',['copy','superseded','failed_read','expired','rollback','closed','candidate','witness'])
def test_current_observation_binding_and_invalidation(setup,fault):
    reader,peer,now=setup;value=reader.read_namespace(NAME,api_names=WITNESSES)
    candidate=NAME;witness=WITNESSES
    if fault=='copy':value=replace(value)
    elif fault=='superseded':reader.read_namespace(NAME,api_names=WITNESSES)
    elif fault=='failed_read':
        with pytest.raises(m.TargetQualifiedNamespaceError):reader.read_namespace('invalid',api_names=WITNESSES)
    elif fault=='expired':now[0]=110
    elif fault=='rollback':now[0]=99
    elif fault=='closed':reader.close()
    elif fault=='candidate':candidate=NAME+'2'
    else:witness=('Other A','Other B')
    with pytest.raises(m.TargetQualifiedNamespaceError):reader.check_current(value,candidate_name=candidate,api_names=witness)
    if fault=='rollback':
        now[0]=100
        with pytest.raises(m.TargetQualifiedNamespaceError):reader.check_current(value,candidate_name=NAME,api_names=WITNESSES)


def test_cleanup_deadline_aborts_connection(setup):
    reader,peer,now=setup
    async def hang():await asyncio.Event().wait()
    peer.wait_closed=hang
    with pytest.raises(m.TargetQualifiedNamespaceError):reader.read_namespace(NAME,api_names=WITNESSES)
    assert peer.disconnected==1 and reader._current is None


@pytest.mark.parametrize('names',[(),('One',),['A','B'],('A','A'),('A','B\nunsafe'),('A','B\\unsafe')])
def test_unqualified_witnesses_no_connection(setup,names):
    reader,peer,now=setup
    with pytest.raises(m.TargetQualifiedNamespaceError):reader.read_namespace(NAME,api_names=names)
    assert peer.connected==0
