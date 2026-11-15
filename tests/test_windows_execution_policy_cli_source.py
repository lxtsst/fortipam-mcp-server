"""Fixed Policy CLI evidence rejects incomplete names, false zero and drift."""
import pytest

import fortipam_mcp.windows_execution_policy_cli_source as m
from fortipam_mcp.target_ssh_transport import TargetSshTransportConfig
from test_windows_execution_policy_contract import compile_request, SERIAL, BINDING

ROOT = b'FPA-SYNTHETIC #'
POLICY = b'FPA-SYNTHETIC (policy) #'


def frame(command, lines, prompt):
    return command.encode()+b'\r\r\n'+b''.join(line+b'\r\n' for line in lines)+prompt


class Peer:
    def __init__(self, *, present=False, failure=None):
        self.names = tuple(sorted(('default', 'other-policy', *((BINDING.name,) if present else ()))))
        self.failure = failure
        self.stdout = self.stdin = self
        self.commands = []
        self.connected = self.closed = self.waited = self.aborted = 0
        self.names_reads = 0

    async def connect(self):
        self.connected += 1
        return self

    async def create_process(self, **kwargs):
        assert kwargs == dict(term_type='vt100', term_size=(200,24), encoding=None)
        return self

    async def login(self, *args, **kwargs):
        if self.failure == 'login':raise OSError('synthetic private failure')
        return ROOT

    async def dynamic(self, process, command, prompt, deadline):
        assert process is self and prompt == ROOT
        self.commands.append(command)
        assert command in ('config secret policy','end')
        if self.failure == 'context':return b'FPA-SYNTHETIC (target) #'
        return POLICY if command == 'config secret policy' else ROOT

    async def read(self, process, command, prompt, deadline):
        assert process is self
        self.commands.append(command)
        if command == m._SERIAL:
            rows=[b'Serial-Number: '+(b'WRONG' if self.failure == 'serial' else SERIAL.encode())]
        elif command == m._VERSION:
            rows=[b'Version: FortiPAM-VM v7.0.0,build'+(b'0030' if self.failure == 'version' else b'0029')+b', synthetic']
        elif command == m._NAMES:
            self.names_reads += 1
            names=self.names
            if self.failure == 'hidden' or self.failure == 'names-drift' and self.names_reads == 2:
                names=(*names,'hidden-policy')
            rows=[b'    edit "'+name.encode()+b'"' for name in names]
            if self.failure == 'truncated':rows.append(b'--More--')
            if self.failure == 'duplicate':rows.append(rows[0])
        elif command == m._REFERENCE+'"default"':
            rows=[] if self.failure == 'false-control-zero' else [b'entry used by secret.folder:1',b'entry used by secret.folder:2']
            if self.failure == 'command-error':rows=[b'command parse error before name']
        elif command == m._REFERENCE+'"'+BINDING.name+'"':
            rows=[b'entry used by secret.folder:3'] if self.failure == 'candidate-reference' else []
        else:pytest.fail('Uncompiled command.')
        return frame(command,rows,prompt)

    def close(self):self.closed += 1
    async def wait_closed(self):self.waited += 1
    def abort(self):self.aborted += 1


def make(tmp_path, monkeypatch, *, present=False, failure=None, reference_profile=m.ZERO_PROFILE):
    path=tmp_path/'known-hosts';path.write_text('synthetic-pin\n');path.chmod(0o600)
    config=TargetSshTransportConfig('pam.example',22,'synthetic-owner','synthetic-password',path,30)
    now=[100.0]
    source=m.WindowsPolicyCliSource(config,request=compile_request(),control_policy_name='default',clock=lambda:now[0],
        reference_profile=reference_profile)
    peer=Peer(present=present,failure=failure)
    monkeypatch.setattr(source._ssh,'_connection',peer.connect)
    monkeypatch.setattr(m,'_complete_pre_login',peer.login)
    monkeypatch.setattr(m,'_send_and_read',peer.read)
    monkeypatch.setattr(m,'_send_and_read_dynamic_prompt',peer.dynamic)
    return source,peer,now,path


def test_one_reference_requires_distinct_explicit_folder_profile(tmp_path,monkeypatch):
    source,peer,_,_=make(tmp_path,monkeypatch,present=True,failure='candidate-reference')
    with pytest.raises(m.WindowsPolicyCliSourceError):
        source.observe(api_names=peer.names,control_reference_count=2,candidate_reference_count=1,before_send=lambda:None)
    assert not peer.commands
    source,peer,_,_=make(tmp_path,monkeypatch,present=True,failure='candidate-reference',reference_profile=m.FOLDER_LINK_PROFILE)
    observed=source.observe(api_names=peer.names,control_reference_count=2,candidate_reference_count=1,before_send=lambda:None)
    source.check_current(observed,api_names=peer.names,control_reference_count=2,candidate_reference_count=1)
    assert observed.candidate_reference_count==1 and observed.command_count==12
    source.close()


def test_legacy_context_digest_is_unchanged_and_profile_rebinding_poisoned(tmp_path,monkeypatch):
    import hashlib
    source,peer,_,hosts=make(tmp_path,monkeypatch,present=True)
    value=source._config
    old=m._digest((m._CONTRACT,source._request.request_digest,source._control,value.host,value.port,value.username,
        hashlib.sha256(value.password.encode()).hexdigest(),hashlib.sha256(hosts.read_bytes()).hexdigest(),value.timeout_seconds))
    assert source._context()==old
    source._reference_profile=m.FOLDER_LINK_PROFILE
    assert source._context()!=old
    with pytest.raises(m.WindowsPolicyCliSourceError):
        source.observe(api_names=peer.names,control_reference_count=2,candidate_reference_count=0,before_send=lambda:None)
    assert not peer.commands


@pytest.mark.parametrize('present',[False,True])
def test_global_namespace_and_positive_control_bind_absence_or_existing_zero(tmp_path,monkeypatch,present):
    source,peer,now,_=make(tmp_path,monkeypatch,present=present)
    count=0 if present else None
    observation=source.observe(api_names=peer.names,control_reference_count=2,
        candidate_reference_count=count,before_send=lambda:None)
    assert observation.candidate_absent is (not present) and observation.candidate_reference_count == count
    assert observation.global_count == len(peer.names) and observation.control_reference_count == 2
    assert len(peer.commands) == (12 if present else 11)
    assert peer.closed == peer.waited == peer.aborted == 1
    source.check_current(observation,api_names=peer.names,control_reference_count=2,candidate_reference_count=count)
    with pytest.raises(m.WindowsPolicyCliSourceError):source.check_current(observation,api_names=peer.names,
        control_reference_count=3,candidate_reference_count=count)
    now[0]=130.0
    with pytest.raises(m.WindowsPolicyCliSourceError):source.check_current(observation,api_names=peer.names,
        control_reference_count=2,candidate_reference_count=count)


@pytest.mark.parametrize('failure',['serial','version','context','login','hidden','names-drift','truncated',
    'duplicate','false-control-zero','command-error','candidate-reference'])
def test_incomplete_or_mismatching_evidence_refuses_and_closes(tmp_path,monkeypatch,failure):
    source,peer,_,_=make(tmp_path,monkeypatch,present=True,failure=failure)
    with pytest.raises(m.WindowsPolicyCliSourceError):source.observe(api_names=peer.names,
        control_reference_count=2,candidate_reference_count=0,before_send=lambda:None)
    assert peer.closed == peer.waited == peer.aborted == 1
    before=list(peer.commands)
    with pytest.raises(m.WindowsPolicyCliSourceError):source.observe(api_names=peer.names,
        control_reference_count=2,candidate_reference_count=0,before_send=lambda:None)
    assert peer.commands == before


@pytest.mark.parametrize('failure',['pin','role-guard','clock','closed'])
def test_source_or_guard_failure_prevents_new_io(tmp_path,monkeypatch,failure):
    source,peer,now,path=make(tmp_path,monkeypatch)
    if failure == 'pin':path.write_text('changed-pin\n')
    if failure == 'clock':now[0]=float('nan')
    if failure == 'closed':source.close()
    def guard():
        if failure == 'role-guard':raise ValueError('synthetic private role drift')
    with pytest.raises(m.WindowsPolicyCliSourceError):source.observe(api_names=peer.names,
        control_reference_count=2,candidate_reference_count=None,before_send=guard)
    assert not peer.connected and not peer.commands


def test_false_zero_for_absent_candidate_is_not_an_existing_key_reference_observation(tmp_path,monkeypatch):
    source,peer,_,_=make(tmp_path,monkeypatch)
    with pytest.raises(m.WindowsPolicyCliSourceError):source.observe(api_names=peer.names,
        control_reference_count=2,candidate_reference_count=0,before_send=lambda:None)
    assert not peer.connected


def test_clock_failure_invalidates_the_previous_observation_permanently(tmp_path,monkeypatch):
    source,peer,_,_=make(tmp_path,monkeypatch)
    observation=source.observe(api_names=peer.names,control_reference_count=2,
        candidate_reference_count=None,before_send=lambda:None)
    def unavailable():raise ValueError('synthetic unavailable clock')
    source._clock=unavailable
    with pytest.raises(m.WindowsPolicyCliSourceError):source.check_current(observation,api_names=peer.names,
        control_reference_count=2,candidate_reference_count=None)
    source._clock=lambda:100.0
    with pytest.raises(m.WindowsPolicyCliSourceError):source.check_current(observation,api_names=peer.names,
        control_reference_count=2,candidate_reference_count=None)
