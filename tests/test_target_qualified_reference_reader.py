import hashlib

import pytest

import fortipam_mcp.target_qualified_reference_reader as m
from fortipam_mcp.target_ssh_transport import TargetSshTransportConfig

NAME = 'mcp-v4-target-synthetic'
ROOT = b'FPA-SYNTHETIC #'
SERIAL = b'SYNTHETIC_SERIAL'
VERSION = b'Version: FortiPAM-VM v7.0.0,build0029, synthetic'


def frame(command, lines=(), ending=b'\r\r\n', prompt=ROOT):
    return command.encode() + ending + b''.join(line + b'\r\n' for line in lines) + prompt


class Peer:
    def __init__(self):
        self.commands = []
        self.closed = self.waited = self.disconnected = self.connected = 0
        self.stdout = self.stdin = self
        self.prompt = ROOT
        self.overrides = {}
        self.raise_login = False

    async def _connection(self):
        self.connected += 1
        return self

    def abort(self):
        self.disconnected = 1

    async def create_process(self, **kwargs):
        assert kwargs == dict(term_type='vt100', term_size=(200, 24), encoding=None)
        return self

    async def login(self, stdout, stdin, deadline, limit, **kwargs):
        assert stdout is self and stdin is self and limit == 65536
        assert kwargs == dict(accept_pre_login_banner=False)
        if self.raise_login:
            raise OSError('synthetic private login')
        return self.prompt

    async def read(self, process, command, prompt, deadline):
        assert process is self and prompt == ROOT
        self.commands.append(command)
        index = len(self.commands)
        if index in self.overrides:
            value = self.overrides[index]
            if isinstance(value, Exception):
                raise value
            return value
        lines = [b'Serial-Number: ' + SERIAL] if command == m._SERIAL else [VERSION] if command == m._VERSION else []
        return frame(command, lines)

    def close(self):
        self.closed += 1

    async def wait_closed(self):
        self.waited += 1


@pytest.fixture
def setup(tmp_path, monkeypatch):
    path = tmp_path / 'known_hosts'
    path.write_text('synthetic pin\n')
    path.chmod(0o600)
    config = TargetSshTransportConfig('synthetic.invalid', 22, 'synthetic', 'synthetic-password', path, 10)
    peer = Peer()
    monkeypatch.setattr(m, 'FortiPamTargetReferenceSshTransport', lambda config: peer)
    monkeypatch.setattr(m, '_complete_pre_login', peer.login)
    monkeypatch.setattr(m, '_send_and_read', peer.read)
    reader = m.FortiPamTargetQualifiedReferenceReader(config, serial_digest=hashlib.sha256(SERIAL).hexdigest())
    return reader, peer, config


@pytest.mark.parametrize('count', [0, 1, 3])
def test_same_session_binding_and_count(setup, count):
    reader, peer, _ = setup
    peer.overrides[3] = frame(m._REFERENCE + NAME, [b'entry used by synthetic'] * count)
    assert reader.reference_count(NAME) == count
    assert peer.commands == [m._SERIAL, m._VERSION, m._REFERENCE + NAME, m._SERIAL, m._VERSION]
    assert (peer.connected, peer.closed, peer.waited, peer.disconnected) == (1, 1, 1, 1)


@pytest.mark.parametrize('index,output', [
    (1, frame(m._SERIAL, [b'Serial-Number: OTHER'])),
    (4, frame(m._SERIAL, [b'Serial-Number: OTHER'])),
    (1, frame(m._SERIAL, [b'Serial-Number: ' + SERIAL] * 2)),
    (2, frame(m._VERSION, [VERSION.replace(b'0029', b'0290')])),
    (5, frame(m._VERSION, [VERSION.replace(b'7.0.0', b'7.0.1')])),
    (2, frame(m._VERSION, [VERSION] * 2)),
    (2, frame(m._VERSION, [VERSION, b'Unknown: value'])),
    (3, frame(m._REFERENCE + NAME, [b'Command fail'])),
    (3, frame(m._REFERENCE + NAME, [b'\x1bentry used by synthetic'])),
    (3, frame(m._REFERENCE + NAME, [b'\rentry used by synthetic'])),
    (3, frame('different command')),
    (3, frame(m._REFERENCE + NAME, prompt=b'OTHER #')),
    (3, frame(m._REFERENCE + NAME, ending=b'\n')),
    (3, b'x' * 65537),
    (3, OSError('synthetic private transport failure')),
])
def test_drift_framing_and_transport_fail_closed(setup, index, output):
    reader, peer, _ = setup
    peer.overrides[index] = output
    with pytest.raises(m.TargetQualifiedReferenceError) as error:
        reader.reference_count(NAME)
    assert str(error.value) == m._UNAVAILABLE and error.value.__suppress_context__
    assert len(peer.commands) == index
    assert (peer.closed, peer.waited, peer.disconnected) == (1, 1, 1)


@pytest.mark.parametrize('failure', ['prompt', 'login'])
def test_login_failure_closes_process(setup, failure):
    reader, peer, _ = setup
    peer.prompt = b'FPA (folder) #' if failure == 'prompt' else ROOT
    peer.raise_login = failure == 'login'
    with pytest.raises(m.TargetQualifiedReferenceError):
        reader.reference_count(NAME)
    assert not peer.commands
    assert (peer.closed, peer.waited, peer.disconnected) == (1, 1, 1)


@pytest.mark.parametrize('name', ['', 'other', NAME + '\nend', None, 1])
def test_invalid_name_no_io(setup, name):
    reader, peer, _ = setup
    with pytest.raises(m.TargetQualifiedReferenceError):
        reader.reference_count(name)
    assert peer.connected == 0


@pytest.mark.parametrize('digest', ['', 'A' * 64, 'g' * 64, None, b'a' * 64])
def test_invalid_binding_no_io(setup, digest):
    _, peer, config = setup
    with pytest.raises(m.TargetQualifiedReferenceError):
        m.FortiPamTargetQualifiedReferenceReader(config, serial_digest=digest)
    assert peer.connected == 0


def test_known_hosts_revalidated(setup):
    _, peer, config = setup
    config.known_hosts_file.chmod(0o644)
    with pytest.raises(m.TargetQualifiedReferenceError):
        m.FortiPamTargetQualifiedReferenceReader(config, serial_digest='a' * 64)
    assert peer.connected == 0


def test_valid_release_label_and_echo(setup):
    reader, peer, _ = setup
    peer.overrides[2] = frame(m._VERSION, [VERSION, b'Release Version Information: synthetic'], ending=b'\r\n')
    peer.overrides[3] = frame(m._REFERENCE + NAME, [b''], prompt=ROOT + b' ')
    assert reader.reference_count(NAME) == 0


def test_session_deadline_closes_process(setup, monkeypatch):
    import asyncio
    reader, peer, _ = setup
    reader._timeout = 0.01

    async def slow_read(*args):
        await asyncio.sleep(10)
        raise AssertionError('deadline did not cancel read')

    monkeypatch.setattr(m, '_send_and_read', slow_read)
    with pytest.raises(m.TargetQualifiedReferenceError):
        reader.reference_count(NAME)
    assert (peer.closed, peer.waited, peer.disconnected) == (1, 1, 1)


def test_string_subclass_rejected_before_io(setup):
    class Derived(str):
        pass

    reader, peer, config = setup
    with pytest.raises(m.TargetQualifiedReferenceError):
        reader.reference_count(Derived(NAME))
    with pytest.raises(m.TargetQualifiedReferenceError):
        m.FortiPamTargetQualifiedReferenceReader(config, serial_digest=Derived('a' * 64))
    assert peer.connected == 0


@pytest.mark.parametrize('read_timeout', [False, True])
def test_unresponsive_close_is_bounded_and_aborted(setup, monkeypatch, read_timeout):
    import asyncio
    import time
    reader, peer, _ = setup
    reader._timeout = 0.01 if read_timeout else 10

    async def hang(*args):
        await asyncio.Event().wait()

    monkeypatch.setattr(peer, 'wait_closed', hang)
    if read_timeout:
        monkeypatch.setattr(m, '_send_and_read', hang)
    started = time.monotonic()
    with pytest.raises(m.TargetQualifiedReferenceError):
        reader.reference_count(NAME)
    assert time.monotonic() - started < 2
    assert peer.closed == 1 and peer.disconnected == 1
