"""One fixed global Job-name projection, never script/configuration output."""
import pytest

from fortipam_mcp import job_namespace_ssh_reader as module
from test_folder_namespace_ssh_reader import Peer as FolderPeer, config, frame

CANDIDATE = "mcp-v4-bp008-job-20261022-r31"
WITNESSES = ("mcp-v4-bp008-job-20260930-r3", "mcp-v4-bp008-job-20261001-r6")
JOB = b"FPA-SYNTHETIC (job) #"


def names_frame(names):
    return frame(module._NAME_PROJECTION, [b'    edit "' + name.encode() + b'"' for name in names], JOB)


class JobPeer(FolderPeer):
    def __init__(self):
        super().__init__()
        self.folder = JOB
        self.names = names_frame(WITNESSES + ("Other hidden Job",))
        self.hook = lambda: None

    async def read(self, process, command, prompt, deadline):
        if command in (module._SERIAL_COMMAND, module._VERSION_COMMAND):
            return await super().read(process, command, prompt, deadline)
        assert process is self and prompt == JOB and command == module._NAME_PROJECTION
        self.commands.append(command)
        self.name_reads += 1
        if self.name_reads == 2:
            self.hook()
            if self.second_names is not None:
                return self.second_names
        return self.names

    async def dynamic(self, process, command, prompt, deadline):
        assert process is self and prompt == self.root and deadline == 12345
        self.commands.append(command)
        assert command in ("config secret job", "end")
        return self.folder if command == "config secret job" else self.returned


@pytest.fixture
def peer(monkeypatch, config):
    value = JobPeer()
    value._config = config
    monkeypatch.setattr(module, "FortiPamTargetReferenceSshTransport", lambda config: value)
    monkeypatch.setattr(module, "_send_and_read", value.read)
    monkeypatch.setattr(module, "_send_and_read_dynamic_prompt", value.dynamic)
    monkeypatch.setattr(module, "_close_cli", value.close)
    return value


def reader(config, **changes):
    args = dict(candidate_name=CANDIDATE, positive_witness_names=WITNESSES, expected_device_serial="SYNTHETIC_SERIAL")
    return module.FortiPamJobNamespaceSshReader(config, **(args | changes))


@pytest.mark.parametrize("candidate", [None, CANDIDATE, CANDIDATE.upper()])
def test_global_subset_positive_controls_and_casefold_collisions(config, peer, candidate):
    names = WITNESSES + ("Other hidden Job",) + (() if candidate is None else (candidate,))
    peer.names = names_frame(names)
    source = reader(config)
    result = source.read_namespace()
    assert result.global_name_absent is (candidate is None)
    assert result.job_count == len(names) and result.positive_witness_count == 2
    assert source._names == names and len(result.namespace_digest) == 64
    assert all(name not in repr(result) for name in names)
    assert peer.commands == [module._SERIAL_COMMAND, module._VERSION_COMMAND, "config secret job",
        module._NAME_PROJECTION, module._NAME_PROJECTION, "end"]
    assert peer.closed == peer.connection_closed == 1
    with pytest.raises(module.JobNamespaceSshReaderError): source.read_namespace()
    assert peer.connection_closed == 1
    source.close()
    assert not source._names


@pytest.mark.parametrize("fault", ["case-duplicate", "missing-positive", "script", "drift", "serial", "context", "exit", "source", "close"])
def test_unqualified_global_projection_never_proves_absence_or_leaks_native_values(config, peer, fault):
    source = reader(config)
    if fault == "case-duplicate": peer.names = names_frame(WITNESSES + (WITNESSES[0].upper(),))
    if fault == "missing-positive": peer.names = names_frame(WITNESSES[1:])
    if fault == "script": peer.names = frame(module._NAME_PROJECTION, [b'    set script "SENSITIVE_SENTINEL"'], JOB)
    if fault == "drift": peer.second_names = names_frame(tuple(reversed(WITNESSES)))
    if fault == "serial": peer.serial = frame(module._SERIAL_COMMAND, [b"Serial-Number: OTHER"])
    if fault == "context": peer.folder = b"FPA-SYNTHETIC (target) #"
    if fault == "exit": peer.returned = b"OTHER #"
    if fault == "source": peer.hook = lambda: config.known_hosts_file.write_text("Changed pinned source")
    if fault == "close": peer.close_error = True
    with pytest.raises(module.JobNamespaceSshReaderError) as caught: source.read_namespace()
    assert str(caught.value) == module._ERROR and not source._names and source._closed
    assert peer.closed == peer.connection_closed == 1


@pytest.mark.parametrize("changes", [{"candidate_name": "arbitrary"}, {"positive_witness_names": WITNESSES[:1]},
    {"positive_witness_names": WITNESSES + (WITNESSES[0].upper(),)}, {"expected_device_serial": "bad serial"}])
def test_invalid_binding_rejects_before_ssh(config, peer, changes):
    with pytest.raises(module.JobNamespaceSshReaderError): reader(config, **changes)
    assert not peer.commands and peer.connection_closed == 0
