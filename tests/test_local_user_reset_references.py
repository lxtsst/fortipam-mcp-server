"""Positive calibration and stable reference frames precede any zero claim."""
import pytest

from fortipam_mcp import local_user_reset_references as module
from test_folder_namespace_ssh_reader import Peer as BasePeer, config, frame

CANDIDATE = "mcp-v4-user-reset-new-fixture"
POSITIVE = "synthetic-owner"
POSITIVE_COMMAND = "diagnose sys cmdb refcnt show system.admin.name " + POSITIVE
CANDIDATE_COMMAND = "diagnose sys cmdb refcnt show system.admin.name " + CANDIDATE


def references(command, count, *, changed=False):
    return frame(command, [b"entry used by table synthetic.field '" + str(i + int(changed)).encode() + b"'" for i in range(count)])


class Peer(BasePeer):
    def __init__(self):
        super().__init__()
        self.positive = references(POSITIVE_COMMAND, 3)
        self.candidate = references(CANDIDATE_COMMAND, 0)
        self.after = None
        self.positive_reads = 0
        self.hook = lambda:None

    async def read(self, process, command, prompt, deadline):
        if command in (module._SERIAL_COMMAND, module._VERSION_COMMAND):
            return await super().read(process, command, prompt, deadline)
        assert process is self and prompt == self.root
        self.commands.append(command); self.hook()
        if command == CANDIDATE_COMMAND: return self.candidate
        assert command == POSITIVE_COMMAND
        self.positive_reads += 1
        return self.after if self.positive_reads == 2 and self.after is not None else self.positive


@pytest.fixture
def peer(monkeypatch, config):
    value = Peer(); value._config = config
    monkeypatch.setattr(module, "FortiPamTargetReferenceSshTransport", lambda config:value)
    monkeypatch.setattr(module, "_send_and_read", value.read)
    monkeypatch.setattr(module, "_close_cli", value.close)
    return value


def reader(config, **changes):
    args = dict(candidate_name=CANDIDATE, positive_name=POSITIVE, api_positive_count=3,
        expected_serial="SYNTHETIC_SERIAL", before_send=lambda:None)
    return module.LocalResetReferenceReader(config, **(args | changes))


@pytest.mark.parametrize("count", [0, 2])
def test_five_fixed_reads_calibrate_before_observing_zero_or_nonzero(config, peer, count):
    peer.candidate = references(CANDIDATE_COMMAND, count)
    source = reader(config); observed = source.read_references()
    assert observed.candidate_reference_count == count and observed.candidate_unreferenced is (count == 0)
    assert observed.positive_reference_count == 3 and CANDIDATE not in repr(observed)
    assert peer.commands == [module._SERIAL_COMMAND, module._VERSION_COMMAND, POSITIVE_COMMAND, CANDIDATE_COMMAND, POSITIVE_COMMAND]
    assert peer.closed == peer.connection_closed == 1
    with pytest.raises(ValueError): source.read_references()
    assert peer.connection_closed == 1


@pytest.mark.parametrize("fault", ["zero-positive", "changed-count", "unknown-candidate", "drift", "serial", "source", "guard", "close"])
def test_uncalibrated_drifting_or_unrecognized_output_never_qualifies_zero(config, peer, fault):
    allowed = [True]
    def guard():
        if not allowed[0]: raise ValueError
    source = reader(config, before_send=guard)
    if fault == "zero-positive": peer.positive = references(POSITIVE_COMMAND, 0)
    if fault == "changed-count": peer.after = references(POSITIVE_COMMAND, 2)
    if fault == "unknown-candidate": peer.candidate = frame(CANDIDATE_COMMAND, [b"unsupported private output"])
    if fault == "drift": peer.after = references(POSITIVE_COMMAND, 3, changed=True)
    if fault == "serial": peer.serial = frame(module._SERIAL_COMMAND, [b"Serial-Number: FOREIGN"])
    if fault == "source": peer.hook = lambda:config.known_hosts_file.write_text("changed")
    if fault == "guard": peer.hook = lambda:allowed.__setitem__(0, False)
    if fault == "close": peer.close_error = True
    with pytest.raises(ValueError) as caught: source.read_references()
    assert str(caught.value) == module._ERROR and source._closed
    assert peer.closed == peer.connection_closed == 1


@pytest.mark.parametrize("changes", [{"candidate_name":"unbounded"}, {"positive_name":"bad;command"},
    {"positive_name":CANDIDATE}, {"api_positive_count":0}, {"api_positive_count":True},
    {"expected_serial":"bad serial"}, {"before_send":None}])
def test_invalid_binding_stops_before_ssh(config, peer, changes):
    with pytest.raises(ValueError): reader(config, **changes)
    assert not peer.commands and not peer.connection_closed


def test_api_and_cli_positive_counts_remain_independent_and_nonzero(config, peer):
    peer.positive = references(POSITIVE_COMMAND, 36)
    observed = reader(config, api_positive_count=37).read_references()
    assert observed.api_positive_count == 37 and observed.positive_reference_count == 36
    assert observed.candidate_unreferenced and observed.candidate_reference_count == 0
