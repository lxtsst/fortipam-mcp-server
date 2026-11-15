"""Bounded native reference calibration cannot grant Job deletion authority."""
import pytest

from fortipam_mcp import job_definition_reference_reader as module
from test_folder_namespace_ssh_reader import Peer as BasePeer, config, frame

CANDIDATE = "mcp-v4-bp008-job-20261022-r31"
ANCHOR = "mcp-v4-bp008-job-20260930-r6"


class Peer(BasePeer):
    def __init__(self):
        super().__init__()
        self.failure = None

    async def read(self, process, command, prompt, deadline):
        if command in (module._SERIAL_COMMAND, module._VERSION_COMMAND):
            return await super().read(process, command, prompt, deadline)
        assert process is self and prompt == self.root
        self.commands.append(command)
        if "secret.database.id" in command:
            assert command.endswith(" 999")
            names = (module._SOURCE, ANCHOR)
            if self.failure == "prefix": names = tuple(name + "-other" for name in names)
            lines = [b"entry used by secret.job:" + name.encode() for name in names]
            if self.failure == "false-control": lines = []
        else:
            assert command in tuple("diagnose sys cmdb refcnt show secret.job.name " + name for name in (ANCHOR, CANDIDATE))
            lines = [b"entry used by secret.other:bound"] if self.failure == command.rsplit(" ", 1)[-1] else []
            if self.failure == "error": lines = [b"Command fail."]
        return frame(command, lines or [b""], self.root)


@pytest.fixture
def peer(monkeypatch, config):
    peer = Peer()
    monkeypatch.setattr(module, "FortiPamTargetReferenceSshTransport", lambda config: peer)
    monkeypatch.setattr(module, "_send_and_read", peer.read)
    monkeypatch.setattr(module, "_close_cli", peer.close)
    return peer


def read(config, **changes):
    fields = dict(candidate_name=CANDIDATE, anchor_name=ANCHOR, secret_id=999,
        serial="SYNTHETIC_SERIAL", before_send=lambda: None)
    return module.read_job_reference_control(config, **(fields | changes))


def test_actual_two_job_reference_controls_precede_fixed_zero_reads(config, peer):
    result = read(config)
    assert result.candidate_unreferenced and result.anchor_unreferenced and result.positive_reference_count == 2
    assert len(result.snapshot_digest) == 64 and ANCHOR not in repr(result) and CANDIDATE not in repr(result)
    assert peer.commands == [module._SERIAL_COMMAND, module._VERSION_COMMAND,
        "diagnose sys cmdb refcnt show secret.database.id 999",
        "diagnose sys cmdb refcnt show secret.job.name " + ANCHOR,
        "diagnose sys cmdb refcnt show secret.job.name " + CANDIDATE]
    assert peer.closed == peer.connection_closed == 1


@pytest.mark.parametrize("failure", ["false-control", "prefix", "error", ANCHOR, CANDIDATE])
def test_false_calibration_or_nonzero_job_cannot_qualify_empty_references(config, peer, failure):
    peer.failure = failure
    with pytest.raises(RuntimeError) as error: read(config)
    assert str(error.value) == module._ERROR
    assert peer.closed == peer.connection_closed == 1


@pytest.mark.parametrize("binding", [{"secret_id": True}, {"candidate_name": "unbounded; command"},
    {"anchor_name": CANDIDATE}, {"serial": "invalid serial"}])
def test_invalid_bound_subjects_refuse_before_contact(config, peer, binding):
    with pytest.raises(RuntimeError): read(config, **binding)
    assert not peer.commands and peer.connection_closed == 0
