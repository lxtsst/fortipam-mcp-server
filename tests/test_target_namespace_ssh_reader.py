from dataclasses import FrozenInstanceError

import pytest

from fortipam_mcp import target_namespace_ssh_reader as module
from test_folder_namespace_ssh_reader import Peer as FolderPeer, config, frame


CANDIDATE = "mcp-v4-target-web-20261007-r123"
WITNESSES = ("Synthetic Web Target", "Synthetic Other Target")
NAMES = WITNESSES + ("Third Target",)
TARGET = b"FPA-SYNTHETIC (target) #"


def names_frame(names=NAMES):
    return frame(module._NAME_PROJECTION, [b'    edit "' + name.encode() + b'"' for name in names], TARGET)


class TargetPeer(FolderPeer):
    def __init__(self):
        super().__init__()
        self.folder = TARGET
        self.names = names_frame()

    async def read(self, process, command, prompt, deadline):
        if command in {module._SERIAL_COMMAND, module._VERSION_COMMAND}:
            return await super().read(process, command, prompt, deadline)
        assert process is self and prompt == self.folder and deadline == 12345
        assert command == module._NAME_PROJECTION
        self.commands.append(command)
        if self.raise_at == command:
            raise OSError("synthetic private failure")
        self.name_reads += 1
        return self.second_names if self.name_reads == 2 and self.second_names is not None else self.names

    async def dynamic(self, process, command, prompt, deadline):
        assert process is self and prompt == self.root and deadline == 12345
        self.commands.append(command)
        if self.raise_at == command:
            raise OSError("synthetic private failure")
        assert command in {"config secret target", "end"}
        return self.folder if command == "config secret target" else self.returned


@pytest.fixture
def peer(monkeypatch):
    value = TargetPeer()
    monkeypatch.setattr(module, "FortiPamTargetReferenceSshTransport", lambda config: value)
    monkeypatch.setattr(module, "_send_and_read", value.read)
    monkeypatch.setattr(module, "_send_and_read_dynamic_prompt", value.dynamic)
    monkeypatch.setattr(module, "_close_cli", value.close)
    return value


def reader(config, **changes):
    args = dict(candidate_name=CANDIDATE, positive_witness_names=WITNESSES,
                expected_device_serial="SYNTHETIC_SERIAL", expected_api_names=NAMES)
    args.update(changes)
    return module.FortiPamTargetNamespaceSshReader(config, **args)


@pytest.mark.parametrize("present", (False, True))
def test_native_projection_is_stable_crosschecked_private_and_frozen(config, peer, present):
    names = NAMES + ((CANDIDATE,) if present else ())
    peer.names = names_frame(names)
    result = reader(config, expected_api_names=tuple(reversed(names))).read_namespace()
    assert result.status == ("name_present" if present else "name_absent")
    assert result.global_name_absent is not present
    assert result.target_count == len(names) and result.positive_witness_count == 2
    assert len(result.namespace_digest) == 64 and result.matches_candidate(CANDIDATE)
    assert not result.matches_candidate("mcp-v4-target-web-20261007-r124")
    assert not result.matches_candidate("invalid")
    assert all(value not in repr(result) for value in (*names, CANDIDATE, "SYNTHETIC_SERIAL"))
    with pytest.raises(FrozenInstanceError): result.target_count = 0
    assert peer.commands == [module._SERIAL_COMMAND, module._VERSION_COMMAND, "config secret target",
                             module._NAME_PROJECTION, module._NAME_PROJECTION, "end"]
    assert peer.closed == peer.connection_closed == 1


def test_only_qualified_echo_prompt_footer_and_unicode_names_are_allowed(config, peer):
    names = WITNESSES + ("测试 Target",)
    peer.names = names_frame(names).removesuffix(TARGET) + b"\r\n" + TARGET + b" "
    assert reader(config, expected_api_names=names).read_namespace().target_count == 3


@pytest.mark.parametrize("fault", (
    "duplicate", "nested", "unmatched", "escape", "control", "unicode_control", "empty", "long",
    "too_many", "missing_witness", "api_mismatch", "drift", "serial", "build", "root", "context", "exit",
    "echo", "footer", "page", "bare_lf",
))
def test_unqualified_projection_never_proves_absence_and_closes_peer(config, peer, fault):
    if fault == "duplicate": peer.names = names_frame(WITNESSES + (WITNESSES[0],))
    elif fault == "missing_witness": peer.names = names_frame(("Other",) + NAMES[1:])
    elif fault == "api_mismatch": peer.names = names_frame(WITNESSES + ("Unexpected",))
    elif fault == "too_many": peer.names = names_frame(tuple(f"Target {n}" for n in range(129)))
    elif fault in {"nested", "unmatched", "escape", "control", "unicode_control", "empty", "long", "page"}:
        line = {"nested": b'        edit "Nested"', "unmatched": b'    set name "Unexpected"',
                "escape": b'    edit "bad\\escape"', "control": b'    edit "bad\rname"',
                "unicode_control": '    edit "bad\u200bname"'.encode(), "empty": b'    edit ""',
                "long": b'    edit "' + b"x" * 65 + b'"', "page": b"--More--"}[fault]
        peer.names = frame(module._NAME_PROJECTION, [line], TARGET)
    elif fault == "drift": peer.second_names = names_frame(tuple(reversed(NAMES)))
    elif fault == "serial": peer.serial = frame(module._SERIAL_COMMAND, [b"Serial-Number: OTHER"])
    elif fault == "build": peer.version = frame(module._VERSION_COMMAND, [b"Version: FortiPAM v7.0.0,build30"])
    elif fault == "root": peer.root = b"FPA-SYNTHETIC $"
    elif fault == "context": peer.folder = b"FPA-SYNTHETIC (folder) #"
    elif fault == "exit": peer.returned = b"OTHER #"
    elif fault == "echo": peer.names = peer.names.replace(b'^    edit ', b'edit ', 1)
    elif fault == "footer": peer.names = peer.names.removesuffix(TARGET) + b"\r\n\r\n" + TARGET
    elif fault == "bare_lf": peer.names = peer.names.replace(b"\r\n", b"\n")
    with pytest.raises(module.TargetNamespaceSshReaderError, match=module._UNAVAILABLE):
        reader(config).read_namespace()
    assert peer.closed == peer.connection_closed == 1


@pytest.mark.parametrize("stage", ("open", module._NAME_PROJECTION, "end", "close"))
def test_failed_peer_always_closes_connection_without_native_details(config, peer, stage):
    peer.raise_at = stage
    peer.close_error = stage == "close"
    with pytest.raises(module.TargetNamespaceSshReaderError) as error: reader(config).read_namespace()
    assert str(error.value) == module._UNAVAILABLE
    assert peer.connection_closed == 1 and peer.closed == (0 if stage == "open" else 1)


@pytest.mark.parametrize("changes", (
    {"candidate_name": "other"}, {"positive_witness_names": (WITNESSES[0],)},
    {"positive_witness_names": (WITNESSES[0], WITNESSES[0])},
    {"expected_api_names": (WITNESSES[0],)}, {"expected_device_serial": "bad serial"},
))
def test_invalid_private_binding_rejects_before_contact(config, peer, changes):
    with pytest.raises(ValueError): reader(config, **changes)
    assert peer.commands == [] and peer.connection_closed == 0
