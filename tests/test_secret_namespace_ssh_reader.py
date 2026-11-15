from dataclasses import FrozenInstanceError

import pytest

from fortipam_mcp import secret_namespace_ssh_reader as module
from test_folder_namespace_ssh_reader import Peer as FolderPeer, config, frame


CANDIDATE = "mcp-v4-domain-secret-synthetic"
WITNESSES = ("Synthetic Owner Secret A", "Synthetic Owner Secret B")
DATABASE = b"FPA-SYNTHETIC (database) #"
NAMES = WITNESSES + tuple(f"Synthetic Secret {index}" for index in range(2, 64))


def name_frame(names=NAMES):
    return frame(module._NAME_PROJECTION, [b'        set name "' + value.encode() + b'"' for value in names], DATABASE)


def folder_frame(values=tuple(range(64))):
    return frame(module._FOLDER_PROJECTION, [f"        set folder {value}".encode() for value in values], DATABASE)


class SecretPeer(FolderPeer):
    def __init__(self):
        super().__init__()
        self.folder = DATABASE
        self.names = name_frame()
        self.folders = folder_frame()
        self.version = frame(module._VERSION_COMMAND, [
            b"Version: FortiPAM-VM v7.0.0,build0029, synthetic metadata",
            b"Release Version Information: Synthetic release metadata", b"",
        ]) + b" "

    async def read(self, process, command, prompt, deadline):
        if command in {module._SERIAL_COMMAND, module._VERSION_COMMAND}:
            return await super().read(process, command, prompt, deadline)
        assert process is self and prompt == self.folder and deadline == 12345
        self.commands.append(command)
        if self.raise_at == command:
            raise OSError("synthetic private peer failure")
        if command == module._NAME_PROJECTION:
            self.name_reads += 1
            return self.second_names if self.name_reads == 2 and self.second_names is not None else self.names
        assert command == module._FOLDER_PROJECTION
        return self.folders

    async def dynamic(self, process, command, prompt, deadline):
        assert process is self and prompt == self.root and deadline == 12345
        self.commands.append(command)
        if self.raise_at == command:
            raise OSError("synthetic private peer failure")
        assert command in {"config secret database", "end"}
        return self.folder if command == "config secret database" else self.returned


@pytest.fixture
def peer(monkeypatch):
    value = SecretPeer()
    monkeypatch.setattr(module, "FortiPamTargetReferenceSshTransport", lambda config: value)
    monkeypatch.setattr(module, "_send_and_read", value.read)
    monkeypatch.setattr(module, "_send_and_read_dynamic_prompt", value.dynamic)
    monkeypatch.setattr(module, "_close_cli", value.close)
    return value


def reader(config, **changes):
    args = dict(candidate_name=CANDIDATE, positive_witness_names=WITNESSES,
                expected_device_serial="SYNTHETIC_SERIAL")
    args.update(changes)
    return module.FortiPamSecretNamespaceSshReader(config, **args)


def test_native_shaped_top_level_secret_projection_returns_only_frozen_summary(config, peer):
    peer.names = peer.names.removesuffix(DATABASE) + b"\r\n" + DATABASE + b" "
    peer.folders = peer.folders.removesuffix(DATABASE) + b"\r\n" + DATABASE + b" "
    result = reader(config).read_namespace()
    assert result.status == "name_absent" and result.global_name_absent
    assert result.secret_count == 64 and result.positive_witness_count == 2
    assert len(result.namespace_digest) == 64
    assert all(value not in repr(result) for value in (*WITNESSES, CANDIDATE, "SYNTHETIC_SERIAL"))
    with pytest.raises(FrozenInstanceError): result.secret_count = 0
    assert peer.commands == [module._SERIAL_COMMAND, module._VERSION_COMMAND, "config secret database",
                             'show full-configuration | grep "^        set name "',
                             'show full-configuration | grep "^        set folder "',
                             module._NAME_PROJECTION, "end"]
    assert peer.closed == peer.connection_closed == 1


def test_repeated_candidate_names_in_any_folder_deny_global_absence_without_deduplication(config, peer):
    names = list(NAMES)
    names[30] = names[63] = CANDIDATE
    peer.names = name_frame(names)
    peer.folders = folder_frame((0,) * 30 + (2_147_483_647,) + (17,) * 33)
    result = reader(config).read_namespace()
    assert result.status == "name_present" and not result.global_name_absent
    assert result.secret_count == 64
    assert peer.closed == peer.connection_closed == 1


@pytest.mark.parametrize("count",[65,200])
def test_large_qualified_namespace_hashes_all_rows_without_widening_m2(config,peer,count):
    from v4_planning import canonical_digest
    from v4_planning.canonical import CanonicalValueError
    names=WITNESSES+tuple(f"Synthetic Secret {index}"for index in range(2,count))
    peer.names=name_frame(names);peer.folders=folder_frame(range(count))
    with pytest.raises(CanonicalValueError):canonical_digest({'names':list(names)})
    first=reader(config).read_namespace()
    assert first.secret_count==count and first.global_name_absent and len(first.namespace_digest)==64
    peer.name_reads=0
    changed=names[:-1]+('Synthetic changed final row',)
    peer.names=name_frame(changed)
    second=reader(config).read_namespace()
    assert second.namespace_digest!=first.namespace_digest and second.global_name_absent
    peer.name_reads=0
    peer.names=name_frame(names[:-1]+(CANDIDATE,))
    present=reader(config).read_namespace()
    assert not present.global_name_absent and present.status=='name_present'


def test_legacy_64_row_namespace_digest_remains_identical(config,peer):
    from v4_planning import canonical_digest
    result=reader(config).read_namespace()
    assert result.namespace_digest==canonical_digest({'contract':'fortipam-700-build29-secret-name-namespace-candidate-v1',
        'names':list(NAMES),'folder_values':list(range(64))})


def test_safe_unicode_and_literal_spaces_are_preserved_up_to_255_characters(config, peer):
    names = list(NAMES)
    names[2] = "测试" * 127 + "x"
    names[3] = " literal set name text "
    peer.names = name_frame(names)
    assert reader(config).read_namespace().global_name_absent
    assert module._secret_names(peer.names, DATABASE)[2:4] == tuple(names[2:4])


def test_unanchored_220_name_rows_with_156_nested_fields_cannot_establish_namespace(config, peer):
    lines = [b'        set name "' + name.encode() + b'"' for name in NAMES]
    lines += [f'                set name "Nested Field {index}"'.encode() for index in range(156)]
    assert len(lines) == 220
    peer.names = frame(module._NAME_PROJECTION, lines, DATABASE)
    with pytest.raises(module.SecretNamespaceSshReaderError): reader(config).read_namespace()
    assert peer.closed == peer.connection_closed == 1
    assert module._FOLDER_PROJECTION not in peer.commands


@pytest.mark.parametrize("fault", (
    "name_indent", "name_escape", "name_unknown", "name_control", "name_unicode_control", "name_too_long",
    "name_empty", "folder_nested", "folder_negative", "folder_overflow", "folder_leading_zero", "folder_unknown",
    "count", "witness", "drift", "root_restricted", "wrong_context", "wrong_exit", "serial", "build",
    "double_footer", "unanchored_echo",
))
def test_secret_source_boundary_fails_closed_and_closes_peer(config, peer, fault):
    if fault.startswith("name_"):
        value = {
            "name_indent": b'       set name "Synthetic"', "name_escape": b'        set name "bad\\escape"',
            "name_unknown": b'        set comment "set name"', "name_control": b'        set name "bad\rname"',
            "name_unicode_control": '        set name "bad\u200bname"'.encode(),
            "name_too_long": b'        set name "' + b"x" * 256 + b'"', "name_empty": b'        set name ""',
        }[fault]
        peer.names = frame(module._NAME_PROJECTION, [value], DATABASE)
    elif fault.startswith("folder_"):
        value = {
            "folder_nested": b"                set folder 17", "folder_negative": b"        set folder -1",
            "folder_overflow": b"        set folder 2147483648", "folder_leading_zero": b"        set folder 01",
            "folder_unknown": b'        set comment "set folder 17"',
        }[fault]
        peer.folders = frame(module._FOLDER_PROJECTION, [value], DATABASE)
    elif fault == "count": peer.folders = folder_frame(range(63))
    elif fault == "witness": peer.names = name_frame(("Other",) + NAMES[1:])
    elif fault == "drift": peer.second_names = name_frame(tuple(reversed(NAMES)))
    elif fault == "root_restricted": peer.root = b"FPA-SYNTHETIC $"
    elif fault == "wrong_context": peer.folder = b"FPA-SYNTHETIC (folder) #"
    elif fault == "wrong_exit": peer.returned = b"OTHER #"
    elif fault == "serial": peer.serial = frame(module._SERIAL_COMMAND, [b"Serial-Number: OTHER_SERIAL"])
    elif fault == "build": peer.version = frame(module._VERSION_COMMAND, [b"Version: FortiPAM v7.0.0,build30"])
    elif fault == "double_footer": peer.names = peer.names.removesuffix(DATABASE) + b"\r\n\r\n" + DATABASE
    elif fault == "unanchored_echo": peer.names = peer.names.replace(b'grep "^        set name "', b'grep "set name"', 1)
    with pytest.raises(module.SecretNamespaceSshReaderError) as error: reader(config).read_namespace()
    assert str(error.value) == module._UNAVAILABLE
    assert peer.closed == peer.connection_closed == 1


@pytest.mark.parametrize("stage", ("open", module._NAME_PROJECTION, module._FOLDER_PROJECTION, "end", "close"))
def test_secret_peer_failure_preserves_shutdown_and_suppresses_private_details(config, peer, stage):
    peer.raise_at = stage
    peer.close_error = stage == "close"
    with pytest.raises(module.SecretNamespaceSshReaderError) as error: reader(config).read_namespace()
    assert str(error.value) == module._UNAVAILABLE
    assert peer.connection_closed == 1 and peer.closed == (0 if stage == "open" else 1)


@pytest.mark.parametrize("changes", (
    {"candidate_name": "existing-secret"}, {"candidate_name": "mcp-v4-" + "x" * 64},
    {"positive_witness_names": ("one",)}, {"positive_witness_names": ("same", "same")},
    {"positive_witness_names": ("safe", "bad\u200bname")}, {"expected_device_serial": "bad serial"},
))
def test_secret_binding_rejects_unqualified_inputs_without_peer_contact(config, peer, changes):
    with pytest.raises(ValueError): reader(config, **changes)
    assert peer.commands == [] and peer.connection_closed == peer.closed == 0
