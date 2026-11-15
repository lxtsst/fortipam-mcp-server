from contextlib import asynccontextmanager
from pathlib import Path

import pytest

import fortipam_mcp.folder_namespace_ssh_reader as module
from fortipam_mcp.target_ssh_transport import TargetSshTransportConfig


CANDIDATE = "mcp-v4-domain-owner-synthetic"
WITNESSES = ("Synthetic Public", "Synthetic Child")
ROOT = b"FPA-SYNTHETIC #"
FOLDER = b"FPA-SYNTHETIC (folder) #"


def frame(command, lines, prompt=ROOT, echo_ending=b"\r\r\n"):
    return command.encode() + echo_ending + b"".join(line + b"\r\n" for line in lines) + prompt


def name_frame(names=WITNESSES):
    return frame(module._NAME_PROJECTION, [b'    set name "' + name.encode() + b'"' for name in names], FOLDER)


@pytest.fixture
def config(tmp_path: Path) -> TargetSshTransportConfig:
    known_hosts = tmp_path / "synthetic_known_hosts"
    known_hosts.write_text("synthetic pinned peer\n")
    known_hosts.chmod(0o600)
    return TargetSshTransportConfig("synthetic.invalid", 22, "synthetic", "synthetic-password", known_hosts, 15)


class Peer:
    def __init__(self):
        self.commands = []
        self.closed = 0
        self.connection_closed = 0
        self.name_reads = 0
        self.root = ROOT
        self.folder = FOLDER
        self.returned = ROOT
        self.raise_at = None
        self.close_error = False
        self.serial = frame(module._SERIAL_COMMAND, [b"Serial-Number: SYNTHETIC_SERIAL"])
        self.version = frame(module._VERSION_COMMAND, [b"Version: FortiPAM-VM v7.0.0,build0029, synthetic metadata"])
        self.names = name_frame()
        self.second_names = None
        self.parents = frame(module._PARENT_PROJECTION, [b"    set parent-folder 0", b"    set parent-folder 7"], FOLDER)

    @asynccontextmanager
    async def _connection(self):
        try:
            yield self
        finally:
            self.connection_closed += 1

    async def _open_cli(self, connection):
        assert connection is self
        if self.raise_at == "open":
            raise OSError("synthetic private peer failure")
        return self, self.root, 12345

    async def read(self, process, command, prompt, deadline):
        assert process is self and deadline == 12345
        self.commands.append(command)
        if self.raise_at == command:
            raise OSError("synthetic private peer failure")
        if command == module._SERIAL_COMMAND:
            assert prompt == self.root
            return self.serial
        if command == module._VERSION_COMMAND:
            assert prompt == self.root
            return self.version
        if command == module._NAME_PROJECTION:
            assert prompt == self.folder
            self.name_reads += 1
            if self.name_reads == 2 and self.second_names is not None:
                return self.second_names
            return self.names
        assert command == module._PARENT_PROJECTION and prompt == self.folder
        return self.parents

    async def dynamic(self, process, command, prompt, deadline):
        assert process is self and prompt == self.root and deadline == 12345
        self.commands.append(command)
        if self.raise_at == command:
            raise OSError("synthetic private peer failure")
        assert command in {"config secret folder", "end"}
        return self.folder if command == "config secret folder" else self.returned

    async def close(self, process):
        assert process is self
        self.closed += 1
        if self.close_error:
            raise OSError("synthetic private close failure")


@pytest.fixture
def peer(monkeypatch: pytest.MonkeyPatch) -> Peer:
    value = Peer()
    monkeypatch.setattr(module, "FortiPamTargetReferenceSshTransport", lambda config: value)
    monkeypatch.setattr(module, "_send_and_read", value.read)
    monkeypatch.setattr(module, "_send_and_read_dynamic_prompt", value.dynamic)
    monkeypatch.setattr(module, "_close_cli", value.close)
    return value


def reader(config, **changes):
    binding = dict(candidate_name=CANDIDATE, positive_witness_names=WITNESSES,
                   expected_device_serial="SYNTHETIC_SERIAL")
    binding.update(changes)
    return module.FortiPamFolderNamespaceSshReader(config, **binding)


def test_private_complete_columns_preserve_old_minimized_observation(config,peer):
    columns=reader(config).read_complete_namespace()
    assert columns.names==WITNESSES and columns.parent_values==(0,7)
    assert columns.observation==reader(config).read_namespace()
    assert WITNESSES[0] not in repr(columns)
    assert peer.closed==peer.connection_closed==2


@pytest.mark.parametrize("present", (False, True))
def test_global_name_observation_preserves_duplicates_and_returns_no_private_values(config, peer, present):
    names = WITNESSES + (WITNESSES[0],) + ((CANDIDATE,) if present else ())
    peer.names = name_frame(names)
    # An existing name under ANY parent is sufficient; no column pairing is used.
    peer.parents = frame(module._PARENT_PROJECTION, [b"    set parent-folder 0"] * len(names), FOLDER)
    result = reader(config).read_namespace()
    assert result.status == ("name_present" if present else "name_absent")
    assert result.global_name_absent is not present
    assert result.folder_count == len(names)
    assert result.positive_witness_count == 2
    assert len(result.namespace_digest) == 64
    assert all(value not in repr(result) for value in (*WITNESSES, CANDIDATE, "SYNTHETIC_SERIAL"))
    assert peer.commands == [module._SERIAL_COMMAND, module._VERSION_COMMAND, "config secret folder",
                             module._NAME_PROJECTION, module._PARENT_PROJECTION,
                             module._NAME_PROJECTION, "end"]
    assert peer.closed == peer.connection_closed == 1


@pytest.mark.parametrize("echo_ending", (b"\r\r\n", b"\r\n"))
def test_identity_frames_allow_only_qualified_line_terminators_and_empty_metadata_lines(config, peer, echo_ending):
    peer.serial = frame(module._SERIAL_COMMAND, [b"", b"Serial-Number: SYNTHETIC_SERIAL", b""], echo_ending=echo_ending)
    peer.version = frame(module._VERSION_COMMAND, [b"Version: FortiPAM v7.0.0, build29 bounded-tail"], echo_ending=echo_ending)
    assert reader(config).read_namespace().global_name_absent


def test_qualified_single_prompt_space_and_projection_blank_footer(config, peer):
    peer.serial += b" "
    peer.version += b" "
    peer.names = peer.names.removesuffix(FOLDER) + b"\r\n" + FOLDER + b" "
    peer.parents = peer.parents.removesuffix(FOLDER) + b"\r\n" + FOLDER + b" "
    result = reader(config).read_namespace()
    assert result.global_name_absent and result.folder_count == 2
    assert peer.closed == peer.connection_closed == 1


def test_qualified_release_metadata_footer_is_not_version_evidence(config, peer):
    peer.version = frame(module._VERSION_COMMAND, [
        b"Version: FortiPAM-VM v7.0.0,build0029, synthetic metadata",
        b"Release Version Information: Synthetic bounded release metadata", b"",
    ]) + b" "
    result = reader(config).read_namespace()
    assert result.global_name_absent and result.folder_count == 2
    assert peer.closed == peer.connection_closed == 1


@pytest.mark.parametrize("extra", (
    [b"Release Version Information: Synthetic"] * 2,
    [b"Unknown Metadata: Synthetic"], [b"BIOS-Version: Synthetic"],
    [b"Release Version Information:"], [b"Release Version Information:   "],
    [b"Release Version Information: Synthetic\x01"],
    [b"Release Version Information: " + b"x" * 256],
))
def test_release_metadata_rejects_unknown_duplicate_empty_control_and_unbounded_rows(config, peer, extra):
    peer.version = frame(module._VERSION_COMMAND, [b"Version: FortiPAM v7.0.0,build29", *extra])
    with pytest.raises(module.FolderNamespaceSshReaderError):
        reader(config).read_namespace()
    assert peer.closed == peer.connection_closed == 1


def test_release_metadata_cannot_replace_required_version_field(config, peer):
    peer.version = frame(module._VERSION_COMMAND, [
        b"Release Version Information: FortiPAM v7.0.0,build29",
    ])
    with pytest.raises(module.FolderNamespaceSshReaderError):
        reader(config).read_namespace()
    assert peer.closed == peer.connection_closed == 1


@pytest.mark.parametrize("projection", ("names", "parents"))
@pytest.mark.parametrize("unqualified", ("two_prompt_spaces", "double_blank_footer", "space_footer",
                                       "tab_footer", "internal_blank", "extra_newline"))
def test_projection_rejects_unqualified_whitespace_and_newlines(config, peer, projection, unqualified):
    value = getattr(peer, projection)
    if unqualified == "two_prompt_spaces":
        value += b"  "
    elif unqualified == "extra_newline":
        value += b"\r\n"
    elif unqualified == "internal_blank":
        echo, body = value.split(b"\r\r\n", 1)
        value = echo + b"\r\r\n\r\n" + body
    else:
        footer = {"double_blank_footer": b"\r\n\r\n", "space_footer": b" \r\n",
                  "tab_footer": b"\t\r\n"}[unqualified]
        value = value.removesuffix(FOLDER) + footer + FOLDER
    setattr(peer, projection, value)
    with pytest.raises(module.FolderNamespaceSshReaderError):
        reader(config).read_namespace()
    assert peer.closed == peer.connection_closed == 1


@pytest.mark.parametrize("body", (
    b'    set name Synthetic', b'    set name ""', b'    set name "bad\\escape"',
    b'    set name "bad\\"quote"', b'    set name "Synthetic Public" extra',
    b'    set comment "set name"', b'    set name "bad\rname"',
    b'    set name "bad\x1b[0mname"', b'    set name "bad\x00name"',
    b'    set name "bad\tname"', b'    set name "bad\x7fname"',
    b'    set name "bad\xc2\x85name"', b'    set name "bad\xffname"',
    b'    set name "Synthetic Public"\nset name "Synthetic Child"',
    b'--More--', b'Permission denied', b'',
))
def test_name_projection_rejects_unknown_syntax_controls_or_non_name_rows(config, peer, body):
    peer.names = frame(module._NAME_PROJECTION, [body], FOLDER)
    with pytest.raises(module.FolderNamespaceSshReaderError, match="evidence is unavailable"):
        reader(config).read_namespace()
    assert peer.closed == peer.connection_closed == 1


@pytest.mark.parametrize("fault", (
    "serial_other", "serial_duplicate", "version_other", "version_duplicate", "version_not_field",
    "version_other_build", "version_other_product", "version_control", "name_changed", "name_count",
    "witness_missing", "parent_negative", "parent_overflow", "parent_extra", "parent_embedded_cr",
    "root_restricted", "context_restricted", "context_wrong", "end_restricted", "end_host",
    "echo_lf", "body_lf", "prompt_missing", "prompt_extra", "output_limit",
))
def test_namespace_rejects_unqualified_identity_framing_and_complete_namespace(config, peer, fault):
    if fault == "serial_other":
        peer.serial = frame(module._SERIAL_COMMAND, [b"Serial-Number: OTHER"])
    elif fault == "serial_duplicate":
        peer.serial = frame(module._SERIAL_COMMAND, [b"Serial-Number: SYNTHETIC_SERIAL"] * 2)
    elif fault.startswith("version_"):
        lines = {
            "version_other": [b"Version: FortiPAM v7.0.1,build29"],
            "version_duplicate": [b"Version: FortiPAM v7.0.0,build29"] * 2,
            "version_not_field": [b"Other: Version: FortiPAM v7.0.0,build29"],
            "version_other_build": [b"Version: FortiPAM v7.0.0,build290"],
            "version_other_product": [b"Version: Other v7.0.0,build29"],
            "version_control": [b"Version: FortiPAM v7.0.0,build29\x1b[0m"],
        }
        peer.version = frame(module._VERSION_COMMAND, lines[fault])
    elif fault == "name_changed":
        peer.second_names = name_frame(tuple(reversed(WITNESSES)))
    elif fault == "name_count":
        peer.names = name_frame(WITNESSES + ("Other",))
    elif fault == "witness_missing":
        peer.names = name_frame((WITNESSES[0], "Other"))
    elif fault.startswith("parent_"):
        body = {"parent_negative": b"set parent-folder -1", "parent_overflow": b"set parent-folder 2147483648",
                "parent_extra": b'set comment "set parent-folder 7"',
                "parent_embedded_cr": b"set parent-folder 1\r2"}[fault]
        peer.parents = frame(module._PARENT_PROJECTION, [body, b"set parent-folder 0"], FOLDER)
    elif fault == "root_restricted":
        peer.root = b"FPA-SYNTHETIC $"
    elif fault.startswith("context_"):
        peer.folder = b"FPA-SYNTHETIC (folder) $" if fault == "context_restricted" else b"FPA-SYNTHETIC (target) #"
    elif fault.startswith("end_"):
        peer.returned = b"FPA-SYNTHETIC $" if fault == "end_restricted" else b"OTHER #"
    elif fault == "echo_lf":
        peer.names = peer.names.replace(b"\r\r\n", b"\n", 1)
    elif fault == "body_lf":
        peer.names = peer.names.replace(b'"\r\n', b'"\n', 1)
    elif fault == "prompt_missing":
        peer.names = peer.names.removesuffix(FOLDER)
    elif fault == "prompt_extra":
        peer.names += b"  "
    else:
        peer.names = b"x" * (module._MAX_OUTPUT_BYTES + 1)
    with pytest.raises(module.FolderNamespaceSshReaderError) as error:
        reader(config).read_namespace()
    assert str(error.value) == module._UNAVAILABLE
    assert peer.closed == peer.connection_closed == 1


@pytest.mark.parametrize("stage", ("open", module._SERIAL_COMMAND, module._VERSION_COMMAND,
                                  "config secret folder", module._NAME_PROJECTION,
                                  module._PARENT_PROJECTION, "end", "close"))
def test_every_peer_exception_closes_connection_and_suppresses_private_details(config, peer, stage):
    peer.raise_at = stage
    peer.close_error = stage == "close"
    with pytest.raises(module.FolderNamespaceSshReaderError) as error:
        reader(config).read_namespace()
    assert str(error.value) == module._UNAVAILABLE
    assert peer.connection_closed == 1
    assert peer.closed == (0 if stage == "open" else 1)


@pytest.mark.parametrize("changes", (
    {"candidate_name": "existing-folder"}, {"candidate_name": "mcp-v4-bad\nname"},
    {"candidate_name": "mcp-v4-" + "x" * 64}, {"positive_witness_names": ("only-one",)},
    {"positive_witness_names": ("same", "same")}, {"positive_witness_names": ("", "other")},
    {"positive_witness_names": ('bad"name', "other")}, {"positive_witness_names": ["one", "two"]},
    {"expected_device_serial": "bad serial"}, {"expected_device_serial": ""},
))
def test_binding_rejection_never_opens_peer(config, peer, changes):
    with pytest.raises(ValueError, match="evidence is unavailable"):
        reader(config, **changes)
    assert peer.commands == [] and peer.closed == peer.connection_closed == 0
