from dataclasses import FrozenInstanceError

import pytest

from fortipam_mcp import secret_dlp_dependency_ssh_reader as module
from test_folder_namespace_ssh_reader import Peer as FolderPeer, config, frame


SENSOR = "mcp-v4-dlp-sftp-audit-synthetic"
SECRET_WITNESSES = ("Synthetic Secret A", "Synthetic Secret B")
POLICY_WITNESSES = ("Synthetic Policy A", "Synthetic Policy B")
SECRET_NAMES = SECRET_WITNESSES + tuple(f"Synthetic Secret {index}" for index in range(2, 64))
POLICY_NAMES = POLICY_WITNESSES + ("Synthetic Policy C",)
DATABASE = b"FPA-SYNTHETIC (database) #"
POLICY = b"FPA-SYNTHETIC (policy) #"
SECRET_REFS = ("", "another-sensor") + ("",) * 62
POLICY_REFS = ("", "another-sensor", "")
SECRET_WITNESS_ROWS = (module.DlpReferenceWitness("1", SECRET_NAMES[0], ""),
                       module.DlpReferenceWitness("2", SECRET_NAMES[1], "another-sensor"))
POLICY_WITNESS_ROWS = (module.DlpReferenceWitness(POLICY_NAMES[0], POLICY_NAMES[0], ""),
                       module.DlpReferenceWitness(POLICY_NAMES[1], POLICY_NAMES[1], "another-sensor"))


def grouped_frame(table, references, *, omit_empty=True, names=None):
    command = module._DATABASE_GROUPED if table == "database" else module._POLICY_GROUPED
    if names is None:
        names = SECRET_NAMES if table == "database" else POLICY_NAMES
    lines = [b"config secret " + table.encode()]
    for index, (name, reference) in enumerate(zip(names, references), start=1):
        lines.append(f"    edit {index}".encode() if table == "database" else b'    edit "' + name.encode() + b'"')
        if table == "database": lines.append(b'        set name "' + name.encode() + b'"')
        if reference or not omit_empty: lines.append(b'        set dlp-sensor "' + reference.encode() + b'"')
        lines.append(b"    next")
    lines.append(b"end")
    return frame(command, lines, DATABASE if table == "database" else POLICY)


def reference_frame(table, references, *, omit_empty=True):
    return frame(module._DLP_PROJECTION,
                 [b'        set dlp-sensor "' + value.encode() + b'"' for value in references if value or not omit_empty],
                 DATABASE if table == "database" else POLICY)


class DependencyPeer(FolderPeer):
    def __init__(self):
        super().__init__()
        self.context = None
        self.columns = {
            ("database", module._EDIT_PROJECTION): frame(module._EDIT_PROJECTION,
                [f"    edit {index}".encode() for index in range(1, 65)], DATABASE),
            ("database", module._NAME_PROJECTION): frame(module._NAME_PROJECTION,
                [b'        set name "' + name.encode() + b'"' for name in SECRET_NAMES], DATABASE),
            ("database", module._DLP_PROJECTION): reference_frame("database", SECRET_REFS),
            ("database", module._DATABASE_GROUPED): grouped_frame("database", SECRET_REFS),
            ("policy", module._EDIT_PROJECTION): frame(module._EDIT_PROJECTION,
                [b'    edit "' + name.encode() + b'"' for name in POLICY_NAMES], POLICY),
            ("policy", module._DLP_PROJECTION): reference_frame("policy", POLICY_REFS),
            ("policy", module._POLICY_GROUPED): grouped_frame("policy", POLICY_REFS),
        }
        self.second_columns = {}
        self.read_counts = {}
        self.wrong_prompt = None

    async def read(self, process, command, prompt, deadline):
        if command in {module._SERIAL_COMMAND, module._VERSION_COMMAND}:
            return await super().read(process, command, prompt, deadline)
        assert process is self and deadline == 12345
        assert prompt == {"database": DATABASE, "policy": POLICY}[self.context]
        self.commands.append(command)
        if self.raise_at == command:
            raise OSError("synthetic private peer detail")
        key = (self.context, command)
        self.read_counts[key] = self.read_counts.get(key, 0) + 1
        if self.read_counts[key] == 2 and key in self.second_columns:
            return self.second_columns[key]
        return self.columns[key]

    async def dynamic(self, process, command, prompt, deadline):
        assert process is self and prompt == self.root and deadline == 12345
        self.commands.append(command)
        if self.raise_at == command:
            raise OSError("synthetic private peer detail")
        if command == "end":
            self.context = None
            return self.returned
        assert command in {"config secret database", "config secret policy"}
        self.context = command.split()[-1]
        return self.wrong_prompt or {"database": DATABASE, "policy": POLICY}[self.context]


@pytest.fixture
def peer(monkeypatch):
    value = DependencyPeer()
    monkeypatch.setattr(module, "FortiPamTargetReferenceSshTransport", lambda config: value)
    monkeypatch.setattr(module, "_send_and_read", value.read)
    monkeypatch.setattr(module, "_send_and_read_dynamic_prompt", value.dynamic)
    monkeypatch.setattr(module, "_close_cli", value.close)
    return value


def reader(config, **changes):
    args = dict(sensor_name=SENSOR, expected_device_serial="SYNTHETIC_SERIAL",
                secret_witnesses=SECRET_WITNESS_ROWS, policy_witnesses=POLICY_WITNESS_ROWS)
    args.update(changes)
    return module.FortiPamSecretDlpDependencySshReader(config, **args)


def test_complete_repeated_native_columns_return_typed_frozen_minimized_evidence(config, peer):
    result = reader(config).inspect(SENSOR)
    assert result.version == "v7.0.0" and type(result.build) is int and result.build == 29
    assert result.secret_object_count == 64 and result.policy_object_count == 3
    assert result.secret_reference_count == result.policy_reference_count == 0
    assert len(result.evidence_digest) == 64
    assert result.sensor_name == SENSOR and result.device_serial == "SYNTHETIC_SERIAL"
    assert all(value not in repr(result) for value in (SENSOR, "SYNTHETIC_SERIAL", *SECRET_NAMES, *POLICY_NAMES))
    with pytest.raises(FrozenInstanceError):
        result.secret_object_count = 59
    assert peer.commands == [module._SERIAL_COMMAND, module._VERSION_COMMAND,
        "config secret database", *([module._EDIT_PROJECTION, module._NAME_PROJECTION, module._DLP_PROJECTION,
                                      module._DATABASE_GROUPED] * 2),
        "end", "config secret policy", *([module._EDIT_PROJECTION, module._DLP_PROJECTION, module._POLICY_GROUPED] * 2), "end"]
    assert peer.closed == peer.connection_closed == 1


def test_any_global_reference_counts_without_joining_independent_columns(config, peer):
    first = reader(config).inspect(SENSOR)
    peer.commands.clear()
    peer.read_counts.clear()
    secret_refs = ("", "another-sensor", SENSOR, SENSOR) + ("",) * 60
    policy_refs = ("", "another-sensor", SENSOR)
    peer.columns[("database", module._DLP_PROJECTION)] = reference_frame("database", secret_refs)
    peer.columns[("database", module._DATABASE_GROUPED)] = grouped_frame("database", secret_refs)
    peer.columns[("policy", module._DLP_PROJECTION)] = reference_frame("policy", policy_refs)
    peer.columns[("policy", module._POLICY_GROUPED)] = grouped_frame("policy", policy_refs)
    result = reader(config).inspect(SENSOR)
    assert result.secret_reference_count == 2 and result.policy_reference_count == 1
    assert result.evidence_digest != first.evidence_digest
    assert result.secret_object_count == 64 and result.policy_object_count == 3


@pytest.mark.parametrize("object_count", (65, 129))
def test_large_complete_table_binds_last_object_reference_and_full_count(config, peer, object_count):
    names = SECRET_WITNESSES + tuple(f"Synthetic Secret {index}" for index in range(2, object_count))
    references = ("", "another-sensor") + ("",) * (object_count - 2)
    peer.columns[("database", module._EDIT_PROJECTION)] = frame(module._EDIT_PROJECTION,
        [f"    edit {index}".encode() for index in range(1, object_count + 1)], DATABASE)
    peer.columns[("database", module._NAME_PROJECTION)] = frame(module._NAME_PROJECTION,
        [b'        set name "' + name.encode() + b'"' for name in names], DATABASE)
    peer.columns[("database", module._DLP_PROJECTION)] = reference_frame("database", references)
    peer.columns[("database", module._DATABASE_GROUPED)] = grouped_frame("database", references, names=names)
    observer = reader(config)
    before = observer.inspect(SENSOR)
    assert before.secret_object_count == object_count and before.secret_reference_count == 0
    peer.read_counts.clear()
    references = references[:-1] + (SENSOR,)
    peer.columns[("database", module._DLP_PROJECTION)] = reference_frame("database", references)
    peer.columns[("database", module._DATABASE_GROUPED)] = grouped_frame("database", references, names=names)
    after = observer.inspect(SENSOR)
    assert after.secret_object_count == object_count and after.secret_reference_count == 1
    assert after.evidence_digest != before.evidence_digest


@pytest.mark.parametrize("table,column,lines", (
    ("database", module._DLP_PROJECTION, [b'        set dlp-sensor ""'] * 59),
    ("database", module._EDIT_PROJECTION, [b"    edit 1"] * 64),
    ("database", module._EDIT_PROJECTION, [b"    edit 01"] * 64),
    ("database", module._EDIT_PROJECTION, [b"    edit 2147483648"] * 64),
    ("database", module._EDIT_PROJECTION, [b'    edit "1"'] * 64),
    ("database", module._NAME_PROJECTION, [b'        set name "Other"'] * 64),
    ("database", module._DLP_PROJECTION, [b'                set dlp-sensor ""'] * 64),
    ("database", module._DLP_PROJECTION, [b'        set password "synthetic-denial-marker"'] * 64),
    ("database", module._DLP_PROJECTION, [b'        set dlp-sensor "bad\\name"'] * 64),
    ("database", module._DLP_PROJECTION, ['        set dlp-sensor "bad\u200bname"'.encode()] * 64),
    ("database", module._DLP_PROJECTION, [b'        set dlp-sensor "' + b"x" * 80 + b'"'] * 64),
    ("policy", module._EDIT_PROJECTION, [b'    edit "Synthetic Policy A"'] * 3),
    ("policy", module._EDIT_PROJECTION, [b"    edit 1"] * 3),
    ("policy", module._DLP_PROJECTION, [b'        set dlp-sensor ""'] * 2),
    ("policy", module._DLP_PROJECTION, []),
))
def test_incomplete_nested_unknown_or_ambiguous_columns_fail_closed(config, peer, table, column, lines):
    peer.columns[(table, column)] = frame(column, lines, DATABASE if table == "database" else POLICY)
    with pytest.raises(module.SecretDlpDependencySshReaderError) as error:
        reader(config).inspect(SENSOR)
    assert str(error.value) == module._UNAVAILABLE
    assert peer.closed == peer.connection_closed == 1


@pytest.mark.parametrize("table,column", (
    ("database", module._EDIT_PROJECTION), ("database", module._NAME_PROJECTION),
    ("database", module._DLP_PROJECTION), ("policy", module._EDIT_PROJECTION), ("policy", module._DLP_PROJECTION),
    ("database", module._DATABASE_GROUPED), ("policy", module._POLICY_GROUPED),
))
def test_each_anchor_and_relation_frame_must_repeat_byte_for_byte(config, peer, table, column):
    peer.second_columns[(table, column)] = peer.columns[(table, column)].replace(b"\r\r\n", b"\r\n", 1)
    with pytest.raises(module.SecretDlpDependencySshReaderError):
        reader(config).inspect(SENSOR)
    assert peer.closed == peer.connection_closed == 1


@pytest.mark.parametrize("fault", ("restricted_root", "serial", "version", "context", "exit",
                                  "command_echo", "footer", "raw_cr", "oversize"))
def test_binding_prompt_and_frame_faults_are_non_disclosing(config, peer, fault):
    key = ("database", module._DLP_PROJECTION)
    if fault == "restricted_root": peer.root = b"FPA-SYNTHETIC $"
    elif fault == "serial": peer.serial = frame(module._SERIAL_COMMAND, [b"Serial-Number: OTHER_SERIAL"])
    elif fault == "version": peer.version = frame(module._VERSION_COMMAND, [b"Version: FortiPAM v7.0.0,build30"])
    elif fault == "context": peer.wrong_prompt = b"FPA-SYNTHETIC (folder) #"
    elif fault == "exit": peer.returned = b"OTHER #"
    elif fault == "command_echo": peer.columns[key] = peer.columns[key].replace(b'^        set dlp-sensor ', b'set dlp-sensor ', 1)
    elif fault == "footer": peer.columns[key] = peer.columns[key].removesuffix(DATABASE) + b"\r\n\r\n" + DATABASE
    elif fault == "raw_cr": peer.columns[key] = peer.columns[key].replace(b'        set dlp-sensor "another-sensor"', b'        set dlp-sensor "bad\rname"', 1)
    elif fault == "oversize": peer.columns[key] = b"x" * (65536 + 1)
    with pytest.raises(module.SecretDlpDependencySshReaderError) as error:
        reader(config).inspect(SENSOR)
    assert str(error.value) == module._UNAVAILABLE
    assert peer.closed == peer.connection_closed == 1


@pytest.mark.parametrize("stage", ("open", "config secret database", "config secret policy",
                                  module._EDIT_PROJECTION, module._DLP_PROJECTION, "end", "close"))
def test_peer_failures_close_resources_and_suppress_peer_details(config, peer, stage):
    peer.raise_at = stage
    peer.close_error = stage == "close"
    with pytest.raises(module.SecretDlpDependencySshReaderError) as error:
        reader(config).inspect(SENSOR)
    assert str(error.value) == module._UNAVAILABLE
    assert peer.connection_closed == 1 and peer.closed == (0 if stage == "open" else 1)


@pytest.mark.parametrize("changes", (
    {"sensor_name": "another-sensor"}, {"expected_device_serial": "bad serial"},
    {"secret_witnesses": SECRET_WITNESS_ROWS[:1]}, {"policy_witnesses": POLICY_WITNESS_ROWS[:1] * 2},
    {"policy_witnesses": (module.DlpReferenceWitness("safe", "bad\u200bname", ""), POLICY_WITNESS_ROWS[1])},
    {"secret_witnesses": (SECRET_WITNESS_ROWS[0], module.DlpReferenceWitness("2", SECRET_NAMES[1], ""))},
    {"secret_witnesses": ({"qualified": True}, {"qualified": True})},
))
def test_unqualified_constructor_inputs_do_not_contact_peer(config, peer, changes):
    with pytest.raises(ValueError, match="unavailable"):
        reader(config, **changes)
    assert peer.commands == [] and peer.closed == peer.connection_closed == 0


def test_observer_cannot_be_retargeted_after_binding(config, peer):
    with pytest.raises(module.SecretDlpDependencySshReaderError):
        reader(config).inspect("mcp-v4-dlp-sftp-audit-other")
    assert peer.commands == [] and peer.closed == peer.connection_closed == 0


def test_explicit_empty_and_native_omitted_empty_have_the_same_dependency_digest(config, peer):
    omitted = reader(config).inspect(SENSOR)
    peer.read_counts.clear()
    for table, references in (("database", SECRET_REFS), ("policy", POLICY_REFS)):
        command = module._DATABASE_GROUPED if table == "database" else module._POLICY_GROUPED
        peer.columns[(table, command)] = grouped_frame(table, references, omit_empty=False)
        peer.columns[(table, module._DLP_PROJECTION)] = reference_frame(table, references, omit_empty=False)
    assert reader(config).inspect(SENSOR) == omitted


@pytest.mark.parametrize("fault", ("header", "end", "next", "extra_next", "nested_field",
    "duplicate_relation", "duplicate_name", "orphan_relation", "scope_truncated", "bad_witness_reference",
    "missing_nonempty_column", "sequence_drift", "usage_only"))
def test_grouped_scope_closure_exact_witnesses_and_independent_columns_are_required(config, peer, fault):
    key = ("database", module._DATABASE_GROUPED)
    value = peer.columns[key]
    if fault == "header": value = value.replace(b"config secret database\r\n", b"config secret policy\r\n", 1)
    elif fault == "end": value = value.replace(b"end\r\n", b"", 1)
    elif fault == "next": value = value.replace(b"    next\r\n", b"", 1)
    elif fault == "extra_next": value = value.replace(b"    next\r\n", b"    next\r\n    next\r\n", 1)
    elif fault == "nested_field": value = value.replace(b"    next\r\n", b'                set value "synthetic-denial-marker"\r\n    next\r\n', 1)
    elif fault == "duplicate_relation": value = value.replace(b'        set dlp-sensor "another-sensor"\r\n', b'        set dlp-sensor "another-sensor"\r\n' * 2, 1)
    elif fault == "duplicate_name": value = value.replace(b'        set name "Synthetic Secret A"\r\n', b'        set name "Synthetic Secret A"\r\n' * 2, 1)
    elif fault == "orphan_relation": value = value.replace(b"config secret database\r\n", b'config secret database\r\n        set dlp-sensor "another-sensor"\r\n', 1)
    elif fault == "scope_truncated":
        value = frame(module._DATABASE_GROUPED, [b"config secret database", b"    next", b"end"], DATABASE)
    elif fault == "bad_witness_reference":
        refs = ("unexpected-sensor", *SECRET_REFS[1:])
        value = grouped_frame("database", refs)
        peer.columns[("database", module._DLP_PROJECTION)] = reference_frame("database", refs)
    elif fault == "missing_nonempty_column":
        peer.columns[("database", module._DLP_PROJECTION)] = reference_frame("database", ("",) * 64)
    elif fault == "sequence_drift":
        value = value.replace(b'        set name "Synthetic Secret A"', b'        set name "Synthetic Secret B"', 1)
    elif fault == "usage_only": value = frame(module._DATABASE_GROUPED, [b"Usage: grep [-invfcABC] PATTERN"], DATABASE)
    peer.columns[key] = value
    with pytest.raises(module.SecretDlpDependencySshReaderError):
        reader(config).inspect(SENSOR)
    assert peer.closed == peer.connection_closed == 1
