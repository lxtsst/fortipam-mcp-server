"""Private build-29 global DLP dependency columns; no mutation authority.

Only compiled top-level edit/name/DLP columns can leave SSH. Native column
qualification is separate from these offline structural checks. The caller
must freshly qualify the local super_admin Owner and same API device binding;
neither REST pagination nor a caller-supplied boolean establishes completeness.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import hashlib
import hmac
import re

from v4_planning import canonical_digest

from .folder_namespace_ssh_reader import (
    _SERIAL_COMMAND, _VERSION_COMMAND, _frame_lines, _projection_lines, _qualified_version_metadata,
)
from .secret_dlp_association_contract import fixed_log_only_sensor_profile
from .secret_namespace_ssh_reader import _NAME_PROJECTION, _safe_secret_name, _secret_names
from .target_reference_ssh_transport import FortiPamTargetReferenceSshTransport
from .target_ssh_transport import (
    TargetSshTransportConfig, _close_cli, _require_root_prompt, _send_and_read, _send_and_read_dynamic_prompt,
)


_EDIT_PROJECTION = 'show full-configuration | grep "^    edit "'
_DLP_PROJECTION = 'show full-configuration | grep "^        set dlp-sensor "'
# Build-29 native grep accepts escaped alternation, but does not support -E.
_DATABASE_GROUPED = 'show full-configuration | grep "' + r"\|".join((
    "^config secret database$", "^    edit ", "^        set name ",
    "^        set dlp-sensor ", "^    next$", "^end$",
)) + '"'
_POLICY_GROUPED = 'show full-configuration | grep "' + r"\|".join((
    "^config secret policy$", "^    edit ", "^        set dlp-sensor ", "^    next$", "^end$",
)) + '"'
_UNAVAILABLE = "FortiPAM fixed Sensor dependency evidence is unavailable."


class SecretDlpDependencySshReaderError(RuntimeError):
    """Stable failure without names, serials, raw columns or peer details."""


@dataclass(frozen=True, slots=True)
class DlpDependencyInspection:
    """Typed private read evidence; never a caller-supplied qualification flag."""

    sensor_name: str = field(repr=False)
    device_serial: str = field(repr=False)
    version: str
    build: int
    secret_object_count: int
    policy_object_count: int
    secret_reference_count: int
    policy_reference_count: int
    evidence_digest: str


@dataclass(frozen=True, slots=True, repr=False)
class DlpReferenceWitness:
    """Private exact object/reference metadata; never a qualification boolean."""

    object_key: str
    object_name: str
    sensor_reference: str


@dataclass(frozen=True, slots=True, repr=False)
class _GroupedColumns:
    objects: tuple[DlpReferenceWitness, ...]
    explicit_references: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _TableEvidence:
    object_count: int
    reference_count: int
    digest: str


class FortiPamSecretDlpDependencySshReader:
    """Observe one fixed Sensor in complete stable native Secret/Policy columns.

    Independent columns are never joined to identify a referring Secret. Any
    exact occurrence counts as a reference. Grouped frames provide scope and
    object closure; separate anchors/reference sequences verify completeness.
    The native build-29 static schema/default for both dlp-sensor fields is
    string/size79/default empty. Only that qualified omitted value is inferred,
    with fresh exact empty/nonempty witnesses required in each table.
    """

    def __init__(self, config: TargetSshTransportConfig, *, sensor_name: str,
                 expected_device_serial: str, secret_witnesses: tuple[DlpReferenceWitness, ...],
                 policy_witnesses: tuple[DlpReferenceWitness, ...]) -> None:
        try:
            fixed_log_only_sensor_profile(sensor_name=sensor_name)
            if (not isinstance(config, TargetSshTransportConfig)
                    or type(expected_device_serial) is not str
                    or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", expected_device_serial) is None):
                raise ValueError
            _validate_witnesses(secret_witnesses, numeric=True)
            _validate_witnesses(policy_witnesses, numeric=False)
            self._ssh = FortiPamTargetReferenceSshTransport(config)
            self._sensor_name = sensor_name
            self._device_serial = expected_device_serial
            self._secret_witnesses = secret_witnesses
            self._policy_witnesses = policy_witnesses
        except Exception:
            raise ValueError(_UNAVAILABLE) from None

    def inspect(self, sensor_name: str) -> DlpDependencyInspection:
        try:
            if type(sensor_name) is not str or not hmac.compare_digest(sensor_name, self._sensor_name):
                raise ValueError
            return asyncio.run(self._inspect())
        except Exception:
            raise SecretDlpDependencySshReaderError(_UNAVAILABLE) from None

    async def _inspect(self) -> DlpDependencyInspection:
        async with self._ssh._connection() as connection:
            process, root, deadline = await self._ssh._open_cli(connection)
            try:
                if re.fullmatch(rb"[A-Za-z0-9._-]{1,63} #", root) is None:
                    raise ValueError
                serial = await _send_and_read(process, _SERIAL_COMMAND, root, deadline)
                serial_lines = tuple(line for line in _frame_lines(serial, _SERIAL_COMMAND, root)
                                     if line.strip(b" \t"))
                if (len(serial_lines) != 1 or not hmac.compare_digest(
                        serial_lines[0], b"Serial-Number: " + self._device_serial.encode("ascii"))):
                    raise ValueError
                version = await _send_and_read(process, _VERSION_COMMAND, root, deadline)
                version_lines = tuple(line for line in _frame_lines(version, _VERSION_COMMAND, root)
                                      if line.strip(b" \t"))
                if not _qualified_version_metadata(version_lines):
                    raise ValueError
                secret = await self._table(process, root, deadline, table="database", witnesses=self._secret_witnesses)
                policy = await self._table(process, root, deadline, table="policy", witnesses=self._policy_witnesses)
                return DlpDependencyInspection(
                    sensor_name=self._sensor_name, device_serial=self._device_serial,
                    version="v7.0.0", build=29, secret_object_count=secret.object_count,
                    policy_object_count=policy.object_count, secret_reference_count=secret.reference_count,
                    policy_reference_count=policy.reference_count,
                    evidence_digest=canonical_digest({
                        "contract": "fortipam-build29-fixed-dlp-dependencies-v1",
                        "sensor": self._sensor_name, "serial": self._device_serial,
                        "version": "v7.0.0", "build": 29,
                        "secret_columns": secret.digest, "policy_columns": policy.digest,
                    }),
                )
            finally:
                await _close_cli(process)

    async def _table(self, process: object, root: bytes, deadline: float, *, table: str,
                     witnesses: tuple[DlpReferenceWitness, ...]) -> _TableEvidence:
        if table not in {"database", "policy"}:
            raise ValueError
        prompt = await _send_and_read_dynamic_prompt(process, "config secret " + table, root, deadline)
        if prompt != root[:-2] + b" (" + table.encode("ascii") + b") #":
            raise ValueError
        grouped_command = _DATABASE_GROUPED if table == "database" else _POLICY_GROUPED
        commands = (_EDIT_PROJECTION, _NAME_PROJECTION, _DLP_PROJECTION, grouped_command) if table == "database" else (
            _EDIT_PROJECTION, _DLP_PROJECTION, grouped_command)
        first = {command: await _send_and_read(process, command, prompt, deadline) for command in commands}
        second = {command: await _send_and_read(process, command, prompt, deadline) for command in commands}
        if any(not hmac.compare_digest(first[command], second[command]) for command in commands):
            raise ValueError
        anchors = _edit_values(first[_EDIT_PROJECTION], prompt, numeric=table == "database")
        names = _secret_names(first[_NAME_PROJECTION], prompt) if table == "database" else anchors
        explicit_sensors = _dlp_values(first[_DLP_PROJECTION], prompt)
        grouped = _grouped_columns(_projection_lines(_frame_lines(first[grouped_command], grouped_command, prompt)),
                                   table=table)
        if (len(anchors) != len(set(anchors)) or len(names) != len(anchors)
                or tuple(row.object_key for row in grouped.objects) != anchors
                or tuple(row.object_name for row in grouped.objects) != names
                or grouped.explicit_references != explicit_sensors
                or any(witness not in grouped.objects for witness in witnesses)):
            raise ValueError
        returned = await _send_and_read_dynamic_prompt(process, "end", root, deadline)
        _require_root_prompt(root, returned)
        if returned != root:
            raise ValueError
        sensors = tuple(row.sensor_reference for row in grouped.objects)
        return _TableEvidence(len(anchors), sensors.count(self._sensor_name),
                              _table_digest(table, grouped.objects))


def _table_digest(table: str, objects: tuple[DlpReferenceWitness, ...]) -> str:
    """Bind every verified row in order without a canonical sequence size limit."""
    domain = "fortipam-build29-dlp-dependency-ordered-rows-v1"
    sequence = hashlib.sha256(domain.encode("ascii") + b"\0")
    for position, row in enumerate(objects):
        row_digest = canonical_digest({
            "position": position, "anchor": row.object_key, "name": row.object_name,
            "sensor": {"reference": row.sensor_reference} if row.sensor_reference else {"empty_reference": True},
        })
        sequence.update(bytes.fromhex(row_digest))
    return canonical_digest({
        "contract": domain, "table": table, "object_count": len(objects),
        "ordered_rows_sha256": sequence.hexdigest(),
    })


def _edit_values(output: bytes, prompt: bytes, *, numeric: bool) -> tuple[str, ...]:
    values = []
    for line in _projection_lines(_frame_lines(output, _EDIT_PROJECTION, prompt)):
        values.append(_edit_value(line, numeric=numeric))
    return tuple(values)


def _edit_value(line: bytes, *, numeric: bool) -> str:
    match = re.fullmatch(rb"    edit ([1-9][0-9]*)", line) if numeric else re.fullmatch(
        rb'    edit "([^"\\\r\n]*)"', line)
    if match is None:
        raise ValueError
    value = match[1].decode("utf-8")
    if (numeric and int(value) > 2_147_483_647) or not _safe_secret_name(value):
        raise ValueError
    return value


def _dlp_values(output: bytes, prompt: bytes) -> tuple[str, ...]:
    return tuple(_dlp_value(line) for line in _projection_lines(_frame_lines(output, _DLP_PROJECTION, prompt)))


def _dlp_value(line: bytes) -> str:
    match = re.fullmatch(rb'        set dlp-sensor "([^"\\\r\n]*)"', line)
    if match is None:
        raise ValueError
    value = match[1].decode("utf-8")
    if value and (not _safe_secret_name(value) or len(value) > 79):
        raise ValueError
    return value


def _validate_witnesses(witnesses: object, *, numeric: bool) -> None:
    if not isinstance(witnesses, tuple) or len(witnesses) < 2:
        raise ValueError
    for witness in witnesses:
        if (not isinstance(witness, DlpReferenceWitness) or type(witness.object_key) is not str
                or not _safe_secret_name(witness.object_name) or type(witness.sensor_reference) is not str
                or (witness.sensor_reference and (not _safe_secret_name(witness.sensor_reference)
                                                  or len(witness.sensor_reference) > 79))):
            raise ValueError
        if numeric:
            if re.fullmatch(r"[1-9][0-9]*", witness.object_key) is None or int(witness.object_key) > 2_147_483_647:
                raise ValueError
        elif witness.object_key != witness.object_name:
            raise ValueError
    if (len({witness.object_key for witness in witnesses}) != len(witnesses)
            or not any(not witness.sensor_reference for witness in witnesses)
            or not any(witness.sensor_reference for witness in witnesses)):
        raise ValueError


def _grouped_columns(lines: tuple[bytes, ...], *, table: str) -> _GroupedColumns:
    if (table not in {"database", "policy"} or len(lines) < 2
            or lines[0] != b"config secret " + table.encode() or lines[-1] != b"end"):
        raise ValueError
    objects: list[DlpReferenceWitness] = []
    explicit: list[str] = []
    key: str | None = None
    name: str | None = None
    reference: str | None = None
    for line in lines[1:-1]:
        if line.startswith(b"    edit "):
            if key is not None:
                raise ValueError
            key = _edit_value(line, numeric=table == "database")
            name = key if table == "policy" else None
        elif line == b"    next":
            if key is None or name is None:
                raise ValueError
            objects.append(DlpReferenceWitness(key, name, "" if reference is None else reference))
            key = name = reference = None
        elif line.startswith(b"        set name "):
            match = re.fullmatch(rb'        set name "([^"\\\r\n]*)"', line)
            if table != "database" or key is None or name is not None or match is None:
                raise ValueError
            name = match[1].decode("utf-8")
            if not _safe_secret_name(name):
                raise ValueError
        elif line.startswith(b"        set dlp-sensor "):
            if key is None or reference is not None:
                raise ValueError
            reference = _dlp_value(line)
            explicit.append(reference)
        else:
            raise ValueError
    if key is not None or not objects or len({row.object_key for row in objects}) != len(objects):
        raise ValueError
    return _GroupedColumns(tuple(objects), tuple(explicit))
