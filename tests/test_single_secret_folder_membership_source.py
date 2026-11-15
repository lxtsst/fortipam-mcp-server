"""Synthetic complete-column stability and fixed detail qualification only."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from typing import Any

import pytest

from fortipam_mcp.folder_archive_reference_ssh_transport import _PARENT_PROJECTION
from fortipam_mcp.folder_namespace_ssh_reader import (
    _NAME_PROJECTION as FOLDER_NAMES, _SERIAL_COMMAND, _VERSION_COMMAND,
)
from fortipam_mcp.secret_namespace_ssh_reader import (
    _FOLDER_PROJECTION, _NAME_PROJECTION as SECRET_NAMES,
)
from fortipam_mcp.single_secret_folder_membership_source import (
    SingleSecretFolderMembershipBinding, SingleSecretFolderMembershipColumns,
    SingleSecretFolderMembershipObservation, SingleSecretFolderMembershipSource,
    SingleSecretFolderMembershipSourceError,
)

ROOT = b"FPA-SYNTHETIC #"
FOLDER = b"FPA-SYNTHETIC (folder) #"
DATABASE = b"FPA-SYNTHETIC (database) #"
SERIAL = "SYNTHETIC_SERIAL"
FOLDER_NAME, SECRET_NAME = "mcp-v4-single-folder-synthetic", "mcp-v4-single-secret-synthetic"


def frame(command: str, lines: list[bytes], prompt: bytes = ROOT) -> bytes:
    return command.encode() + b"\r\r\n" + b"".join(line + b"\r\n" for line in lines) + prompt


def binding() -> SingleSecretFolderMembershipBinding:
    return SingleSecretFolderMembershipBinding(
        42, FOLDER_NAME, 17, SECRET_NAME, SERIAL, "Synthetic Folder Witness", "Synthetic Secret Witness",
    )


def columns(
    *, parents: tuple[int, ...] = (0, 7), folders: tuple[int, ...] = (42, 7),
) -> SingleSecretFolderMembershipColumns:
    return SingleSecretFolderMembershipColumns(
        ROOT, frame(_SERIAL_COMMAND, [b"Serial-Number: " + SERIAL.encode()]),
        frame(_VERSION_COMMAND, [b"Version: FortiPAM-VM v7.0.0,build0029, synthetic metadata"]),
        frame(FOLDER_NAMES, [b'    set name "' + name.encode() + b'"'
                            for name in (FOLDER_NAME, "Synthetic Folder Witness")], FOLDER),
        frame(_PARENT_PROJECTION, [f"    set parent-folder {value}".encode() for value in parents], FOLDER),
        frame(SECRET_NAMES, [b'        set name "' + name.encode() + b'"'
                            for name in (SECRET_NAME, "Synthetic Secret Witness")], DATABASE),
        frame(_FOLDER_PROJECTION, [f"        set folder {value}".encode() for value in folders], DATABASE), ROOT,
    )


def metadata() -> dict[str, Any]:
    return {
        "version": "v7.0.0", "build": 29, "serial": SERIAL, "http_method": "GET", "http_status": 200,
        "path": "secret", "name": "database", "action": "", "vdom": "root", "status": "OK",
        "results": {"id": 17, "name": SECRET_NAME, "folder": 42, "q_origin_key": 17},
        "size": 1, "matched_count": 1, "limit_reached": False,
    }


class Provider:
    def __init__(self) -> None:
        self.snapshots = [columns(), columns()]
        self.details = [metadata(), metadata()]
        self.calls: list[str] = []

    def read_global_columns(self) -> SingleSecretFolderMembershipColumns:
        self.calls.append("columns")
        return self.snapshots.pop(0)

    def read_bound_secret_metadata(self) -> dict[str, Any]:
        self.calls.append("metadata")
        return self.details.pop(0)


def test_closed_membership_binds_complete_stable_columns_and_exact_metadata_without_private_output() -> None:
    provider = Provider()
    result = SingleSecretFolderMembershipSource(binding(), provider).observe()
    assert provider.calls == ["columns", "metadata", "columns", "metadata"]
    assert isinstance(result, SingleSecretFolderMembershipObservation)
    output = result.as_dict()
    assert all(value is True for key, value in output.items() if key not in {"contract", "membership_digest"})
    assert len(result.membership_digest) == 64
    assert not {"id", "name", "columns", "raw", "count", "prompt"} & output.keys()
    for value in (FOLDER_NAME, SECRET_NAME, SERIAL, "Synthetic Folder Witness", "FPA-SYNTHETIC"):
        assert value not in str(output) and value not in repr(binding()) and value not in repr(columns())
    with pytest.raises(FrozenInstanceError):
        result.observations_stable = False  # type: ignore[misc]

    # Changing an unrelated membership still changes the complete-scope digest.
    changed = Provider()
    changed.snapshots = [columns(folders=(42, 8)), columns(folders=(42, 8))]
    assert SingleSecretFolderMembershipSource(binding(), changed).observe().membership_digest != result.membership_digest
    rebound = replace(binding(), secret_id=18)
    changed = Provider()
    for detail in changed.details:
        detail["results"].update(id=18, q_origin_key=18)
    assert SingleSecretFolderMembershipSource(rebound, changed).observe().membership_digest != result.membership_digest


def test_complete_native_namespaces_above_the_planning_digest_sequence_limit_remain_bounded() -> None:
    provider = Provider()
    native = columns(parents=(0,) + (7,) * 64, folders=(42,) + (7,) * 64)
    native = replace(native,
        folder_names=frame(FOLDER_NAMES, [b'    set name "' + name.encode() + b'"' for name in
            (FOLDER_NAME, "Synthetic Folder Witness", *(f"Synthetic Folder {index}" for index in range(63)))], FOLDER),
        secret_names=frame(SECRET_NAMES, [b'        set name "' + name.encode() + b'"' for name in
            (SECRET_NAME, "Synthetic Secret Witness", *(f"Synthetic Secret {index}" for index in range(63)))], DATABASE),
    )
    provider.snapshots = [native, native]
    assert SingleSecretFolderMembershipSource(binding(), provider).observe().observations_stable


def test_native_action_absence_is_preserved_bound_to_digest_and_checked_for_stability() -> None:
    present = SingleSecretFolderMembershipSource(binding(), Provider()).observe()
    absent = Provider()
    for detail in absent.details:
        del detail["action"]
    source = SingleSecretFolderMembershipSource(binding(), absent)
    assert "action" not in source._metadata(absent.details[0])
    observed = source.observe()
    assert observed.membership_digest != present.membership_digest
    mixed = Provider()
    del mixed.details[1]["action"]
    with pytest.raises(SingleSecretFolderMembershipSourceError):
        SingleSecretFolderMembershipSource(binding(), mixed).observe()


@pytest.mark.parametrize("fault", (
    "child", "sibling", "missing_secret", "column_drift", "name_drift", "metadata_drift",
    "folder_count", "secret_count", "folder_duplicate", "secret_duplicate",
    "folder_witness", "secret_witness", "pagination",
    "truncated", "blank", "nested", "parent_format", "folder_overflow", "echo", "context",
    "serial", "build", "return_prompt", "rest_columns",
))
def test_scope_or_incomplete_unstable_native_source_fails_closed(fault: str) -> None:
    provider = Provider()
    current = columns()
    if fault == "child": current = columns(parents=(0, 42))
    elif fault == "sibling": current = columns(folders=(42, 42))
    elif fault == "missing_secret": current = columns(folders=(7, 8))
    elif fault == "column_drift": provider.snapshots[1] = columns(folders=(42, 8))
    elif fault == "name_drift":
        provider.snapshots[1] = replace(current, secret_names=current.secret_names.replace(b"Synthetic Secret Witness", b"Another Witness"))
    elif fault == "metadata_drift": provider.details[1]["results"]["folder"] = 7
    elif fault == "folder_count": current = columns(parents=(0,))
    elif fault == "secret_count": current = columns(folders=(42,))
    elif fault == "folder_duplicate":
        current = replace(columns(parents=(0, 7, 7)), folder_names=frame(FOLDER_NAMES,
            [b'    set name "' + name.encode() + b'"' for name in
             (FOLDER_NAME, "Synthetic Folder Witness", FOLDER_NAME)], FOLDER))
    elif fault == "secret_duplicate":
        current = replace(columns(folders=(42, 7, 8)), secret_names=frame(SECRET_NAMES,
            [b'        set name "' + name.encode() + b'"' for name in
             (SECRET_NAME, "Synthetic Secret Witness", SECRET_NAME)], DATABASE))
    elif fault == "folder_witness":
        current = replace(current, folder_names=current.folder_names.replace(b"Synthetic Folder Witness", b"Other"))
    elif fault == "secret_witness":
        current = replace(current, secret_names=current.secret_names.replace(b"Synthetic Secret Witness", b"Other"))
    elif fault == "pagination":
        current = replace(current, secret_folders=frame(_FOLDER_PROJECTION, [b"        set folder 42", b"--More--"], DATABASE))
    elif fault == "truncated": current = replace(current, secret_folders=current.secret_folders[:-1])
    elif fault == "blank":
        current = replace(current, folder_parents=frame(_PARENT_PROJECTION, [b"    set parent-folder 0", b"", b"    set parent-folder 7"], FOLDER))
    elif fault == "nested":
        current = replace(current, secret_folders=frame(_FOLDER_PROJECTION, [b"                set folder 42", b"        set folder 7"], DATABASE))
    elif fault == "parent_format":
        current = replace(current, folder_parents=frame(_PARENT_PROJECTION, [b"    set parent-folder 00", b"    set parent-folder 7"], FOLDER))
    elif fault == "folder_overflow": current = columns(folders=(42, 2_147_483_648))
    elif fault == "echo": current = replace(current, secret_folders=current.secret_folders.replace(b"^        set folder", b"set folder", 1))
    elif fault == "context": current = replace(current, secret_folders=current.secret_folders.replace(DATABASE, FOLDER))
    elif fault == "serial": current = replace(current, serial_output=frame(_SERIAL_COMMAND, [b"Serial-Number: OTHER"]))
    elif fault == "build": current = replace(current, version_output=frame(_VERSION_COMMAND, [b"Version: FortiPAM v7.0.0,build30"]))
    elif fault == "return_prompt": current = replace(current, returned_root_prompt=b"OTHER #")
    elif fault == "rest_columns": provider.snapshots[0] = metadata()  # type: ignore[call-overload]
    if fault not in {"column_drift", "name_drift", "metadata_drift", "rest_columns"}:
        provider.snapshots = [current, current]
    with pytest.raises(SingleSecretFolderMembershipSourceError) as error:
        SingleSecretFolderMembershipSource(binding(), provider).observe()
    assert str(error.value) == "The fixed single-Secret Folder membership observation is unavailable."
    assert FOLDER_NAME not in str(error.value) and SERIAL not in str(error.value)


@pytest.mark.parametrize("field,value", (
    ("id", True), ("id", 18), ("folder", 7), ("folder", True), ("name", "Other"),
    ("q_origin_key", "different"), ("field", []), ("password", "SYNTHETIC_DENIAL_MARKER"),
))
def test_fixed_secret_metadata_rejects_identity_substitution_or_unredacted_fields(field: str, value: object) -> None:
    provider = Provider()
    provider.details[0]["results"][field] = value
    with pytest.raises(SingleSecretFolderMembershipSourceError):
        SingleSecretFolderMembershipSource(binding(), provider).observe()


@pytest.mark.parametrize("field,value", (
    ("version", "v1.9.1"), ("build", 30), ("build", True), ("serial", "OTHER"),
    ("action", "schema"), ("action", None), ("action", False), ("action", 0), ("action", []),
    ("path", "system"), ("name", "folder"), ("http_method", "POST"),
    ("http_status", 404), ("status", "error"), ("vdom", "other"),
    ("size", 2), ("matched_count", True), ("limit_reached", True), ("unexpected", "denied"),
    ("results", []), ("results", [{"id": 17}, {"id": 18}]),
))
def test_detail_envelope_is_exact_and_never_accepts_paginated_collection(field: str, value: object) -> None:
    provider = Provider()
    provider.details[0][field] = value
    with pytest.raises(SingleSecretFolderMembershipSourceError):
        SingleSecretFolderMembershipSource(binding(), provider).observe()


def test_provider_is_required_and_bound_observation_has_no_selector_input() -> None:
    source = SingleSecretFolderMembershipSource(binding())
    with pytest.raises(SingleSecretFolderMembershipSourceError): source.observe()
    with pytest.raises(TypeError): source.observe(folder_id=42)  # type: ignore[call-arg]
    for changed in ({"folder_id": True}, {"secret_id": 0}, {"folder_name": "bad\nname"},
                    {"expected_serial": "bad serial"}, {"secret_witness_name": SECRET_NAME}):
        with pytest.raises(SingleSecretFolderMembershipSourceError): replace(binding(), **changed)

    provider = Provider()
    # Single-result native detail lists are accepted, but cannot multiply rows.
    for detail in provider.details:
        detail["results"] = [deepcopy(detail["results"])]
    assert SingleSecretFolderMembershipSource(binding(), provider).observe().exactly_one_secret
