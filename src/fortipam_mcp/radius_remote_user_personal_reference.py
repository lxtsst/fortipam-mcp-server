"""Private original-ACK observation of one empty Personal Folder reference.

No writer, Tool, authorization, created-record repair or default provider exists.
The provider independently qualifies native actor/route/closure and returns only
fixed metadata frames. This consumer joins them to original terminal M4 custody
and complete stable User state; request/job/session cascade remains unqualified.
"""
from __future__ import annotations

from dataclasses import dataclass, fields
import hashlib
import hmac
import re
import time
from typing import Protocol
from urllib.parse import quote

from v4_planning.material_provider import _OpaqueC3Object

from . import secret_bulk_import_metadata as m
from .folder_archive_reference_ssh_transport import _PARENT_PROJECTION, _folder_parent_ids
from .folder_namespace_ssh_reader import (
    _NAME_PROJECTION as _FOLDER_NAMES, _SERIAL_COMMAND, _VERSION_COMMAND,
    _folder_names, _frame_lines, _qualified_version_metadata,
)
from .ldap_server_projection import _array, _digest
from .local_user_reset_metadata_reader import _monitor_results
from .radius_remote_user_contract import project_radius_remote_user_detail
from .radius_remote_user_live_workflow import RadiusRemoteUserLiveWorkflow
from .radius_server_projection import RadiusServerState
from .secret_metadata_http_transport import _zeroize_mutable
from .secret_namespace_ssh_reader import _FOLDER_PROJECTION, _secret_folder_values, _secret_names
from .single_secret_folder_membership_source import SingleSecretFolderMembershipColumns
from .target_lifecycle_dependencies import _spans
from .target_preservation_contract import _token_digest

CONTRACT = "fortipam-build29-radius-user-personal-reference-observation-v1"
_ERROR = "The original User Personal Folder observation is unavailable."
_TTL = 30
_ROOT_FIELDS = frozenset({b"name", b"parent-folder", b"folder-type", b"inherit-policy",
    b"secret-policy", b"inherit-permission", b"inherit-folder-ztna", b"ztna-tags-match-logic", b"ztna-ems-tag"})
_ACL_FIELDS = frozenset({b"user-name", b"folder-permission", b"secret-permission", b"allowed-launcher-type"})


class RadiusPersonalReferenceError(RuntimeError):
    """Non-disclosing refusal without selectors, upstream values or authority."""

    stage = "unavailable"


@dataclass(frozen=True, slots=True, repr=False)
class RadiusPersonalReferenceFrames(_OpaqueC3Object):
    """Fresh private metadata; four mutable buffers are consumed on every exit."""

    folder_id: int
    captured_at: int
    usage_before: bytearray
    usage_after: bytearray
    detail_before: bytearray
    detail_after: bytearray
    columns_before: SingleSecretFolderMembershipColumns
    columns_after: SingleSecretFolderMembershipColumns


class RadiusPersonalReferenceProvider(Protocol):
    def read_reference(self) -> RadiusPersonalReferenceFrames:
        """Read only the constructor-bound User/reference using qualified sources."""
        ...


def _pair_reference_delta_matches_original(state: RadiusServerState, original_digest: str) -> bool:
    """Compare only a historical q_ref=0 digest hypothesis; grant no authority.

    The actual immutable state keeps q_ref=1 and remains ineligible for the
    existing zero-reference qualifier. No replacement state is constructed.
    The caller must separately establish original custody and fresh provenance.
    """
    if (type(state) is not RadiusServerState or type(original_digest) is not str
        or re.fullmatch(r"[a-f0-9]{64}", original_digest) is None
        or type(state.metadata.get("q_ref")) is not int or state.metadata["q_ref"] != 1):
        return False
    historical_metadata = dict(state.metadata) | {"q_ref": 0}
    historical_digest = _digest({"values": dict(state.values),
        "opaque": dict(state.opaque_token_digests), "metadata": historical_metadata,
        "schema": state.schema_digest})
    return hmac.compare_digest(historical_digest, original_digest)


@dataclass(frozen=True, slots=True, repr=False)
class RadiusPersonalReferenceObservation(_OpaqueC3Object):
    evidence_digest: str
    complete_user_digest: str
    original_provenance_digest: str
    observed_at: int
    global_folder_count: int
    global_secret_metadata_count: int

    def as_dict(self) -> dict[str, object]:
        return {"contract": CONTRACT, "original_ack_and_terminal_m4_verified": True,
            "complete_user_state_stable": True, "personal_folder_observed": True,
            "sole_original_user_folder_and_secret_owner": True, "user_reference_count": 1,
            "child_folder_count": 0, "secret_membership_count": 0,
            "global_folder_count": self.global_folder_count,
            "global_secret_metadata_count": self.global_secret_metadata_count,
            "observation_only": True, "recovery_authority": False,
            "request_job_session_cascade_qualified": False,
            "live_pair_preservation_qualified": False, "device_write_executed": False}


def _folder(raw: bytearray, root: bytes, folder_id: int, username: str) -> None:
    command = f'show full-configuration secret folder "{folder_id}"'
    lines = tuple(line for line in _frame_lines(bytes(raw), command, root) if line.strip(b" \t"))
    identifier = str(folder_id).encode("ascii")
    if (len(lines) < 4 or lines[0] != b"config secret folder" or lines[-2:] != (b"    next", b"end")
        or lines[1] not in (b"    edit " + identifier, b'    edit "' + identifier + b'"')):
        raise ValueError
    values: dict[bytes, bytes] = {}
    users: list[dict[bytes, bytes]] = []
    table = False
    seen_user_table = False
    current: dict[bytes, bytes] | None = None
    for line in lines[2:-2]:
        if not table:
            match = re.fullmatch(rb"        set ([a-z][a-z0-9-]*) (.+)", line)
            if match is not None:
                if match[1] not in _ROOT_FIELDS or match[1] in values:
                    raise ValueError
                values[match[1]] = match[2]
            elif line == b"        config user-permission" and not seen_user_table:
                table = True
                seen_user_table = True
            else:
                # No group ACL, nested extra table, unset or unclassified syntax.
                raise ValueError
        elif current is None:
            if re.fullmatch(rb'            edit (?:"[1-9][0-9]*"|[1-9][0-9]*)', line) is not None:
                current = {}
            elif line == b"        end":
                table = False
            else:
                raise ValueError
        else:
            match = re.fullmatch(rb"                set ([a-z][a-z0-9-]*) (.+)", line)
            if match is not None:
                if match[1] not in _ACL_FIELDS or match[1] in current:
                    raise ValueError
                current[match[1]] = match[2]
            elif line == b"            next":
                users.append(current)
                current = None
            else:
                raise ValueError
    expected_name = username.encode("ascii")
    if (table or current is not None or len(values) != 8
        or values.get(b"name") not in (expected_name, b'"' + expected_name + b'"')
        or values.get(b"folder-type") != b"personal" or values.get(b"parent-folder") != b"0"
        or len(users) != 1
        or users[0].get(b"user-name") not in (expected_name, b'"' + expected_name + b'"')
        or users[0].get(b"folder-permission") != b"owner" or users[0].get(b"secret-permission") != b"owner"):
        raise ValueError
    for name in (b"inherit-policy", b"inherit-permission", b"inherit-folder-ztna"):
        if name in values and values[name] not in (b"enable", b"disable"):
            raise ValueError
    if b"ztna-tags-match-logic" in values and values[b"ztna-tags-match-logic"] not in (b"and", b"or"):
        raise ValueError


def _usage(raw: bytearray, serial: str, username: str, folder_id: int) -> str:
    row = _monitor_results(raw, expected_route="system/object/usage", expected_mkey=username)
    top = _spans(raw)
    if m._scalar(raw, top["serial"]) != serial or m._scalar(raw, top["vdom"]) != "root":
        raise ValueError
    entries = m._object_spans(raw, *row, frozenset({"currently_using"}))
    rows = _array(raw, entries["currently_using"])
    if len(rows) != 1:
        raise ValueError
    reference = m._object_spans(raw, *rows[0], frozenset({"path", "name", "mkey"}))
    identifier = m._scalar(raw, reference["mkey"])
    if (m._scalar(raw, reference["path"]) != "secret" or m._scalar(raw, reference["name"]) != "folder"
        or type(identifier) not in (int, str) or str(identifier) != str(folder_id)):
        raise ValueError
    if "static" in reference and m._scalar(raw, reference["static"]) is not False:
        raise ValueError
    return _token_digest(raw, rows[0])


def _columns(snapshot: SingleSecretFolderMembershipColumns, serial: str, username: str,
        folder_id: int) -> tuple[int, int]:
    if (type(snapshot) is not SingleSecretFolderMembershipColumns
        or any(type(getattr(snapshot, item.name)) is not bytes for item in fields(snapshot))
        or re.fullmatch(rb"[A-Za-z0-9._-]{1,63} #", snapshot.root_prompt) is None
        or snapshot.returned_root_prompt != snapshot.root_prompt):
        raise ValueError
    root = snapshot.root_prompt
    lines = tuple(line for line in _frame_lines(snapshot.serial_output, _SERIAL_COMMAND, root) if line.strip(b" \t"))
    if lines != (b"Serial-Number: " + serial.encode("ascii"),):
        raise ValueError
    lines = tuple(line for line in _frame_lines(snapshot.version_output, _VERSION_COMMAND, root) if line.strip(b" \t"))
    if not _qualified_version_metadata(lines):
        raise ValueError
    folder_prompt, secret_prompt = root[:-2] + b" (folder) #", root[:-2] + b" (database) #"
    names = _folder_names(snapshot.folder_names, folder_prompt)
    parents = _folder_parent_ids(snapshot.folder_parents, folder_prompt)
    secrets = _secret_names(snapshot.secret_names, secret_prompt)
    folder_values = _secret_folder_values(snapshot.secret_folders, secret_prompt)
    if (not 1 < len(names) <= 512 or len(names) != len(parents) or len(set(names)) != len(names)
        or username not in names or not 1 < len(secrets) <= 512 or len(secrets) != len(folder_values)
        or len(set(secrets)) != len(secrets) or folder_id in parents or folder_id in folder_values):
        raise ValueError
    return len(names), len(secrets)


class RadiusRemoteUserPersonalReferenceInspector(_OpaqueC3Object):
    """Inspect only; reuse original verifier without its created-record writer."""

    def __init__(self, workflow: RadiusRemoteUserLiveWorkflow,
            provider: RadiusPersonalReferenceProvider | None = None) -> None:
        if (type(workflow) is not RadiusRemoteUserLiveWorkflow or workflow._operation != "remove"
            or provider is not None and not callable(getattr(provider, "read_reference", None))):
            raise RadiusPersonalReferenceError(_ERROR)
        self._workflow, self._provider = workflow, provider

    def inspect(self) -> RadiusPersonalReferenceObservation:
        snapshot: RadiusPersonalReferenceFrames | None = None
        raw = bytearray()
        key = bytearray()
        stage = "original_context"
        try:
            w, provider = self._workflow, self._provider
            if provider is None:
                raise ValueError
            w._gate(execute=False)
            started = w._now()
            stop = time.monotonic() + _TTL
            reader = w._reader
            with reader._locked(existing=True):
                reader._namespace(existing_only=True)
                if (w._store.claim_count != 0 or any(reader._exists(name)
                        for name in ("delete.claim.json", "delete-ack.json", "deleted.json"))):
                    raise ValueError
                provenance = w._original_provenance(locked=True)
                claim, _ = reader._ownership()
                schema, draft = reader._components(stop)
                if (draft.request_digest != claim["request_digest"] or draft.source_defaults_digest != claim["defaults_digest"]
                    or draft._response_vdom != "root"):
                    raise ValueError
                path = "/api/v2/cmdb/system/admin/" + quote(reader._binding.username, safe="") + "?with_meta=true"
                stage = "user_before"
                code, raw = reader._exchange("GET", path, stop=stop)
                if code != 200:
                    raise ValueError
                before = project_radius_remote_user_detail(raw, schema, draft, expected_serial=reader._serial)
                if before.reported_reference_count != 1:
                    raise ValueError
                stage = "source_capture"
                snapshot = provider.read_reference()
                stage = "source_freshness"
                now = w._now()
                if (type(snapshot) is not RadiusPersonalReferenceFrames
                    or type(snapshot.folder_id) is not int or not 0 < snapshot.folder_id <= 2_147_483_647
                    or type(snapshot.captured_at) is not int or not started <= snapshot.captured_at <= now
                    or now - started >= _TTL or time.monotonic() >= stop):
                    raise ValueError
                buffers = (snapshot.usage_before, snapshot.usage_after, snapshot.detail_before, snapshot.detail_after)
                if any(type(buf) is not bytearray or not 0 < len(buf) <= 1_048_576 for buf in buffers):
                    raise ValueError
                if snapshot.columns_before != snapshot.columns_after:
                    raise ValueError
                stage = "global_columns"
                counts = _columns(snapshot.columns_before, reader._serial, reader._binding.username, snapshot.folder_id)
                _columns(snapshot.columns_after, reader._serial, reader._binding.username, snapshot.folder_id)
                stage = "usage_envelope"
                if (_usage(snapshot.usage_before, reader._serial, reader._binding.username, snapshot.folder_id)
                    != _usage(snapshot.usage_after, reader._serial, reader._binding.username, snapshot.folder_id)):
                    raise ValueError
                for buf in (snapshot.detail_before, snapshot.detail_after):
                    stage = "folder_detail"
                    _folder(buf, snapshot.columns_before.root_prompt, snapshot.folder_id, reader._binding.username)
                if snapshot.detail_before != snapshot.detail_after:
                    raise ValueError
                stage = "user_after"
                fresh_schema, fresh_draft = reader._components(stop)
                if (fresh_draft.request_digest != draft.request_digest
                    or fresh_draft.source_defaults_digest != draft.source_defaults_digest
                    or fresh_draft._schema_digest != draft._schema_digest):
                    raise ValueError
                code, raw = reader._exchange("GET", path, stop=stop)
                if code != 200:
                    raise ValueError
                after = project_radius_remote_user_detail(raw, fresh_schema, fresh_draft, expected_serial=reader._serial)
                stage = "original_preservation"
                if before != after or w._original_provenance(locked=True) != provenance:
                    raise ValueError
                if (w._store.claim_count != 0 or any(reader._exists(name)
                        for name in ("delete.claim.json", "delete-ack.json", "deleted.json"))):
                    raise ValueError
                w._gate(execute=False)
                if w._now() - started >= _TTL or time.monotonic() >= stop or w._original_key is None:
                    raise ValueError
                key.extend(hmac.new(w._original_key, (CONTRACT + "\x00" + w._parameters).encode(), hashlib.sha256).digest())
                digest = hmac.new(key, digestmod=hashlib.sha256)
                for value in (provenance.encode(), before.nonmaterial_state_digest.encode(), str(snapshot.folder_id).encode(),
                        snapshot.detail_before, snapshot.usage_before, snapshot.usage_after):
                    digest.update(len(value).to_bytes(8, "big")); digest.update(value)
                for item in fields(snapshot.columns_before):
                    value = getattr(snapshot.columns_before, item.name)
                    digest.update(len(value).to_bytes(8, "big")); digest.update(value)
                return RadiusPersonalReferenceObservation(digest.hexdigest(), before.nonmaterial_state_digest,
                    provenance, snapshot.captured_at, counts[0], counts[1])
        except Exception:
            failure = RadiusPersonalReferenceError(_ERROR)
            failure.stage = stage
            raise failure from None
        finally:
            _zeroize_mutable(raw)
            _zeroize_mutable(key)
            if type(snapshot) is RadiusPersonalReferenceFrames:
                for buf in (snapshot.usage_before, snapshot.usage_after, snapshot.detail_before, snapshot.detail_after):
                    if isinstance(buf, bytearray):
                        _zeroize_mutable(buf)
