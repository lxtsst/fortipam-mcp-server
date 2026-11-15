"""Private, injected build-29 single-Secret Folder membership observation.

The provider must independently qualify the same fresh enabled local Owner,
complete native namespaces, API/SSH appliance serial/build and fixed Secret
detail, and close its sessions. That provider composition is not currently
live-accepted by this module. Actor-filtered or paginated REST collections must
never substitute for native global columns. This module has no network client,
MCP registration, selector argument, default provider or mutation authority.

Two identical complete column observations surrounding fixed detail reads
establish observed stability, not an atomic appliance transaction: a change
and reversal between reads can remain unseen. A future workflow must obtain a
fresh observation before dispatch and reconcile independently after dispatch.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import re
from typing import Protocol

from .folder_archive_reference_ssh_transport import _PARENT_PROJECTION, _folder_parent_ids
from .folder_namespace_ssh_reader import (
    _SERIAL_COMMAND, _VERSION_COMMAND, _folder_names, _frame_lines,
    _projection_lines, _qualified_version_metadata, _safe_observed_name,
)
from .secret_namespace_ssh_reader import (
    _safe_secret_name, _secret_folder_values, _secret_names,
)


CONTRACT = "fortipam-build29-single-secret-folder-membership-v1"
_UNAVAILABLE = "The fixed single-Secret Folder membership observation is unavailable."
_MAX_OBJECTS = 512


class SingleSecretFolderMembershipSourceError(RuntimeError):
    """Stable refusal without IDs, names, columns, prompts or upstream errors."""


@dataclass(frozen=True, slots=True, repr=False)
class SingleSecretFolderMembershipBinding:
    """Constructor-bound private selectors and independent namespace witnesses."""

    folder_id: int
    folder_name: str
    secret_id: int
    secret_name: str
    expected_serial: str
    folder_witness_name: str
    secret_witness_name: str

    def __post_init__(self) -> None:
        if (any(type(value) is not int or not 0 < value <= 2_147_483_647
                for value in (self.folder_id, self.secret_id))
            or any(type(value) is not str or not _safe_observed_name(value)
                   for value in (self.folder_name, self.folder_witness_name))
            or any(type(value) is not str or not _safe_secret_name(value)
                   for value in (self.secret_name, self.secret_witness_name))
            or self.folder_name == self.folder_witness_name
            or self.secret_name == self.secret_witness_name
            or type(self.expected_serial) is not str
            or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", self.expected_serial) is None):
            raise SingleSecretFolderMembershipSourceError(_UNAVAILABLE)


@dataclass(frozen=True, slots=True, repr=False)
class SingleSecretFolderMembershipColumns:
    """Native CLI frames only, with no credential fields or REST collection."""

    root_prompt: bytes
    serial_output: bytes
    version_output: bytes
    folder_names: bytes
    folder_parents: bytes
    secret_names: bytes
    secret_folders: bytes
    returned_root_prompt: bytes


class SingleSecretFolderMembershipProvider(Protocol):
    """Private qualified provider; both operations accept no caller selectors.

    The metadata operation must redact before decoding, project only fixed
    id/name/folder (optional q_origin_key), and retain the exact native detail
    header. It must not provide raw Secret fields or an actor-filtered listing.
    Owner/namespace permissions and transport lifecycle belong to the provider;
    the source's structural checks do not qualify those prerequisites.
    """

    def read_global_columns(self) -> SingleSecretFolderMembershipColumns: ...

    def read_bound_secret_metadata(self) -> Mapping[str, object]: ...


@dataclass(frozen=True, slots=True)
class SingleSecretFolderMembershipObservation:
    """Closed observed membership only; no access, Policy or execution claim."""

    no_child_folders: bool
    exactly_one_secret: bool
    bound_secret_folder_matches: bool
    observations_stable: bool
    membership_digest: str

    def as_dict(self) -> dict[str, object]:
        return {
            "contract": CONTRACT,
            "no_child_folders": self.no_child_folders,
            "exactly_one_secret": self.exactly_one_secret,
            "bound_secret_folder_matches": self.bound_secret_folder_matches,
            "observations_stable": self.observations_stable,
            "membership_digest": self.membership_digest,
        }


@dataclass(frozen=True, slots=True, repr=False)
class _ParsedColumns:
    folder_names: tuple[str, ...]
    folder_parents: tuple[int, ...]
    secret_names: tuple[str, ...]
    secret_folders: tuple[int, ...]


class SingleSecretFolderMembershipSource:
    """Observe one fixed scope through an explicitly injected private provider."""

    def __init__(
        self, binding: SingleSecretFolderMembershipBinding,
        provider: SingleSecretFolderMembershipProvider | None = None,
    ) -> None:
        if (type(binding) is not SingleSecretFolderMembershipBinding
            or provider is not None and any(not callable(getattr(provider, method, None))
                for method in ("read_global_columns", "read_bound_secret_metadata"))):
            raise SingleSecretFolderMembershipSourceError(_UNAVAILABLE)
        self._binding, self._provider = binding, provider

    def observe(self) -> SingleSecretFolderMembershipObservation:
        """Require zero children, one Secret and stable independent detail reads."""
        try:
            if self._provider is None:
                raise ValueError
            first = self._columns(self._provider.read_global_columns())
            before = self._metadata(self._provider.read_bound_secret_metadata())
            second = self._columns(self._provider.read_global_columns())
            after = self._metadata(self._provider.read_bound_secret_metadata())
            if (first != second or before != after
                or first.folder_parents.count(self._binding.folder_id) != 0
                or first.secret_folders.count(self._binding.folder_id) != 1):
                raise ValueError
            digest_content = json.dumps({
                "contract": CONTRACT, "binding": asdict(self._binding),
                "first_columns": asdict(first), "second_columns": asdict(second),
                "before_metadata": before, "after_metadata": after,
            }, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
            digest = hashlib.sha256(digest_content).hexdigest()
            return SingleSecretFolderMembershipObservation(True, True, True, True, digest)
        except Exception:
            raise SingleSecretFolderMembershipSourceError(_UNAVAILABLE) from None

    def _columns(self, snapshot: SingleSecretFolderMembershipColumns) -> _ParsedColumns:
        if (type(snapshot) is not SingleSecretFolderMembershipColumns
            or any(type(value) is not bytes for value in asdict(snapshot).values())
            or re.fullmatch(rb"[A-Za-z0-9._-]{1,63} #", snapshot.root_prompt) is None
            or snapshot.returned_root_prompt != snapshot.root_prompt):
            raise ValueError
        root = snapshot.root_prompt
        serial = tuple(line for line in _frame_lines(snapshot.serial_output, _SERIAL_COMMAND, root)
                       if line.strip(b" \t"))
        if (len(serial) != 1 or not hmac.compare_digest(
                serial[0], b"Serial-Number: " + self._binding.expected_serial.encode("ascii"))):
            raise ValueError
        version = tuple(line for line in _frame_lines(snapshot.version_output, _VERSION_COMMAND, root)
                        if line.strip(b" \t"))
        if not _qualified_version_metadata(version):
            raise ValueError
        folder_prompt, secret_prompt = root[:-2] + b" (folder) #", root[:-2] + b" (database) #"
        folder_names = _folder_names(snapshot.folder_names, folder_prompt)
        parent_lines = _projection_lines(_frame_lines(snapshot.folder_parents, _PARENT_PROJECTION, folder_prompt))
        if any(re.fullmatch(rb"[ \t]*set parent-folder (0|[1-9][0-9]*)[ \t]*", line) is None
               for line in parent_lines):
            raise ValueError
        parents = _folder_parent_ids(snapshot.folder_parents, folder_prompt)
        secret_names = _secret_names(snapshot.secret_names, secret_prompt)
        folders = _secret_folder_values(snapshot.secret_folders, secret_prompt)
        b = self._binding
        if (not 1 < len(folder_names) <= _MAX_OBJECTS or len(folder_names) != len(parents)
            or not 1 < len(secret_names) <= _MAX_OBJECTS or len(secret_names) != len(folders)
            or len(set(folder_names)) != len(folder_names)
            or len(set(secret_names)) != len(secret_names)
            or any(name not in folder_names for name in (b.folder_name, b.folder_witness_name))
            or any(name not in secret_names for name in (b.secret_name, b.secret_witness_name))):
            raise ValueError
        # Columns remain independent. Only global numeric occurrence counts are
        # used; no name/parent or name/Folder positional join is inferred.
        return _ParsedColumns(folder_names, parents, secret_names, folders)

    def _metadata(self, payload: Mapping[str, object]) -> dict[str, object]:
        b = self._binding
        expected: dict[str, object] = {
            "version": "v7.0.0", "build": 29, "serial": b.expected_serial,
            "http_method": "GET", "http_status": 200, "path": "secret",
            "name": "database", "vdom": "root",
        }
        if (not isinstance(payload, Mapping)
            or not set(expected) | {"status", "results"} <= set(payload)
            or not set(payload) <= set(expected) | {"action", "status", "results", "size", "matched_count", "limit_reached"}
            or "action" in payload and (type(payload["action"]) is not str or payload["action"] != "")
            or any(type(payload.get(key)) is not type(value) or payload.get(key) != value
                   for key, value in expected.items())
            or type(payload.get("status")) is not str or payload["status"] not in {"OK", "success"}
            or any(type(payload[key]) is not int or payload[key] != 1
                   for key in ("size", "matched_count") if key in payload)
            or payload.get("limit_reached", False) is not False):
            raise ValueError
        row = payload["results"]
        if isinstance(row, list) and len(row) == 1:
            row = row[0]
        identity = {"id": b.secret_id, "name": b.secret_name, "folder": b.folder_id}
        if (not isinstance(row, Mapping) or not set(identity) <= set(row)
            or not set(row) <= set(identity) | {"q_origin_key"}
            or any(type(row.get(key)) is not type(value) or row.get(key) != value
                   for key, value in identity.items())
            or "q_origin_key" in row and (type(row["q_origin_key"]) not in {int, str}
                or row["q_origin_key"] not in {b.secret_id, str(b.secret_id)})):
            raise ValueError
        return {**expected, **({"action": payload["action"]} if "action" in payload else {}),
                "status": payload["status"], "results": dict(row)}
