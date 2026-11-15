"""Private, bounded Terraform 1.2 action-metadata projection; no execution.

Raw JSON belongs only inside a future protected artifact boundary. It may contain
unmarked credentials, so no source string/value is deserialized or returned.
This partial projection is neither a completed security review nor evidence of
plan provenance, TLS enforcement, permission, device state or apply authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
from pathlib import Path
from threading import Lock

from v4_planning.material_provider import _OpaqueC3Object

from . import secret_bulk_import_metadata as metadata
from .secret_bulk_import_file import _read_owned
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable
from .target_preservation_contract import _member_count

CONTRACT = "fortipam-terraform-plan-action-metadata-private-v1"
_ERROR = "The private Terraform plan projection is unavailable."
_PROVIDER = b'"registry.terraform.io/fortinetdev/fortipam"'
_FOLDER = b'"fortipam_resource_folder"'
_SECRET = b'"fortipam_resource_secret"'
_DATA = b'"fortipam_secret"'
_MAX_BYTES = 2 * 1024 * 1024
_MAX_ENTRIES = 4096
_ACTIONS = (
    ("no-op",), ("create",), ("update",), ("delete",), ("read",),
    ("delete", "create"), ("create", "delete"), ("forget",), ("create", "forget"), ("forget", "create"),
)
_CATEGORIES = ("no_op", "create", "update", "delete", "read", "replace_destroy_first",
    "replace_create_first", "forget", "create_then_forget", "forget_then_create")
_TOP = frozenset({"format_version", "terraform_version", "variables", "planned_values",
    "resource_changes", "resource_drift", "relevant_attributes", "output_changes", "prior_state",
    "configuration", "timestamp", "applyable", "complete", "errored", "checks", "deferred_changes"})
_RESOURCE = frozenset({"address", "previous_address", "module_address", "mode", "type", "name",
    "index", "provider_name", "deposed", "change", "action_reason"})
_CHANGE = frozenset({"actions", "before", "after", "after_unknown", "before_sensitive", "after_sensitive",
    "replace_paths", "importing", "generated_config", "before_identity", "after_identity"})
_PROVIDER_FIELDS = frozenset({"name", "full_name", "alias", "module_address", "expressions", "version_constraint"})
_EXPRESSIONS = frozenset({"base_url", "access_token", "verify_ssl"})
_BOOL = {b"true": True, b"false": False}
Span = tuple[int, int]


class TerraformPlanProjectionError(ValueError):
    """A fixed error without source bytes, selectors or partial results."""


def _equals(content: bytearray, span: Span, literal: bytes) -> bool:
    with memoryview(content)[slice(*span)] as value:
        return value == literal


def _object(content: bytearray, span: Span, allowed: frozenset[str]) -> dict[str, Span]:
    result = metadata._object_spans(content, *span, allowed)
    # Unknown/duplicate structural fields cannot be hidden by projection. Keys
    # are matched as ASCII bytes against compiled names, never deserialized.
    if len(result) != _member_count(content, span):
        raise ValueError
    return result


def _object_values(content: bytearray, span: Span) -> list[Span]:
    """Read provider-config values without decoding arbitrary alias keys."""
    left, right = span
    if content[left] != 123 or content[right - 1] != 125:
        raise ValueError
    cursor = _skip_json_space(content, left + 1)
    result: list[Span] = []
    while cursor < right - 1:
        if len(result) >= 128:
            raise ValueError
        end = _json_value_end(content, cursor)
        separator = _skip_json_space(content, end)
        if content[separator] != 58:
            raise ValueError
        start = _skip_json_space(content, separator + 1)
        end = _json_value_end(content, start)
        result.append((start, end))
        cursor = _skip_json_space(content, end)
        if cursor < right - 1:
            cursor = _skip_json_space(content, cursor + 1)
    return result


def _reported_bool(content: bytearray, fields: dict[str, Span], key: str) -> bool | None:
    if key not in fields:
        return None
    for literal, value in _BOOL.items():
        if _equals(content, fields[key], literal):
            return value
    raise ValueError


def _action(content: bytearray, span: Span) -> int:
    parts = metadata._array(content, span, 2)
    for index, actions in enumerate(_ACTIONS):
        if len(parts) == len(actions) and all(
                _equals(content, part, b'"' + action.encode("ascii") + b'"')
                for part, action in zip(parts, actions, strict=True)):
            return index
    raise ValueError


def _resources(content: bytearray, span: Span) -> tuple[tuple[int, ...], int, int]:
    counts = [0] * len(_ACTIONS)
    material = updates = 0
    for item in metadata._array(content, span, _MAX_ENTRIES):
        fields = _object(content, item, _RESOURCE)
        if not {"address", "mode", "type", "name", "provider_name", "change"} <= fields.keys():
            raise ValueError
        if not _equals(content, fields["provider_name"], _PROVIDER):
            raise ValueError
        managed = _equals(content, fields["mode"], b'"managed"')
        folder = managed and _equals(content, fields["type"], _FOLDER)
        secret = managed and _equals(content, fields["type"], _SECRET)
        data = _equals(content, fields["mode"], b'"data"') and _equals(content, fields["type"], _DATA)
        if not (folder or secret or data):
            raise ValueError
        # Names and addresses are opaque locators, not output metadata.
        for key in ("address", "name"):
            if content[fields[key][0]] != 34:
                raise ValueError
        change = _object(content, fields["change"], _CHANGE)
        action = _action(content, change["actions"])
        if data and action not in (0, 4):
            raise ValueError
        counts[action] += 1
        material += int(secret or data)
        updates += int(folder and action in (2, 5, 6, 8, 9))
    return tuple(counts), material, updates


def _tls(content: bytearray, span: Span) -> tuple[int, int]:
    configuration = _object(content, span, frozenset({"provider_config", "root_module"}))
    # Root module expressions/provisioners remain opaque and explicitly unreviewed.
    if "root_module" not in configuration or content[configuration["root_module"][0]] != 123:
        raise ValueError
    providers = _object_values(content, configuration["provider_config"])
    if not providers:
        raise ValueError
    unproven = 0
    for item in providers:
        provider = _object(content, item, _PROVIDER_FIELDS)
        if not _equals(content, provider["full_name"], _PROVIDER):
            raise ValueError
        expressions = _object(content, provider["expressions"], _EXPRESSIONS)
        verified = False
        if "verify_ssl" in expressions:
            expression = _object(content, expressions["verify_ssl"], frozenset({"constant_value", "references"}))
            verified = set(expression) == {"constant_value"} and _equals(content, expression["constant_value"], b"true")
        unproven += int(not verified)
    return len(providers), unproven


@dataclass(frozen=True, slots=True, repr=False)
class TerraformPlanProjection(_OpaqueC3Object):
    """Counts describe supplied entries, never unique resources or device state."""
    action_counts: tuple[int, ...]
    drift_entries: int
    material_resource_entries: int
    folder_update_or_replace_entries: int
    provider_entries: int
    tls_unproven_provider_entries: int
    reported_applyable: bool | None
    reported_complete: bool | None
    reported_errored: bool | None
    deferred_changes_present: bool

    def summary(self) -> dict[str, object]:
        return dict(contract=CONTRACT, json_format="1.2", scope="action_metadata_only",
            action_entry_counts=dict(zip(_CATEGORIES, self.action_counts, strict=True)),
            resource_change_entries=sum(self.action_counts), resource_drift_entries=self.drift_entries,
            material_resource_entries=self.material_resource_entries,
            folder_acl_preservation_unqualified_entries=self.folder_update_or_replace_entries,
            provider_entries=self.provider_entries, tls_unproven_provider_entries=self.tls_unproven_provider_entries,
            reported_applyable=self.reported_applyable, reported_complete=self.reported_complete,
            reported_errored=self.reported_errored, deferred_changes_present=self.deferred_changes_present,
            configuration_and_provisioner_effects_reviewed=False, value_analysis_performed=False,
            source_provenance_verified=False, provider_binary_verified=False, permission_verified=False,
            review_complete=False, apply_authorized=False, execution_ready=False,
            fortipam_contacted=False, untrusted_input_present=True)


def project_private_terraform_plan(content: bytearray) -> TerraformPlanProjection:
    """Own and wipe one private JSON buffer; no file/CLI/MCP/provider invocation."""
    try:
        if type(content) is not bytearray or not 0 < len(content) <= _MAX_BYTES:
            raise ValueError
        left = _skip_json_space(content, 0)
        right = _json_value_end(content, left)
        if _skip_json_space(content, right) != len(content):
            raise ValueError
        metadata._validate_json(content, left, right, depth=0, budget=[100_000])
        fields = _object(content, (left, right), _TOP)
        if not _equals(content, fields["format_version"], b'"1.2"') or "configuration" not in fields:
            raise ValueError
        provider_entries, unproven = _tls(content, fields["configuration"])
        counts, material, updates = (0,) * len(_ACTIONS), 0, 0
        if "resource_changes" in fields:
            counts, material, updates = _resources(content, fields["resource_changes"])
        drift = 0
        if "resource_drift" in fields:
            drift_counts, drift_material, drift_updates = _resources(content, fields["resource_drift"])
            drift = sum(drift_counts)
            material += drift_material
            updates += drift_updates
        deferred = "deferred_changes" in fields and bool(metadata._array(content, fields["deferred_changes"], _MAX_ENTRIES))
        return TerraformPlanProjection(counts, drift, material, updates, provider_entries, unproven,
            _reported_bool(content, fields, "applyable"), _reported_bool(content, fields, "complete"),
            _reported_bool(content, fields, "errored"), deferred)
    except Exception:
        raise TerraformPlanProjectionError(_ERROR) from None
    finally:
        if type(content) is bytearray:
            _zeroize_mutable(content)


class PinnedTerraformPlanArtifact(_OpaqueC3Object):
    """Read one owner-only artifact selected by private trusted composition.

    A prebound hash is integrity data, not signed producer provenance or caller
    permission. Paths/hashes must never be MCP or planner inputs. The existing
    no-symlink reader binds owner, mode, link count and stable descriptor state.
    It has its own fixed file-size budget; this projection additionally caps2MiB.
    Failed attempts are consumed, files are retained and no process is launched.
    """

    def __init__(self, *, path: Path, expected_sha256: str) -> None:
        try:
            if not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts:
                raise ValueError
            if (type(expected_sha256) is not str or len(expected_sha256) != 64
                    or any(char not in "0123456789abcdef" for char in expected_sha256)):
                raise ValueError
            self._path, self._expected_sha256 = path, expected_sha256
            self._attempted = False
            self._lock = Lock()
        except Exception:
            raise TerraformPlanProjectionError(_ERROR) from None

    def read_once(self) -> TerraformPlanProjection:
        raw = bytearray()
        try:
            with self._lock:
                if self._attempted:
                    raise ValueError
                self._attempted = True
            raw, _ = _read_owned(self._path)
            if not 0 < len(raw) <= _MAX_BYTES or not hmac.compare_digest(
                    hashlib.sha256(raw).hexdigest(), self._expected_sha256):
                raise ValueError
            return project_private_terraform_plan(raw)
        except Exception:
            raise TerraformPlanProjectionError(_ERROR) from None
        finally:
            _zeroize_mutable(raw)
