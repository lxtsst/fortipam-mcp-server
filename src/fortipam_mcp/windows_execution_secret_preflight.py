"""Private fresh owned dependencies for one associated Windows credential.

This joins original signed Folder/Target creation records to fixed native reads.
It does not prove Secret absence, grant creation/removal, acquire material, or
register a Tool. A later projection must separately qualify the Secret namespace.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import math
from pathlib import Path
from threading import RLock
import time
from typing import cast

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from . import secret_bulk_import_metadata as m
from . import target_preservation_contract as c
from .isolated_folder_creation_ownership import validate_creation_snapshot, ownership_payload
from .isolated_folder_http_transport import IsolatedFolderHttpTransport
from .isolated_folder_live_workflow import IsolatedFolderLiveWorkflow
from .secret_metadata_http_transport import _zeroize_mutable
from .target_api_dependency_reader import (
    TargetApiDependencyReader, TargetApiDependencyObservation, _TEMPLATES, _private_http_logs,
)
from .target_creation_http_transport import TargetCreationHttpTransport
from .windows_execution_secret_contract import WindowsExecutionSecretBinding
from .windows_execution_secret_ack import WindowsExecutionSecretAckCustody

_ERROR = "The private Windows execution Secret owned dependencies are unavailable."
_CONTRACT = "fortipam-700-build29-windows-execution-owned-dependencies-v1"


class WindowsExecutionPreflightError(RuntimeError):
    """Categorical refusal without native objects, selectors or partial proof."""


@dataclass(frozen=True, slots=True, repr=False)
class WindowsExecutionOwnedDependencyObservation(_OpaqueC3Object):
    binding_digest: str
    source_context_digest: str
    target_creation_digest: str
    folder_creation_digest: str
    dependency_digest: str
    observed_at: float
    expires_at: float


def _read_windows_template(api: TargetApiDependencyReader, observation: TargetApiDependencyObservation,
        before_send: Callable[[], None]) -> None:
    """Qualify exact Windows field kinds against the same dependency row."""
    from .secret_bulk_import_dependencies import project_importable_templates
    from .target_lifecycle_dependencies import _spans
    raw = bytearray()
    try:
        before_send()
        api.check_current(observation)
        with _private_http_logs(), api._factory(verify=api._context,
                timeout=min(10.0, api._config.timeout_seconds), follow_redirects=False, trust_env=False) as client:
            try:
                client.cookies.clear()
                raw = api._receive(client, _TEMPLATES, observation.expires_at, template=True)
            finally:
                client.cookies.clear()
        if not client.is_closed:
            raise ValueError
        fields = _spans(raw)
        selected = []
        for row in m._array(raw, fields["results"], m._MAX_ROWS):
            names = m._object_spans(raw, *row, frozenset({"name"}))
            if m._scalar(raw, names["name"]) == "Windows Machine":
                selected.append(c._token_digest(raw, row))
        if selected != [dict(observation.dependencies.template_digests)["Windows Machine"]]:
            raise ValueError
        view = m.project_native_import_metadata(raw, table="template", expected_serial_digest=api._serial)
        records = tuple(row for row in view.rows if type(row) is m.ImportMetadataTemplate)
        templates = [value for value in project_importable_templates(records) if value.name == "Windows Machine"]
        if len(templates) != 1 or {field.name:(field.kind, field.mandatory) for field in templates[0].fields} != {
                "Host":("target-address", True), "Username":("username", False), "Password":("password", False)}:
            raise ValueError
        before_send()
        api.check_current(observation)
    finally:
        _zeroize_mutable(raw)


def _target_profile(raw: bytearray, profile: WindowsExecutionSecretBinding, owner: str,
        *, original_secret_id: int | None = None) -> c.TargetState:
    """Decode selected nonmaterial guards/ACL only; fingerprint the full row."""
    # Use the existing strict JSON framing; unknown Target fields remain subject
    # to the complete consuming state contract below.
    from .target_lifecycle_dependencies import _spans, _one
    envelope = _spans(raw)
    row = _one(raw, envelope["results"])
    fields = m._object_spans(raw, *row, c.TARGET_STATE_FIELDS | c._METADATA)
    wanted: dict[str, object] = {
        "name": profile.target_name, "template": "Windows Machine", "address": profile.target_address,
        "class": "Other", "access": "customized", "domain": "", "url": "",
        "winrm-https": "disable", "dynamic-gateway": "disable", "gateway": "", "gateway-cn": "",
        "user-base": "", "user-naming-attribute": "sAMAccountName", "kdc-address": "",
        "sql-server-log-status": "disable", "web-proxy-status": "disable",
        "q_ref": 0 if original_secret_id is None else 1, "q_static": False,
    }
    for name, expected in wanted.items():
        actual = m._scalar(raw, fields[name])
        if type(actual) is not type(expected) or actual != expected:
            raise ValueError
    # Build29 Target detail may omit this metadata. Omission proves nothing
    # about the association; only Secret target-info is a qualified read locus.
    # This prerequisite observation grants no privilege-absence authority.
    if "priv_acct" in fields:
        privilege = m._scalar(raw, fields["priv_acct"])
        if type(privilege) is not int or privilege != 0:
            raise ValueError
    for name in ("group-permission", "service-addrs", "hostkey"):
        if m._array(raw, fields[name], 1):
            raise ValueError
    entries = m._array(raw, fields["user-permission"], 2)
    if len(entries) != 1:
        raise ValueError
    relation = m._object_spans(raw, *entries[0], frozenset({"id", "user-name", "permission", "q_origin_key"}))
    identifier = m._scalar(raw, relation["id"])
    if type(identifier) is not int or not 0 < identifier <= 2147483647 or m._scalar(raw, relation["permission"]) != "owner":
        raise ValueError
    if "q_origin_key" in relation and m._scalar(raw, relation["q_origin_key"]) != identifier:
        raise ValueError
    users = m._array(raw, relation["user-name"], 2)
    if len(users) != 1:
        raise ValueError
    user = m._object_spans(raw, *users[0], frozenset({"name", "q_origin_key"}))
    if m._scalar(raw, user["name"]) != owner or "q_origin_key" in user and m._scalar(raw, user["q_origin_key"]) != owner:
        raise ValueError
    return c.capture_target_state(raw, expected_name=profile.target_name,
        expected_serial_digest=profile.serial_digest)


class WindowsExecutionOwnedDependencies(_OpaqueC3Object):
    """One bounded read of original owned prerequisites, never object adoption."""

    def __init__(self, profile: WindowsExecutionSecretBinding, *,
            creator: TargetCreationHttpTransport, folder_workflow: IsolatedFolderLiveWorkflow,
            folder_preview_ref: str, requester_digest: str, api: TargetApiDependencyReader,
            created_secret: WindowsExecutionSecretAckCustody | None = None,
            clock: Callable[[], float] = time.monotonic) -> None:
        try:
            if (type(profile) is not WindowsExecutionSecretBinding
                    or type(creator) is not TargetCreationHttpTransport
                    or type(folder_workflow) is not IsolatedFolderLiveWorkflow
                    or type(api) is not TargetApiDependencyReader or not callable(clock)
                    or type(folder_workflow._isolated_transport) is not IsolatedFolderHttpTransport):
                raise ValueError
            require_digest(requester_digest, "windows_preflight_requester")
            self._profile, self._creator, self._workflow, self._api = profile, creator, folder_workflow, api
            self._profile_digest = profile.parameters_digest
            self._folders = folder_workflow._isolated_transport
            self._preview_ref, self._requester = folder_preview_ref, requester_digest
            self._target = creator.load_creation_evidence()
            self._folder = folder_workflow.read_creation_ownership(folder_preview_ref, requester_digest)
            self._source, self._target_namespace = api._source, creator._namespace
            self._folder_binding = folder_workflow._binding
            self._parent_path = self._folders._parent_path
            self._folder_key = hashlib.sha256(folder_workflow._key).hexdigest()
            self._workflow_database = folder_workflow._database
            self._created_secret = created_secret
            self._original_secret = None
            if created_secret is not None:
                if (type(created_secret) is not WindowsExecutionSecretAckCustody
                        or created_secret._profile != profile or created_secret._config is not creator._config
                        or created_secret._plan.requester_digest != requester_digest
                        or dict(self._target.created.metadata_digests).get('q_ref') != c._digest(0)):
                    raise ValueError
                original = created_secret.inspect_original_creation()
                if original.native_uuid is None or original.state_digest is None:
                    raise ValueError
                self._original_secret = (original.native_secret_id, original.native_uuid,
                    original.state_digest, original.custody_digest)
            if (not self._folder_binding.empty_inactive_policy
                    or self._folder.native_folder_id != profile.folder_id
                    or hashlib.sha256(self._folder.serial.encode()).hexdigest() != profile.serial_digest
                    or self._target.created.name != profile.target_name
                    or self._target.created.serial_digest != profile.serial_digest
                    or self._target.created.coordinates != c.TargetCoordinates("Windows Machine", profile.target_address, "", "")):
                raise ValueError
            self._folder_digest = hashlib.sha256(ownership_payload(self._folder).encode()).hexdigest()
            self._binding = canonical_digest({"contract": _CONTRACT, "profile": profile.parameters_digest,
                "source": self._source, "target_namespace": self._target_namespace,
                "target_creation": self._target.evidence_digest, "folder_creation": self._folder_digest,
                "requester": requester_digest, "folder_key": self._folder_key,
                "folder_database": str(self._workflow_database), "parent_path": self._parent_path,
                "creation": "before-original-create" if self._original_secret is None else self._original_secret[3]})
            self._clock, self._last = clock, -1.0
            self._deadline: float | None = None
            self._used = self._failed = self._closed = False
            self._dependency: TargetApiDependencyObservation | None = None
            self._current: WindowsExecutionOwnedDependencyObservation | None = None
            self._lock = RLock()
            self._local()
        except Exception:
            raise WindowsExecutionPreflightError(_ERROR) from None

    def _now(self) -> float:
        value = self._clock()
        if (self._failed or self._closed or type(value) not in (int, float)
                or not math.isfinite(value) or value < self._last or value < 0
                or self._deadline is not None and value >= self._deadline):
            self._failed = True
            raise ValueError
        self._last = float(value)
        return self._last

    def _source_digest(self) -> str:
        config = self._creator._config
        config.__post_init__()
        if config.ca_file is None:
            raise ValueError
        with Path(config.ca_file).open("rb") as stream:
            ca = stream.read(1048577)
        if not 0 < len(ca) <= 1048576:
            raise ValueError
        return c._api_source_context(config.base_url, hashlib.sha256(config.bearer_token.encode()).hexdigest(),
            hashlib.sha256(ca).hexdigest(), self._profile.serial_digest)

    def _local(self) -> None:
        if (self._profile.parameters_digest != self._profile_digest
                or self._source_digest() != self._source or self._creator._source_context_digest != self._source
                or self._api._config is not self._creator._config or self._api._serial != self._profile.serial_digest
                or self._api._source != self._source or self._creator._namespace != self._target_namespace
                or self._workflow._isolated_transport is not self._folders
                or cast(object, self._workflow._transport) is not self._folders
                or self._folders._metadata._config is not self._creator._config
                or self._folders._owner_session is None
                or self._folders._owner_session._config is not self._creator._config
                or self._folders._parent_path != self._parent_path
                or self._folders._child_name != self._folder_binding.name
                or self._folders._owner_name != self._folder_binding.owner_name
                or self._workflow._binding != self._folder_binding
                or self._workflow._database != self._workflow_database
                or hashlib.sha256(self._workflow._key).hexdigest() != self._folder_key
                or self._creator.load_creation_evidence() != self._target
                or self._workflow.read_creation_ownership(self._preview_ref, self._requester) != self._folder):
            raise ValueError
        if self._created_secret is not None:
            original = self._created_secret.inspect_original_creation()
            if (original.native_secret_id, original.native_uuid, original.state_digest, original.custody_digest) != self._original_secret:
                raise ValueError

    def _guard(self) -> None:
        self._now()
        self._local()
        if self._dependency is not None:
            self._api.check_transport_source(self._dependency, self._creator)
        self._now()

    def read_once(self) -> WindowsExecutionOwnedDependencyObservation:
        raw = bytearray()
        try:
            with self._lock:
                if self._used:
                    raise ValueError
                self._used = True
                started = self._now()
                self._deadline = started + min(30.0, self._creator._config.timeout_seconds)
                self._guard()
                self._dependency = self._api.observe((self._target.created.coordinates,))
                self._guard()
                _read_windows_template(self._api, self._dependency, self._guard)
                raw = self._creator._exchange("GET", deadline=self._creator._now() + 30, guard=self._guard)
                current = _target_profile(raw, self._profile, self._folder_binding.owner_name,
                    original_secret_id=None if self._original_secret is None else self._original_secret[0])
                if self._original_secret is None:
                    if current != self._target.created:
                        raise ValueError
                else:
                    expected_metadata = {**dict(self._target.created.metadata_digests), "q_ref":c._digest(1)}
                    if (current.field_digests != self._target.created.field_digests
                            or dict(current.metadata_digests) != expected_metadata):
                        raise ValueError
                self._guard()
                if self._folders.read_parent_digest(self._folder_binding.parent_folder_id) != self._folder_binding.parent_digest:
                    raise ValueError
                self._guard()
                snapshot = self._folders.read_created_folder_snapshot(self._profile.folder_id,
                    name=self._folder_binding.name, parent_folder_id=self._folder_binding.parent_folder_id,
                    owner_name=self._folder_binding.owner_name)
                if validate_creation_snapshot(snapshot, expected_serial=self._folder.serial,
                        folder_id=self._profile.folder_id, binding=self._folder_binding) != self._folder.baseline_json:
                    raise ValueError
                self._guard()
                result = WindowsExecutionOwnedDependencyObservation(self._binding, self._source,
                    self._target.evidence_digest, self._folder_digest,
                    self._dependency.dependencies.dependency_digest, started, self._deadline)
                self._current = result
                return result
        except BaseException as error:
            self._failed, self._current = True, None
            if isinstance(error, Exception):
                raise WindowsExecutionPreflightError(_ERROR) from None
            raise
        finally:
            _zeroize_mutable(raw)

    def check_current(self, observation: WindowsExecutionOwnedDependencyObservation) -> None:
        try:
            with self._lock:
                if observation is not self._current or self._dependency is None:
                    raise ValueError
                self._guard()
        except Exception:
            self._failed, self._current = True, None
            raise WindowsExecutionPreflightError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._closed, self._current = True, None
