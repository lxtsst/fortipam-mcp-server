"""Explicit fixed single-Secret Folder transition; default disabled and unregistered.

Creation evidence is obtained from the signed workflow, never supplied as a
receipt argument. One Owner session carries API and complete CLI qualification.
Only verified conversion in this instance can establish restoration ownership.
Every qualification verifies the fixed parent's complete creation-bound digest.
Restore sends an empty explicit Policy relation and requires the signed full
baseline readback, including any observed nonempty inherited Policy value.
An explicit complete-definition profile reads the qualified native Policy route
as opaque bytes and binds all 54 configuration fields at every inspection.
It does not qualify complete Secret preservation or an inactive Request scope.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import contextmanager
from hashlib import sha256
from http.cookies import SimpleCookie
import hmac
import json
import os
from pathlib import Path
import re
import stat
from threading import Lock
from typing import Any, Iterator, Literal
from urllib.parse import quote

import httpx
from v4_planning import canonical_digest

from .isolated_folder_creation_ownership import IsolatedFolderCreationSnapshot
from .isolated_folder_http_transport import IsolatedFolderHttpTransport, _FOLDER_FIELDS
from .isolated_folder_live_workflow import IsolatedFolderLiveWorkflow
from .isolated_folder_policy_transition_contract import (
    IsolatedFolderPolicyTransitionBinding, IsolatedFolderPolicyTransitionInspection,
    IsolatedFolderPolicyTransitionReadback, qualify_isolated_folder_policy_transition_inspection,
    validate_transition_readback,
)
from .local_user_reset_metadata_reader import _validate_value
from .policy_assignment_definition import PolicyAssignmentDefinition, consume_policy_assignment_definition
from .policy_assignment_fixture_guard import PolicyAssignmentFixtureGuard
from .owner_session_metadata import OwnerSessionMetadataTransport
from .secret_metadata_http_transport import (
    MAX_RESPONSE_BYTES, UTILITY_ID_PATH, SecretMetadataHttpTransportConfig, _folder_path, _json_value_end, _path_for_url, _record,
    _redact_json_field_values, _skip_json_space, _zeroize_mutable,
)
from .single_secret_folder_membership_candidate import _SessionProvider, _known_hosts
from .single_secret_folder_membership_source import SingleSecretFolderMembershipSource
from .single_secret_folder_membership_ssh_reader import SingleSecretFolderMembershipSshReader
from .target_api_dependency_reader import _private_http_logs
from .target_ssh_transport import TargetSshTransportConfig

_UNAVAILABLE = "The fixed isolated Folder Policy transition is unavailable."
_POLICY_FIELDS = "name|recording|block-clipboard|rdp-event-filter"
_ACK_FIELDS = frozenset({"version", "build", "http_method", "http_status", "status", "path", "name",
                         "vdom", "serial", "revision", "old_revision", "revision_changed", "mkey", "action", "error"})


class IsolatedFolderPolicyHttpTransportError(RuntimeError):
    """Stable categorical refusal without private identifiers or upstream data."""


class IsolatedFolderPolicyHttpTransport:
    def __init__(self, config: SecretMetadataHttpTransportConfig, *, binding: IsolatedFolderPolicyTransitionBinding,
                 creation_workflow: IsolatedFolderLiveWorkflow, creation_preview_ref: str, creator_digest: str,
                 parent_path: str, credentials: Callable[[], tuple[str, str]], ssh_host: str, ssh_port: int,
                 ssh_known_hosts_file: Path, claim_dir: Path, execution_enabled: bool = False,
                 client_factory: Callable[..., Any] = httpx.Client,
                 bind_complete_policy_definition: bool = False,
                 fixture_guard: PolicyAssignmentFixtureGuard | None = None) -> None:
        try:
            if (type(config) is not SecretMetadataHttpTransportConfig
                or type(binding) is not IsolatedFolderPolicyTransitionBinding
                or type(creation_workflow) is not IsolatedFolderLiveWorkflow
                or type(creator_digest) is not str or re.fullmatch(r"[0-9a-f]{64}", creator_digest) is None
                or type(creation_preview_ref) is not str
                or re.fullmatch(r"folder-preview-[A-Za-z0-9_-]{20,100}", creation_preview_ref) is None
                or not callable(credentials) or not callable(client_factory) or type(execution_enabled) is not bool
                or type(bind_complete_policy_definition) is not bool):
                raise ValueError
            if fixture_guard is not None and (type(fixture_guard) is not PolicyAssignmentFixtureGuard
                    or not bind_complete_policy_definition or fixture_guard._record._config != config):
                raise ValueError
            _known_hosts(ssh_known_hosts_file)
            _folder_path(parent_path + "/" + binding.creation_binding.name)
            TargetSshTransportConfig(ssh_host, ssh_port, binding.creation_binding.owner_name,
                                    "configuration-validation", ssh_known_hosts_file, config.timeout_seconds)
            self._config, self._binding = config, binding
            self._creation, self._creation_ref, self._creator = creation_workflow, creation_preview_ref, creator_digest
            self._parent_path, self._credentials, self._client_factory = parent_path, credentials, client_factory
            self._ssh_host, self._ssh_port, self._known_hosts = ssh_host, ssh_port, ssh_known_hosts_file
            self._claim_dir = claim_dir
            self._directory_identity = self._directory()
            self._enabled, self._lock = execution_enabled, Lock()
            self._complete_policy = bind_complete_policy_definition
            self._fixture_guard = fixture_guard
            self._converted: tuple[IsolatedFolderPolicyTransitionInspection, IsolatedFolderPolicyTransitionInspection] | None = None
            self._assign_attempted = self._restore_attempted = False
            self._claim_key = sha256((binding.membership_binding.expected_serial + ":"
                                     + str(binding.membership_binding.folder_id) + ":" + creation_preview_ref).encode()).hexdigest()
        except Exception:
            raise IsolatedFolderPolicyHttpTransportError(_UNAVAILABLE) from None

    def _directory(self) -> tuple[int, int]:
        info = self._claim_dir.lstat()
        if (not self._claim_dir.is_absolute() or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError
        return info.st_dev, info.st_ino

    def _claim_path(self, restore: bool) -> Path:
        return self._claim_dir / (self._claim_key + (".restore.claim" if restore else ".assign.claim"))

    def _available(self, restore: bool) -> None:
        if (self._directory() != self._directory_identity or os.path.lexists(self._claim_path(restore))
            or (self._restore_attempted if restore else self._assign_attempted)
            or restore and self._converted is None
            or not restore and (self._converted is not None or os.path.lexists(self._claim_path(True)))):
            raise ValueError

    @contextmanager
    def _session(self) -> Iterator[tuple[IsolatedFolderHttpTransport, SingleSecretFolderMembershipSshReader]]:
        pair = self._credentials()
        if (type(pair) is not tuple or len(pair) != 2 or pair[0] != self._binding.creation_binding.owner_name
            or type(pair[1]) is not str or not pair[1]):
            raise ValueError
        _known_hosts(self._known_hosts)
        b = self._binding
        reader = IsolatedFolderHttpTransport(
            self._config, parent_path=self._parent_path, child_name=b.creation_binding.name,
            owner_name=pair[0], owner_credentials=lambda: pair, owner_client_factory=self._client_factory,
        )
        if reader._owner_session is None:
            raise ValueError
        # One compiled parent lookup is added only to this private session.
        reader._owner_session._allowed_paths.add(UTILITY_ID_PATH + "/" + _path_for_url(self._parent_path))
        ssh = SingleSecretFolderMembershipSshReader(
            TargetSshTransportConfig(self._ssh_host, self._ssh_port, pair[0], pair[1], self._known_hosts,
                                     self._config.timeout_seconds), expected_serial=b.membership_binding.expected_serial,
        )
        with reader._child_reader(b.creation_binding.name):
            yield reader, ssh
        if reader._owner_session is None or not reader._owner_session.logout_verified:
            raise ValueError

    def _read(self, reader: IsolatedFolderHttpTransport,
              ssh: SingleSecretFolderMembershipSshReader, *,
              expected_complete_policy_digest: str | None = None,
              expected_effective_policy_digest: str | None = None) -> IsolatedFolderPolicyTransitionInspection:
        b = self._binding
        # Only this trusted signed getter may supply creation evidence.
        ownership = self._creation.read_creation_ownership(self._creation_ref, self._creator)
        if self._fixture_guard is not None:
            self._fixture_guard.check_binding(b, ownership)
        owner = reader._owner_session
        if owner is None:
            raise ValueError
        provider = _SessionProvider(owner, b.membership_binding, b.creation_binding.owner_name, ssh)
        provider.qualify()
        membership = SingleSecretFolderMembershipSource(b.membership_binding, provider).observe()
        if owner._lookup_id("folder", self._parent_path) != b.creation_binding.parent_folder_id:
            raise ValueError
        parent = reader._read_creation_payload(
            "/api/v2/cmdb/secret/folder/" + str(b.creation_binding.parent_folder_id)
            + "?format=" + quote(_FOLDER_FIELDS, safe=""), path="secret", table="folder",
        )
        parent_row = _record(parent)
        if (not isinstance(parent_row, Mapping)
            or not set(_FOLDER_FIELDS.split("|")) <= set(parent_row)
            or type(parent_row.get("id")) is not int
            or parent_row["id"] != b.creation_binding.parent_folder_id
            or parent["serial"] != ownership.serial
            or "mkey" in parent and (type(parent["mkey"]) not in {int, str}
                or parent["mkey"] not in {b.creation_binding.parent_folder_id,
                                         str(b.creation_binding.parent_folder_id)})
            or canonical_digest({k: parent_row[k] for k in _FOLDER_FIELDS.split("|")})
                != b.creation_binding.parent_digest):
            raise ValueError
        if owner._lookup_id("folder", self._parent_path + "/" + b.creation_binding.name) != ownership.native_folder_id:
            raise ValueError
        folder = reader._read_creation_payload(
            "/api/v2/cmdb/secret/folder/" + str(ownership.native_folder_id) + "?format=" + quote(_FOLDER_FIELDS, safe=""),
            path="secret", table="folder",
        )
        row = _record(folder)
        if (not isinstance(row, Mapping) or not set(_FOLDER_FIELDS.split("|")) <= set(row)
            or "mkey" in folder and (type(folder["mkey"]) not in {int, str}
                or folder["mkey"] not in {ownership.native_folder_id, str(ownership.native_folder_id)})):
            raise ValueError
        if folder["serial"] != ownership.serial:
            raise ValueError
        complete_digest = expected_complete_policy_digest
        definition: Mapping[str, object] | None
        if self._complete_policy and expected_complete_policy_digest is None:
            complete = self._read_complete_policy(owner)
            definition = dict(zip(_POLICY_FIELDS.split("|"), (b.policy_name, *complete.controls), strict=True))
            complete_digest = complete.configuration_digest
        else:
            policy = reader._read_creation_payload(
                "/api/v2/cmdb/secret/policy/" + quote(b.policy_name, safe="") + "?format=" + quote(_POLICY_FIELDS, safe=""),
                path="secret", table="policy",
            )
            definition = _record(policy)
            if (not isinstance(definition, Mapping) or not set(_POLICY_FIELDS.split("|")) <= set(definition)
                or folder["serial"] != policy["serial"]
                or "mkey" in policy and (type(policy["mkey"]) is not str or policy["mkey"] != b.policy_name)):
                raise ValueError
        phase: Literal["inherited", "explicit"] = "inherited" if row.get("inherit-policy") == "enable" else "explicit"
        retention = None
        effective = expected_effective_policy_digest
        if self._fixture_guard is not None:
            retention = self._fixture_guard.preservation_digest
            if expected_effective_policy_digest is None:
                relation = self._fixture_guard.read_relation(owner, phase=phase,
                    expected_folder={k: row[k] for k in _FOLDER_FIELDS.split("|")})
                effective = relation.policy_configuration_digest
            if phase == "explicit" and effective != complete_digest:
                raise ValueError
        return qualify_isolated_folder_policy_transition_inspection(
            b, ownership=ownership,
            snapshot=IsolatedFolderCreationSnapshot(str(folder["serial"]), {k: row[k] for k in _FOLDER_FIELDS.split("|")}),
            membership=membership, policy_definition={k: definition[k] for k in _POLICY_FIELDS.split("|")}, phase=phase,
            complete_policy_configuration_digest=complete_digest,
            complete_secret_preservation_digest=retention,
            effective_policy_configuration_digest=effective,
        )

    def _read_complete_policy(self, owner: OwnerSessionMetadataTransport) -> PolicyAssignmentDefinition:
        """Fixed native source; classify before decoding and clear on every exit."""
        raw = bytearray()
        try:
            if owner._client is None or owner._clock() >= owner._expires_at:
                raise ValueError
            route = ("/api/v2/cmdb/secret/policy/" + quote(self._binding.policy_name, safe="")
                     + "?with_meta=true&vdom=root")
            with _private_http_logs(), owner._client.stream("GET", route, headers={"Accept": "application/json"}) as response:
                if response.status_code != 200 or "json" not in response.headers.get("content-type", "").lower():
                    raise ValueError
                for chunk in response.iter_bytes():
                    if len(raw) + len(chunk) > MAX_RESPONSE_BYTES:
                        raise ValueError
                    raw.extend(chunk)
            return consume_policy_assignment_definition(raw, policy_name=self._binding.policy_name,
                serial_digest=sha256(self._binding.membership_binding.expected_serial.encode("ascii")).hexdigest())
        finally:
            _zeroize_mutable(raw)

    def _phase(self, current: IsolatedFolderPolicyTransitionInspection, restore: bool) -> None:
        if restore:
            if self._converted is None or current != self._converted[1]:
                raise ValueError
        elif current.phase != "inherited":
            raise ValueError

    def _inspect(self, restore: bool) -> IsolatedFolderPolicyTransitionInspection:
        with self._lock:
            try:
                self._available(restore)
                with self._session() as (reader, ssh):
                    current = self._read(reader, ssh)
                    self._phase(current, restore)
                return current
            except Exception:
                raise IsolatedFolderPolicyHttpTransportError(_UNAVAILABLE) from None

    def inspect_transition(self) -> IsolatedFolderPolicyTransitionInspection:
        return self._inspect(False)

    def inspect_owned_restore(self) -> IsolatedFolderPolicyTransitionInspection:
        return self._inspect(True)

    def transition_and_readback(self, expected_state_digest: str, *, expires_at: int,
                               clock: Callable[[], int]) -> IsolatedFolderPolicyTransitionReadback:
        return self._dispatch(expected_state_digest, expires_at, clock, False)

    def restore_and_readback(self, expected_state_digest: str, *, expires_at: int,
                            clock: Callable[[], int]) -> IsolatedFolderPolicyTransitionReadback:
        return self._dispatch(expected_state_digest, expires_at, clock, True)

    @staticmethod
    def _deadline(expires_at: int, clock: Callable[[], int]) -> None:
        now = clock()
        if type(expires_at) is not int or type(now) is not int or not 0 <= now < expires_at:
            raise ValueError

    def _reserve(self, restore: bool, state: IsolatedFolderPolicyTransitionInspection) -> None:
        self._available(restore)
        directory = os.open(self._claim_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(directory)
            if ((info.st_dev, info.st_ino) != self._directory_identity
                or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
                raise ValueError
            fd = os.open(self._claim_path(restore).name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
            if restore: self._restore_attempted = True
            else: self._assign_attempted = True
            with os.fdopen(fd, "w") as stream:
                json.dump({"contract": "isolated-folder-policy-claim-v1", "operation": "restore" if restore else "assign",
                           "state_digest": state.state_digest}, stream)
                stream.flush(); os.fsync(stream.fileno())
            os.fsync(directory)
        finally:
            os.close(directory)

    def _put(self, owner: OwnerSessionMetadataTransport, body: bytearray, *, expires_at: int,
             clock: Callable[[], int]) -> None:
        path = "/api/v2/cmdb/secret/folder/" + str(self._binding.membership_binding.folder_id)
        if owner._client is None or owner._clock() >= owner._expires_at:
            raise ValueError
        jar: SimpleCookie = SimpleCookie()
        jar.load(owner._client.build_request("GET", path).headers.get("cookie", ""))
        token = jar.get("ccsrftoken")
        if token is None or not token.value or any(not 33 <= ord(c) <= 126 for c in token.value):
            raise ValueError
        raw = bytearray()
        try:
            self._deadline(expires_at, clock)
            with owner._client.stream("PUT", path, content=bytes(body),
                    headers={"Accept": "application/json", "Content-Type": "application/json", "X-CSRFTOKEN": token.value}) as response:
                if response.status_code != 200 or "json" not in response.headers.get("content-type", "").lower():
                    raise ValueError
                for chunk in response.iter_bytes():
                    if len(raw) + len(chunk) > MAX_RESPONSE_BYTES:
                        raise ValueError
                    raw.extend(chunk)
            _redact_json_field_values(raw)
            left = _skip_json_space(raw, 0); right = _json_value_end(raw, left)
            if _skip_json_space(raw, right) != len(raw): raise ValueError
            _validate_value(raw, left, right, depth=0)
            ack = json.loads(raw)
            expected = {"version": "v7.0.0", "build": 29, "http_method": "PUT", "http_status": 200,
                        "serial": self._binding.membership_binding.expected_serial,
                        "path": "secret", "name": "folder", "vdom": "root"}
            if (type(ack) is not dict or not set(ack) <= _ACK_FIELDS
                or any(type(ack.get(k)) is not type(v) or ack.get(k) != v for k, v in expected.items())
                or ack.get("status") not in {"OK", "success"}
                or "error" in ack and (type(ack["error"]) is not int or ack["error"] != 0)
                or "action" in ack and (type(ack["action"]) is not str or ack["action"] != "")
                or "mkey" in ack and (type(ack["mkey"]) not in {int, str}
                    or ack["mkey"] not in {self._binding.membership_binding.folder_id, str(self._binding.membership_binding.folder_id)})):
                raise ValueError
        finally:
            _zeroize_mutable(raw)

    def _dispatch(self, digest: str, expires_at: int, clock: Callable[[], int], restore: bool) -> IsolatedFolderPolicyTransitionReadback:
        with self._lock:
            body = bytearray()
            try:
                if not self._enabled or type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                    raise ValueError
                self._available(restore)
                self._deadline(expires_at, clock)
                with self._session() as (reader, ssh):
                    before = self._read(reader, ssh)
                    self._phase(before, restore)
                    if not hmac.compare_digest(before.state_digest, digest): raise ValueError
                    if self._fixture_guard is not None:
                        self._fixture_guard.read_preservation("policy-restore-current" if restore else "policy-assign-current")
                    body.extend(before.native_body_json.encode("ascii"))
                    final = self._read(reader, ssh)
                    if final != before: raise ValueError
                    if self._fixture_guard is not None:
                        self._fixture_guard.read_preservation("policy-restore-dispatch" if restore else "policy-assign-dispatch")
                    self._deadline(expires_at, clock)
                    self._reserve(restore, before)
                    owner = reader._owner_session
                    if owner is None: raise ValueError
                    self._put(owner, body, expires_at=expires_at, clock=clock)
                    # Preserve the original ACK/full-Folder/logout recovery basis
                    # before the additional complete-definition postcondition.
                    effective_after = (self._converted[0].effective_policy_configuration_digest
                                       if restore and self._converted is not None else before.complete_policy_configuration_digest)
                    after = (self._read(reader, ssh, expected_complete_policy_digest=before.complete_policy_configuration_digest,
                                       expected_effective_policy_digest=effective_after if self._fixture_guard is not None else None)
                             if self._complete_policy else self._read(reader, ssh))
                # The session context verifies logout before any successful readback is qualified.
                result = IsolatedFolderPolicyTransitionReadback(True, True, after)
                verified = validate_transition_readback(result, before, "restore" if restore else "assign")
                if restore and (self._converted is None or verified != self._converted[0]): raise ValueError
                # Logout has succeeded before restoration ownership is created.
                if not restore: self._converted = before, verified
                if self._complete_policy:
                    with self._session() as (reader, ssh):
                        observed = self._read(reader, ssh)
                        if observed != verified:
                            raise ValueError
                    if self._fixture_guard is not None:
                        self._fixture_guard.read_preservation("policy-restored" if restore else "policy-assigned")
                    result = IsolatedFolderPolicyTransitionReadback(True, True, observed)
                return result
            except Exception:
                raise IsolatedFolderPolicyHttpTransportError(_UNAVAILABLE) from None
            finally:
                _zeroize_mutable(body)
