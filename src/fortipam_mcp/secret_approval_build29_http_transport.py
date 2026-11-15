"""Default-off fixed build-29 approval candidate; no registered Tool.

The Owner detail envelope is qualified separately from the four-field schema.
Only minimized redacted projections remain private; inspection exposes flags
and a digest of redacted non-approval metadata. That digest does not prove
preservation of Secret material or of full native configuration.
Redacted nulls, including TOTP shared-key, prove neither empty values nor
preserved material; all metadata digests cover only redacted configuration.
Mutation additionally requires private Profile/native witnesses, durable
claims, and an independently qualified ACK verifier. No PUT ACK shape or live
mutation/preservation/restore acceptance is inferred here.
"""

from collections.abc import Callable, Iterator, Mapping
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import hmac
from http.cookies import SimpleCookie
from ipaddress import IPv4Address
import json
import math
import os
from pathlib import Path
import re
import stat
from threading import Lock
from urllib.parse import urlsplit

from .owner_session_metadata import OwnerSessionMetadataTransport
from .target_contract import DEFAULT_TEMPLATE
from .secret_approval_build29_contract import (
    APPROVAL_FIELDS, CONTRACT, compile_secret_approval_build29_enable_body,
    compile_secret_approval_build29_restore_body, qualify_secret_approval_build29_schema,
)
from .secret_metadata_http_transport import (
    COLLECTION_PATH, MAX_RESPONSE_BYTES, UTILITY_ID_PATH,
    _folder_path, _json_string_end, _json_value_end, _path_for_url,
    _secret_name,
    _skip_json_space, _zeroize_mutable,
)


_UNAVAILABLE = "The fixed build-29 Secret approval read is unavailable."
_IDENTITY = frozenset({"id", "name", "folder"})
_NATIVE_ENVELOPE = {
    "version": "v7.0.0", "build": 29, "http_method": "GET", "http_status": 200,
    "status": "OK", "path": "secret", "name": "database", "vdom": "root",
}
_FIELD_ORDER = ("need-approval", "need-approval-job", "bypass-approval", "approval-profile")
WEB_FIELDS_CONTRACT = "fortipam-700-build29-web-account-retained-fields-v1"


class SecretApprovalBuild29HttpTransportError(RuntimeError):
    """Non-disclosing rejection of an unavailable read producer."""

    def __init__(self, message: str, *, stage: str = "unavailable") -> None:
        super().__init__(message)
        self.stage = stage if stage in {
            "unavailable", "preflight", "owner_login", "current_read", "current_drift",
            "body_compile", "csrf_check", "final_read", "final_drift", "claim_reserve",
            "dispatch_deadline", "put_dispatch", "ack_check", "readback", "readback_verify",
            "logout", "restore_readback",
        } else "unavailable"


@dataclass(frozen=True, slots=True)
class SecretApprovalBuild29Inspection:
    """No selectors, native response, Profile names, or material are exposed."""

    interactive_approval_required: bool
    job_approval_required: bool
    owner_bypass_allowed: bool
    approval_profile_attached: bool
    redacted_metadata_digest: str
    logout_verified: bool


@dataclass(frozen=True, slots=True, repr=False)
class SecretApprovalBuild29WebFieldsBinding:
    """Fixed targetless Web routing and fresh private writable Username span.

    The provider transfers one fresh mutable backing buffer per call. The
    transport erases the entire backing buffer and releases the view, including
    on rejection, using the existing private material lifecycle.
    """

    web_url: str
    username_span_provider: Callable[[], memoryview]

    def __post_init__(self) -> None:
        try:
            if type(self.web_url) is not str or not callable(self.username_span_provider):
                raise ValueError
            parsed = urlsplit(self.web_url)
            if (parsed.scheme not in {"http", "https"} or parsed.hostname is None
                    or parsed.username is not None or parsed.password is not None or parsed.fragment
                    or len(self.web_url) > 2048
                    or any(ord(char) < 32 or ord(char) == 127 for char in self.web_url)):
                raise ValueError
        except Exception:
            raise SecretApprovalBuild29HttpTransportError(_UNAVAILABLE) from None


@dataclass(frozen=True, slots=True, repr=False)
class SecretApprovalBuild29LinuxFieldsBinding:
    """Fixed Linux routing and transferred mutable Username material."""

    target_name: str
    target_ipv4_address: str
    username_span_provider: Callable[[], memoryview]

    def __post_init__(self) -> None:
        try:
            _linux_target_name(self.target_name)
            if (type(self.target_ipv4_address) is not str
                    or str(IPv4Address(self.target_ipv4_address)) != self.target_ipv4_address
                    or not callable(self.username_span_provider)):
                raise ValueError
        except Exception:
            raise SecretApprovalBuild29HttpTransportError(_UNAVAILABLE) from None


def _linux_target_name(value: str) -> str:
    if (type(value) is not str or not 0 < len(value.encode("utf-8")) <= 79
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ValueError
    return value


@dataclass(frozen=True, slots=True, repr=False)
class SecretApprovalBuild29MutationBinding:
    """Trusted private dependencies; a name alone never proves a Profile.

    Profile witness must freshly qualify the separately observed Profile
    envelope/semantics and return its bound configuration digest. Native
    witness receives only the four approval values, verifies their exact
    association with its sealed Secret, and digests all other native/material
    configuration. ACK verifier receives bounded, material-redacted raw bytes;
    its actual source qualification remains an external prerequisite.
    """

    schema: object
    approval_profile_name: str
    profile_digest: Callable[[], str]
    native_preservation_digest: Callable[[tuple[str, str, str, str]], str]
    claim_directory: Path
    ack_verifier: Callable[[int, bytearray], bool] | None = None
    web_fields: SecretApprovalBuild29WebFieldsBinding | None = None
    linux_fields: SecretApprovalBuild29LinuxFieldsBinding | None = None
    expected_folder_acl_digest: str | None = None


@dataclass(frozen=True, slots=True, repr=False)
class SecretApprovalBuild29PrivateState:
    """Only trusted callers retain these values; never an MCP response."""

    approval_values: tuple[str, str, str, str]
    metadata_digest: str
    profile_digest: str
    native_digest: str
    state_digest: str


@dataclass(frozen=True, slots=True)
class SecretApprovalBuild29Readback:
    """Value-free success categories; no private digests are serialized."""

    acknowledged: bool
    approval_verified: bool
    preservation_verified: bool
    logout_verified: bool

    @property
    def verified(self) -> bool:
        return all((self.acknowledged, self.approval_verified,
                    self.preservation_verified, self.logout_verified))


class FortiPamSecretApprovalBuild29HttpTransport:
    """Inspect one sealed existing Secret using one fixed Owner GET path."""

    def __init__(
        self, owner: OwnerSessionMetadataTransport, *, expected_secret_id: int,
        expected_secret_name: str, expected_folder_id: int, folder_path: str,
        expected_serial: str, mutation: SecretApprovalBuild29MutationBinding | None = None,
        execution_enabled: bool = False, linux_target_name: str | None = None,
    ) -> None:
        try:
            if not isinstance(owner, OwnerSessionMetadataTransport) or owner._client is not None:
                raise ValueError
            for number in (expected_secret_id, expected_folder_id):
                if type(number) is not int or not 0 < number <= 2_147_483_647:
                    raise ValueError
            name = _secret_name(expected_secret_name, bound_name=owner._bound_secret_name)
            folder = _folder_path(folder_path)
            if (name != owner._bound_secret_name
                    or owner._folder_lookup_path != UTILITY_ID_PATH + "/" + _path_for_url(folder)
                    or owner._secret_lookup_path != UTILITY_ID_PATH + "/" + _path_for_url(folder + "/" + name)
                    or type(expected_serial) is not str or not 1 <= len(expected_serial) <= 64
                    or any(not char.isascii() or not char.isalnum() for char in expected_serial)):
                raise ValueError
            self._linux_target_name = None if linux_target_name is None else _linux_target_name(linux_target_name)
            self._owner = owner
            self._folder_path = folder
            self._serial = expected_serial
            self._identity = {"id": expected_secret_id, "name": name, "folder": expected_folder_id}
            self._path = f"{COLLECTION_PATH}/{expected_secret_id}"
            if type(execution_enabled) is not bool:
                raise ValueError
            self._mutation = mutation
            self._execution_enabled = execution_enabled
            self._lock = Lock()
            self._closed = False
            self._attempted = {False: False, True: False}
            self._ownership: tuple[SecretApprovalBuild29PrivateState, SecretApprovalBuild29PrivateState] | None = None
            self._schema: object = None
            self._directory_identity: tuple[int, int] | None = None
            self._claim_key = _digest({"contract": CONTRACT, "serial": expected_serial, "id": expected_secret_id})
            if mutation is not None:
                if (type(mutation) is not SecretApprovalBuild29MutationBinding
                        or not callable(mutation.profile_digest)
                        or not callable(mutation.native_preservation_digest)
                        or mutation.ack_verifier is not None and not callable(mutation.ack_verifier)
                        or mutation.web_fields is not None and type(mutation.web_fields) is not SecretApprovalBuild29WebFieldsBinding
                        or mutation.linux_fields is not None and type(mutation.linux_fields) is not SecretApprovalBuild29LinuxFieldsBinding
                        or mutation.web_fields is not None and mutation.linux_fields is not None
                        or mutation.linux_fields is not None and mutation.linux_fields.target_name != self._linux_target_name
                        or self._linux_target_name is not None and mutation.web_fields is not None):
                    raise ValueError
                if self._linux_target_name is not None:
                    if (type(mutation.expected_folder_acl_digest) is not str
                            or re.fullmatch(r"[0-9a-f]{64}", mutation.expected_folder_acl_digest) is None):
                        raise ValueError
                elif mutation.expected_folder_acl_digest is not None:
                    raise ValueError
                self._schema = deepcopy(mutation.schema)
                qualify_secret_approval_build29_schema(self._schema)
                compile_secret_approval_build29_enable_body(
                    self._projection(("disable", "disable", "disable", "")),
                    schema=self._schema, identity=self._identity,
                    approval_profile_name=mutation.approval_profile_name,
                )
                self._directory_identity = self._check_claim_directory()
            elif execution_enabled:
                raise ValueError
        except Exception:
            raise SecretApprovalBuild29HttpTransportError(_UNAVAILABLE) from None

    def inspect(self) -> SecretApprovalBuild29Inspection:
        projection, digest = self._read_private_projection()
        row = projection["results"]
        assert isinstance(row, Mapping)
        return SecretApprovalBuild29Inspection(
            interactive_approval_required=row["need-approval"] == "enable",
            job_approval_required=row["need-approval-job"] == "enable",
            owner_bypass_allowed=row["bypass-approval"] == "enable",
            approval_profile_attached=row["approval-profile"] != "",
            redacted_metadata_digest=digest,
            logout_verified=True,
        )

    def _read_private_projection(self) -> tuple[dict[str, object], str]:
        """Private normalization seam for a future separately authorized adapter."""
        try:
            with self._owner.authenticated():
                projection, digest = self._read()
            if not self._owner.logout_verified:
                raise ValueError
            return projection, digest
        except Exception:
            raise SecretApprovalBuild29HttpTransportError(_UNAVAILABLE) from None

    def inspect_transition(self) -> SecretApprovalBuild29PrivateState:
        """Read private expected state without granting execution or restoration."""
        with self._lock:
            try:
                if self._closed or self._mutation is None:
                    raise ValueError
                with self._owner.authenticated():
                    current = self._read_transition()
                if not self._owner.logout_verified:
                    raise ValueError
                return current
            except Exception:
                raise SecretApprovalBuild29HttpTransportError(_UNAVAILABLE) from None

    def enable_and_readback(
        self, expected: SecretApprovalBuild29PrivateState, *,
        expires_at: float, clock: Callable[[], float],
    ) -> SecretApprovalBuild29Readback:
        return self._dispatch(expected, expires_at=expires_at, clock=clock, restore=False)

    def restore_and_readback(
        self, expected: SecretApprovalBuild29PrivateState, *,
        expires_at: float, clock: Callable[[], float],
    ) -> SecretApprovalBuild29Readback:
        return self._dispatch(expected, expires_at=expires_at, clock=clock, restore=True)

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._ownership = None

    def _read_transition(self) -> SecretApprovalBuild29PrivateState:
        mutation = self._mutation
        if mutation is None:
            raise ValueError
        projection, metadata = self._read()
        row = projection["results"]
        assert isinstance(row, Mapping)
        values = tuple(row[key] for key in _FIELD_ORDER)
        if len(values) != 4 or not all(type(value) is str for value in values):
            raise ValueError
        approval: tuple[str, str, str, str] = (values[0], values[1], values[2], values[3])
        profile = mutation.profile_digest()
        native = mutation.native_preservation_digest(approval)
        return self._transition_state(approval, metadata, profile, native)

    def _transition_state(
        self, approval: tuple[str, str, str, str], metadata: str, profile: str, native: str,
    ) -> SecretApprovalBuild29PrivateState:
        """Construct only the sealed canonical state; perform no product read."""
        mutation = self._mutation
        if mutation is None:
            raise ValueError
        if not _hash(metadata) or not _hash(profile) or not _hash(native):
            raise ValueError
        digest = _digest({"contract": CONTRACT, "binding": {**self._identity, "serial": self._serial,
                                     "profile": mutation.approval_profile_name},
                          "approval": approval, "metadata": metadata, "profile": profile, "native": native})
        return SecretApprovalBuild29PrivateState(approval, metadata, profile, native, digest)

    def _projection(self, values: tuple[str, str, str, str]) -> dict[str, object]:
        return {"version": "v7.0.0", "build": 29,
                "results": {**self._identity, **dict(zip(_FIELD_ORDER, values))}}

    def _dispatch(
        self, expected: SecretApprovalBuild29PrivateState, *, expires_at: float,
        clock: Callable[[], float], restore: bool,
    ) -> SecretApprovalBuild29Readback:
        with self._lock:
            body, ack, fields = bytearray(), bytearray(), bytearray()
            stage = "preflight"
            try:
                self._available(restore)
                _deadline(expires_at, clock)
                if type(expected) is not SecretApprovalBuild29PrivateState:
                    raise ValueError
                mutation = self._mutation
                assert mutation is not None and mutation.ack_verifier is not None
                if restore and (self._ownership is None or expected != self._ownership[1]):
                    raise ValueError
                stage = "owner_login"
                with self._owner.authenticated():
                    stage = "current_read"
                    before = self._read_transition()
                    stage = "current_drift"
                    if before != expected:
                        raise ValueError
                    stage = "body_compile"
                    if restore:
                        assert self._ownership is not None
                        proposed = compile_secret_approval_build29_restore_body(
                            self._projection(before.approval_values), self._projection(self._ownership[0].approval_values),
                            schema=self._schema, identity=self._identity, approval_profile_name=mutation.approval_profile_name,
                        )
                    else:
                        if (self._linux_target_name is not None
                                and before.approval_values != ("disable", "disable", "disable", "")):
                            raise ValueError
                        proposed = compile_secret_approval_build29_enable_body(
                            self._projection(before.approval_values), schema=self._schema,
                            identity=self._identity, approval_profile_name=mutation.approval_profile_name,
                        )
                    stage = "csrf_check"
                    csrf = self._csrf()
                    stage = "body_compile"
                    fields = self._read_bound_fields(before)
                    routing = {**self._identity, "template": "Web Account"}
                    if self._linux_target_name is not None:
                        routing.update(template=DEFAULT_TEMPLATE, target=self._linux_target_name)
                    body.extend(json.dumps({**routing, **proposed}, separators=(",", ":")).encode()[:-1])
                    body.extend(b',"field":')
                    body.extend(fields)
                    body.extend(b"}")
                    stage = "final_read"
                    final = self._read_transition()
                    stage = "final_drift"
                    if final != before:
                        raise ValueError
                    _deadline(expires_at, clock)
                    stage = "claim_reserve"
                    self._reserve(restore, before)
                    stage = "dispatch_deadline"
                    _deadline(expires_at, clock)
                    stage = "put_dispatch"
                    status = self._put_once(body, ack, csrf)
                    stage = "ack_check"
                    _redact_material_members(ack)
                    if mutation.ack_verifier(status, ack) is not True:
                        raise ValueError
                    stage = "readback"
                    after = self._read_transition()
                    stage = "readback_verify"
                    actual = dict(zip(_FIELD_ORDER, after.approval_values))
                    if (actual != proposed or after.metadata_digest != before.metadata_digest
                            or after.profile_digest != before.profile_digest or after.native_digest != before.native_digest):
                        raise ValueError
                    stage = "logout"
                if not self._owner.logout_verified:
                    raise ValueError
                if restore:
                    stage = "restore_readback"
                    assert self._ownership is not None
                    if after != self._ownership[0]:
                        raise ValueError
                    self._ownership = None
                else:
                    self._ownership = (before, after)
                return SecretApprovalBuild29Readback(True, True, True, True)
            except Exception:
                # A reserved claim never becomes dispatchable; failure grants no restore.
                raise SecretApprovalBuild29HttpTransportError(_UNAVAILABLE, stage=stage) from None
            finally:
                _zeroize_mutable(body)
                _zeroize_mutable(ack)
                _zeroize_mutable(fields)

    def _read_bound_fields(self, expected: SecretApprovalBuild29PrivateState) -> bytearray:
        # Local imports keep the fixed projector's shared parser imports acyclic.
        from .secret_approval_build29_web_fields import project_secret_approval_build29_web_fields
        from .secret_approval_build29_linux_fields import project_secret_approval_build29_linux_fields
        from .local_user_reset_http_transport import _dispose_password, _valid_password

        mutation = self._mutation
        if mutation is None:
            raise ValueError
        binding = mutation.linux_fields if self._linux_target_name is not None else mutation.web_fields
        if binding is None:
            raise ValueError
        raw, redacted = bytearray(), bytearray()
        username: memoryview | None = None
        try:
            raw = self._read_raw()
            redacted.extend(raw)
            projection, metadata = self._project_raw(redacted)
            if projection != self._projection(expected.approval_values) or metadata != expected.metadata_digest:
                raise ValueError
            username = binding.username_span_provider()
            if not _valid_password(username):
                raise ValueError
            if isinstance(binding, SecretApprovalBuild29LinuxFieldsBinding):
                return project_secret_approval_build29_linux_fields(
                    raw, identity={**self._identity, "template": DEFAULT_TEMPLATE, "target": binding.target_name},
                    expected_serial=self._serial, expected_metadata_digest=expected.metadata_digest,
                    username=username, target_ipv4_address=binding.target_ipv4_address,
                )
            return project_secret_approval_build29_web_fields(
                raw, identity={**self._identity, "template": "Web Account", "target": ""},
                expected_metadata_digest=expected.metadata_digest,
                username=username, web_url=binding.web_url,
            )
        finally:
            _zeroize_mutable(raw)
            _zeroize_mutable(redacted)
            if isinstance(username, memoryview):
                _dispose_password(username)

    def _put_once(self, body: bytearray, ack: bytearray, csrf: str) -> int:
        owner = self._owner
        if owner._client is None or owner._clock() >= owner._expires_at:
            raise ValueError
        with owner._client.stream("PUT", self._path, content=bytes(body), headers={
            "Accept": "application/json", "Content-Type": "application/json", "X-CSRFTOKEN": csrf,
            "X-Requested-With": "XMLHttpRequest",
        }) as response:
            if "json" not in response.headers.get("content-type", "").lower():
                raise ValueError
            for chunk in response.iter_bytes():
                if len(ack) + len(chunk) > MAX_RESPONSE_BYTES:
                    raise ValueError
                ack.extend(chunk)
            return int(response.status_code)

    def _csrf(self) -> str:
        owner = self._owner
        if owner._client is None:
            raise ValueError
        cookie = owner._client.build_request("GET", owner._config.base_url + self._path).headers.get("cookie")
        jar: SimpleCookie = SimpleCookie()
        jar.load(cookie or "")
        token = jar.get("ccsrftoken")
        if (token is None or not token.value or len(token.value) > 4096
                or any(ord(char) < 33 or ord(char) > 126 for char in token.value)):
            raise ValueError
        return token.value

    def _check_claim_directory(self) -> tuple[int, int]:
        mutation = self._mutation
        if mutation is None:
            raise ValueError
        path = mutation.claim_directory
        info = path.lstat()
        if (not path.is_absolute() or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError
        return info.st_dev, info.st_ino

    def _claim_path(self, restore: bool) -> Path:
        assert self._mutation is not None
        return self._mutation.claim_directory / (self._claim_key + (".restore.claim" if restore else ".enable.claim"))

    def _available(self, restore: bool) -> None:
        if (self._closed or self._execution_enabled is not True or self._mutation is None
                or self._mutation.ack_verifier is None
                or (type(self._mutation.linux_fields) is not SecretApprovalBuild29LinuxFieldsBinding
                    if self._linux_target_name is not None
                    else type(self._mutation.web_fields) is not SecretApprovalBuild29WebFieldsBinding)
                or self._check_claim_directory() != self._directory_identity
                or self._attempted[restore] or os.path.lexists(self._claim_path(restore))
                or restore and self._ownership is None
                or not restore and (self._ownership is not None or os.path.lexists(self._claim_path(True)))):
            raise ValueError

    def _reserve(self, restore: bool, current: SecretApprovalBuild29PrivateState) -> None:
        self._available(restore)
        assert self._mutation is not None
        directory = os.open(self._mutation.claim_directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(directory)
            if ((info.st_dev, info.st_ino) != self._directory_identity
                    or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
                raise ValueError
            fd = os.open(self._claim_path(restore).name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
            self._attempted[restore] = True
            with os.fdopen(fd, "w") as file:
                json.dump({"contract": CONTRACT, "operation": "restore" if restore else "enable",
                           "state": "reserved", "state_digest": current.state_digest, "replay_permitted": False}, file)
                file.flush()
                os.fsync(file.fileno())
            os.fsync(directory)
        finally:
            os.close(directory)

    def _read(self) -> tuple[dict[str, object], str]:
        raw = self._read_raw()
        return self._project_raw(raw)

    def _read_raw(self) -> bytearray:
        owner = self._owner
        if owner._client is None or owner._clock() >= owner._expires_at:
            raise ValueError
        folder_id = owner.resolve_folder_id(self._folder_path)
        secret_id = owner._lookup_id("secret", self._folder_path + "/" + str(self._identity["name"]))
        if (type(folder_id) is not int or folder_id != self._identity["folder"]
                or type(secret_id) is not int or secret_id != self._identity["id"]
                or owner._clock() >= owner._expires_at):
            raise ValueError
        raw = bytearray()
        try:
            with owner._client.stream("GET", self._path, headers={
                "Accept": "application/json", "Cache-Control": "no-cache, no-store",
            }) as response:
                if response.status_code != 200 or "json" not in response.headers.get("content-type", "").lower():
                    raise ValueError
                for chunk in response.iter_bytes():
                    if len(raw) + len(chunk) > MAX_RESPONSE_BYTES:
                        raise ValueError
                    raw.extend(chunk)
            return raw
        except Exception:
            _zeroize_mutable(raw)
            raise

    def _project_raw(self, raw: bytearray) -> tuple[dict[str, object], str]:
        try:
            if self._linux_target_name is not None:
                from .secret_approval_build29_linux_metadata import qualify_secret_approval_build29_linux_metadata
                observed = qualify_secret_approval_build29_linux_metadata(
                    raw, identity={**self._identity, "template": DEFAULT_TEMPLATE, "target": self._linux_target_name},
                    expected_serial=self._serial,
                )
                if (not observed.totp_disabled or len(observed.slots) != 3
                        or {slot.name: slot.type for slot in observed.slots} != {
                            "Host": "target-address", "Username": "username", "Password": "password"}):
                    raise ValueError
                return self._projection(observed.approval_values), observed.metadata_digest
            _normalize_one_native_metadata_duplicate(raw)
            _redact_material_members(raw)
            payload = json.loads(raw, object_pairs_hook=_unique_members)
            if (not isinstance(payload, Mapping)
                    or set(payload) != set(_NATIVE_ENVELOPE) | {"serial", "results"}
                    or any(type(payload.get(key)) is not type(value) or payload[key] != value
                           for key, value in _NATIVE_ENVELOPE.items())
                    or type(payload.get("serial")) is not str or payload["serial"] != self._serial):
                raise ValueError
            row = payload["results"]
            if type(row) is not list or len(row) != 1 or not isinstance(row[0], Mapping):
                raise ValueError
            row = row[0]
            if any(type(row.get(key)) is not type(value) or row[key] != value
                   for key, value in self._identity.items()):
                raise ValueError
            for key in APPROVAL_FIELDS:
                value = row.get(key)
                if type(value) is not str:
                    raise ValueError
                if key == "approval-profile":
                    if len(value.encode("utf-8")) > 79 or any(ord(char) < 32 or ord(char) == 127 for char in value):
                        raise ValueError
                elif value not in ("enable", "disable"):
                    raise ValueError
            origin = row.get("q_origin_key", self._identity["id"])
            if type(origin) not in (int, str) or origin not in (self._identity["id"], str(self._identity["id"])):
                raise ValueError
            projection = {"version": payload["version"], "build": payload["build"],
                          "results": {key: row[key] for key in _IDENTITY | APPROVAL_FIELDS}}
            return projection, _preserved_metadata_digest(row)
        finally:
            _zeroize_mutable(raw)


def _unique_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _preserved_metadata_digest(row: Mapping[str, object]) -> str:
    """Normalize only qualified build-29 computed approval annotations.

    The selected CMDB schema defines neither annotation. The fixed disabled
    source omits num-approval-tiers and has approval_status=none; its single-tier
    enable source has integer 1 and required. A separately qualified request-field
    annotation is absent or an explicit empty list; its CMDB schema has no such
    writable member. Other types/values are refused.
    Keep the permissions container and all other permissions/configuration;
    never mutate the input or remove matching names recursively.
    """
    if "num-approval-tiers" in row:
        tiers = row["num-approval-tiers"]
        if type(tiers) is not int or tiers != 1:
            raise ValueError
    if "request-field" in row:
        request_fields = row["request-field"]
        if type(request_fields) is not list or request_fields:
            raise ValueError
    preserved = {key: value for key, value in row.items()
                 if key not in APPROVAL_FIELDS | {"field", "keyinfo", "num-approval-tiers", "request-field"}}
    if "permissions" in preserved:
        permissions = preserved["permissions"]
        if (not isinstance(permissions, Mapping)
                or type(permissions.get("approval_status")) is not str
                or permissions["approval_status"] not in {"none", "required"}):
            raise ValueError
        preserved["permissions"] = {key: value for key, value in permissions.items() if key != "approval_status"}
    return _digest(preserved)


def qualify_secret_approval_build29_put_ack(
    http_status: int, raw: bytearray, *, expected_serial: str, expected_secret_id: int,
) -> bool:
    """Qualify fixed root markers only; no results decoding or readback proof.

    This pure helper does not consume/change raw. The private caller must erase
    material before invocation and wipe ACK afterwards. Root error or
    schema_errors members are refused even when empty/zero; the qualified mkey
    is an integer and status is success. Independent readback remains required.
    """
    try:
        if (type(http_status) is not int or http_status != 200 or type(raw) is not bytearray
                or not 0 < len(raw) <= MAX_RESPONSE_BYTES
                or type(expected_serial) is not str or not 1 <= len(expected_serial) <= 64
                or any(not char.isascii() or not char.isalnum() for char in expected_serial)
                or type(expected_secret_id) is not int or not 0 < expected_secret_id <= 2_147_483_647):
            return False
        left = _skip_json_space(raw, 0)
        right = _json_value_end(raw, left)
        if _skip_json_space(raw, right) != len(raw):
            return False
        _validate_ack_json(raw, left, right)
        spans: dict[str, tuple[int, int]] = {}
        for name, _, start, end, _ in _raw_members(raw, left, right):
            if name in spans:
                return False
            spans[name] = (start, end)
        if "error" in spans or "schema_errors" in spans:
            return False
        expected = {"version": "v7.0.0", "build": 29, "http_method": "PUT", "http_status": 200,
                    "path": "secret", "name": "database", "serial": expected_serial, "vdom": "root",
                    "status": "success", "mkey": expected_secret_id}
        for name, value in expected.items():
            if name not in spans:
                return False
            start, end = spans[name]
            if raw[start:end] != json.dumps(value, separators=(",", ":")).encode():
                return False
        return True
    except Exception:
        return False


_ACK_STRING = re.compile(rb'"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"\Z')
_ACK_PRIMITIVE = re.compile(rb'(?:null|true|false|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)\Z')


def _validate_ack_json(raw: bytearray, start: int, end: int, depth: int = 0) -> None:
    """Bounded ACK syntax only; never decode string/number values or inner keys."""
    from .secret_create_191_http_transport import _valid_utf8

    if depth > 64:
        raise ValueError
    first = raw[start]
    if first == 34:
        with memoryview(raw)[start:end] as view:
            if _ACK_STRING.fullmatch(view) is None or not _valid_utf8(view):
                raise ValueError
        return
    if first not in {91, 123}:
        if _ACK_PRIMITIVE.fullmatch(memoryview(raw)[start:end]) is None:
            raise ValueError
        return
    closing = 93 if first == 91 else 125
    if raw[end - 1] != closing:
        raise ValueError
    cursor = _skip_json_space(raw, start + 1)
    if cursor == end - 1:
        return
    while cursor < end - 1:
        if first == 123:
            if raw[cursor] != 34:
                raise ValueError
            key_end = _json_string_end(raw, cursor) + 1
            _validate_ack_json(raw, cursor, key_end, depth + 1)
            cursor = _skip_json_space(raw, key_end)
            if raw[cursor] != 58:
                raise ValueError
            cursor = _skip_json_space(raw, cursor + 1)
        value_end = _json_value_end(raw, cursor)
        if value_end >= end:
            raise ValueError
        _validate_ack_json(raw, cursor, value_end, depth + 1)
        cursor = _skip_json_space(raw, value_end)
        if cursor == end - 1:
            return
        if raw[cursor] != 44:
            raise ValueError
        cursor = _skip_json_space(raw, cursor + 1)
    raise ValueError


def _normalize_one_native_metadata_duplicate(raw: bytearray) -> None:
    """Permit at most one identical raw non-selected row member; guess no name.

    The current fixed source proves one raw-byte-equal non-selected duplicate.
    No field name is guessed or broadened. Envelope, identity, approval,
    material and nested members retain strict duplicate rejection.
    """
    start = _skip_json_space(raw, 0)
    end = _json_value_end(raw, start)
    if _skip_json_space(raw, end) != len(raw):
        raise ValueError
    root: dict[str, tuple[int, int]] = {}
    for key, _, left, right, _ in _raw_members(raw, start, end):
        if key in root:
            raise ValueError
        root[key] = (left, right)
    left, right = root["results"]
    if raw[left] != 91 or raw[right - 1] != 93:
        raise ValueError
    row_start = _skip_json_space(raw, left + 1)
    row_end = _json_value_end(raw, row_start)
    if _skip_json_space(raw, row_end) != right - 1:
        raise ValueError
    protected = _IDENTITY | APPROVAL_FIELDS | {
        "field", "keyinfo", "q_origin_key", "template", "target", "totp-setting", "shared-key",
        "num-approval-tiers", "permissions", "request-field",
    }
    seen: dict[str, tuple[int, int]] = {}
    duplicate_count = 0
    for key, _, a, b, comma in _raw_members(raw, row_start, row_end):
        if key in seen:
            duplicate_count += 1
            if key in protected or duplicate_count != 1 or comma is None:
                raise ValueError
            old_a, old_b = seen[key]
            with memoryview(raw)[old_a:old_b] as old, memoryview(raw)[a:b] as new:
                if not hmac.compare_digest(old, new):
                    raise ValueError
            # Keep offsets stable and retain the first member's exact value.
            raw[comma:b] = b" " * (b - comma)
        else:
            seen[key] = (a, b)


def _raw_members(
    raw: bytearray, start: int, end: int,
) -> Iterator[tuple[str, int, int, int, int | None]]:
    """Read bounded member names/spans without decoding their values."""
    if raw[start] != 123 or raw[end - 1] != 125:
        raise ValueError
    cursor = _skip_json_space(raw, start + 1)
    comma: int | None = None
    count = 0
    while cursor < end - 1:
        count += 1
        key_end = _json_string_end(raw, cursor)
        key = json.loads(raw[cursor:key_end + 1])
        if type(key) is not str or key_end - cursor > 258 or count > 128:
            raise ValueError
        separator = _skip_json_space(raw, key_end + 1)
        if raw[separator] != 58:
            raise ValueError
        a = _skip_json_space(raw, separator + 1)
        b = _json_value_end(raw, a)
        if b >= end:
            raise ValueError
        yield key, cursor, a, b, comma
        cursor = _skip_json_space(raw, b)
        if cursor == end - 1:
            return
        if raw[cursor] != 44:
            raise ValueError
        comma = cursor
        cursor = _skip_json_space(raw, cursor + 1)
        if cursor >= end - 1:
            raise ValueError


def _redact_material_members(raw: bytearray) -> None:
    """Null fixed field/keyinfo/shared-key members before decoding, at any depth."""
    index = 0
    while index < len(raw):
        if raw[index] != 34:
            index += 1
            continue
        end = _json_string_end(raw, index)
        separator = _skip_json_space(raw, end + 1)
        if (separator < len(raw) and raw[separator] == 58
                and json.loads(raw[index:end + 1]) in ("field", "keyinfo", "shared-key")):
            start = _skip_json_space(raw, separator + 1)
            finish = _json_value_end(raw, start)
            width = finish - start
            if (width < 4 and raw[start] not in {34, 91, 123}
                    and re.fullmatch(rb"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?", raw[start:finish]) is None):
                raise ValueError
            # Grow short values; retain the old span width for longer values.
            # Continue at the new end so later siblings/nested members are scanned.
            raw[start:finish] = b"null" + b" " * max(0, width - 4)
            index = start + max(4, width)
        else:
            index = end + 1


def _hash(value: object) -> bool:
    return type(value) is str and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _deadline(expires_at: float, clock: Callable[[], float]) -> None:
    now = clock()
    if (type(expires_at) not in (int, float) or type(now) not in (int, float)
            or not math.isfinite(expires_at) or not math.isfinite(now) or now >= expires_at):
        raise ValueError
