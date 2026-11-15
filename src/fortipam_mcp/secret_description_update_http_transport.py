"""One fixed build-29 Owner-session metadata PUT, with durable replay denial."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import hmac
from http.cookies import SimpleCookie
import json
import os
from pathlib import Path
import re
import secrets
import stat
from threading import Lock
import time
from typing import Any

from .owner_session_metadata import OwnerSessionMetadataTransport
from .secret_description_update_contract import (
    MAX_DESCRIPTION_BYTES, compile_secret_description_update_body,
    project_secret_description_metadata,
)
from .secret_metadata_http_transport import (
    COLLECTION_PATH, MAX_RESPONSE_BYTES, FortiPamSecretMetadataHttpTransport,
    SecretMetadataHttpTransportConfig, _record, _redact_json_field_values, _zeroize_mutable,
    _json_string_end, _json_value_end, _skip_json_space,
)

_UNAVAILABLE = "The fixed Secret description update is unavailable."
_FIXTURE = re.compile(r"mcp-v4-secret-metadata-update-r[1-9][0-9]*\Z")


class SecretDescriptionUpdateHttpTransportError(RuntimeError):
    """No response, credential or protected binding values in failures."""

    def __init__(self, message: str, *, stage: str = "unavailable") -> None:
        super().__init__(message)
        self.stage = stage if stage in {
            "unavailable", "baseline_read", "baseline_drift", "body_compile",
            "csrf_check", "claim_reserve", "put_dispatch", "readback",
        } else "unavailable"


@dataclass(frozen=True, slots=True, repr=False)
class SecretDescriptionBinding:
    owner_name: str
    folder_path: str
    secret_name: str
    target_name: str
    template_name: str
    target_address: str = ""


@dataclass(frozen=True, slots=True, repr=False)
class SecretDescriptionInspection:
    secret_id: int
    folder_id: int
    description: str
    preserved_metadata_digest: str


@dataclass(frozen=True, slots=True)
class SecretDescriptionReadback:
    accepted: bool
    description_matches: bool
    preserved_metadata_matches: bool
    logout_verified: bool
    credential_field_bytes_preserved: bool
    http_status: int
    retained_field_values_match: bool = False

    @property
    def verified(self) -> bool:
        return all((self.accepted, self.description_matches,
                    self.preserved_metadata_matches, self.logout_verified,
                    self.credential_field_bytes_preserved or self.retained_field_values_match))


class FortiPamSecretDescriptionUpdateHttpTransport:
    """Bind one disposable Secret, text delta and claim before any dispatch."""

    def __init__(
        self, config: SecretMetadataHttpTransportConfig,
        binding: SecretDescriptionBinding, credentials: Callable[[], tuple[str, str]],
        *, description: str, claim_path: Path,
        owner_factory: Callable[[], Any] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        retained_account: Callable[[], str] | None = None,
    ) -> None:
        if (not isinstance(config, SecretMetadataHttpTransportConfig)
                or not isinstance(binding, SecretDescriptionBinding)
                or not self._fixture_binding_matches(binding)
                or not isinstance(description, str)
                or len(description.encode("utf-8")) > MAX_DESCRIPTION_BYTES
                or any(ord(c) < 32 or ord(c) == 127 for c in description)
                or not callable(credentials)
                or (retained_account is not None and (not callable(retained_account)
                    or not binding.target_address))):
            raise SecretDescriptionUpdateHttpTransportError(_UNAVAILABLE)
        self._config, self._binding, self._credentials = config, binding, credentials
        self._description, self._claim = description, Path(claim_path)
        self._retained_account = retained_account
        self._owner_factory, self._sleep, self._lock = owner_factory, sleep, Lock()
        self._check_parent()

    @staticmethod
    def _fixture_binding_matches(binding: SecretDescriptionBinding) -> bool:
        return _FIXTURE.fullmatch(binding.secret_name) is not None

    def _owner(self) -> Any:
        if self._owner_factory is not None:
            return self._owner_factory()
        b = self._binding
        return OwnerSessionMetadataTransport(
            self._config, owner_name=b.owner_name, credentials=self._credentials,
            folder_path=b.folder_path, secret_name=b.secret_name, target_name=b.target_name,
            witness=FortiPamSecretMetadataHttpTransport(self._config),
        )

    def inspect(self) -> SecretDescriptionInspection:
        self._unconsumed()
        try:
            owner = self._owner()
            with owner.authenticated():
                state, _, _ = self._read(owner)
            if not owner.logout_verified:
                raise ValueError
            return state
        except Exception:
            raise SecretDescriptionUpdateHttpTransportError(_UNAVAILABLE) from None

    def update_and_readback(self, expected: SecretDescriptionInspection) -> SecretDescriptionReadback:
        with self._lock:
            self._unconsumed()
            witness_key = bytearray(secrets.token_bytes(32))
            stage = "baseline_read"
            retained: list[dict[str, object]] = []
            body: dict[str, object] = {}
            try:
                owner = self._owner()
                with owner.authenticated():
                    before, envelope, before_fields = self._read(owner, witness_key)
                    stage = "baseline_drift"
                    if not isinstance(expected, SecretDescriptionInspection) or before != expected:
                        raise ValueError
                    b = self._binding
                    stage = "body_compile"
                    body = dict(compile_secret_description_update_body(
                        project_secret_description_metadata(envelope),
                        expected_secret_id=before.secret_id, expected_folder_id=before.folder_id,
                        expected_name=b.secret_name, expected_template=b.template_name,
                        description=self._description,
                    ))
                    if self._retained_account is not None:
                        retained = self._retained_fields(owner, before)
                        body = {**body, "target": b.target_name, "field": retained}
                    client = owner._client
                    stage = "csrf_check"
                    cookie = client.build_request("GET", self._config.base_url + COLLECTION_PATH).headers.get("cookie")
                    jar = SimpleCookie()
                    if not cookie:
                        raise ValueError
                    jar.load(cookie)
                    token = jar.get("ccsrftoken")
                    if token is None or not token.value or any(ord(c) < 33 or ord(c) > 126 for c in token.value):
                        raise ValueError
                    stage = "claim_reserve"
                    self._reserve(before)
                    stage = "put_dispatch"
                    status, response, _ = self._exchange(owner, "PUT", before.secret_id, body,
                                                      headers={"X-CSRFTOKEN": token.value})
                    accepted = status == 200 and self._qualified(response, "PUT")
                    after = before
                    after_fields = None
                    stage = "readback"
                    for attempt in range(4):
                        after, _, after_fields = self._read(owner, witness_key)
                        if after.description == self._description:
                            break
                        if attempt < 3:
                            self._sleep(0.5)
                    retained_match = False
                    if self._retained_account is not None:
                        check = self._retained_fields(owner, after)
                        retained_match = check == retained
                        for item in check:
                            item.clear()
                        check.clear()
                return SecretDescriptionReadback(
                    accepted, after.description == self._description,
                    after.secret_id == before.secret_id and after.folder_id == before.folder_id
                    and after.preserved_metadata_digest == before.preserved_metadata_digest,
                    owner.logout_verified,
                    before_fields is not None and after_fields is not None
                    and hmac.compare_digest(before_fields, after_fields),
                    status, retained_match,
                )
            except Exception:
                raise SecretDescriptionUpdateHttpTransportError(_UNAVAILABLE, stage=stage) from None
            finally:
                for item in retained:
                    item.clear()
                retained.clear()
                body.clear()
                _zeroize_mutable(witness_key)

    def _read(self, owner: Any, witness_key: bytearray | None = None
              ) -> tuple[SecretDescriptionInspection, Mapping[str, object], bytes | None]:
        b = self._binding
        folder = owner.resolve_folder_id(b.folder_path)
        secret = owner._lookup_id("secret", b.folder_path + "/" + b.secret_name)
        if type(secret) is not int or type(folder) is not int or secret <= 0 or folder <= 0:
            raise ValueError
        status, envelope, fields = self._exchange(owner, "GET", secret, witness_key=witness_key)
        if status != 200 or not self._qualified(envelope, "GET"):
            raise ValueError
        row = _record(envelope)
        if not isinstance(row, Mapping) or any(row.get(k) != v for k, v in {
            "id": secret, "folder": folder, "name": b.secret_name,
            "template": b.template_name, "target": b.target_name,
        }.items()) or type(row.get("id")) is not int or type(row.get("folder")) is not int:
            raise ValueError
        description = row.get("description")
        if not isinstance(description, str) or len(description.encode("utf-8")) > MAX_DESCRIPTION_BYTES:
            raise ValueError
        digest = _metadata_digest(row)
        return SecretDescriptionInspection(secret, folder, description, digest), envelope, fields

    def _retained_fields(self, owner: Any, expected: SecretDescriptionInspection) -> list[dict[str, object]]:
        """Decode credential values only at the private final dispatch boundary.

        Preserve the returned opaque Password token without interpreting it as
        plaintext or stored-password proof. Host is supplied by the bound Target,
        as in the build-29
        frontend serializer and the accepted password-schedule transport.
        """
        raw, field_bytes = bytearray(), bytearray()
        fields: list[Any] = []
        try:
            if owner._client is None or self._retained_account is None:
                raise ValueError
            with owner._client.stream("GET", f"{COLLECTION_PATH}/{expected.secret_id}",
                                      headers={"Accept": "application/json"}) as response:
                if response.status_code != 200 or "json" not in response.headers.get("content-type", "").lower():
                    raise ValueError
                for chunk in response.iter_bytes():
                    if len(raw) + len(chunk) > MAX_RESPONSE_BYTES:
                        raise ValueError
                    raw.extend(chunk)
            start, end = _field_span(raw)
            field_bytes.extend(memoryview(raw)[start:end])
            _redact_json_field_values(raw)
            envelope = json.loads(raw)
            row = _record(envelope)
            if (not self._qualified(envelope, "GET") or not isinstance(row, Mapping)
                    or row.get("id") != expected.secret_id or row.get("folder") != expected.folder_id
                    or row.get("description") != expected.description
                    or _metadata_digest(row) != expected.preserved_metadata_digest):
                raise ValueError
            fields = json.loads(field_bytes)
            if not isinstance(fields, list) or len(fields) not in {2, 3} or not all(isinstance(item, dict) for item in fields):
                raise ValueError
            named = {item.get("name"): item for item in fields}
            account = self._retained_account()
            if (not isinstance(account, str) or not account or len(named) != len(fields)
                    or set(named) not in ({"Username", "Password"}, {"Host", "Username", "Password"})
                    or not isinstance(named["Password"].get("value"), str)
                    or not named["Password"]["value"]
                    or named["Username"].get("value") != account
                    or ("Host" in named and named["Host"].get("value") != self._binding.target_address)):
                raise ValueError
            retained: list[dict[str, object]] = []
            for name in ("Password", "Username"):
                item = named[name]
                if (type(item.get("id")) is not int or item["id"] <= 0
                        or ("keyinfo" in item and not isinstance(item["keyinfo"], str))):
                    raise ValueError
                retained.append({key: item[key] for key in ("id", "name", "value", "keyinfo") if key in item})
            return retained
        finally:
            if isinstance(fields, list):
                for item in fields:
                    if isinstance(item, dict):
                        item.clear()
                fields.clear()
            _zeroize_mutable(field_bytes)
            _zeroize_mutable(raw)

    def _exchange(self, owner: Any, method: str, secret: int,
                  body: Mapping[str, object] | None = None,
                  *, headers: dict[str, str] | None = None,
                  witness_key: bytearray | None = None,
                  response_status: Callable[[int], None] | None = None) -> tuple[int, Any, bytes | None]:
        raw, encoded = bytearray(), bytearray()
        try:
            client = owner._client
            if client is None:
                raise ValueError
            kwargs: dict[str, Any] = {"headers": {"Accept": "application/json", **(headers or {})}}
            if body is not None:
                encoded.extend(json.dumps(body, separators=(",", ":")).encode())
                kwargs["content"] = bytes(encoded)
                kwargs["headers"]["Content-Type"] = "application/json"
            with client.stream(method, f"{COLLECTION_PATH}/{secret}", **kwargs) as response:
                if response_status is not None:
                    response_status(response.status_code)
                if "json" not in response.headers.get("content-type", "").lower():
                    raise ValueError
                for chunk in response.iter_bytes():
                    if len(raw) + len(chunk) > MAX_RESPONSE_BYTES:
                        raise ValueError
                    raw.extend(chunk)
                # Only the final private exchange witnesses the opaque field
                # bytes. No values are decoded, copied into PUT, or persisted;
                # the per-dispatch key is wiped and only equality leaves here.
                fields = _field_witness(raw, witness_key) if witness_key is not None else None
                _redact_json_field_values(raw)
                return response.status_code, json.loads(raw), fields
        finally:
            _zeroize_mutable(raw)
            _zeroize_mutable(encoded)

    @staticmethod
    def _qualified(payload: Any, method: str) -> bool:
        return isinstance(payload, Mapping) and type(payload.get("build")) is int and all(
            payload.get(k) == v for k, v in {
                "version": "v7.0.0", "build": 29, "http_status": 200,
                "http_method": method, "path": "secret", "name": "database",
            }.items()
        ) and payload.get("status") in {"success", "OK"}

    def _check_parent(self) -> None:
        try:
            info = self._claim.parent.lstat()
            if (not self._claim.is_absolute() or not stat.S_ISDIR(info.st_mode)
                    or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
                raise ValueError
        except Exception:
            raise SecretDescriptionUpdateHttpTransportError(_UNAVAILABLE) from None

    def _unconsumed(self) -> None:
        self._check_parent()
        if os.path.lexists(self._claim):
            raise SecretDescriptionUpdateHttpTransportError(_UNAVAILABLE)

    def _reserve(self, expected: SecretDescriptionInspection) -> None:
        self._unconsumed()
        directory = os.open(self._claim.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(directory)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError
            fd = os.open(self._claim.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
            with os.fdopen(fd, "w") as file:
                json.dump({"contract": "secret-description-update-claim-v1", "state": "reserved",
                           "metadata_digest": expected.preserved_metadata_digest,
                           "binding_digest": hashlib.sha256(json.dumps({
                               "secret": self._binding.secret_name, "folder": self._binding.folder_path,
                               "target": self._binding.target_name, "description": self._description,
                           }, sort_keys=True).encode()).hexdigest()}, file)
                file.flush()
                os.fsync(file.fileno())
            os.fsync(directory)
        finally:
            os.close(directory)


def _metadata_digest(row: Mapping[str, Any]) -> str:
    preserved = {k: v for k, v in row.items() if k not in {"description", "field"}}
    return hashlib.sha256(json.dumps(preserved, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _field_witness(raw: bytearray, key: bytearray) -> bytes:
    """Witness exact returned bytes, without claiming stored-password proof."""
    start, end = _field_span(raw)
    with memoryview(raw)[start:end] as value:
        return hmac.digest(key, value, "sha256")


def _field_span(raw: bytearray) -> tuple[int, int]:
    """Locate one field array, rejecting conflicting duplicate JSON members."""
    def members(start: int) -> dict[str, tuple[int, int]]:
        if raw[start] != 123:
            raise ValueError("witness_object_required")
        positions: dict[str, tuple[int, int]] = {}
        cursor = _skip_json_space(raw, start + 1)
        while raw[cursor] != 125:
            end = _json_string_end(raw, cursor)
            name = json.loads(raw[cursor:end + 1])
            cursor = _skip_json_space(raw, end + 1)
            if raw[cursor] != 58:
                raise ValueError("witness_colon")
            cursor = _skip_json_space(raw, cursor + 1)
            end = _json_value_end(raw, cursor)
            if name in positions:
                old_start, old_end = positions[name]
                with memoryview(raw)[old_start:old_end] as old, memoryview(raw)[cursor:end] as new:
                    if not hmac.compare_digest(old, new):
                        raise ValueError("witness_duplicate_conflict")
            positions[name] = (cursor, end)
            cursor = _skip_json_space(raw, end)
            if raw[cursor] == 125:
                break
            if raw[cursor] != 44:
                raise ValueError("witness_separator")
            cursor = _skip_json_space(raw, cursor + 1)
        return positions
    root = members(_skip_json_space(raw, 0))
    result_start, _ = root["results"]
    if raw[result_start] == 91:
        result_start = _skip_json_space(raw, result_start + 1)
        result_end = _json_value_end(raw, result_start)
        if raw[_skip_json_space(raw, result_end)] != 93:
            raise ValueError("witness_multiple_results")
    field_start, field_end = members(result_start)["field"]
    if raw[field_start] != 91:
        raise ValueError("witness_field_not_array")
    return field_start, field_end
