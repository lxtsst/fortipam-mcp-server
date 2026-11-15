"""Private full-row and original-material observation for one owned Windows Secret.

Only the original sealed ACK/UUID selects the subject. Seven fixed requests
bracket one complete row with Password/TOTP witnesses. New Windows source pins
must be qualified on its own fixture; Web source records cannot be imported.
This reader has no configuration writer, material output or MCP registration.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import hmac
import json
import math
import os
import ssl
from threading import RLock
import time
from typing import Literal, cast

import httpx

from . import secret_bulk_import_metadata as parser
from .ldap_server_runtime import _read
from .local_user_reset_projection import _object_spans
from .secret_approval_build29_native_preservation import _qualify_bracket
from .secret_approval_build29_totp_boundary import (
    SecretApprovalBuild29TotpWitness, _ENVELOPE_NAMES, consume_secret_approval_build29_totp_response,
)
from .secret_instruction_build29_api_preservation import (
    SecretInstructionBuild29CredentialWitness, _credential_bracket,
    _credential_pinned_tokens, consume_secret_instruction_build29_credential_response,
)
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _ssl_context, _zeroize_mutable
from .target_api_dependency_reader import _private_http_logs
from .windows_execution_secret_ack import (
    WindowsExecutionSecretAckCustody, WindowsExecutionSecretOriginalCreation, _SEND, _SEND_FIELDS, _USERNAME_DOMAIN,
)
from .windows_execution_secret_contract import REQUEST_UUID, _project_windows_execution_secret_metadata
from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object

_ERROR = "The private Windows execution Secret preservation observation is unavailable."
_CLEAR = "/api/v2/internal/secret-clear-text"
_PHASES = frozenset({"baseline", "recovery", "dispatch"})
_RECORD_FIELDS = frozenset({"context_digest", "original_digest", "phase", "framing_digest",
                          "preservation_digest", "credential_envelope_digest", "totp_envelope_digest"})


class WindowsExecutionSecretPreservationError(RuntimeError):
    """Categorical refusal; source responses and credential values stay private."""


@dataclass(frozen=True, slots=True, repr=False)
class WindowsExecutionSecretPreservation(_OpaqueC3Object):
    custody_digest: str
    preservation_digest: str
    observed_at: float
    expires_at: float


@dataclass(frozen=True, slots=True, repr=False)
class _Frame(_OpaqueC3Object):
    password_field_id: int
    framing_digest: str


def _full_frame(raw: bytearray, custody: WindowsExecutionSecretAckCustody,
        original: WindowsExecutionSecretOriginalCreation, key: bytes) -> _Frame:
    if original.native_uuid is None or original.state_digest is None:
        raise ValueError
    observed = _project_windows_execution_secret_metadata(raw, custody._profile,
        expected_secret_id=original.native_secret_id, create_uuid=REQUEST_UUID,
        expected_native_uuid=original.native_uuid)
    if observed.state_digest != original.state_digest:
        raise ValueError
    start = _skip_json_space(raw, 0); end = _json_value_end(raw, start)
    envelope = _object_spans(raw, start, end)
    left, right = envelope["results"]
    if raw[left] == 91:
        rows = parser._array(raw, (left, right), 1)
        if len(rows) != 1:
            raise ValueError
        left, right = rows[0]
    row = _object_spans(raw, left, right)
    if parser._scalar(raw, row["instruction-profile"]) != "":
        raise ValueError
    for name in ("dependency", "subscriber"):
        if parser._array(raw, row[name], 0):
            raise ValueError
    slots: dict[str, dict[str, tuple[int, int]]] = {}
    identifiers = set()
    for entry in parser._array(raw, row["field"], 3):
        fields = _object_spans(raw, *entry)
        field_name = parser._scalar(raw, fields["name"])
        if type(field_name) is not str or field_name not in {"Password", "Username", "Host"} or field_name in slots:
            raise ValueError
        identifier = parser._integer(parser._scalar(raw, fields["id"]))
        if identifier in identifiers or raw[fields["value"][0]] != 34:
            raise ValueError
        identifiers.add(identifier); slots[field_name] = fields
    if not {"Password", "Username"} <= slots.keys():
        raise ValueError
    if "Host" in slots:
        expected = json.dumps(custody._profile.target_address).encode("ascii")
        with memoryview(raw)[slice(*slots["Host"]["value"])] as host:
            if host != expected:
                raise ValueError
    sent = custody._record(_SEND, _SEND_FIELDS)
    username = hmac.new(key, _USERNAME_DOMAIN, hashlib.sha256)
    with memoryview(raw)[slice(*slots["Username"]["value"])] as value:
        username.update(value)
    if not hmac.compare_digest(username.hexdigest(), cast(str, sent["username_digest"])):
        raise ValueError
    totp = _object_spans(raw, *row["totp-setting"])
    if parser._scalar(raw, totp["status"]) != "disable":
        raise ValueError
    first, last = totp["shared-key"]
    with memoryview(raw)[first:last] as token:
        if not hmac.compare_digest(token, b"null") and token[0] != 34:
            raise ValueError
    # This replacement is framing only. Independent explicit-empty witnesses
    # are mandatory below before it can contribute to a preservation result.
    digest = hmac.new(key, b"windows-execution-secret-full-row/v1\x00", hashlib.sha256)
    with memoryview(raw)[left:first] as value:
        digest.update(value)
    digest.update(b'"independently-qualified-empty-totp"')
    with memoryview(raw)[last:right] as value:
        digest.update(value)
    return _Frame(parser._integer(parser._scalar(raw, slots["Password"]["id"])), digest.hexdigest())


def _complete(raw: bytearray, *, custody: WindowsExecutionSecretAckCustody,
        original: WindowsExecutionSecretOriginalCreation, key: bytes,
        password_before: SecretInstructionBuild29CredentialWitness,
        password_after: SecretInstructionBuild29CredentialWitness,
        totp_before: SecretApprovalBuild29TotpWitness, totp_after: SecretApprovalBuild29TotpWitness) -> str:
    frame = _full_frame(raw, custody, original, key)
    _credential_bracket(password_before, password_after, secret_id=original.native_secret_id,
        field_id=frame.password_field_id, key=key)
    sent = custody._record(_SEND, _SEND_FIELDS)
    if not hmac.compare_digest(password_before.material_digest, cast(str, sent["password_digest"])):
        raise ValueError
    _qualify_bracket(totp_before, totp_after, key)
    if totp_before.explicit_empty is not True:
        raise ValueError
    return hmac.new(key, b"windows-execution-secret-preserved/v1\x00" +
        frame.framing_digest.encode("ascii") + password_before.material_digest.encode("ascii") +
        totp_before.material_digest.encode("ascii"), hashlib.sha256).hexdigest()


class WindowsExecutionSecretPreservationReader(_OpaqueC3Object):
    """One durable phase, seven fixed reads; phase names do not grant write rights."""
    def __init__(self, custody: WindowsExecutionSecretAckCustody, *,
            phase: Literal["baseline", "recovery", "dispatch"],
            client_factory: Callable[..., httpx.Client] = httpx.Client,
            http_clock: Callable[[], float] = time.monotonic) -> None:
        try:
            if (type(custody) is not WindowsExecutionSecretAckCustody or type(phase) is not str
                    or phase not in _PHASES or not callable(client_factory) or not callable(http_clock)):
                raise ValueError
            self._custody: WindowsExecutionSecretAckCustody = custody
            self._phase: str = phase
            self._factory: Callable[..., httpx.Client] = client_factory
            self._clock: Callable[[], float] = http_clock
            self._original: WindowsExecutionSecretOriginalCreation = custody.inspect_original_creation()
            if (self._original.original_outcome == "in_progress" or self._original.native_uuid is None
                    or self._original.state_digest is None):
                raise ValueError
            self._started: bool = False
            self._lock: RLock = RLock()
            self._attempt: str = "preservation." + phase + ".attempt.json"
            self._result: str = "preservation." + phase + ".result.json"
            self._attempt_identity: tuple[int, int] | None = None
            self._validate()
        except Exception:
            raise WindowsExecutionSecretPreservationError(_ERROR) from None

    def _validate(self) -> None:
        if (self._custody.inspect_original_creation() != self._original or self._phase not in _PHASES
                or self._attempt != "preservation." + self._phase + ".attempt.json"
                or self._result != "preservation." + self._phase + ".result.json"):
            raise ValueError
        if self._attempt_identity is not None:
            self._check_attempt(self._phase, self._attempt_identity)

    def _check_attempt(self, phase: str, identity: tuple[int, int] | None = None) -> None:
        name = "preservation." + phase + ".attempt.json"
        path = self._custody._directory / name
        raw = _read(path, 4096)
        try:
            left = _skip_json_space(raw, 0); right = _json_value_end(raw, left)
            if _skip_json_space(raw, right) != len(raw):
                raise ValueError
            parser._validate_json(raw, left, right, depth=0, budget=[10000])
            _object_spans(raw, left, right)
            value = json.loads(raw)
            signature = value.pop("signature")
            if (set(value) != {"context_digest", "original_digest", "phase"}
                    or value["context_digest"] != self._custody._context or value["phase"] != phase
                    or value["original_digest"] != self._original.custody_digest or type(signature) is not str
                    or not hmac.compare_digest(signature, self._custody._signature(name, value))):
                raise ValueError
            info = path.stat()
            if identity is not None and (info.st_dev, info.st_ino) != identity:
                raise ValueError
        finally:
            _zeroize_mutable(raw)

    def _record(self, phase: str) -> dict[str, object]:
        name = "preservation." + phase + ".result.json"
        raw = _read(self._custody._directory / name, 16384)
        try:
            self._validate()
            self._check_attempt(phase)
            left = _skip_json_space(raw, 0); right = _json_value_end(raw, left)
            if _skip_json_space(raw, right) != len(raw):
                raise ValueError
            parser._validate_json(raw, left, right, depth=0, budget=[10000])
            spans = _object_spans(raw, left, right)
            if set(spans) != _RECORD_FIELDS | {"signature"}:
                raise ValueError
            value = json.loads(raw)
            signature = value.pop("signature")
            if (type(signature) is not str
                    or not hmac.compare_digest(signature, self._custody._signature(name, value))
                    or value["phase"] != phase or value["context_digest"] != self._custody._context
                    or value["original_digest"] != self._original.custody_digest):
                raise ValueError
            for key in ("framing_digest", "preservation_digest", "credential_envelope_digest", "totp_envelope_digest"):
                if type(value[key]) is not str or parser._DIGEST.fullmatch(value[key]) is None:
                    raise ValueError
            return cast(dict[str, object], value)
        finally:
            _zeroize_mutable(raw)

    def read_once(self, *, max_deadline: float | None = None) -> WindowsExecutionSecretPreservation:
        with self._lock:
            if self._started:
                raise WindowsExecutionSecretPreservationError(_ERROR)
            self._started = True
        core, scratch = bytearray(), bytearray()
        previous: float | None = None
        client: httpx.Client | None = None
        responses = []
        try:
            if max_deadline is not None and (type(max_deadline) not in (int, float)
                    or not math.isfinite(max_deadline) or max_deadline < 0):
                raise ValueError
            self._validate()
            baseline = self._record("baseline") if self._phase != "baseline" else None
            if os.path.lexists(self._custody._directory / self._result):
                raise ValueError
            self._custody._write(self._attempt, {"context_digest": self._custody._context,
                "original_digest": self._original.custody_digest, "phase": self._phase})
            info = (self._custody._directory / self._attempt).stat()
            self._attempt_identity = info.st_dev, info.st_ino
            self._validate()
            key = self._custody._material_key()

            def now() -> float:
                nonlocal previous
                value = self._clock()
                if (type(value) not in (int, float) or not math.isfinite(value) or value < 0
                        or previous is not None and value < previous):
                    raise ValueError
                previous = float(value)
                return float(value)

            begin = now()
            deadline = begin + min(30.0, float(self._custody._config.timeout_seconds))
            if max_deadline is not None:
                deadline = min(deadline, max_deadline)
            def remaining() -> float:
                value = deadline - now()
                if value <= 0:
                    raise ValueError
                return min(10.0, value)

            context = _ssl_context(self._custody._config)
            if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
                raise ValueError
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            pins = {"credential_envelope_digest": cast(str, baseline["credential_envelope_digest"]) if baseline else "",
                    "totp_envelope_digest": cast(str, baseline["totp_envelope_digest"]) if baseline else ""}

            def observe(raw: bytearray, *, credential: bool, field_id: int) -> dict[str, str | int]:
                left = _skip_json_space(raw, 0); right = _json_value_end(raw, left)
                parser._validate_json(raw, left, right, depth=0, budget=[10000])
                fields = _object_spans(raw, left, right)
                allowed = _ENVELOPE_NAMES | {"results"} | ({"field-id"} if credential else set())
                if not set(fields) <= allowed:
                    raise ValueError
                values = {name:parser._scalar(raw, span) for name, span in fields.items() if name != "results"}
                for name, expected in {"http_method":"POST", "http_status":200, "status":"OK",
                                       "secret-id":self._original.native_secret_id}.items():
                    if type(values.get(name)) is not type(expected) or values[name] != expected:
                        raise ValueError
                if "serial" in values and (type(values["serial"]) is not str
                        or hashlib.sha256(values["serial"].encode("ascii")).hexdigest() != self._custody._profile.serial_digest):
                    raise ValueError
                if "field-id" in values and (type(values["field-id"]) is not int or values["field-id"] != field_id):
                    raise ValueError
                if "msg" not in values:
                    raise ValueError
                # Existing strict token grammar qualifies the remaining optional metadata.
                _credential_pinned_tokens(cast(Mapping[str, str | int], values))
                return cast(dict[str, str | int], values)

            def pin_envelope(raw: bytearray, *, credential: bool, field_id: int) -> dict[str, str | int]:
                values = observe(raw, credential=credential, field_id=field_id)
                # Native messages are not stored. Even untrusted envelope text
                # contributes only keyed tokens to the durable source pins.
                left = _skip_json_space(raw, 0); right = _json_value_end(raw, left)
                fields = _object_spans(raw, left, right)
                digest = hmac.new(key, b"windows-execution-secret-envelope/v1\x00", hashlib.sha256)
                for name in sorted(set(fields) - {"results"}):
                    digest.update(name.encode("ascii") + b"\x00")
                    with memoryview(raw)[slice(*fields[name])] as token:
                        digest.update(token)
                    digest.update(b"\x00")
                label = "credential_envelope_digest" if credential else "totp_envelope_digest"
                actual = digest.hexdigest()
                if pins[label] and not hmac.compare_digest(pins[label], actual):
                    raise ValueError
                pins[label] = actual
                return values

            with _private_http_logs(), self._factory(verify=context, timeout=remaining(),
                    follow_redirects=False, trust_env=False) as client:
                def request(method: str, target: bytearray, body: dict[str, int] | None = None) -> None:
                    self._validate(); remaining(); _zeroize_mutable(target); client.cookies.clear()
                    route = ("/api/v2/cmdb/secret/database/" + str(self._original.native_secret_id)
                             + "?with_meta=true&vdom=root") if method == "GET" else _CLEAR
                    headers = {"Authorization":"Bearer " + self._custody._config.bearer_token,
                        "Accept":"application/json", "Accept-Encoding":"identity", "Cache-Control":"no-store",
                        "Connection":"close", "X-Requested-With":"XMLHttpRequest"}
                    try:
                        with client.stream(method, self._custody._config.base_url.rstrip("/") + route,
                                headers=headers, json=body, timeout=remaining()) as response:
                            responses.append(response)
                            remaining()
                            if (type(response.status_code) is not int or response.status_code != 200
                                    or response.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json"
                                    or response.headers.get("content-encoding", "identity") not in ("", "identity")):
                                raise ValueError
                            iterator = response.iter_raw()
                            while True:
                                remaining()
                                try: chunk = next(iterator)
                                except StopIteration: break
                                remaining()
                                if len(target) + len(chunk) > (1048576 if method == "GET" else 16384):
                                    raise ValueError
                                target.extend(chunk)
                    finally:
                        client.cookies.clear()
                    remaining(); self._validate()

                def password(field_id: int) -> SecretInstructionBuild29CredentialWitness:
                    request("POST", scratch, {"secret-id":self._original.native_secret_id, "field-id":field_id})
                    envelope = pin_envelope(scratch, credential=True, field_id=field_id)
                    return consume_secret_instruction_build29_credential_response(scratch,
                        expected_secret_id=self._original.native_secret_id, expected_field_id=field_id,
                        http_status=200, content_type="application/json", expected_envelope=envelope,
                        witness_key=key)

                def totp() -> SecretApprovalBuild29TotpWitness:
                    request("POST", scratch, {"secret-id":self._original.native_secret_id, "totp-share-key":1})
                    envelope = pin_envelope(scratch, credential=False, field_id=0)
                    return consume_secret_approval_build29_totp_response(scratch, http_status=200,
                        content_type="application/json", expected_envelope=envelope, witness_key=key)

                request("GET", scratch)
                frame = _full_frame(scratch, self._custody, self._original, key); _zeroize_mutable(scratch)
                if baseline and frame.framing_digest != baseline["framing_digest"]:
                    raise ValueError
                password_before, totp_before = password(frame.password_field_id), totp()
                request("GET", core)
                if _full_frame(core, self._custody, self._original, key) != frame:
                    raise ValueError
                password_after, totp_after = password(frame.password_field_id), totp()
                request("GET", scratch)
                if _full_frame(scratch, self._custody, self._original, key) != frame:
                    raise ValueError
                digest = _complete(core, custody=self._custody, original=self._original, key=key,
                    password_before=password_before, password_after=password_after,
                    totp_before=totp_before, totp_after=totp_after)
            remaining(); self._validate()
            if (client is None or not client.is_closed or len(client.cookies)
                    or len(responses) != 7 or any(not response.is_closed for response in responses)):
                raise ValueError
            if baseline and (digest != baseline["preservation_digest"] or frame.framing_digest != baseline["framing_digest"]):
                raise ValueError
            self._custody._write(self._result, {"context_digest":self._custody._context,
                "original_digest":self._original.custody_digest, "phase":self._phase,
                "framing_digest":frame.framing_digest, "preservation_digest":digest, **pins})
            remaining(); self._validate()
            return WindowsExecutionSecretPreservation(self._original.custody_digest, digest, now(), deadline)
        except Exception:
            raise WindowsExecutionSecretPreservationError(_ERROR) from None
        finally:
            _zeroize_mutable(core); _zeroize_mutable(scratch)
