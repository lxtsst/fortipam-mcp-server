"""Inactive one-shot private fixture reader; no login, mutation or Tool.

This binds fixed requests to the original sealed creation record. Each fixed
observation phase reserves a durable attempt before HTTP, blocking restart
replay. Source qualification and live workflow authority remain prerequisites.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
import hashlib
import hmac
import json
import math
import os
import ssl
import stat
import threading
import time
from typing import Literal, cast
from urllib.parse import urlsplit

import httpx

from . import secret_bulk_import_metadata as metadata
from .instruction_profile_contract import _NAME
from .policy_assignment_preservation import (
    PolicyAssignmentPreservation, _NAME as _POLICY_NAME, consume_policy_assignment_preservation,
)
from .secret_approval_build29_native_preservation import _qualify_bracket
from .secret_approval_build29_totp_boundary import (
    SecretApprovalBuild29TotpWitness, _ENVELOPE_NAMES, _pinned_tokens, consume_secret_approval_build29_totp_response,
)
from .secret_instruction_build29_api_preservation import (
    SecretInstructionBuild29ApiPreservationWitness, SecretInstructionBuild29CredentialWitness,
    _IDENTITY, _credential_bracket, _credential_pinned_tokens, _qualify_web_detail,
    consume_secret_instruction_build29_api_preservation,
    consume_secret_instruction_build29_credential_response,
)
from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig, _json_value_end, _skip_json_space, _ssl_context, _zeroize_mutable,
)
from .target_api_dependency_reader import _private_http_logs
from .web_secret_fixture_creation import WebSecretFixtureCreationEvidence
from .web_secret_fixture_creation_record import WebSecretFixtureCreationRecord

_CLEAR = "/api/v2/internal/secret-clear-text"
_ERROR = "The private Web fixture API preservation source is unavailable."
_ATTEMPT_DOMAIN = b"web-fixture-api-attempt/v1\0"
_ATTEMPTS = {phase: "api-preservation." + phase + ".attempt"
             for phase in ("baseline", "applied", "restored", "recovery", "recovery-dispatch", "source", "reconciliation",
                           "reconciled-cleanup-baseline", "reconciled-cleanup-current", "reconciled-cleanup-dispatch",
                           "instruction-attach-current", "instruction-attach-dispatch",
                           "instruction-restore-current", "instruction-restore-dispatch")}
_InstructionPhase = Literal["baseline", "applied", "restored", "recovery", "recovery-dispatch", "source",
    "reconciliation", "reconciled-cleanup-baseline", "reconciled-cleanup-current", "reconciled-cleanup-dispatch",
    "instruction-attach-current", "instruction-attach-dispatch", "instruction-restore-current", "instruction-restore-dispatch"]
_PolicyPhase = Literal["policy-baseline", "policy-assign-current", "policy-assign-dispatch", "policy-assigned",
    "policy-restore-current", "policy-restore-dispatch", "policy-restored"]
_POLICY_PHASES = frozenset({"policy-baseline", "policy-assign-current", "policy-assign-dispatch", "policy-assigned",
    "policy-restore-current", "policy-restore-dispatch", "policy-restored"})
_ATTEMPTS.update({phase: "api-preservation." + phase + ".attempt" for phase in _POLICY_PHASES})


class WebSecretFixtureApiPreservationReadError(ValueError):
    """Categorical refusal without source responses, identities or credentials."""

    def __init__(self) -> None:
        super().__init__(_ERROR)


class WebSecretFixtureApiPreservationReader:
    """One observation, selected solely from an original signed fixture record.

    Three full detail GETs guard one interval; Password/TOTP requests bracket
    the middle GET. The first GET derives the exact Password field id, and all
    detail rows must match original identity/UUID and stable complete row bytes
    apart from the direct volatile TOTP render. The same Bearer is used for all
    requests; no browser cookies, CSRF extraction or password login is attempted.

    Both envelope pins must come from independently qualified private sources.
    Constructing this reader cannot qualify Bearer internal authorization, grant
    read/ownership rights, admission, dispatch or cleanup. Each phase is consumed
    durably before any HTTP; a later phase is not workflow authorization or proof
    that an earlier phase succeeded. The separate reconciliation phase observes
    current pins after restart without replacing the original source attempt;
    the ordinary recovery guard explicitly rejects it. No default runtime
    wiring is supplied.

    A separately prebound Policy profile requires an original native ACK and
    empty Instruction reference. Its distinct phases check the exact Policy
    before any material request and return only the Policy preservation type.
    It cannot qualify source pins, generate an Instruction body or substitute
    for the original source observer in the existing recovery lifecycle.
    """

    def __init__(self, record: WebSecretFixtureCreationRecord, *, instruction_profile_name: str,
            credential_envelope: Mapping[str, str | int] | None, totp_envelope: Mapping[str, str | int] | None,
            phase: _InstructionPhase | _PolicyPhase = "baseline", policy_name: str | None = None,
            client_factory: Callable[..., httpx.Client] = httpx.Client,
            clock: Callable[[], float] = time.monotonic) -> None:
        try:
            if (type(record) is not WebSecretFixtureCreationRecord or type(instruction_profile_name) is not str
                    or instruction_profile_name and _NAME.fullmatch(instruction_profile_name) is None
                    or type(phase) is not str or phase not in _ATTEMPTS
                    or (phase in {"applied", "instruction-restore-current", "instruction-restore-dispatch"})
                       != bool(instruction_profile_name)):
                raise ValueError
            policy_profile = phase in _POLICY_PHASES
            if (policy_profile != (policy_name is not None)
                    or policy_profile and (type(policy_name) is not str or _POLICY_NAME.fullmatch(policy_name) is None
                        or instruction_profile_name != "" or record._ack_capture is None)):
                raise ValueError
            record._config.__post_init__()
            origin = urlsplit(record._config.base_url)
            if (origin.scheme != "https" or not origin.hostname or origin.path not in {"", "/"}
                    or origin.query or origin.fragment or origin.username is not None or origin.password is not None
                    or record._config != record._transport._config):
                raise ValueError
            evidence = record.read_creation()
            if policy_profile:
                record.read_acknowledged_creation()
            if phase in {"source", "reconciliation"}:
                if (credential_envelope is not None or totp_envelope is not None
                        or record._ack_capture is None
                        or phase == "source" and not record._ack_capture.observe_source):
                    raise ValueError
                record.read_acknowledged_creation()
                self._credential_envelope: dict[str, str | int] = {}
                self._totp_envelope: dict[str, str | int] = {}
            else:
                if credential_envelope is None or totp_envelope is None:
                    raise ValueError
                self._credential_envelope = self._envelope(credential_envelope, evidence, credential=True)
                self._totp_envelope = self._envelope(totp_envelope, evidence)
            self._record: WebSecretFixtureCreationRecord = record
            self._original: WebSecretFixtureCreationEvidence = evidence
            self._config: SecretMetadataHttpTransportConfig = record._config
            self._reference: str = instruction_profile_name
            self._phase: _InstructionPhase | _PolicyPhase = phase
            self._policy_name: str | None = policy_name
            self._source_completed: bool = False
            self._source_result: SecretInstructionBuild29ApiPreservationWitness | None = None
            self._attempt_identity: tuple[int, int] | None = None
            self._attempt_payload: bytes = hmac.new(record._key, _ATTEMPT_DOMAIN
                + record._namespace.encode("ascii") + b"\0" + phase.encode("ascii") + b"\0"
                + instruction_profile_name.encode("ascii") + b"\0"
                + (b"policy-profile/v1\0" + policy_name.encode("utf-8") + b"\0" if policy_name is not None else b"")
                + json.dumps([self._credential_envelope, self._totp_envelope],
                    sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii"),
                hashlib.sha256).hexdigest().encode("ascii") + b"\n"
            self._factory: Callable[..., httpx.Client] = client_factory
            self._clock: Callable[[], float] = clock
            self._lock: threading.Lock = threading.Lock()
            self._started: bool = False
        except Exception:
            raise WebSecretFixtureApiPreservationReadError() from None

    def __repr__(self) -> str:
        return "<WebSecretFixtureApiPreservationReader redacted>"

    __str__ = __repr__

    def observed_envelopes(self) -> tuple[dict[str, str | int], dict[str, str | int]]:
        """Private original-response pins, available only after the complete source read.

        This does not certify a mock as live evidence or authorize a lifecycle.
        The acceptance operator must separately verify actual transport provenance.
        """
        try:
            if self._phase not in {"source", "reconciliation"} or not self._source_completed:
                raise ValueError
            self._original_record()
            self._record.read_acknowledged_creation()
            return dict(self._credential_envelope), dict(self._totp_envelope)
        except Exception:
            raise WebSecretFixtureApiPreservationReadError() from None

    def _observe_envelope(self, raw: bytearray, *, credential: bool = False) -> dict[str, str | int]:
        # Decode only fixed envelope scalars; results remain in the byte consumer.
        left = _skip_json_space(raw, 0)
        right = _json_value_end(raw, left)
        if _skip_json_space(raw, right) != len(raw):
            raise ValueError
        metadata._validate_json(raw, left, right, depth=0, budget=[50_000])
        names = _ENVELOPE_NAMES | {"field-id"} if credential else _ENVELOPE_NAMES
        spans = metadata._object_spans(raw, left, right, names)
        values: dict[str, str | int] = {}
        for name, span in spans.items():
            value = metadata._scalar(raw, span)
            if type(value) not in (str, int):
                raise ValueError
            values[name] = cast(str | int, value)
        return self._envelope(values, self._original, credential=credential)

    @staticmethod
    def _envelope(value: Mapping[str, str | int], evidence: WebSecretFixtureCreationEvidence, *,
            credential: bool = False) -> dict[str, str | int]:
        if not isinstance(value, Mapping):
            raise ValueError
        result = dict(value)
        required: dict[str, str | int] = {"http_method": "POST", "http_status": 200,
                                         "status": "OK", "secret-id": evidence.native_secret_id}
        if ("msg" not in result or any(type(result.get(key)) is not type(expected) or result[key] != expected
                                      for key, expected in required.items())):
            raise ValueError
        if credential:
            _credential_pinned_tokens(result)
        else:
            _pinned_tokens(result)
        if "serial" in result:
            serial = result["serial"]
            if (type(serial) is not str
                    or hashlib.sha256(serial.encode("ascii")).hexdigest() != evidence.serial_digest):
                raise ValueError
        return result

    def _original_record(self) -> WebSecretFixtureCreationEvidence:
        if (self._record._config != self._config or self._record._transport._config != self._config
                or self._record.read_creation() != self._original):
            raise ValueError
        if self._phase in {"source", "reconciliation"} or self._policy_name is not None:
            self._record.read_acknowledged_creation()
        if self._attempt_identity is not None:
            self._check_attempt()
        return self._original

    def _check_attempt(self) -> None:
        directory = self._record._directory_fd()
        descriptor: int | None = None
        try:
            descriptor = os.open(_ATTEMPTS[self._phase], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                 dir_fd=directory)
            info = os.fstat(descriptor)
            if (self._attempt_identity != (info.st_dev, info.st_ino)
                    or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                    or info.st_size != len(self._attempt_payload)):
                raise ValueError
            payload = os.read(descriptor, len(self._attempt_payload) + 1)
            after = os.fstat(descriptor)
            linked = os.stat(_ATTEMPTS[self._phase], dir_fd=directory, follow_symlinks=False)
            if (not hmac.compare_digest(payload, self._attempt_payload)
                    or (after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_nlink,
                        after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                    != (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
                        info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                    or (linked.st_dev, linked.st_ino) != (info.st_dev, info.st_ino)):
                raise ValueError
        finally:
            try:
                if descriptor is not None:
                    os.close(descriptor)
            finally:
                os.close(directory)

    def _reserve(self) -> None:
        """Consume this phase once in the original pinned owner-only directory.

        Never remove or reuse the marker, including after write/fsync failures.
        Existence alone blocks a new instance; it cannot supply a prior witness.
        """
        directory = self._record._directory_fd()
        descriptor: int | None = None
        try:
            descriptor = os.open(_ATTEMPTS[self._phase], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=directory)
            info = os.fstat(descriptor)
            self._attempt_identity = info.st_dev, info.st_ino
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = None
                stream.write(self._attempt_payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(directory)
            self._original_record()
        finally:
            try:
                if descriptor is not None:
                    os.close(descriptor)
            finally:
                os.close(directory)

    def read_once(self, *, max_deadline: float | None = None) -> SecretInstructionBuild29ApiPreservationWitness:
        if self._policy_name is not None:
            raise WebSecretFixtureApiPreservationReadError()
        witness, body = self._read_once(max_deadline=max_deadline)
        assert body is None
        return cast(SecretInstructionBuild29ApiPreservationWitness, witness)

    def read_policy_assignment_once(self, *, max_deadline: float | None = None) -> PolicyAssignmentPreservation:
        """Fixed Policy-only projection; never a material-source qualification.

        Startup binds one Policy name and one distinct durable phase. The
        original native ACK is required before every request and publication.
        Legacy source qualification/recovery and Instruction reads stay separate.
        """
        if self._policy_name is None or self._phase not in _POLICY_PHASES:
            raise WebSecretFixtureApiPreservationReadError()
        witness, body = self._read_once(max_deadline=max_deadline)
        assert body is None
        return cast(PolicyAssignmentPreservation, witness)

    def read_instruction_update_once(self, proposed_reference: str, *, max_deadline: float | None = None
            ) -> tuple[SecretInstructionBuild29ApiPreservationWitness, bytearray]:
        """Private normal-fixture projection, only at fixed Instruction read phases."""
        if (self._policy_name is not None or self._phase not in {"instruction-attach-current", "instruction-attach-dispatch",
                "instruction-restore-current", "instruction-restore-dispatch"}
                or self._record._ack_capture is None or self._record._ack_capture.observe_source
                or type(proposed_reference) is not str
                or proposed_reference and _NAME.fullmatch(proposed_reference) is None
                or bool(proposed_reference) == bool(self._reference)):
            raise WebSecretFixtureApiPreservationReadError()
        witness, body = self._read_once(max_deadline=max_deadline, proposed_reference=proposed_reference)
        assert body is not None
        return cast(SecretInstructionBuild29ApiPreservationWitness, witness), body

    def _read_once(self, *, max_deadline: float | None = None, proposed_reference: str | None = None
            ) -> tuple[SecretInstructionBuild29ApiPreservationWitness | PolicyAssignmentPreservation, bytearray | None]:
        """Perform at most seven fixed requests; failure never retries in this instance.

        The original record and M4 are checked before the client, each request,
        and publication. All buffers and HTTP resources close before returning a
        private middle-frame witness. A permanent phase attempt precedes HTTP;
        neither the creation record nor original M4 is changed.
        """
        if self._policy_name is not None and proposed_reference is not None:
            raise WebSecretFixtureApiPreservationReadError()
        with self._lock:
            if self._started:
                raise WebSecretFixtureApiPreservationReadError()
            self._started = True
        key, core, scratch = bytearray(), bytearray(), bytearray()
        body: bytearray | None = None
        succeeded = False
        client: httpx.Client | None = None
        responses: list[httpx.Response] = []
        previous: float | None = None
        try:
            if max_deadline is not None and (type(max_deadline) not in (int, float)
                    or not math.isfinite(max_deadline) or max_deadline < 0):
                raise ValueError
            evidence = self._original_record()
            self._reserve()
            baseline = json.loads(evidence.baseline_json)
            identity = {name: baseline[name] for name in _IDENTITY}
            route = "/api/v2/cmdb/secret/database/" + str(evidence.native_secret_id)
            key.extend(hmac.new(self._record._key,
                b"web-fixture-api-witness/v1\0" + self._record._namespace.encode("ascii"), hashlib.sha256).digest())

            def now() -> float:
                nonlocal previous
                value = self._clock()
                if (type(value) not in (int, float) or not math.isfinite(value) or value < 0
                        or previous is not None and value < previous):
                    raise ValueError
                previous = value
                return value

            deadline = now() + min(30.0, self._config.timeout_seconds)
            if max_deadline is not None:
                deadline = min(deadline, max_deadline)

            def remaining() -> float:
                value = deadline - now()
                if value <= 0:
                    raise ValueError
                return min(10.0, value)

            context = _ssl_context(self._config)
            if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
                raise ValueError
            context.minimum_version = ssl.TLSVersion.TLSv1_2

            def detail(raw: bytearray) -> tuple[int, str]:
                field = bytearray()
                try:
                    left, right, _, field_id, shared = _qualify_web_detail(raw, identity=identity,
                        serial_digest=evidence.serial_digest, instruction_profile_name=self._reference, field=field)
                    spans = metadata._object_spans(raw, left, right, frozenset(baseline))
                    expected = {**baseline, "instruction-profile": self._reference}
                    for name, value in expected.items():
                        actual = metadata._scalar(raw, spans[name])
                        if type(actual) is not type(value) or actual != value:
                            raise ValueError
                    if self._policy_name is not None:
                        policy = metadata._object_spans(raw, left, right, frozenset({"policy"}))["policy"]
                        if metadata._scalar(raw, policy) != self._policy_name:
                            raise ValueError
                    # Internal framing guard only, not standalone material evidence.
                    digest = hmac.new(key, b"web-fixture-framing/v1\0", hashlib.sha256)
                    first, last = shared
                    with memoryview(raw)[left:first] as view:
                        digest.update(view)
                    digest.update(b'"qualified-totp-render-excluded"')
                    with memoryview(raw)[last:right] as view:
                        digest.update(view)
                    return field_id, digest.hexdigest()
                finally:
                    _zeroize_mutable(field)

            with _private_http_logs(), self._factory(verify=context, timeout=remaining(),
                    follow_redirects=False, trust_env=False) as client:
                def request(method: str, path: str, raw: bytearray, body: dict[str, int] | None = None) -> None:
                    self._original_record()
                    remaining()
                    _zeroize_mutable(raw)
                    client.cookies.clear()
                    headers = {"Authorization": "Bearer " + self._config.bearer_token,
                        "Accept": "application/json", "Accept-Encoding": "identity", "Cache-Control": "no-store",
                        "Connection": "close", "X-Requested-With": "XMLHttpRequest"}
                    try:
                        url = self._config.base_url.rstrip("/") + path
                        stream = (client.stream(method, url, headers=headers, timeout=remaining(), json=body)
                                  if body is not None else client.stream(method, url, headers=headers, timeout=remaining()))
                        with stream as response:
                            responses.append(response)
                            remaining()
                            if (response.status_code != 200
                                    or response.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json"
                                    or response.headers.get("content-encoding", "identity") not in ("", "identity")):
                                raise ValueError
                            limit = 524_288 if method == "GET" else 16_384
                            iterator = response.iter_raw()
                            while True:
                                remaining()
                                try:
                                    chunk = next(iterator)
                                except StopIteration:
                                    remaining()
                                    break
                                remaining()
                                if len(raw) + len(chunk) > limit:
                                    raise ValueError
                                raw.extend(chunk)
                    finally:
                        client.cookies.clear()
                    remaining()
                    if not response.is_closed:
                        raise ValueError

                def password(field_id: int) -> SecretInstructionBuild29CredentialWitness:
                    request("POST", _CLEAR, scratch, {"secret-id": evidence.native_secret_id, "field-id": field_id})
                    if self._phase in {"source", "reconciliation"} and not self._credential_envelope:
                        self._credential_envelope = self._observe_envelope(scratch, credential=True)
                    return consume_secret_instruction_build29_credential_response(scratch,
                        expected_secret_id=evidence.native_secret_id, expected_field_id=field_id, http_status=200,
                        content_type="application/json", expected_envelope=self._credential_envelope, witness_key=key)

                def totp() -> SecretApprovalBuild29TotpWitness:
                    request("POST", _CLEAR, scratch, {"secret-id": evidence.native_secret_id, "totp-share-key": 1})
                    if self._phase in {"source", "reconciliation"} and not self._totp_envelope:
                        self._totp_envelope = self._observe_envelope(scratch)
                    witness = consume_secret_approval_build29_totp_response(scratch, http_status=200,
                        content_type="application/json", expected_envelope=self._totp_envelope, witness_key=key)
                    if witness.explicit_empty is not True:
                        raise ValueError
                    return witness

                try:
                    request("GET", route, scratch)
                    field_id, framing = detail(scratch)
                    _zeroize_mutable(scratch)
                    credential_before = password(field_id)
                    totp_before = totp()
                    request("GET", route, core)
                    if detail(core) != (field_id, framing):
                        raise ValueError
                    totp_after = totp()
                    _qualify_bracket(totp_before, totp_after, key)
                    credential_after = password(field_id)
                    _credential_bracket(credential_before, credential_after,
                        secret_id=evidence.native_secret_id, field_id=field_id, key=key)
                    request("GET", route, scratch)
                    if detail(scratch) != (field_id, framing):
                        raise ValueError
                finally:
                    client.cookies.clear()
            remaining()
            if (not client.is_closed or client.cookies or len(responses) != 7
                    or any(not response.is_closed for response in responses)):
                raise ValueError
            self._original_record()
            result: SecretInstructionBuild29ApiPreservationWitness | PolicyAssignmentPreservation
            if self._policy_name is None:
                result = consume_secret_instruction_build29_api_preservation(core, identity=identity,
                    serial_digest=evidence.serial_digest, instruction_profile_name=self._reference,
                    credential_before=credential_before, credential_after=credential_after,
                    totp_before=totp_before, totp_after=totp_after, witness_key=key)
            else:
                result = consume_policy_assignment_preservation(core, identity=identity,
                    serial_digest=evidence.serial_digest, expected_policy_name=self._policy_name,
                    credential_before=credential_before, credential_after=credential_after,
                    totp_before=totp_before, totp_after=totp_after, witness_key=key)
            remaining()
            self._original_record()
            if proposed_reference is not None:
                from .secret_instruction_build29_retained_fields import compile_instruction_retained_web_body
                body = compile_instruction_retained_web_body(scratch, identity=identity,
                    serial_digest=evidence.serial_digest, current_reference=self._reference,
                    proposed_reference=proposed_reference)
                remaining()
                self._original_record()
            self._source_completed = self._phase in {"source", "reconciliation"}
            if self._source_completed:
                self._source_result = cast(SecretInstructionBuild29ApiPreservationWitness, result)
            succeeded = True
            return result, body
        except Exception:
            raise WebSecretFixtureApiPreservationReadError() from None
        finally:
            if not succeeded and body is not None:
                _zeroize_mutable(body)
            for buffer in (key, core, scratch):
                _zeroize_mutable(buffer)
