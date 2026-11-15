"""Default-closed same-process Instruction association and original-ACK restore.

Trusted lab composition joins the original normal Web lifecycle and original
successful Profile creation. Each phase has a separate one-time M4 grant,
durable attempt, original native ACK and full independent material readback.
No Tool, environment/main activation, source-status qualification or browser
acceptance is supplied. Unknown effects never acquire restore authority.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
import hashlib
import hmac
import http.client
import json
import math
import os
import secrets
import ssl
import stat
from threading import RLock
from typing import Any, Literal
from urllib.parse import urlsplit

from v4_planning import (M4AdapterAmbiguous, M4AdapterDenied, M4ClaimState,
    M4ExecutionAuthorization, M4ExecutionKernel, M4ExecutionPlan, canonical_digest)
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_ref
from .instruction_profile_live_workflow import InstructionProfileLiveWorkflow
from .instruction_profile_contract import InstructionProfileCreatePlan
from .secret_instruction_build29_api_preservation import SecretInstructionBuild29ApiPreservationWitness
from .secret_instruction_build29_contract import (
    compile_secret_instruction_build29_attach_body,
    qualify_secret_instruction_build29_schema,
)
from .secret_instruction_build29_put_ack import (
    SecretInstructionBuild29PutAckPins, consume_secret_instruction_build29_put_ack,
)
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig, _ssl_context, _zeroize_mutable
from .target_api_dependency_reader import _private_http_logs
from .v4_plan_runtime import V4PlanningPrincipal
from .web_secret_fixture_api_preservation_reader import WebSecretFixtureApiPreservationReader
from .web_secret_fixture_lifecycle import WebSecretFixtureLifecycleFactory, _FixtureRunner
from .web_secret_fixture_creation_record import WebSecretFixtureCreationRecord, WebSecretFixtureAcknowledgedCreation
from .web_secret_fixture_recovery_guard import WebSecretFixtureRecoveryGuard

CONTRACT = "fortipam-build29-owned-web-instruction-association/v2"
_DOMAIN = b"fortipam-owned-web-instruction-lab-auto/v2\x00"
_ERROR = "The private Web Secret Instruction workflow is unavailable."
_SUCCESS = {"outcome": "succeeded", "verification": "verified",
    "compensation": "not_requested", "idempotent_replay": False}


class WebSecretInstructionWorkflowError(ValueError):
    """Categorical refusal without object, content or material values."""


class WebSecretInstructionWorkflow(_OpaqueC3Object):
    """One normally admitted fixture and Profile, one attach and one restore.

    The PUT TLS connection opens before a fresh complete Secret/material read
    and full owned Profile read. This is bounded drift rejection, not atomic
    backend CAS. Restore additionally needs this instance's sealed attach ACK,
    exact signed successful attach claim and complete applied preservation.
    """
    _lifecycle: WebSecretFixtureLifecycleFactory
    _runner: _FixtureRunner
    _guard: WebSecretFixtureRecoveryGuard
    _record: WebSecretFixtureCreationRecord
    _original: WebSecretFixtureAcknowledgedCreation
    _profile: InstructionProfileLiveWorkflow
    _principal: V4PlanningPrincipal
    _identity: dict[str, str]
    _config: SecretMetadataHttpTransportConfig
    _name: str
    _profile_binding: InstructionProfileCreatePlan
    _source: str
    _baseline: SecretInstructionBuild29ApiPreservationWitness
    _schema: Any
    _schema_digest: str
    _key: bytes
    _status: Literal["OK", "success"]
    _enabled: bool
    _factory: Callable[..., Any]
    _factory_pin: Callable[..., Any]
    _namespace: dict[str, str]
    _creation_row: dict[str, object]
    _object_identity: dict[str, object]
    _body: dict[str, str]
    _parameters: str
    _state: str
    _attach: _Phase | None
    _phase: _Phase | None
    _lock: Any
    _readers: dict[str, tuple[WebSecretFixtureApiPreservationReader, WebSecretFixtureApiPreservationReader]]

    def __init__(self, lifecycle: WebSecretFixtureLifecycleFactory, profile: InstructionProfileLiveWorkflow, *,
            schema: object, authority_key: bytes, environment_ref: str, scope_ref: str, audience_ref: str,
            success_status: Literal["OK", "success"], execution_enabled: bool = False,
            connection_factory: Callable[..., Any] = http.client.HTTPSConnection) -> None:
        try:
            if (type(lifecycle) is not WebSecretFixtureLifecycleFactory or type(profile) is not InstructionProfileLiveWorkflow
                    or type(authority_key) is not bytes or not 32 <= len(authority_key) <= 4096
                    or type(execution_enabled) is not bool or not callable(connection_factory)
                    or type(success_status) is not str or success_status not in {"OK", "success"}):
                raise ValueError
            for ref in (environment_ref, scope_ref, audience_ref): require_ref(ref, "namespace_ref")
            qualify_secret_instruction_build29_schema(schema)
            lifecycle._current()
            runner = lifecycle._runner
            if runner is None or runner._state != "baseline" or runner._guard_source is None:
                raise ValueError
            guard = runner._guard_source
            guard._guard()
            record = guard._record
            if (guard._state != "baseline" or guard._witness is None
                    or guard._reconciled_source is not None or guard._source_observer is not None
                    or record._ack_capture is None or record._ack_capture.observe_source
                    or (environment_ref, scope_ref) != lifecycle._namespace[:2]
                    or (environment_ref, scope_ref) != (profile._authority._namespace["environment_ref"],
                        profile._authority._namespace["scope_ref"])
                    or profile._transport._config != record._config
                    or profile._transport._serial_digest != guard._original.creation.serial_digest
                    or not 32 <= len(record._key) <= 128 or authority_key == record._key):
                raise ValueError
            principal = runner._principal
            identity = dict(requester_digest=principal.requester.digest,
                transport_digest=principal.transport_namespace_digest)
            profile.check_original_creation(**identity)
            self._lifecycle, self._runner, self._guard = lifecycle, runner, guard
            self._record, self._original, self._profile, self._principal = record, guard._original, profile, principal
            self._identity, self._config, self._name = identity, record._config, profile._binding._name
            self._profile_binding, self._source, self._baseline = profile._binding, guard._source, guard._witness
            self._schema = json.loads(json.dumps(schema, allow_nan=False))
            self._schema_digest = hashlib.sha256(json.dumps(self._schema, sort_keys=True).encode()).hexdigest()
            self._key, self._status, self._enabled = authority_key, success_status, execution_enabled
            self._factory = self._factory_pin = connection_factory
            self._namespace = dict(environment_ref=environment_ref, scope_ref=scope_ref, audience_ref=audience_ref)
            self._creation_row = json.loads(self._original.creation.baseline_json)
            self._object_identity = {key: self._creation_row[key] for key in ("id", "name", "folder", "template")}
            self._body = compile_secret_instruction_build29_attach_body(self._metadata(""), schema=self._schema,
                identity=self._object_identity, instruction_profile_name=self._name)
            self._parameters = self._parameters_digest()
            self._state, self._attach, self._phase = "new", None, None
            self._lock = RLock()
            self._readers = {
                "attach": (self._reader("instruction-attach-current", ""), self._reader("instruction-attach-dispatch", "")),
                "restore": (self._reader("instruction-restore-current", self._name),
                    self._reader("instruction-restore-dispatch", self._name)),
            }
            self._unconsumed()
            lifecycle.bind_instruction_profile(self._name, principal)
            self._local()
        except Exception:
            raise WebSecretInstructionWorkflowError(_ERROR) from None

    def _metadata(self, reference: str) -> dict[str, object]:
        return {"version": "v7.0.0", "build": 29,
            "results": {**self._object_identity, "instruction-profile": reference}}

    def _reader(self, phase: Any, reference: str) -> WebSecretFixtureApiPreservationReader:
        return WebSecretFixtureApiPreservationReader(self._record, instruction_profile_name=reference,
            credential_envelope=self._guard._baseline._credential_envelope,
            totp_envelope=self._guard._baseline._totp_envelope, phase=phase,
            client_factory=self._guard._factory, clock=self._guard._http_clock)

    def _local(self) -> None:
        self._lifecycle._current()
        self._guard._guard()
        if (self._lifecycle._runner is not self._runner or self._runner._guard_source is not self._guard
                or self._guard._record is not self._record or self._record._config != self._config
                or self._profile._transport._config != self._config or self._profile._binding is not self._profile_binding
                or self._profile._transport._serial_digest != self._original.creation.serial_digest
                or self._profile._binding._name != self._name or self._guard._source != self._source
                or self._guard._witness != self._baseline or self._guard._transition_reference != self._name
                or self._record.read_acknowledged_creation() != self._original or self._factory is not self._factory_pin
                or self._guard._source_observer is not None or self._guard._reconciled_source is not None
                or self._record._ack_capture is None or self._record._ack_capture.observe_source
                or hashlib.sha256(json.dumps(self._schema, sort_keys=True).encode()).hexdigest() != self._schema_digest
                or self._parameters_digest() != self._parameters
                or self._object_identity != {key: json.loads(self._original.creation.baseline_json)[key]
                    for key in ("id", "name", "folder", "template")}):
            raise ValueError
        if set(self._readers) != {"attach", "restore"}: raise ValueError
        for phase, readers in self._readers.items():
            if phase not in {"attach", "restore"}: raise ValueError
            for reader, stage in zip(readers, ("current", "dispatch"), strict=True):
                if (type(reader) is not WebSecretFixtureApiPreservationReader or reader._record is not self._record
                        or reader._config != self._config or reader._factory is not self._guard._factory
                        or reader._clock is not self._guard._http_clock or reader._phase != "instruction-" + phase + "-" + stage
                        or reader._reference != (self._name if phase == "restore" else "")
                        or reader._credential_envelope != self._guard._baseline._credential_envelope
                        or reader._totp_envelope != self._guard._baseline._totp_envelope): raise ValueError
                if reader._started: reader._check_attempt()
        self._profile.check_original_creation(**self._identity)

    def _parameters_digest(self) -> str:
        return canonical_digest({"contract": CONTRACT, **self._namespace,
            "creation": self._original.creation.creation_digest, "source": self._source,
            "profile": self._profile._binding.digest, "schema": self._schema_digest,
            "body": hashlib.sha256(json.dumps(self._body, separators=(",", ":")).encode()).hexdigest(),
            "status": self._status, **self._identity})

    def _unconsumed(self) -> None:
        directory = self._record._directory_fd()
        try:
            for phase in ("attach", "restore"):
                for name in (f"instruction.{phase}.attempt", f"instruction.{phase}.ack"):
                    try: os.stat(name, dir_fd=directory, follow_symlinks=False)
                    except FileNotFoundError: continue
                    raise ValueError
                if any(reader._started for reader in self._readers[phase]): raise ValueError
                for reader in self._readers[phase]:
                    try: os.stat("api-preservation." + reader._phase + ".attempt", dir_fd=directory, follow_symlinks=False)
                    except FileNotFoundError: continue
                    raise ValueError
        finally:
            os.close(directory)

    def _write(self, name: str, payload: bytes) -> tuple[int, int]:
        directory = self._record._directory_fd()
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload); stream.flush(); os.fsync(stream.fileno())
                info = os.fstat(stream.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                        or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size != len(payload)): raise ValueError
            os.fsync(directory)
            return info.st_dev, info.st_ino
        finally:
            os.close(directory)

    def _file(self, name: str, identity: tuple[int, int] | None, payload: bytes | None) -> None:
        directory, fd = self._record._directory_fd(), None
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            info = os.fstat(fd)
            if (payload is None or (info.st_dev, info.st_ino) != identity or not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.getuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_size != len(payload) or not hmac.compare_digest(os.read(fd, len(payload) + 1), payload)):
                raise ValueError
            after = os.fstat(fd)
            linked = os.stat(name, dir_fd=directory, follow_symlinks=False)
            def stable(item: os.stat_result) -> tuple[int, ...]:
                return (item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_nlink,
                    item.st_size, item.st_mtime_ns, item.st_ctime_ns)
            if stable(after) != stable(info) or (linked.st_dev, linked.st_ino) != identity: raise ValueError
        finally:
            try:
                if fd is not None: os.close(fd)
            finally: os.close(directory)

    def _original_attach(self) -> None:
        phase = self._attach
        if (phase is None or phase.owner is not self or phase.name != "attach"
                or not phase.acknowledged or not phase.post_verified
                or (phase.plan, phase.authorization) != phase.derive()
                or phase.marker != phase.attempt_payload()): raise ValueError
        self._file("instruction.attach.attempt", phase.marker_identity, phase.marker)
        self._file("instruction.attach.ack", phase.ack_identity, phase.ack)
        phase.check_claim(successful=True)

    def _read_body(self, reader: WebSecretFixtureApiPreservationReader, reference: str,
            *, deadline: float | None = None) -> bytearray:
        body = bytearray()
        try:
            self._local()
            witness, body = reader.read_instruction_update_once(reference, max_deadline=deadline)
            if witness.preservation_digest != self._baseline.preservation_digest: raise ValueError
            self._local()
            return body
        except BaseException:
            _zeroize_mutable(body)
            raise

    def attach_once(self, principal: V4PlanningPrincipal) -> Mapping[str, object]:
        return self._execute("attach", principal)

    def restore_once(self, principal: V4PlanningPrincipal) -> Mapping[str, object]:
        return self._execute("restore", principal)

    def _execute(self, phase_name: Literal["attach", "restore"], principal: V4PlanningPrincipal) -> Mapping[str, object]:
        with self._lock, self._runner._lock:
            body = bytearray()
            try:
                if (not self._enabled or type(principal) is not V4PlanningPrincipal
                        or (principal.requester.digest, principal.transport_namespace_digest) !=
                           (self._identity["requester_digest"], self._identity["transport_digest"])
                        or self._state != ("new" if phase_name == "attach" else "applied")
                        or self._runner._state != ("baseline" if phase_name == "attach" else "applied")):
                    raise ValueError
                self._local()
                if phase_name == "restore": self._original_attach()
                self._state = "reading-" + phase_name
                started = self._guard._now()
                profile = self._profile.inspect_owned_reference_state(
                    expected_reference_count=0 if phase_name == "attach" else 1, **self._identity)
                body = self._read_body(self._readers[phase_name][0], self._name if phase_name == "attach" else "")
                phase = _Phase(self, phase_name, profile, started, body)
                self._phase = phase
                phase.reserve()
                result = M4ExecutionKernel(phase, phase, self._record._execution_store,
                    clock=self._guard._now).execute(phase.plan, phase.authorization).as_dict()
                if result == _SUCCESS:
                    if phase_name == "attach": self._attach = phase
                    self._state = "applied" if phase_name == "attach" else "restored"
                else: self._state = "failed"
                return result
            except Exception:
                if self._state.startswith("reading-"): self._state = "failed"
                raise WebSecretInstructionWorkflowError(_ERROR) from None
            finally:
                _zeroize_mutable(body)
                try:
                    if self._phase is not None: self._phase.close_connection()
                except Exception:
                    raise WebSecretInstructionWorkflowError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._enabled, self._key = False, b""
            if self._phase is not None: self._phase.close_connection()


class _Phase:
    plan: M4ExecutionPlan
    authorization: M4ExecutionAuthorization
    marker_identity: tuple[int, int] | None
    ack_identity: tuple[int, int] | None
    marker: bytes | None
    ack: bytes | None
    def __init__(self, owner: WebSecretInstructionWorkflow, name: Literal["attach", "restore"],
            profile_digest: str, created_at: int, body: bytearray) -> None:
        self.owner = owner
        self.name: Literal["attach", "restore"] = name
        self.profile_digest = profile_digest
        self.created_at, self.expires_at, self.nonce = created_at, created_at + 60, secrets.token_hex(24)
        self.authorized = self.acknowledged = self.post_verified = False
        self.connection: Any = None
        self.socket: Any = None
        self.marker_identity = self.ack_identity = None
        self.marker = self.ack = None
        self.last_http: float | None = None
        self.deadline: float | None = None
        self.body = body
        self.body_digest = self.body_mac(body)
        self.plan, self.authorization = self.derive()

    def body_mac(self, body: bytearray) -> str:
        digest = hmac.new(self.owner._key, _DOMAIN + b"retained-body\x00", hashlib.sha256)
        digest.update(body)
        return digest.hexdigest()

    def derive(self) -> tuple[M4ExecutionPlan, M4ExecutionAuthorization]:
        owner = self.owner
        context = {"contract": CONTRACT, "phase": self.name, "parameters": owner._parameters,
            "profile": self.profile_digest, "nonce": self.nonce, "created": self.created_at,
            "expires": self.expires_at, "body": self.body_digest}
        def mac(purpose: str, value: object) -> str:
            return hmac.new(owner._key, _DOMAIN + purpose.encode() + b"\x00" +
                json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(), hashlib.sha256).hexdigest()
        def state(assigned: bool) -> str:
            return canonical_digest({"creation": owner._original.creation.creation_digest,
                "preservation": owner._baseline.preservation_digest if owner._baseline else "unavailable",
                "profile": owner._profile_binding.digest, "assigned": assigned})
        values: dict[str, Any] = dict(plan_ref="web-instruction-plan-" + mac("plan", context), revision=1,
            action_id="web-secret-instruction-" + self.name, action_version="2.0.0",
            adapter_ref="fortipam-build29-web-instruction-" + self.name + "-v2",
            target_ref="web-instruction-" + owner._original.creation.creation_digest[:40],
            requester_digest=owner._identity["requester_digest"], summary_digest=mac("summary", context),
            confirmation_digest=mac("standing-intent", context), approval_digest=mac("lab-policy", context),
            parameters_digest=canonical_digest(context), expected_current_digest=state(self.name == "restore"),
            expected_state_digest=state(self.name == "attach"), idempotency_digest=mac("idempotency", context),
            expires_at=self.expires_at, compensation_ref=None)
        plan = M4ExecutionPlan(**values, plan_digest=canonical_digest(values))
        signed = {**context, "plan": plan.plan_digest}
        auth: dict[str, Any] = dict(authorization_ref="web-instruction-auth-" + mac("authorization", signed),
            plan_ref=plan.plan_ref, plan_digest=plan.plan_digest, requester_digest=plan.requester_digest,
            confirmation_ref="web-instruction-intent-" + mac("intent", signed), confirmation_digest=plan.confirmation_digest,
            approval_ref="web-instruction-policy-" + mac("policy", signed), approval_digest=plan.approval_digest,
            approver_digest=mac("authority", owner._namespace), issued_at=self.created_at, expires_at=self.expires_at,
            one_time=True, execution_authorized=True)
        return plan, M4ExecutionAuthorization(**auth, authorization_digest=canonical_digest(auth))

    def check(self) -> None:
        owner = self.owner
        owner._local()
        expected = "applied" if self.name == "restore" else "baseline"
        if self.post_verified: expected = "baseline" if self.name == "restore" else "applied"
        if (not owner._enabled or owner._phase is not self
                or (self.plan, self.authorization) != self.derive()
                or not self.created_at <= owner._guard._now() < self.expires_at
                or owner._runner._state != expected or owner._guard._state != expected): raise ValueError
        if self.name == "restore": owner._original_attach()
        if self.marker is not None: owner._file("instruction." + self.name + ".attempt", self.marker_identity, self.marker)
        if self.acknowledged: owner._file("instruction." + self.name + ".ack", self.ack_identity, self.ack)

    def reserve(self) -> None:
        self.check()
        self.marker = self.attempt_payload()
        self.marker_identity = self.owner._write("instruction." + self.name + ".attempt", self.marker)
        self.check()

    def attempt_payload(self) -> bytes:
        return hmac.new(self.owner._record._key, _DOMAIN + b"attempt\x00" + self.name.encode() +
            self.owner._record._namespace.encode() + self.plan.plan_digest.encode() +
            self.authorization.authorization_digest.encode(), hashlib.sha256).hexdigest().encode()

    def check_claim(self, *, successful: bool = False) -> None:
        claim = self.owner._record._execution_store.inspect_claim(plan_ref=self.plan.plan_ref,
            requester_digest=self.plan.requester_digest, idempotency_digest=self.plan.idempotency_digest,
            authorization_digest=self.authorization.authorization_digest,
            context_digest=canonical_digest({"authorization_digest": self.authorization.authorization_digest,
                "plan_digest": self.plan.plan_digest, "revision": self.plan.revision}))
        if successful:
            if claim.state is not M4ClaimState.REPLAY or claim.result is None or claim.result.as_dict() != _SUCCESS:
                raise ValueError
        elif claim.state is not M4ClaimState.IN_PROGRESS: raise ValueError

    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        self.check()
        if (self.authorized or plan is not self.plan or authorization is not self.authorization
                or type(now_epoch) is not int or not self.created_at <= now_epoch <= self.owner._guard._now() < self.expires_at):
            raise ValueError
        self.check_claim()
        self.authorized = True

    def now_http(self) -> float:
        value = self.owner._guard._http_clock()
        if (type(value) not in (int, float) or not math.isfinite(value) or value < 0
                or self.last_http is not None and value < self.last_http): raise ValueError
        self.last_http = value
        return value

    def remaining(self) -> float:
        self.check()
        if self.deadline is None: raise ValueError
        value = min(self.deadline - self.now_http(), self.expires_at - self.owner._guard._now())
        if value <= 0: raise ValueError
        return min(10., value)

    def close_connection(self) -> None:
        try:
            if self.connection is not None: self.connection.close()
        finally:
            self.connection = self.socket = None
            _zeroize_mutable(self.body)

    def read_current(self, plan: M4ExecutionPlan) -> str:
        try:
            self.check()
            if not self.authorized or plan is not self.plan: raise ValueError
            self.deadline = self.now_http() + min(30., self.owner._config.timeout_seconds)
            context = _ssl_context(self.owner._config)
            if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED: raise ValueError
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            origin = urlsplit(self.owner._config.base_url)
            self.connection = self.owner._factory(origin.hostname, origin.port or 443, context=context, timeout=self.remaining())
            self.connection.connect(); self.socket = self.connection.sock
            if self.socket is None: raise ValueError
            current = self.owner._profile.inspect_owned_reference_state(
                expected_reference_count=0 if self.name == "attach" else 1, **self.owner._identity)
            if current != self.profile_digest: raise ValueError
            fresh = self.owner._read_body(self.owner._readers[self.name][1],
                self.owner._name if self.name == "attach" else "", deadline=self.deadline)
            try:
                if not hmac.compare_digest(self.body_mac(fresh), self.body_digest): raise ValueError
            finally:
                _zeroize_mutable(fresh)
            self.remaining()
            return plan.expected_current_digest
        except Exception:
            raise M4AdapterDenied(_ERROR) from None

    def _record_failure(self, stage: str, error: Exception, status: int | None = None) -> None:
        # Diagnostic metadata never renews a grant or substitutes for a native ACK.
        try:
            value = {"phase": self.name, "stage": stage, "error_class": type(error).__name__,
                "http_status": status, "execution_authority": False, "raw_values_returned": False}
            self.owner._write("instruction." + self.name + ".failure.json",
                json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii"))
        except Exception:
            pass

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        response = None
        stage, status = "dispatch_guard", None
        raw, chunk = bytearray(), bytearray(4096)
        try:
            self.check()
            if (not self.authorized or plan is not self.plan or self.connection is None
                    or self.connection.sock is not self.socket or self.body_mac(self.body) != self.body_digest
                    or not self.owner._readers[self.name][1]._started): raise ValueError
            self.socket.settimeout(self.remaining())
            with _private_http_logs(), memoryview(self.body) as body:
                stage = "send_put"
                self.connection.request("PUT", "/api/v2/cmdb/secret/database/" + str(self.owner._original.creation.native_secret_id),
                    body=body, headers={"Authorization": "Bearer " + self.owner._config.bearer_token,
                        "Content-Type": "application/json", "Accept": "application/json", "Accept-Encoding": "identity",
                        "Connection": "close", "User-Agent": "fortipam-mcp-owned-web-instruction/1"})
                stage = "receive_headers"
                self.remaining(); response = self.connection.getresponse(); self.remaining()
                if type(response.status) is int and 100 <= response.status <= 599: status = response.status
                stage = "qualify_headers"
                if (response.status != 200 or response.getheader("Content-Encoding") not in (None, "", "identity")
                        or response.getheader("Transfer-Encoding") not in (None, "")): raise ValueError
                stage = "read_body"
                length = response.getheader("Content-Length")
                if length is not None and (type(length) is not str or not length.isascii()
                        or not length.isdecimal() or len(length) > 5 or int(length) > 16_384):
                    raise ValueError
                expected_length = None if length is None else int(length)
                for _ in range(4096):
                    if response.isclosed(): break
                    self.socket.settimeout(self.remaining())
                    with memoryview(chunk)[:min(len(chunk), 16_385 - len(raw))] as view:
                        count = response.readinto1(view)
                        if type(count) is not int or not 0 <= count <= len(view): raise ValueError
                        raw.extend(view[:count])
                    self.remaining()
                    if len(raw) > 16_384: raise ValueError
                    if count == 0: break
                else: raise ValueError
                if expected_length is not None and len(raw) != expected_length:
                    raise ValueError
                stage = "qualify_ack"
                pins = SecretInstructionBuild29PutAckPins(self.owner._original.creation.native_secret_id,
                    self.owner._original.creation.serial_digest, self.owner._original.creation.creation_digest,
                    self.owner._name, self.name, plan.plan_digest, self.authorization.authorization_digest,
                    self.owner._status, retained_body_digest=self.body_digest)
                witness = consume_secret_instruction_build29_put_ack(raw, pins=pins, http_status=response.status,
                    content_type=response.getheader("Content-Type", ""), witness_key=self.owner._record._key)
            stage = "seal_ack"
            response.close(); response = None
            self.close_connection()
            self.remaining()
            if self.marker is None: raise ValueError
            self.ack = hmac.new(self.owner._record._key, _DOMAIN + b"native-ack\x00" + self.marker +
                witness.context_digest.encode() + witness.acknowledgement_digest.encode(), hashlib.sha256).hexdigest().encode()
            self.ack_identity = self.owner._write("instruction." + self.name + ".ack", self.ack)
            self.acknowledged = True
            self.check()
        except Exception as exc:
            self._record_failure(stage, exc, status)
            raise M4AdapterAmbiguous(_ERROR) from None
        finally:
            _zeroize_mutable(raw); _zeroize_mutable(chunk)
            try:
                if response is not None: response.close()
            finally: self.close_connection()

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        try:
            self.check()
            if not self.acknowledged or plan is not self.plan: raise ValueError
            self.owner._profile.inspect_owned_reference_state(
                expected_reference_count=1 if self.name == "attach" else 0, **self.owner._identity)
            if self.name == "attach": self.owner._lifecycle.check_instruction_applied_once(self.owner._principal)
            else: self.owner._lifecycle.check_instruction_restored_once(self.owner._principal)
            self.post_verified = True
            self.check()
            return plan.expected_state_digest
        except Exception as exc:
            self._record_failure("read_postcondition", exc)
            raise M4AdapterAmbiguous(_ERROR) from None
