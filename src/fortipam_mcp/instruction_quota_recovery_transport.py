"""Default-closed native transport for one independent incident correction.

Canonical fixed files live beside the original records under the same existing
object lock. They never overwrite/adopt the old restore claim or UNKNOWN. An
uncertain new dispatch is consumed across reopens, keys, plans and nonces. This
private adapter has no policy issuer, startup/Tool or live execution authority.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import ssl
import stat
from typing import Any
from urllib.parse import urlsplit

from v4_planning import M4ExecutionAuthorization, M4ExecutionPlan, canonical_digest

from .mutable_json_buffer import _take_mutable_prefix
from . import secret_bulk_import_metadata as m
from . import target_lifecycle_dependencies as d
from .instruction_feature_contract import _fingerprint, _require_digest
from .instruction_quota_contract import InstructionQuotaState, _Private
from .instruction_quota_http_transport import FortiPamInstructionQuotaHttpTransport, _members
from .instruction_quota_recovery_contract import (
    ACTION, ADAPTER, VERSION, InstructionQuotaBaselineRecoveryCandidate,
    _build_locked, _check_postcondition_locked, _guard,
)
from .instruction_resource_usage import InstructionResourceUsage
from .secret_metadata_http_transport import (
    _json_value_end, _skip_json_space, _ssl_context, _zeroize_mutable,
)

CONTRACT = "fortipam-700-build29-instruction-quota-incident-correction-native-v1"
_PREFIX = "instruction-quota-incident-baseline-correction"
_FILES = frozenset(_PREFIX + suffix for suffix in (".claim.json", ".ack.json", ".result.json"))
_PATH = "/api/v2/cmdb/secret/setting"
_ERROR = "The private Instruction quota incident transport is unavailable."
_STAGES = frozenset({"initialization", "lock", "precondition", "authorization", "connect",
    "claim", "put", "ack_validation", "ack_persistence", "postcondition", "cleanup"})


class InstructionQuotaRecoveryTransportError(RuntimeError):
    """A fixed safe category, never exception text or raw native content."""

    def __init__(self, stage: str) -> None:
        super().__init__(_ERROR)
        self.stage = stage if stage in _STAGES else "authorization"


class FortiPamInstructionQuotaRecoveryTransport(_Private):
    """One fixed PUT guarded by a separately supplied trusted server verifier."""

    __slots__ = ("_candidate", "_original", "_key", "_namespace", "_config_pin",
                 "_enabled", "_lock_pin")
    _candidate: InstructionQuotaBaselineRecoveryCandidate
    _original: FortiPamInstructionQuotaHttpTransport
    _key: bytes
    _namespace: str
    _config_pin: str
    _enabled: bool
    _lock_pin: tuple[int, int] | None

    def __init__(self, candidate: InstructionQuotaBaselineRecoveryCandidate, *,
            state_key: bytes, execution_enabled: bool = False) -> None:
        try:
            if (type(candidate) is not InstructionQuotaBaselineRecoveryCandidate
                    or type(state_key) is not bytes or not 32 <= len(state_key) <= 4096
                    or type(execution_enabled) is not bool):
                raise ValueError
            workflow = candidate._reconciler._workflow
            if any(hmac.compare_digest(state_key, key) for key in (workflow._transport._key,
                    workflow._authority._key,
                    workflow._execution_store._key, workflow._original_store._key if workflow._original_store else b"")):
                raise ValueError
            object.__setattr__(self, "_candidate", candidate)
            object.__setattr__(self, "_original", workflow._transport)
            object.__setattr__(self, "_key", state_key)
            object.__setattr__(self, "_enabled", execution_enabled)
            pin = self._config_digest()
            object.__setattr__(self, "_config_pin", pin)
            object.__setattr__(self, "_namespace", canonical_digest({"contract": CONTRACT,
                "original_namespace": workflow._namespace, "original_witness": candidate._draft._witness,
                "original_plan": candidate._draft._original, "config": pin,
                "state_key": hashlib.sha256(state_key).hexdigest()}))
            with workflow._lock, self._original.operation_lock(require_existing=True):
                object.__setattr__(self, "_lock_pin", self._original._lock_id)
                self._check()
        except Exception:
            raise InstructionQuotaRecoveryTransportError("initialization") from None

    def _config_digest(self) -> str:
        config = self._original._config
        config.__post_init__()
        if type(config.timeout_seconds) not in (int, float):
            raise ValueError
        return canonical_digest({"origin": hashlib.sha256(config.base_url.encode()).hexdigest(),
            "token": hashlib.sha256(config.bearer_token.encode()).hexdigest(),
            "timeout_hex": float(config.timeout_seconds).hex(),
            "ca": hashlib.sha256(Path(config.ca_file).read_bytes()).hexdigest() if config.ca_file else None})

    def _check(self) -> int:
        self._original._locked()
        if (self._config_digest() != self._config_pin or self._original._lock_id != self._lock_pin):
            raise ValueError
        candidate = self._candidate
        return _guard(candidate, candidate._requester, candidate._transport)

    @contextmanager
    def operation_lock(self) -> Iterator[None]:
        try:
            with self._candidate._reconciler._workflow._lock, self._original.operation_lock(require_existing=True):
                if self._original._lock_id != self._lock_pin:
                    raise ValueError
                self._check()
                yield
        except InstructionQuotaRecoveryTransportError:
            raise
        except Exception:
            raise InstructionQuotaRecoveryTransportError("lock") from None

    def _exists(self, name: str) -> bool:
        if name not in _FILES:
            raise ValueError
        return self._original._exists(name)

    def _unconsumed(self) -> None:
        if any(self._exists(name) for name in _FILES):
            raise ValueError

    def _seal(self, value: object) -> str:
        return hmac.new(self._key, (CONTRACT + "\0" + canonical_digest(value)).encode(), hashlib.sha256).hexdigest()

    def _write_once(self, suffix: str, payload: dict[str, Any]) -> None:
        self._check()
        name = _PREFIX + suffix
        if name not in _FILES:
            raise ValueError
        value = {"namespace": self._namespace, "payload": payload}
        value["seal"] = self._seal(value)
        raw = bytearray(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode())
        directory = self._original._directory_fd()
        try:
            if not 0 < len(raw) <= 16384:
                raise ValueError
            fd = os.open(name, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(fd, "wb") as output:
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
            os.fsync(directory)
        finally:
            _zeroize_mutable(raw)
            os.close(directory)

    def _read(self, suffix: str) -> dict[str, Any]:
        self._check()
        name = _PREFIX + suffix
        if name not in _FILES:
            raise ValueError
        directory = self._original._directory_fd()
        descriptor = None
        raw = bytearray()
        try:
            descriptor = os.open(name, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK, dir_fd=directory)
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 16384):
                raise ValueError
            with os.fdopen(descriptor, "rb", closefd=False) as source:
                raw = bytearray(source.read(16385))
            current = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if len(raw) != info.st_size or (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
                raise ValueError
            value = json.loads(raw, object_pairs_hook=_members)
            if (type(value) is not dict or set(value) != {"namespace", "payload", "seal"}
                    or value["namespace"] != self._namespace or type(value["payload"]) is not dict
                    or type(value["seal"]) is not str
                    or not hmac.compare_digest(value["seal"], self._seal({
                        "namespace": value["namespace"], "payload": value["payload"]}))):
                raise ValueError
            return value["payload"]
        finally:
            _zeroize_mutable(raw)
            if descriptor is not None:
                os.close(descriptor)
            os.close(directory)

    def _authorization(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *,
            require_fresh: bool = True) -> int:
        now, candidate = self._check(), self._candidate
        draft = candidate._draft
        if type(plan) is not M4ExecutionPlan or type(authorization) is not M4ExecutionAuthorization:
            raise ValueError
        plan.__post_init__()
        authorization.__post_init__()
        if ((plan.action_id, plan.action_version, plan.adapter_ref) != (ACTION, VERSION, ADAPTER)
                or plan.revision != 1 or plan.compensation_ref is not None
                or plan.target_ref != "instruction-quota-" + self._original._baseline._serial
                or plan.requester_digest != candidate._requester or plan.parameters_digest != candidate.digest
                or (plan.expected_current_digest, plan.expected_state_digest) != (draft._current, draft._expected)
                or (authorization.plan_ref, authorization.plan_digest, authorization.requester_digest,
                    authorization.confirmation_digest, authorization.approval_digest) != (
                    plan.plan_ref, plan.plan_digest, plan.requester_digest, plan.confirmation_digest, plan.approval_digest)
                or not draft._observed <= authorization.issued_at < authorization.expires_at <= draft._expires
                or require_fresh and not authorization.issued_at <= now < authorization.expires_at
                or authorization.expires_at != plan.expires_at):
            raise ValueError
        return now

    def _precondition_context(self) -> tuple[InstructionQuotaState, InstructionResourceUsage]:
        self._check()
        self._unconsumed()
        current, usage = self._original._reader(self._original._config,
            serial_digest=self._original._baseline._serial)
        body = _build_locked(self._candidate, current, usage,
            requester_digest=self._candidate._requester, transport_digest=self._candidate._transport)
        _zeroize_mutable(body)
        self._check()
        return current, usage

    def inspect_precondition(self) -> str:
        try:
            return self._precondition_context()[0]._state
        except Exception:
            raise InstructionQuotaRecoveryTransportError("precondition") from None

    def _claim_payload(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization) -> dict[str, Any]:
        draft = self._candidate._draft
        return {"contract": CONTRACT, "candidate": self._candidate.digest, "draft": draft.digest,
            "original_witness": draft._witness, "original_plan": draft._original,
            "current": draft._current, "expected": draft._expected, "usage": draft._usage,
            "plan": plan.plan_digest, "authorization": authorization.authorization_digest,
            "expires_at": authorization.expires_at}

    def dispatch(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *,
            before_send: Callable[[], None]) -> None:
        """Consume a canonical native claim before one PUT; never retry a failure.

        The trusted M4 composition must supply its exact server verifier. This
        transport validates bindings, but cannot decide or issue that authority.
        """
        connection = response = None
        body = raw = bytearray()
        stage = "authorization"
        cleanup_failed = False
        try:
            self._authorization(plan, authorization)
            if self._enabled is not True or not callable(before_send):
                raise ValueError
            self._unconsumed()
            deadline = min(authorization.expires_at,
                self._check() + min(30, self._original._config.timeout_seconds))
            def remaining() -> float:
                value = deadline - self._check()
                if value <= 0:
                    raise ValueError
                return float(value)
            before_send()
            self._authorization(plan, authorization)
            context = _ssl_context(self._original._config)
            if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
                raise ValueError
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            origin = urlsplit(self._original._config.base_url)
            stage = "connect"
            connection = self._original._factory(origin.hostname, origin.port or 443,
                context=context, timeout=remaining())
            connection.connect()
            remaining()
            stage = "precondition"
            current, usage = self._precondition_context()
            body = _build_locked(self._candidate, current, usage,
                requester_digest=self._candidate._requester, transport_digest=self._candidate._transport)
            stage = "authorization"
            before_send()
            self._authorization(plan, authorization)
            remaining()
            stage = "claim"
            claim = self._claim_payload(plan, authorization)
            self._write_once(".claim.json", claim)
            remaining()
            stage = "authorization"
            before_send()
            self._authorization(plan, authorization)
            if connection.sock is not None:
                connection.sock.settimeout(remaining())
            stage = "put"
            connection.request("PUT", _PATH, body=body, headers={
                "Authorization": "Bearer " + self._original._config.bearer_token,
                "Content-Type": "application/json", "Accept": "application/json",
                "Accept-Encoding": "identity", "Connection": "close",
                "User-Agent": "fortipam-mcp-instruction-quota/1"})
            response = connection.getresponse()
            remaining()
            stage = "ack_validation"
            if (response.status != 200
                    or response.getheader("Content-Type", "").split(";")[0].lower() != "application/json"
                    or response.getheader("Content-Encoding", "identity") not in ("", "identity")):
                raise ValueError
            raw = bytearray(262145)
            used = 0
            while True:
                remaining()
                if connection.sock is not None:
                    connection.sock.settimeout(remaining())
                with memoryview(raw)[used:] as view:
                    count = response.readinto(view)
                remaining()
                if type(count) is not int or count < 0 or used + count > 262144:
                    raise ValueError
                if not count:
                    break
                used += count
            raw = _take_mutable_prefix(raw, used)
            fields = d._spans(raw)
            d._equal(raw, fields, {"version": "v7.0.0", "build": 29, "path": "secret", "name": "setting",
                "http_method": "PUT", "http_status": 200, "status": "success", "vdom": "root"})
            if "action" in fields:
                d._equal(raw, fields, {"action": ""})
            serial = m._scalar(raw, fields["serial"])
            if (type(serial) is not str
                    or hashlib.sha256(serial.encode()).hexdigest() != self._original._baseline._serial):
                raise ValueError
            if "error" in fields:
                error = m._scalar(raw, fields["error"])
                if error is not None and (type(error) is not int or error != 0):
                    raise ValueError
            start = _skip_json_space(raw, 0)
            end = _json_value_end(raw, start)
            remaining()
            stage = "ack_persistence"
            self._write_once(".ack.json", {"claim": canonical_digest(claim),
                "serial": self._original._baseline._serial, "method": "PUT", "http_status": 200,
                "response_digest": _fingerprint(raw, (start, end)),
                "body_digest": hashlib.sha256(body).hexdigest()})
        except Exception:
            raise InstructionQuotaRecoveryTransportError(stage) from None
        finally:
            _zeroize_mutable(body)
            _zeroize_mutable(raw)
            for resource in (response, connection):
                if resource is not None:
                    try:
                        resource.close()
                    except Exception:
                        cleanup_failed = True
            if cleanup_failed:
                raise InstructionQuotaRecoveryTransportError("cleanup") from None

    def inspect_postcondition(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization) -> str:
        """Require this action's signed native ACK and one fixed complete read.

        A result belongs only to this independent correction, never the old
        UNKNOWN. This cannot finalize M4 or qualify original request delivery.
        """
        try:
            self._authorization(plan, authorization, require_fresh=False)
            claim, ack = self._read(".claim.json"), self._read(".ack.json")
            if (claim != self._claim_payload(plan, authorization)
                    or set(ack) != {"claim", "serial", "method", "http_status", "response_digest", "body_digest"}
                    or ack["claim"] != canonical_digest(claim) or ack["serial"] != self._original._baseline._serial
                    or ack["method"] != "PUT" or type(ack["http_status"]) is not int or ack["http_status"] != 200):
                raise ValueError
            for name in ("response_digest", "body_digest"):
                _require_digest(ack[name])
            expected_body = bytearray(json.dumps({"secret-instruction-quota": 0,
                "file-storage-quota": self._original._baseline._quotas[1]}, separators=(",", ":")).encode("ascii"))
            try:
                if hashlib.sha256(expected_body).hexdigest() != ack["body_digest"]:
                    raise ValueError
            finally:
                _zeroize_mutable(expected_body)
            started = self._check()
            current, usage = self._original._reader(self._original._config,
                serial_digest=self._original._baseline._serial)
            _check_postcondition_locked(self._candidate, current, usage,
                requester_digest=self._candidate._requester, transport_digest=self._candidate._transport,
                read_started_at_epoch=started)
            result = {"claim": canonical_digest(claim), "ack": canonical_digest(ack),
                "state": current._state, "usage": usage._state}
            if self._exists(_PREFIX + ".result.json"):
                if self._read(".result.json") != result:
                    raise ValueError
            else:
                self._write_once(".result.json", result)
            _check_postcondition_locked(self._candidate, current, usage,
                requester_digest=self._candidate._requester, transport_digest=self._candidate._transport,
                read_started_at_epoch=started)
            return current._state
        except Exception:
            raise InstructionQuotaRecoveryTransportError("postcondition") from None
