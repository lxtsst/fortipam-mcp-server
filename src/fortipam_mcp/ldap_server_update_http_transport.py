"""Private one-shot LDAP update/restore; no registration or material loading."""
from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
import fcntl
import hashlib
import os
from pathlib import Path
import stat
from typing import Literal
from urllib.parse import quote, quote_from_bytes

from v4_planning.models import require_digest

from .ldap_server_contract import CONTRACT as CREATE_CONTRACT, LdapServerCandidateError, LdapServerCreateBinding
from .ldap_server_http_transport import FortiPamLdapServerHttpTransport, LdapServerReadiness, _Connection, _digest
from .ldap_server_projection import _ProtectedProjection, _destroy, project_ldap_info
from .ldap_server_update_contract import (
    CONTRACT, LdapServerUpdateExpectation, compile_ldap_server_existing_info_body,
    compile_ldap_server_restore, prepare_ldap_server_update,
    project_ldap_server_update_ack, project_ldap_server_update_detail,
)
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig

Phase = Literal["update", "restore"]
_UNAVAILABLE = "The private LDAP update transport is unavailable."
_PATH = "/api/v2/cmdb/user/ldap/"
_PLAN = "update.plan.json"
_LOCK = "operation.lock"
_CREATE_FILES = frozenset({"create.claim.json", "create-ack.json", "created.json"})
_FIELDS = frozenset({"baseline_digest", "expected_digest", "schema_digest", "parameters_digest", "serial_digest"})
_NAMESPACE_FILES = frozenset({"update-runtime.namespace.json", "update-runtime.update.namespace.json",
                              "update-runtime.restore.namespace.json", _LOCK})


def _digests(value: object, keys: frozenset[str]) -> dict[str, str]:
    if type(value) is not dict or set(value) != keys:
        raise ValueError
    result: dict[str, str] = {}
    for key, item in value.items():
        if type(item) is not str:
            raise ValueError
        require_digest(item, key)
        result[key] = item
    return result


def _timestamp(value: object) -> int:
    if type(value) is not int or value < 0:
        raise ValueError
    return value


class _CreationReader(FortiPamLdapServerHttpTransport):
    __slots__ = ()

    def _write_once(self, name: str, value: object) -> None:
        raise LdapServerCandidateError(_UNAVAILABLE)


class LdapServerUpdateReadiness(_ProtectedProjection):
    __slots__ = ("state_digest", "observed_at")
    state_digest: str
    observed_at: int

    def __init__(self, state_digest: str, observed_at: int) -> None:
        object.__setattr__(self, "state_digest", state_digest)
        object.__setattr__(self, "observed_at", observed_at)


class FortiPamLdapServerUpdateHttpTransport(_ProtectedProjection):
    """Two private directories: immutable creation evidence and one A/B ledger."""

    __slots__ = ("_creation", "_state", "_binding", "_serial", "_phase", "_enabled",
                 "_namespace", "_inspected_plan")

    def __init__(self, config: SecretMetadataHttpTransportConfig, binding: LdapServerCreateBinding,
                 *, expected_serial: str, creation_state_directory: Path, state_directory: Path,
                 phase: Phase, execution_enabled: bool = False, clock: Callable[[], int] | None = None,
                 connection_factory: Callable[..., _Connection] | None = None) -> None:
        try:
            if type(phase) is not str or phase not in {"update", "restore"} or type(execution_enabled) is not bool:
                raise ValueError
            for path in (creation_state_directory, state_directory):
                if not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts:
                    raise ValueError
                if any(item.is_symlink() for item in (path, *path.parents)):
                    raise ValueError
            if state_directory != creation_state_directory.with_name(creation_state_directory.name + ".ldap-update"):
                raise ValueError
            creation = _CreationReader(config, binding, expected_serial=expected_serial,
                state_directory=creation_state_directory, clock=clock, connection_factory=connection_factory)
            state = FortiPamLdapServerHttpTransport(config, binding, expected_serial=expected_serial,
                state_directory=state_directory, clock=clock, connection_factory=connection_factory)
            namespace = _digest({"contract": CONTRACT, "parameters": binding.parameters_digest,
                "serial": hashlib.sha256(expected_serial.encode()).hexdigest(),
                "creation_directory": str(creation_state_directory), "creation_identity": creation._directory_identity,
                "state_directory": str(state_directory), "state_identity": state._directory_identity,
                "api_base_url": config.base_url, "api_ca_file": config.ca_file,
                "api_identity": hashlib.sha256(config.bearer_token.encode()).hexdigest()})
            for key, value in (("_creation", creation), ("_state", state), ("_binding", binding),
                               ("_serial", expected_serial), ("_phase", phase), ("_enabled", execution_enabled),
                               ("_namespace", namespace), ("_inspected_plan", None)):
                object.__setattr__(self, key, value)
        except Exception:
            raise LdapServerCandidateError(_UNAVAILABLE) from None

    _creation: _CreationReader
    _state: FortiPamLdapServerHttpTransport
    _binding: LdapServerCreateBinding
    _serial: str
    _phase: Phase
    _enabled: bool
    _namespace: str
    _inspected_plan: str | None

    @contextmanager
    def operation_lock(self) -> Iterator[None]:
        """Hold one nonblocking cross-process lock across the caller's operation."""
        directory = descriptor = None
        locked = False
        try:
            directory = self._state._directory_fd()
            descriptor = os.open(_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                                 0o600, dir_fd=directory)
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_size != 0):
                raise ValueError
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
            current = os.stat(_LOCK, dir_fd=directory, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
                raise ValueError
        except Exception:
            if descriptor is not None:
                os.close(descriptor)
            if directory is not None:
                os.close(directory)
            raise LdapServerCandidateError(_UNAVAILABLE) from None
        try:
            yield
        finally:
            if locked:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
            os.close(directory)

    def _anchors(self) -> tuple[dict[str, str], dict[str, object], dict[str, object]]:
        if any(os.path.lexists(self._creation._directory / name) for name in ("delete.claim.json", "deleted.json")):
            raise ValueError
        claim = self._creation._read_state("create.claim.json")
        ack = self._creation._read_state("create-ack.json")
        created = self._creation._read_state("created.json")
        if (set(claim) != {"contract", "parameters_digest", "request_digest", "current_digest", "claimed_at"}
                or set(ack) != {"claim_digest", "parameters_digest", "acknowledged_at"}
                or set(created) != {"claim_digest", "parameters_digest", "state_digest"}
                or claim["contract"] != CREATE_CONTRACT
                or any(record["parameters_digest"] != self._binding.parameters_digest for record in (claim, ack, created))
                or ack["claim_digest"] != _digest(claim) or created["claim_digest"] != _digest(claim)
                or not _timestamp(claim["claimed_at"]) <= _timestamp(ack["acknowledged_at"]) <= self._state._now()):
            raise ValueError
        _digests({key: claim[key] for key in ("request_digest", "current_digest")},
                 frozenset({"request_digest", "current_digest"}))
        _digests({"state_digest": created["state_digest"]}, frozenset({"state_digest"}))
        return {"create.claim.json": _digest(claim), "create-ack.json": _digest(ack),
                "created.json": _digest(created)}, claim, created

    def _load_plan(self) -> tuple[dict[str, object], LdapServerUpdateExpectation]:
        plan = self._state._read_state(_PLAN)
        if (set(plan) != {"contract", "namespace_digest", "expectation", "components_digest", "creation_anchors"}
                or plan["contract"] != CONTRACT or plan["namespace_digest"] != self._namespace):
            raise ValueError
        expected = LdapServerUpdateExpectation(**_digests(plan["expectation"], _FIELDS))
        anchors, claim, created = self._anchors()
        if (_digests(plan["creation_anchors"], _CREATE_FILES) != anchors
                or plan["components_digest"] != claim["current_digest"]
                or expected.baseline_digest != created["state_digest"]
                or expected.parameters_digest != self._binding.parameters_digest
                or expected.serial_digest != hashlib.sha256(self._serial.encode()).hexdigest()):
            raise ValueError
        return plan, expected

    def _components(self, plan: dict[str, object]) -> LdapServerReadiness:
        current = self._creation._components()
        if current.state_digest != plan["components_digest"] or self._anchors()[0] != plan["creation_anchors"]:
            raise ValueError
        return current

    def _detail(self) -> bytearray:
        code, raw = self._state._exchange("GET", _PATH + quote(self._binding.name, safe="") + "?with_meta=true")
        if code != 200:
            _destroy(raw)
            raise ValueError
        return raw

    def _create_plan(self) -> None:
        directory = self._state._directory_fd()
        try:
            if self._phase != "update" or not set(os.listdir(directory)) <= _NAMESPACE_FILES:
                raise ValueError
        finally:
            os.close(directory)
        anchors, claim, created = self._anchors()
        if not self._creation.inspect_owned():
            raise ValueError
        current = self._creation._components()
        body, expected = prepare_ldap_server_update(self._detail(), current.schema, current.defaults,
            self._binding, expected_serial=self._serial)
        try:
            if (expected.baseline_digest != created["state_digest"] or current.state_digest != claim["current_digest"]
                    or self._anchors()[0] != anchors):
                raise ValueError
            self._state._write_once(_PLAN, {"contract": CONTRACT, "namespace_digest": self._namespace,
                "expectation": {key: getattr(expected, key) for key in _FIELDS},
                "components_digest": current.state_digest, "creation_anchors": anchors})
        finally:
            _destroy(body)

    def _fingerprint(self, plan: dict[str, object], target: str) -> str:
        return _digest({"contract": CONTRACT, "namespace": self._namespace, "phase": self._phase,
                        "plan": _digest(plan), "state": target})

    def _claim(self, phase: Phase, plan: dict[str, object]) -> dict[str, object]:
        claim = self._state._read_state(phase + ".claim.json")
        expected = LdapServerUpdateExpectation(**_digests(plan["expectation"], _FIELDS))
        before = expected.baseline_digest if phase == "update" else expected.expected_digest
        after = expected.expected_digest if phase == "update" else expected.baseline_digest
        if (set(claim) != {"contract", "phase", "state_plan_digest", "plan_digest", "authorization_digest",
                          "before_digest", "after_digest", "claimed_at", "expires_at"}
                or claim["contract"] != CONTRACT or claim["phase"] != phase or claim["state_plan_digest"] != _digest(plan)
                or claim["before_digest"] != before or claim["after_digest"] != after
                or not 0 < _timestamp(claim["expires_at"]) - _timestamp(claim["claimed_at"]) <= 60
                or _timestamp(claim["claimed_at"]) > self._state._now()):
            raise ValueError
        _digests({key: claim[key] for key in ("plan_digest", "authorization_digest")},
                 frozenset({"plan_digest", "authorization_digest"}))
        return claim

    def _ack(self, phase: Phase, plan: dict[str, object]) -> tuple[dict[str, object], dict[str, object]]:
        claim = self._claim(phase, plan)
        ack = self._state._read_state(phase + "-ack.json")
        if (set(ack) != {"contract", "phase", "claim_digest", "acknowledged_at"}
                or ack["contract"] != CONTRACT or ack["phase"] != phase or ack["claim_digest"] != _digest(claim)
                or not _timestamp(claim["claimed_at"]) <= _timestamp(ack["acknowledged_at"]) <= self._state._now()):
            raise ValueError
        return claim, ack

    def _unused(self, plan: dict[str, object]) -> None:
        phases = ("update", "restore") if self._phase == "update" else ("restore",)
        if any(os.path.lexists(self._state._directory / (phase + suffix)) for phase in phases
               for suffix in (".claim.json", "-ack.json", "-verified.json")):
            raise ValueError
        if self._phase == "restore":
            self._ack("update", plan)

    def _compile(self, current: LdapServerReadiness, expected: LdapServerUpdateExpectation) -> bytearray:
        if self._phase == "restore":
            return compile_ldap_server_restore(self._detail(), current.schema, current.defaults,
                self._binding, expected, expected_serial=self._serial)
        body, fresh = prepare_ldap_server_update(self._detail(), current.schema, current.defaults,
            self._binding, expected_serial=self._serial)
        if any(getattr(fresh, key) != getattr(expected, key) for key in _FIELDS):
            _destroy(body)
            raise ValueError
        return body

    def inspect_current(self) -> LdapServerUpdateReadiness:
        try:
            observed_at = self._state._now()
            if not os.path.lexists(self._state._directory / _PLAN):
                self._create_plan()
            plan, expected = self._load_plan()
            self._unused(plan)
            body = self._compile(self._components(plan), expected)
            _destroy(body)
            if not 0 <= self._state._now() - observed_at < 60:
                raise ValueError
            object.__setattr__(self, "_inspected_plan", _digest(plan))
            before = expected.baseline_digest if self._phase == "update" else expected.expected_digest
            return LdapServerUpdateReadiness(self._fingerprint(plan, before), observed_at)
        except Exception:
            raise LdapServerCandidateError(_UNAVAILABLE) from None

    def expected_state_digest(self) -> str:
        try:
            plan, expected = self._load_plan()
            if self._inspected_plan != _digest(plan):
                raise ValueError
            after = expected.expected_digest if self._phase == "update" else expected.baseline_digest
            return self._fingerprint(plan, after)
        except Exception:
            raise LdapServerCandidateError(_UNAVAILABLE) from None

    def _postcondition(self, plan: dict[str, object], expected: LdapServerUpdateExpectation) -> str:
        current = self._components(plan)
        if not project_ldap_server_update_detail(self._detail(), current.schema, current.defaults,
                self._binding, expected, expected_serial=self._serial, restored=self._phase == "restore"):
            raise ValueError
        if self._phase == "restore" and not self._creation.inspect_owned():
            raise ValueError
        after = expected.expected_digest if self._phase == "update" else expected.baseline_digest
        return self._fingerprint(plan, after)

    def _stored_info(self, expires_at: int, guard: Callable[[], None]) -> None:
        body = compile_ldap_server_existing_info_body(self._binding)
        try:
            code, raw = self._state._exchange("GET", "/api/v2/monitor/service/ldap/query?json="
                + quote_from_bytes(body, safe=""), limit=8 * 1048576, before_send=guard, deadline=expires_at)
            if code != 200:
                _destroy(raw)
                raise ValueError
            if not project_ldap_info(raw, self._binding, expected_serial=self._serial):
                raise ValueError
        finally:
            _destroy(body)

    def dispatch(self, *, expected_current_digest: str, expires_at: int,
                 plan_digest: str, authorization_digest: str, before_send: Callable[[], None]) -> None:
        body = bytearray()
        try:
            now = self._state._now()
            if (not self._enabled or type(expected_current_digest) is not str or type(expires_at) is not int
                    or not 0 < expires_at - now <= 60 or not callable(before_send)):
                raise ValueError
            require_digest(expected_current_digest, "current state")
            _digests({"plan_digest": plan_digest, "authorization_digest": authorization_digest},
                     frozenset({"plan_digest", "authorization_digest"}))
            before_send()
            readiness = self.inspect_current()
            if readiness.state_digest != expected_current_digest:
                raise ValueError
            plan, expected = self._load_plan()
            now = self._state._now()
            if now >= expires_at:
                raise ValueError
            before = expected.baseline_digest if self._phase == "update" else expected.expected_digest
            after = expected.expected_digest if self._phase == "update" else expected.baseline_digest
            claim = {"contract": CONTRACT, "phase": self._phase, "state_plan_digest": _digest(plan),
                "plan_digest": plan_digest, "authorization_digest": authorization_digest,
                "before_digest": before, "after_digest": after, "claimed_at": now, "expires_at": expires_at}
            self._state._write_once(self._phase + ".claim.json", claim)

            def guard() -> None:
                if not now <= self._state._now() < expires_at:
                    raise ValueError
                before_send()
                if self._load_plan()[0] != plan or self._claim(self._phase, plan) != claim:
                    raise ValueError

            guard()
            if self._phase == "update":
                self._stored_info(expires_at, guard)
            body = self._compile(self._components(plan), expected)
            code, raw = self._state._exchange("PUT", _PATH + quote(self._binding.name, safe=""),
                body=body, before_send=guard, deadline=expires_at)
            _destroy(body)
            if not project_ldap_server_update_ack(raw, self._binding, expected_serial=self._serial, http_status=code):
                raise ValueError
            self._state._write_once(self._phase + "-ack.json", {"contract": CONTRACT, "phase": self._phase,
                "claim_digest": _digest(claim), "acknowledged_at": self._state._now()})
            self._postcondition(plan, expected)
            self._stored_info(expires_at, guard)
            digest = self._postcondition(plan, expected)
            guard()
            self._state._write_once(self._phase + "-verified.json", {"contract": CONTRACT, "phase": self._phase,
                "claim_digest": _digest(claim), "state_digest": digest, "verified_at": self._state._now()})
        except Exception:
            raise LdapServerCandidateError(_UNAVAILABLE) from None
        finally:
            _destroy(body)

    def inspect_postcondition(self) -> str:
        try:
            observed_at = self._state._now()
            plan, expected = self._load_plan()
            claim, ack = self._ack(self._phase, plan)
            verified = self._state._read_state(self._phase + "-verified.json")
            after = expected.expected_digest if self._phase == "update" else expected.baseline_digest
            if (set(verified) != {"contract", "phase", "claim_digest", "state_digest", "verified_at"}
                    or verified["contract"] != CONTRACT or verified["phase"] != self._phase
                    or verified["claim_digest"] != _digest(claim)
                    or verified["state_digest"] != self._fingerprint(plan, after)
                    or not _timestamp(ack["acknowledged_at"]) <= _timestamp(verified["verified_at"]) <= self._state._now()):
                raise ValueError
            digest = self._postcondition(plan, expected)
            if not 0 <= self._state._now() - observed_at < 60:
                raise ValueError
            return digest
        except Exception:
            raise LdapServerCandidateError(_UNAVAILABLE) from None
