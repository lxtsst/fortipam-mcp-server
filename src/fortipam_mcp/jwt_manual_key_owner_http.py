"""Fixed local-Owner JWT source and wire adapter, with no public registration.

The API-user transport is unchanged. Trusted composition must supply the Owner
credential provider, source policy, original M4 kernel and separate persistent
store. Closed-by-default native writes cannot be authorized by a read witness.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import datetime
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import ssl
import time
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from v4_planning import M4ExecutionAuthorization, M4ExecutionPlan
from v4_planning.execution_kernel import _require_m4_dispatch_ownership
from v4_planning.material_provider import _OpaqueC3Object

from . import secret_bulk_import_metadata as parser
from .jwt_manual_key_contract import _NAME, _digest, _require_digest
from .jwt_manual_key_owner_actor import JwtManualKeyOwnerActorEvidence, _state as _owner_state, consume_jwt_manual_key_owner_actor_inputs
from .jwt_manual_key_preflight import JwtManualKeyPreflight, consume_jwt_manual_key_preflight
from .jwt_manual_key_request_contract import JwtManualCreateRequest, consume_jwt_manual_create_ack
from .jwt_manual_key_owned_state import JwtManualKeyOwnedState, consume_jwt_manual_key_owned_state, expected_jwt_manual_key_created_state
from .ldap_server_runtime import _key, _private_directory, _read
from .local_user_reset_metadata_reader import _monitor_results
from .local_user_reset_projection import _object_spans
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_approval_build29_http_transport import _validate_ack_json
from .secret_metadata_http_transport import MAX_RESPONSE_BYTES, _json_value_end, _skip_json_space, _zeroize_mutable
from .secret_request_approval_revoke_detail_contract import _reject_raw_duplicates
from .secret_request_http_transport import _server_date
from .target_operation_records import _TargetOperationRecords
from .target_api_dependency_reader import _private_http_logs

CONTRACT = "fortipam-build29-jwt-local-owner-wire-v1"
CREATE_ACTION = "manual-jwt-owner-key-create"
REMOVE_ACTION = "manual-jwt-owner-key-remove"
CREATE_ADAPTER = "fortipam-build29-jwt-owner-create-v1"
REMOVE_ADAPTER = "fortipam-build29-jwt-owner-remove-v1"
TARGET = "bound-local-owner-manual-jwt-key"
_STATE = "/api/v2/monitor/web-ui/state"
_JWT = "/api/v2/cmdb/secret/jwt-key"
_KEYS = _JWT + "?format=name%7Ctype&with_meta=true"
_USERS = "/api/v2/cmdb/system/api-user?format=name%7Ctype%7Cjwt-key&with_meta=true"
_ERROR = "The fixed local Owner JWT source is unavailable."
_RECORDS = frozenset({"create.claim.json", "create.response.json", "create.ack.json", "create.state.json",
                      "remove.claim.json", "remove.response.json", "remove.ack.json", "remove.absence.json"})


class JwtManualKeyOwnerHttpError(RuntimeError):
    """Categorical refusal without selectors, credentials or native content."""


@dataclass(frozen=True, slots=True, repr=False)
class JwtManualKeyOwnerHttpConfig:
    base_url: str
    owner_name: str
    credential_reference_digest: str
    ca_file: str
    requester_digest: str
    transport_digest: str
    timeout_seconds: int = 15

    def __post_init__(self) -> None:
        parsed = urlsplit(self.base_url)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.path not in {"", "/"}
                or parsed.query or parsed.fragment or not 0 < (parsed.port or 443) <= 65535
                or type(self.owner_name) is not str or not 0 < len(self.owner_name.encode()) <= 255
                or self.owner_name != self.owner_name.strip()
                or any(ord(c) < 32 or ord(c) == 127 for c in self.owner_name)
                or type(self.timeout_seconds) is not int or not 1 <= self.timeout_seconds <= 30
                or type(self.ca_file) is not str or not Path(self.ca_file).is_absolute()):
            raise JwtManualKeyOwnerHttpError(_ERROR)
        _require_digest(self.credential_reference_digest)
        _require_digest(self.requester_digest)
        _require_digest(self.transport_digest)


@dataclass(frozen=True, slots=True, repr=False)
class JwtManualKeyOwnerPreflight(_OpaqueC3Object):
    actor: JwtManualKeyOwnerActorEvidence
    state: JwtManualKeyPreflight
    source_digest: str
    session_digest: str
    current_digest: str


class JwtManualKeyOwnerHttp(_TargetOperationRecords):
    """One scoped Owner session; exact routes, durable once-only native writes.

    This is a kernel child adapter, not an authority or standalone workflow. A
    production server must supply its own verified issuer and normal entry join.
    Native failure or timeout never permits another POST or unowned DELETE.
    """

    @classmethod
    def from_original_creation(cls, config: JwtManualKeyOwnerHttpConfig,
            credentials: Callable[[], tuple[str, str]], *, directory: Path,
            witness_key_file: Path, source_guard: Callable[[], bool] | None = None,
            execution_enabled: bool = False, client_factory: Callable[..., Any] = httpx.Client,
            clock: Callable[[], int] = lambda: int(time.time())) -> JwtManualKeyOwnerHttp:
        """Restore closed metadata from the original authenticated native claim.

        No public key is loaded and no create body can be borrowed. The native
        namespace, original ACK, and subsequently the workflow's original grant
        and terminal ledger must all qualify before an owned product read.
        """
        raw = bytearray()
        try:
            _private_directory(directory)
            witness = _key(witness_key_file)
            raw = _read(directory / "create.claim.json", 16384)
            start = _skip_json_space(raw, 0); end = _json_value_end(raw, start)
            if _skip_json_space(raw, end) != len(raw):
                raise ValueError
            _validate_ack_json(raw, start, end); _reject_raw_duplicates(raw, start, end)
            record = json.loads(raw)
            if type(record) is not dict:
                raise ValueError
            payload = {k: v for k, v in record.items() if k != "hmac"}
            mac = hmac.new(witness, ("create.claim.json\x00" + json.dumps(payload,
                sort_keys=True, separators=(",", ":"))).encode(), hashlib.sha256).hexdigest()
            if (payload.get("contract") != CONTRACT or type(record.get("hmac")) is not str
                    or not hmac.compare_digest(mac, record["hmac"])):
                raise ValueError
            metadata = payload["request_metadata"]
            fields = {"_name", "plan_digest", "schema_digest", "defaults_digest", "serial_digest", "body_digest", "digest"}
            if (type(metadata) is not dict or set(metadata) != fields
                    or type(metadata["_name"]) is not str or _NAME.fullmatch(metadata["_name"]) is None):
                raise ValueError
            for field in fields - {"_name"}:
                _require_digest(metadata[field])
            request = object.__new__(JwtManualCreateRequest)
            for field, value in {**metadata, "_body": bytearray(), "_closed": True}.items():
                object.__setattr__(request, field, value)
            if request._request_digest() != request.digest or payload["request_digest"] != request.digest:
                raise ValueError
            source = cls(config, request, credentials, directory=directory, witness_key_file=witness_key_file,
                source_guard=source_guard, execution_enabled=execution_enabled,
                client_factory=client_factory, clock=clock)
            if source._sealed("create.claim.json") != payload:
                raise ValueError
            source._acknowledged_creation()
            return source
        except Exception:
            raise JwtManualKeyOwnerHttpError(_ERROR) from None
        finally:
            _zeroize_mutable(raw)

    def __init__(self, config: JwtManualKeyOwnerHttpConfig, request: JwtManualCreateRequest,
            credentials: Callable[[], tuple[str, str]], *, directory: Path, witness_key_file: Path,
            source_guard: Callable[[], bool] | None = None, execution_enabled: bool = False,
            client_factory: Callable[..., Any] = httpx.Client,
            clock: Callable[[], int] = lambda: int(time.time())) -> None:
        try:
            if (type(config) is not JwtManualKeyOwnerHttpConfig or type(request) is not JwtManualCreateRequest
                    or not callable(credentials) or not callable(client_factory) or not callable(clock)
                    or type(execution_enabled) is not bool or source_guard is not None and not callable(source_guard)):
                raise ValueError
            config.__post_init__()
            _private_directory(directory)
            if _NAME.fullmatch(request._name) is None or request._request_digest() != request.digest:
                raise ValueError
            self._config, self._request, self._credentials = config, request, credentials
            self._provider_pin = credentials
            self._directory, self._identity = directory, (directory.stat().st_dev, directory.stat().st_ino)
            self._witness_file, self._witness = witness_key_file, _key(witness_key_file)
            if len(self._witness) != 32:
                raise ValueError
            self._namespace = _digest({"contract": CONTRACT, "origin": config.base_url,
                "directory": str(directory), "directory_identity": self._identity,
                "owner": config.owner_name, "credential_reference": config.credential_reference_digest,
                "requester": config.requester_digest, "transport": config.transport_digest,
                "ca": hashlib.sha256(Path(config.ca_file).read_bytes()).hexdigest(),
                "request": request.digest, "witness_file": str(witness_key_file),
                "witness": hashlib.sha256(self._witness).hexdigest()})
            self._source_pin = self._source_fingerprint()
            self._binding_pin = request._request_digest()
            self._clock, self._last_clock, self._clock_failed = clock, None, False
            self._guard, self._guard_pin = source_guard, source_guard
            self._enabled, self._factory = execution_enabled, client_factory
            self._factory_pin = client_factory
            self._session: Any = None
            self._client_pin: Any = None
            self._http_logs: Any = None
            self._session_digest = secrets.token_hex(32)
            self._entered = self._closed = self._login_attempted = self.logout_verified = False
            self._csrf: str | None = None
            self._deadline = 0.0
            self._baseline: JwtManualKeyOwnerPreflight | None = None
            self._last_owned: JwtManualKeyOwnedState | None = None
            self._owner_role = "/api/v2/cmdb/system/admin/" + quote(config.owner_name, safe="") + "?format=name%7Caccprofile%7Cstatus%7Cremote-auth%7Cwildcard"
            self._schema = _JWT + "?action=schema&with_meta=true"
            self._defaults = _JWT + "?action=default&with_meta=true"
            self._absence = _JWT + "/" + quote(request._name, safe="") + "?format=name%7Ctype&with_meta=true"
            self._detail = _JWT + "/" + quote(request._name, safe="") + "?with_meta=true"
            self._reads = {_STATE, self._owner_role, self._schema, self._defaults, _KEYS, _USERS, self._absence}
        except Exception:
            raise JwtManualKeyOwnerHttpError(_ERROR) from None

    def _source_fingerprint(self) -> str:
        return _digest({"config": {"origin": self._config.base_url, "owner": self._config.owner_name,
            "credential_reference": self._config.credential_reference_digest,
            "requester": self._config.requester_digest, "transport": self._config.transport_digest},
            "ca": hashlib.sha256(Path(self._config.ca_file).read_bytes()).hexdigest(),
            "witness": hashlib.sha256(_key(self._witness_file)).hexdigest()})

    def _integrity(self) -> None:
        if (self._request._request_digest() != self._binding_pin
                or not hmac.compare_digest(_key(self._witness_file), self._witness)):
            raise JwtManualKeyOwnerHttpError(_ERROR)
        _private_directory(self._directory)
        if (self._directory.stat().st_dev, self._directory.stat().st_ino) != self._identity:
            raise JwtManualKeyOwnerHttpError(_ERROR)

    def _source(self) -> None:
        self._integrity()
        if (self._closed or self._credentials is not self._provider_pin
                or self._factory is not self._factory_pin
                or self._session is not None and self._session is not self._client_pin
                or self._guard is None or self._guard is not self._guard_pin or self._guard() is not True
                or self._source_fingerprint() != self._source_pin):
            raise JwtManualKeyOwnerHttpError(_ERROR)

    @staticmethod
    def _raw(response: Any) -> bytearray:
        raw = bytearray()
        try:
            if response.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
                raise ValueError
            for chunk in response.iter_bytes():
                if len(raw) + len(chunk) > MAX_RESPONSE_BYTES:
                    raise ValueError
                raw.extend(chunk)
            start = _skip_json_space(raw, 0); end = _json_value_end(raw, start)
            if _skip_json_space(raw, end) != len(raw):
                raise ValueError
            _validate_ack_json(raw, start, end); _reject_raw_duplicates(raw, start, end)
            return raw
        except BaseException:
            _zeroize_mutable(raw)
            raise

    def __enter__(self) -> JwtManualKeyOwnerHttp:
        try:
            self._source()
            if self._entered:
                raise ValueError
            self._entered = True
            self._http_logs = _private_http_logs(); self._http_logs.__enter__()
            tls = ssl.create_default_context(cafile=self._config.ca_file)
            tls.minimum_version = ssl.TLSVersion.TLSv1_2
            self._session = self._factory(base_url=self._config.base_url, verify=tls,
                timeout=self._config.timeout_seconds, follow_redirects=False, trust_env=False)
            self._client_pin = self._session
            self._session.__enter__()
            page = self._session.get("/remote/login?lang=en")
            if page.status_code != 200 or len(page.content) > MAX_RESPONSE_BYTES or 'action="/XX/YY/ZZ/AUTH"' not in page.text:
                raise ValueError
            username, password = self._credentials()
            if username != self._config.owner_name or type(password) is not str or not password:
                raise ValueError
            self._login_attempted = True
            auth = self._session.post("/XX/YY/ZZ/AUTH", data={"username": username, "password": password,
                "magic": "0", "4Tredir": "/", "4Tmthd": "0"})
            del username, password
            location = auth.headers.get("location", ""); parsed = urlsplit(location)
            if (auth.status_code != 303 or not location.startswith("/") or location.startswith("//")
                    or parsed.scheme or parsed.netloc or parsed.path.startswith("/api/") or len(location) > 2048):
                raise ValueError
            self._session.get(location)
            self._deadline = time.monotonic() + 60
            state, _ = self._get(_STATE)
            try:
                _owner_state(state, self._config.owner_name, self._request.serial_digest)
                left, right = _monitor_results(state, expected_route="web-ui/state")
                fields = _object_spans(state, left, right)
                left, right = fields["ccsrf_token_cookie_name"]
                cookie_name = json.loads(state[left:right])
                if type(cookie_name) is not str or not cookie_name or len(cookie_name.encode()) > 128 or any(ord(c) < 33 or ord(c) > 126 for c in cookie_name):
                    raise ValueError
                csrf = self._session.cookies.get(cookie_name)
                if type(csrf) is str:
                    csrf = csrf.strip('"')
                if type(csrf) is not str or not csrf or any(ord(c) < 33 or ord(c) > 126 for c in csrf):
                    raise ValueError
                self._csrf = csrf
            finally:
                _zeroize_mutable(state)
            return self
        except Exception:
            self.close()
            raise JwtManualKeyOwnerHttpError(_ERROR) from None
        except BaseException:
            self.close()
            raise

    def _get(self, path: str, *, owned: bool = False) -> tuple[bytearray, datetime | None]:
        self._source()
        if self._session is None or time.monotonic() >= self._deadline:
            raise JwtManualKeyOwnerHttpError(_ERROR)
        if owned:
            self._acknowledged_creation()
            if path != self._detail:
                raise JwtManualKeyOwnerHttpError(_ERROR)
        elif path not in self._reads:
            raise JwtManualKeyOwnerHttpError(_ERROR)
        with self._session.stream("GET", path, headers={"Accept": "application/json", "Cache-Control": "no-cache, no-store"}) as response:
            if response.status_code != (404 if path == self._absence else 200):
                raise JwtManualKeyOwnerHttpError(_ERROR)
            return self._raw(response), _server_date(response.headers.get("date"))

    def observe_owner(self) -> JwtManualKeyOwnerActorEvidence:
        self._source(); self._deadline = time.monotonic() + 60
        buffers: list[bytearray] = []; dates: list[datetime | None] = []
        try:
            for path in (_STATE, self._owner_role, _STATE):
                raw, date = self._get(path); buffers.append(raw); dates.append(date)
            if dates[0] is None or dates[-1] is None:
                raise ValueError
            return consume_jwt_manual_key_owner_actor_inputs(*buffers, expected_owner=self._config.owner_name,
                serial_digest=self._request.serial_digest, first_device_date=dates[0], last_device_date=dates[-1])
        finally:
            for raw in buffers:
                _zeroize_mutable(raw)

    def preflight(self) -> JwtManualKeyOwnerPreflight:
        """Fresh absent-name snapshot; never fetch an unacknowledged key body."""
        buffers: list[bytearray] = []; owner_buffers: list[bytearray] = []
        try:
            self._deadline = time.monotonic() + 60
            before, first_date = self._get(_STATE); owner_buffers.append(before)
            _owner_state(before, self._config.owner_name, self._request.serial_digest)
            mapping, _ = self._get(self._owner_role); owner_buffers.append(mapping)
            for path in (self._schema, self._defaults, _KEYS, _USERS, self._absence):
                raw, _ = self._get(path); buffers.append(raw)
            state = consume_jwt_manual_key_preflight(*buffers, name=self._request._name,
                serial_digest=self._request.serial_digest, expected_schema_digest=self._request.schema_digest,
                expected_defaults_digest=self._request.defaults_digest)
            after, last_date = self._get(_STATE); owner_buffers.append(after)
            if first_date is None or last_date is None:
                raise ValueError
            actor = consume_jwt_manual_key_owner_actor_inputs(*owner_buffers, expected_owner=self._config.owner_name,
                serial_digest=self._request.serial_digest, first_device_date=first_date, last_device_date=last_date)
            current = _digest({"contract": CONTRACT, "phase": "create", "request": self._request.digest,
                "actor": actor.actor_digest, "mapping": actor.mapping_digest, "source": self._source_pin,
                "session": self._session_digest, "state": state.state_digest})
            return JwtManualKeyOwnerPreflight(actor, state, self._source_pin, self._session_digest, current)
        finally:
            for raw in buffers + owner_buffers:
                _zeroize_mutable(raw)

    def _seal(self, name: str, value: dict[str, Any]) -> None:
        self._integrity()
        if name not in _RECORDS:
            raise ValueError
        payload = {"contract": CONTRACT, "namespace": self._namespace, **value}
        mac = hmac.new(self._witness, (name + "\x00" + json.dumps(payload, sort_keys=True, separators=(",", ":"))).encode(), hashlib.sha256).hexdigest()
        with self._lock() as directory:
            self._write(directory, name, {**payload, "hmac": mac})

    def _sealed(self, name: str) -> dict[str, Any]:
        self._integrity()
        if name not in _RECORDS:
            raise ValueError
        with self._lock() as directory:
            value = self._read(directory, name)
        if type(value) is not dict:
            raise ValueError
        payload = {k: v for k, v in value.items() if k != "hmac"}
        mac = hmac.new(self._witness, (name + "\x00" + json.dumps(payload, sort_keys=True, separators=(",", ":"))).encode(), hashlib.sha256).hexdigest()
        if payload.get("contract") != CONTRACT or payload.get("namespace") != self._namespace or not hmac.compare_digest(mac, value.get("hmac", "")):
            raise ValueError
        return payload

    def _acknowledged_creation(self) -> dict[str, Any]:
        claim = self._sealed("create.claim.json"); ack = self._sealed("create.ack.json")
        if claim.get("request_digest") != self._request.digest or ack.get("claim_digest") != _digest(claim):
            raise ValueError
        return ack

    def _write_guard(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization,
            store: PersistentM4ExecutionStateStore, *, remove: bool) -> None:
        self._source()
        if self._enabled is not True or self._session is None or self._csrf is None or type(store) is not PersistentM4ExecutionStateStore:
            raise JwtManualKeyOwnerHttpError(_ERROR)
        plan.__post_init__(); authorization.__post_init__()
        if (plan.action_id != (REMOVE_ACTION if remove else CREATE_ACTION) or plan.action_version != "1.0.0"
                or plan.adapter_ref != (REMOVE_ADAPTER if remove else CREATE_ADAPTER) or plan.target_ref != TARGET
                or plan.parameters_digest != self._request.digest or plan.compensation_ref is not None
                or plan.requester_digest != self._config.requester_digest
                or not authorization.issued_at <= self._now() < min(plan.expires_at, authorization.expires_at)
                or hashlib.sha256(store._key).digest() == hashlib.sha256(self._witness).digest()
                or not hmac.compare_digest(_key(store._key_path), store._key)):
            raise JwtManualKeyOwnerHttpError(_ERROR)
        _require_m4_dispatch_ownership(plan, authorization, store)

    def _response_summary(self, raw: bytearray, method: str) -> dict[str, Any]:
        summary: dict[str, Any] = {"native_context_matches": False, "native_status": "unknown",
            "native_http_status": None, "native_error": None, "mkey_matches": False}
        try:
            from .jwt_manual_key_preflight import _top
            fields = _top(raw)
            selected = {k: parser._scalar(raw, fields[k]) for k in
                ("version", "build", "serial", "http_method", "http_status", "status", "path", "name", "vdom")}
            expected = {"version": "v7.0.0", "build": 29, "http_method": method,
                        "path": "secret", "name": "jwt-key", "vdom": "root"}
            matches = all(type(selected.get(k)) is type(v) and selected[k] == v for k, v in expected.items())
            serial = selected["serial"]
            matches = matches and type(serial) is str and hashlib.sha256(serial.encode()).hexdigest() == self._request.serial_digest
            error = parser._scalar(raw, fields["error"]) if "error" in fields else None
            mkey = parser._scalar(raw, fields["mkey"]) if "mkey" in fields else None
            status, code = selected["status"], selected["http_status"]
            summary.update(native_context_matches=matches,
                native_status=status if status in {"success", "error"} else "unknown",
                native_http_status=code if type(code) is int and 100 <= code <= 599 else None,
                native_error=error if type(error) is int and -(2 ** 31) <= error < 2 ** 31 else None,
                mkey_matches=type(mkey) is str and mkey == self._request._name)
        except Exception:
            pass
        return summary

    def _mutation(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization,
            store: PersistentM4ExecutionStateStore, *, remove: bool) -> tuple[bytearray, dict[str, Any]]:
        self._write_guard(plan, authorization, store, remove=remove)
        phase = "remove" if remove else "create"
        raw = bytearray(); status = None; content_kind = "unknown"; complete = False
        method = "DELETE" if remove else "POST"
        path = _JWT + "/" + quote(self._request._name, safe="") if remove else _JWT + "?with_meta=true"
        interrupted: BaseException | None = None
        try:
            with self._session.stream(method, path,
                    content=None if remove else bytes(self._request.borrow_body()),
                    headers={"Accept": "application/json", "Content-Type": "application/json",
                             "X-Requested-With": "XMLHttpRequest", "X-CSRFTOKEN": self._csrf}) as response:
                status = response.status_code
                content_kind = "json" if response.headers.get("content-type", "").split(";", 1)[0].strip().lower() == "application/json" else "other"
                for chunk in response.iter_bytes():
                    remaining = MAX_RESPONSE_BYTES - len(raw)
                    raw.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        raise ValueError
                complete = True
        except BaseException as exc:
            # The native claim is already durable. Never resend an uncertain IO.
            if not isinstance(exc, Exception):
                interrupted = exc
        try:
            summary = self._response_summary(raw, method) if complete and content_kind == "json" else {
                "native_context_matches": False, "native_status": "unknown", "native_http_status": None,
                "native_error": None, "mkey_matches": False}
            record = {"claim_digest": _digest(self._sealed(phase + ".claim.json")),
                "http_status": status if type(status) is int and 100 <= status <= 599 else None,
                "complete": complete, "content_kind": content_kind, "body_bytes": len(raw),
                "body_hmac": hmac.new(self._witness, raw, hashlib.sha256).hexdigest(), **summary}
            self._seal(phase + ".response.json", record)
            if interrupted is not None:
                raise interrupted
            return raw, record
        except BaseException:
            _zeroize_mutable(raw)
            raise

    def _reserve(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization,
            store: PersistentM4ExecutionStateStore, *, remove: bool, baseline: JwtManualKeyOwnerPreflight | None = None) -> None:
        self._write_guard(plan, authorization, store, remove=remove)
        request_metadata = {key: getattr(self._request, key) for key in
            ("_name", "plan_digest", "schema_digest", "defaults_digest", "serial_digest", "body_digest", "digest")}
        value = {"request_digest": self._request.digest, "request_metadata": request_metadata,
            "plan": asdict(plan), "authorization": asdict(authorization),
            "store_path": str(store._path), "store_key_file": str(store._key_path),
            "store_key_digest": hashlib.sha256(store._key).hexdigest()}
        if baseline is not None:
            value["baseline"] = asdict(baseline.state)
            value["owner_actor_digest"] = baseline.actor.actor_digest
            value["owner_mapping_digest"] = baseline.actor.mapping_digest
        self._seal(("remove" if remove else "create") + ".claim.json", value)

    def create_under_m4(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization,
            store: PersistentM4ExecutionStateStore) -> JwtManualKeyOwnedState:
        """One native POST inside the already authorized original M4 dispatch."""
        raw = bytearray()
        try:
            self._write_guard(plan, authorization, store, remove=False)
            if os.path.lexists(self._directory / "create.claim.json"):
                raise ValueError
            baseline = self.preflight()
            if (baseline.current_digest != plan.expected_current_digest
                    or expected_jwt_manual_key_created_state(self._request, baseline.state) != plan.expected_state_digest):
                raise ValueError
            self._baseline = baseline
            self._reserve(plan, authorization, store, remove=False, baseline=baseline)
            raw, response = self._mutation(plan, authorization, store, remove=False)
            if response["http_status"] != 200 or not response["complete"] or response["content_kind"] != "json":
                raise ValueError
            ack = consume_jwt_manual_create_ack(raw, self._request, http_status=200)
            self._write_guard(plan, authorization, store, remove=False)
            self._seal("create.ack.json", {"claim_digest": _digest(self._sealed("create.claim.json")),
                "response_digest": _digest(self._sealed("create.response.json")),
                "original_ack_digest": ack.response_digest})
            owned = self.owned_state()
            self._seal("create.state.json", {"ack_digest": _digest(self._sealed("create.ack.json")), **asdict(owned)})
            return owned
        except Exception:
            raise JwtManualKeyOwnerHttpError(_ERROR) from None
        finally:
            _zeroize_mutable(raw); self._request.close()

    def owned_state(self) -> JwtManualKeyOwnedState:
        """Original-ACK-only full read, including after a failed original postread."""
        self._source(); ack = self._acknowledged_creation()
        claim = self._sealed("create.claim.json")
        baseline = JwtManualKeyPreflight(**claim["baseline"])
        expected_row = None
        if os.path.lexists(self._directory / "create.state.json"):
            original = self._sealed("create.state.json")
            if original.get("ack_digest") != _digest(ack) or original.get("request_digest") != self._request.digest:
                raise ValueError
            expected_row = original["full_row_hmac"]
            _require_digest(expected_row)
        owner = self.observe_owner(); buffers: list[bytearray] = []
        try:
            if (owner.actor_digest != claim["owner_actor_digest"] or owner.mapping_digest != claim["owner_mapping_digest"]):
                raise ValueError
            for path in (self._detail, _KEYS, _USERS, self._detail):
                raw, _ = self._get(path, owned=path == self._detail); buffers.append(raw)
            owned = consume_jwt_manual_key_owned_state(*buffers, request=self._request,
                baseline=baseline, witness_key=self._witness, expected_full_row_hmac=expected_row,
                require_original_body_digest=True)
            after = self.observe_owner()
            if owner.actor_digest != after.actor_digest or owner.mapping_digest != after.mapping_digest:
                raise ValueError
            self._last_owned = owned
            return owned
        finally:
            for raw in buffers:
                _zeroize_mutable(raw)

    def removal_current(self) -> tuple[str, str]:
        owned = self.owned_state()
        ack = self._acknowledged_creation()
        return (_digest({"contract": CONTRACT, "phase": "remove", "source": self._source_pin,
                    "session": self._session_digest, "ack": _digest(ack), "owned": asdict(owned)}),
                _digest({"contract": CONTRACT, "phase": "absent", "request": self._request.digest,
                         "api_users": owned.api_users_digest}))

    def remove_under_m4(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization,
            store: PersistentM4ExecutionStateStore) -> str:
        raw = bytearray()
        try:
            self._write_guard(plan, authorization, store, remove=True)
            if os.path.lexists(self._directory / "remove.claim.json"):
                raise ValueError
            current, expected = self.removal_current()
            if current != plan.expected_current_digest or expected != plan.expected_state_digest:
                raise ValueError
            self._reserve(plan, authorization, store, remove=True)
            raw, response = self._mutation(plan, authorization, store, remove=True)
            if (response["http_status"] != 200 or not response["complete"] or response["content_kind"] != "json"
                    or not response["native_context_matches"] or not response["mkey_matches"]
                    or response["native_status"] != "success" or response["native_http_status"] != 200
                    or response["native_error"] not in {None, 0}):
                raise ValueError
            from .jwt_manual_key_preflight import _top
            fields = _top(raw)
            if "schema_errors" in fields or "action" in fields and parser._scalar(raw, fields["action"]) != "":
                raise ValueError
            if "error" in fields and (type(parser._scalar(raw, fields["error"])) is not int or parser._scalar(raw, fields["error"]) != 0):
                raise ValueError
            self._write_guard(plan, authorization, store, remove=True)
            self._seal("remove.ack.json", {"claim_digest": _digest(self._sealed("remove.claim.json")),
                "response_digest": _digest(self._sealed("remove.response.json"))})
            observed = self.preflight()
            original = JwtManualKeyPreflight(**self._sealed("create.claim.json")["baseline"])
            if observed.state.api_users_digest != original.api_users_digest:
                raise ValueError
            self._seal("remove.absence.json", {"ack_digest": _digest(self._sealed("remove.ack.json")),
                "observed_state_digest": observed.state.state_digest, "expected_digest": expected})
            return expected
        except Exception:
            raise JwtManualKeyOwnerHttpError(_ERROR) from None
        finally:
            _zeroize_mutable(raw)

    def inspect_wire(self, *, remove: bool = False) -> dict[str, Any]:
        """Minimized original records remain readable after logout, not replayable."""
        record = self._sealed(("remove" if remove else "create") + ".response.json")
        return {key: record[key] for key in ("http_status", "complete", "content_kind", "body_bytes",
            "native_context_matches", "native_status", "native_http_status", "native_error", "mkey_matches")}

    def close(self) -> None:
        self._enabled = False
        try:
            if self._session is not None and self._login_attempted:
                retained = httpx.Cookies(self._session.cookies)
                try:
                    response = self._session.get("/logout")
                    self._session.cookies.clear(); self._session.cookies.update(retained)
                    denied = self._session.get(_STATE)
                    self.logout_verified = bool(retained) and response.status_code in (200, 302, 303) and denied.status_code in (401, 403)
                finally:
                    retained.clear(); self._session.cookies.clear()
        finally:
            try:
                if self._session is not None:
                    self._session.close()
            finally:
                self._session = None; self._client_pin = None; self._csrf = None; self._closed = True
                self._request.close()
                if self._http_logs is not None:
                    self._http_logs.__exit__(None, None, None); self._http_logs = None

    def __exit__(self, *_: object) -> None:
        self.close()
