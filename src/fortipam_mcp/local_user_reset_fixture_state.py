"""Fixed read-only complete-state join for a prospective reset fixture.

The existing 34-field creation projection and full schema-aware material
redactor keep separate jobs. Matching present state confers no ownership.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
import hashlib
import http.client
import json
from pathlib import Path
import ssl
from threading import RLock
import time
from typing import Any
from urllib.parse import urlencode

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from . import secret_bulk_import_metadata as m
from .local_user_reset_fixture_create import (
    LocalUserResetFixtureCreateDraft, LocalUserResetFixtureCreatedReadback, _FIELDS,
    prepare_local_user_reset_fixture_create, verify_fixture_created_detail,
)
from .local_user_reset_fixture_preflight import (
    FortiPamLocalUserResetFixturePreflightReader, _ACTOR, _DEFAULT, _SCHEMA, _actor_context,
)
from .local_user_reset_fixture_transport import FortiPamLocalUserResetFixtureTransport
from .local_user_reset_metadata_reader import (
    FortiPamLocalUserResetMetadataReader, LocalUserResetMetadataObservation, _USAGE,
    _array_count, _monitor_results, _validate_value,
)
from .local_user_reset_projection import _object_spans, _schema_fields, project_local_user_reset_detail
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig, _zeroize_mutable
from .target_api_dependency_reader import _private_http_logs

CONTRACT = "build29-local-reset-fixture-created-state/v2"
_ERROR = "The private complete reset-fixture state is unavailable."


def _observation_digest(observed: LocalResetFixtureCreatedState) -> str:
    return hashlib.sha256(json.dumps(asdict(observed), sort_keys=True,
        separators=(",", ":"), allow_nan=False).encode()).hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class LocalResetFixtureCreatedState(_OpaqueC3Object):
    source_context_digest: str
    state_digest: str
    nonmaterial_state_digest: str
    definition_digest: str
    user_id: int
    observed_at: float
    expires_at: float


class LocalResetFixtureStateReader(_OpaqueC3Object):
    def __init__(self, config: SecretMetadataHttpTransportConfig, *, draft: LocalUserResetFixtureCreateDraft,
            api_principal: str, serial_digest: str, actor_context_digest: str, material_directory: Path,
            connection_factory: Callable[..., Any] = http.client.HTTPSConnection,
            clock: Callable[[], float] = time.monotonic) -> None:
        try:
            if type(config) is not SecretMetadataHttpTransportConfig or type(draft) is not LocalUserResetFixtureCreateDraft or not callable(clock):
                raise ValueError
            require_digest(serial_digest, "fixture_serial"); require_digest(actor_context_digest, "fixture_actor")
            expected = json.loads(draft._wire)
            if (draft._response_vdom != "root" or draft.access_profile != "Guest" or expected["status"] != "enable"
                    or expected["name"] != draft.username or expected["accprofile"] != "Guest"
                    or expected["remote-auth"] != "disable" or expected["wildcard"] != "disable"
                    or expected["guest-auth"] != "disable" or expected["sponsor-group"] != "" or expected["schedule"] != ""
                    or hashlib.sha256(draft._wire).hexdigest() != draft.nonmaterial_request_digest):
                raise ValueError
            self._config, self._draft = config, draft
            self._serial, self._actor, self._principal = serial_digest, actor_context_digest, api_principal
            self._reader = FortiPamLocalUserResetFixturePreflightReader(config, username=draft.username,
                api_principal=api_principal, connection_factory=connection_factory)
            self._metadata = FortiPamLocalUserResetMetadataReader(config, username=draft.username, connection_factory=connection_factory)
            self._fixture = FortiPamLocalUserResetFixtureTransport(config, username=draft.username, api_principal=api_principal,
                material_directory=material_directory, enabled=False, connection_factory=connection_factory)
            self._factory, self._clock = connection_factory, clock
            self._routes = self._route_binding()
            self._source = self._context()
            self._closed = self._failed = False
            self._last = -1.0
            self._current: LocalResetFixtureCreatedState | None = None
            self._seal: str | None = None
            self._last_failure_stage: str | None = None
            self._lock = RLock()
        except Exception:
            raise ValueError(_ERROR) from None

    def _context(self) -> str:
        config = self._config
        return canonical_digest(dict(contract=CONTRACT, origin_digest=hashlib.sha256(config.base_url.encode()).hexdigest(),
            token_digest=hashlib.sha256(config.bearer_token.encode()).hexdigest(), serial_digest=self._serial,
            ca_digest=None if config.ca_file is None else hashlib.sha256(Path(config.ca_file).read_bytes()).hexdigest(),
            username_digest=hashlib.sha256(self._draft.username.encode()).hexdigest(), actor_context_digest=self._actor,
            api_principal_digest=hashlib.sha256(self._principal.encode()).hexdigest(),
            request_digest=self._draft.nonmaterial_request_digest, defaults_digest=self._draft.source_defaults_digest,
            expected_vdom=self._draft._response_vdom))

    def _route_binding(self) -> tuple[object, ...]:
        return (self._reader._host, self._reader._port, self._metadata._host, self._metadata._port,
            self._metadata._detail, self._fixture._detail, self._fixture._username,
            self._fixture._preflight._host, self._fixture._preflight._port,
            self._fixture._preflight._username, self._fixture._preflight._principal)

    def _pins(self) -> None:
        if (self._closed or self._failed or self._context() != self._source
                or hashlib.sha256(self._draft._wire).hexdigest() != self._draft.nonmaterial_request_digest
                or self._draft.access_profile != "Guest" or self._draft._response_vdom != "root"
                or self._route_binding() != self._routes
                or self._reader._factory is not self._factory or self._metadata._factory is not self._factory
                or self._reader._config is not self._config or self._metadata._config is not self._config
                or self._fixture._enabled or self._fixture._preflight._factory is not self._factory
                or self._fixture._preflight._config is not self._config
                or self._reader._username != self._draft.username or self._metadata._username != self._draft.username
                or self._reader._principal != self._principal
                or self._fixture._check_directory() != self._fixture._directory_identity
                or any(not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED
                    for context in (self._reader._context, self._metadata._context, self._fixture._preflight._context))):
            raise ValueError

    def _now(self) -> float:
        self._pins()
        now = self._clock()
        if type(now) not in (int, float) or not 0 <= now < float("inf") or now < self._last:
            raise ValueError
        self._last = now
        return now

    def _actor_current(self) -> None:
        raw = self._reader._read(_ACTOR)
        try:
            if _actor_context(raw, expected_name=self._principal) != self._actor: raise ValueError
        finally:
            _zeroize_mutable(raw)

    def _defaults_current(self) -> None:
        schema = self._reader._read(_SCHEMA)
        defaults = bytearray()
        try:
            root = _object_spans(schema, 0, len(schema))
            serial = m._scalar(schema, root["serial"])
            if type(serial) is not str or hashlib.sha256(serial.encode()).hexdigest() != self._serial:
                raise ValueError
            defaults = self._reader._read(_DEFAULT)
            draft = prepare_local_user_reset_fixture_create(defaults, json.loads(schema), username=self._draft.username, access_profile="Guest")
            if draft != self._draft: raise ValueError
        finally:
            _zeroize_mutable(schema); _zeroize_mutable(defaults)

    def _eligible(self, observed: LocalUserResetMetadataObservation) -> None:
        u = observed.user
        if (u.username != self._draft.username or u.status != "enable" or u.access_profile != "Guest" or not u.is_local
                or u.sponsor_group != "" or u.schedule != "" or u.guest_auth != "disable"
                or u.reported_reference_count != 0 or observed.usage_entry_count != 0
                or u.product_version != "7.0.0" or u.product_build != 29):
            raise ValueError

    def _definition_from_full(self, raw: bytearray) -> LocalUserResetFixtureCreatedReadback:
        """Copy only non-material submitted fields before the full redactor runs."""
        from .target_lifecycle_dependencies import _one
        selected = bytearray()
        try:
            root = _object_spans(raw, 0, len(raw))
            serial = m._scalar(raw, root["serial"])
            if type(serial) is not str or hashlib.sha256(serial.encode()).hexdigest() != self._serial: raise ValueError
            fields = _object_spans(raw, *_one(raw, root["results"]))
            if raw[slice(*fields["q_static"])] != b"false": raise ValueError
            selected.extend(b"{")
            for index, (key, span) in enumerate(root.items()):
                if index: selected.extend(b",")
                selected.extend(json.dumps(key).encode("ascii") + b":")
                if key != "results":
                    selected.extend(memoryview(raw)[slice(*span)]); continue
                selected.extend(b"{")
                for number, field in enumerate(sorted(_FIELDS | {"webauthn", "q_ref", "q_static"})):
                    if number: selected.extend(b",")
                    selected.extend(json.dumps(field).encode("ascii") + b":")
                    if field == "webauthn":
                        children = _object_spans(raw, *fields[field])
                        selected.extend(b'{"status":'); selected.extend(memoryview(raw)[slice(*children["status"])]); selected.extend(b"}")
                    else: selected.extend(memoryview(raw)[slice(*fields[field])])
                selected.extend(b"}")
            selected.extend(b"}")
            return verify_fixture_created_detail(selected, self._draft)
        finally:
            _zeroize_mutable(selected)

    def _complete_created(self) -> tuple[LocalUserResetMetadataObservation, LocalUserResetFixtureCreatedReadback]:
        """Same four fixed metadata reads, with the full detail checked twice."""
        buffers: list[bytearray] = []
        try:
            raw = self._metadata._read(_SCHEMA); buffers.append(raw)
            schema = json.loads(raw); _schema_fields(schema)
            raw = self._metadata._read(self._metadata._detail); buffers.append(raw)
            definition = self._definition_from_full(raw)
            user = project_local_user_reset_detail(raw, schema, expected_username=self._draft.username)
            qtype = self._metadata._read_user_type()
            query = urlencode({"mkey":self._draft.username,"qtypes":json.dumps([qtype],separators=(",",":"))})
            raw = self._metadata._read(_USAGE, usage_query=query, qtype=qtype); buffers.append(raw)
            fields = _object_spans(raw, *_monitor_results(raw, expected_route="system/object/usage", expected_mkey=self._draft.username))
            for left, right in fields.values(): _validate_value(raw, left, right, depth=0)
            count = _array_count(raw, *fields["currently_using"], depth=0, objects_only=True)
            return LocalUserResetMetadataObservation(user, count), definition
        finally:
            for raw in buffers: _zeroize_mutable(raw)

    def read_created(self) -> LocalResetFixtureCreatedState:
        stage = "source_binding"
        try:
            with self._lock, _private_http_logs():
                started = self._now(); self._current = self._seal = None
                stage = "actor_before"; self._actor_current()
                stage = "defaults_before"; self._defaults_current()
                stage = "complete_state_before"; before, before_definition = self._complete_created(); self._eligible(before)
                stage = "submitted_definition"; raw = self._fixture._exchange("GET")
                try:
                    root = _object_spans(raw, 0, len(raw))
                    serial = m._scalar(raw, root["serial"])
                    if type(serial) is not str or hashlib.sha256(serial.encode()).hexdigest() != self._serial: raise ValueError
                    from .target_lifecycle_dependencies import _one
                    row = _object_spans(raw, *_one(raw, root["results"]))
                    if raw[slice(*row["q_static"])] != b"false": raise ValueError
                    definition = verify_fixture_created_detail(raw, self._draft)
                finally:
                    _zeroize_mutable(raw)
                stage = "complete_state_after"; after, after_definition = self._complete_created(); self._eligible(after)
                if before != after or not before_definition == definition == after_definition: raise ValueError
                stage = "defaults_after"; self._defaults_current()
                stage = "actor_after"; self._actor_current()
                stage = "verification_window"
                if self._now() >= started + 60: raise ValueError
                state = canonical_digest(dict(contract=CONTRACT, source=self._source,
                    nonmaterial_state=after.user.nonmaterial_state_digest, definition=definition.readback_digest, user_id=definition.user_id))
                observed = LocalResetFixtureCreatedState(self._source, state, after.user.nonmaterial_state_digest,
                    definition.readback_digest, definition.user_id, started, started + 60)
                self._current, self._seal = observed, _observation_digest(observed)
                self._last_failure_stage = None
                return observed
        except Exception:
            self._failed = True; self._current = self._seal = None; self._last_failure_stage = stage
            raise ValueError(_ERROR) from None

    def check_current(self, observed: LocalResetFixtureCreatedState) -> None:
        try:
            if (observed is not self._current or type(observed) is not LocalResetFixtureCreatedState
                    or _observation_digest(observed) != self._seal
                    or not observed.observed_at <= self._now() < observed.expires_at): raise ValueError
        except Exception:
            self._failed = True; self._current = self._seal = None
            raise ValueError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._closed = True; self._current = self._seal = None
