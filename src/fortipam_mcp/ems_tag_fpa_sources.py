"""Fresh fixed FortiPAM admission source for one protected EMS Tag candidate.

Trusted composition supplies the protected Owner factory, physical/TLS route
and exact product identities. No caller route, credentials, issuer, Tag writer
or ownership adoption is exposed. Saved observations never become live reads.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import hmac
import json
from pathlib import Path
from threading import RLock
import time
from typing import Any, Literal
from urllib.parse import urlencode

from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from .crl_import_transport import _frame
from .ems_tag_contract import _canonical
from .ems_tag_custody import EmsTagOriginalCustody, _pairs, _nonfinite
from .ems_tag_fpa_mapping import FpaEmsTagMapping, qualify_fpa_tag_mapping, fpa_address_reference_type
from .ems_tag_http_transport import NativeEmsTagHttpTransport
from .ems_tag_sources import EmsTagSources
from .ems_timeout_transport import COLLECTION, STATUS, connector_projection
from .local_user_reset_fixture_preflight import _actor_context
from .owner_session_metadata import OwnerSessionMetadataTransport
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig, _zeroize_mutable

_ERROR = "The private fresh FortiPAM Tag source is unavailable."
_DOMAIN = b"ems-tag-fixed-fpa-source/v2\x00"
_ACTOR = "/api/v2/monitor/web-ui/state"
_CONNECTORS = COLLECTION + "?with_meta=true"
_TAGS = "/api/v2/cmdb/firewall/address?" + urlencode({"format":
    "name|type|sub-type|obj-tag|obj-type|tag-type|tag-detection-level", "with_meta": "true"})
_URLS = "/api/v2/monitor/web-ui/object-urls"
_USAGE = "/api/v2/monitor/system/object/usage?"


@dataclass(frozen=True, slots=True, repr=False)
class EmsTagFpaBinding(_OpaqueC3Object):
    source_context_digest: str
    baseline_digest: str
    source_key_digest: str

    def __post_init__(self) -> None:
        for value in (self.source_context_digest, self.baseline_digest, self.source_key_digest):
            require_digest(value, "original_fpa_tag_scope")


@dataclass(frozen=True, slots=True, repr=False)
class EmsTagFpaObservation(_OpaqueC3Object):
    source_context_digest: str
    mapping: FpaEmsTagMapping
    observed_at: int
    expires_at: int
    signature: str


class EmsTagFpaSources(_OpaqueC3Object):
    def __init__(self, *, transport: NativeEmsTagHttpTransport, sources: EmsTagSources,
            owner_factory: Callable[[], OwnerSessionMetadataTransport],
            config: SecretMetadataHttpTransportConfig, owner_name: str, expected_serial: str,
            source_key: bytes, clock: Callable[[], int] | None = None) -> None:
        try:
            if (type(transport) is not NativeEmsTagHttpTransport or type(sources) is not EmsTagSources
                    or getattr(sources._get, "__self__", None) is not transport
                    or getattr(sources._get, "__func__", None) is not NativeEmsTagHttpTransport.get_json
                    or type(config) is not SecretMetadataHttpTransportConfig or not callable(owner_factory)
                    or type(config.ca_file) is not str or not Path(config.ca_file).is_absolute()
                    or type(owner_name) is not str or not 0 < len(owner_name) <= 256
                    or type(expected_serial) is not str or not 0 < len(expected_serial) <= 256
                    or type(source_key) is not bytes or not 32 <= len(source_key) <= 4096
                    or hmac.compare_digest(source_key, sources._key)
                    or clock is not None and not callable(clock)):
                raise ValueError
            self._transport, self._sources, self._draft = transport, sources, sources._draft
            self._ems_context = sources.source_context_digest
            self._factory, self._config, self._owner, self._serial = owner_factory, config, owner_name, expected_serial
            self._key = bytearray(source_key)
            self._key_digest = hashlib.sha256(source_key).hexdigest()
            self._clock = clock or (lambda: int(time.time()))
            self._source: str | None = None
            self._current: EmsTagFpaObservation | None = None
            self._closed, self._last, self._lock = False, -1, RLock()
            self.failure_stage: str | None = None
            self.connector_configuration_unchanged: bool | None = None
            self.connector_counter_unchanged: bool | None = None
            self.last_read_stage: str | None = None
            self.last_http_status: int | None = None
            self.mapping_diagnostic: dict[str, int | bool | None] | None = None
            self.owner_logout_verified = False
            self.metadata_get_count = 0
            self._stage = "constructed"
            self._namespace = self._context()
            self._pins()
        except Exception:
            if hasattr(self, "_key"):
                _zeroize_mutable(self._key)
            raise ValueError(_ERROR) from None

    def _context(self) -> str:
        return self._mac("namespace", {"ems_context": self._ems_context, "ems_channel": self._transport._binding,
            "fpa_origin": self._config.base_url, "fpa_ca": self._config.ca_file,
            "fpa_ca_sha256": hashlib.sha256(Path(self._config.ca_file or "").read_bytes()).hexdigest(),
            "fpa_serial": self._serial, "fpa_owner": self._owner, "draft": self._draft.parameters_digest})

    def _mac(self, purpose: str, value: object) -> str:
        return hmac.new(self._key, _DOMAIN + purpose.encode() + b"\x00" + _canonical(value), hashlib.sha256).hexdigest()

    def _now(self) -> int:
        try:
            now = self._clock()
            if self._closed or type(now) is not int or now < 0 or now < self._last:
                raise ValueError
            self._last = now
            return now
        except Exception:
            self._closed = True
            _zeroize_mutable(self._key)
            raise ValueError from None

    def _pins(self) -> None:
        try:
            self._now()
            self._transport._pins()
            if (self._transport._live is not True or self._transport._failed
                    or self._sources._draft is not self._draft
                    or self._sources.source_context_digest != self._ems_context
                    or self._context() != self._namespace or hashlib.sha256(self._key).hexdigest() != self._key_digest):
                raise ValueError
        except Exception:
            self.close()
            raise ValueError from None

    def _signature(self, observation: EmsTagFpaObservation) -> str:
        return self._mac("observation", {"source": observation.source_context_digest,
            "scope": observation.mapping.digest, "observed_at": observation.observed_at,
            "expires_at": observation.expires_at})

    def _mapping(self, frame: Any, ems_serial: str) -> FpaEmsTagMapping:
        rows = frame.get("results") if type(frame) is dict else None
        matched = frame.get("matched_count") if type(frame) is dict else None
        limit = frame.get("limit_reached") if type(frame) is dict else None
        candidates = [row for row in rows if type(row) is dict and type(row.get("obj-tag")) is str
                      and row["obj-tag"].casefold() == self._draft._name.casefold()] if type(rows) is list else []
        self.mapping_diagnostic = {
            "rows": len(rows) if type(rows) is list else None,
            "matched_count": matched if type(matched) is int and 0 <= matched <= 2**31 - 1 else None,
            "limit_reached": limit if type(limit) is bool else None,
            "selected_label_rows": len(candidates),
            "selected_metadata_valid": all(type(row.get("q_ref")) is int and row["q_ref"] >= 0
                and type(row.get("q_global_entry")) is bool and not row["q_global_entry"] for row in candidates),
        }
        return qualify_fpa_tag_mapping(frame, ems_serial=ems_serial, draft=self._draft)

    def observe(self) -> EmsTagFpaObservation:
        owner: OwnerSessionMetadataTransport | None = None
        counts: dict[str, int] = {}
        try:
            with self._lock:
                self.connector_configuration_unchanged = None
                self.connector_counter_unchanged = None
                self.last_read_stage = None
                self.last_http_status = None
                self.mapping_diagnostic = None
                self._stage = "source_pins"
                self._pins()
                self._stage = "owner_factory"
                owner = self._factory()
                if (type(owner) is not OwnerSessionMetadataTransport or owner._config != self._config
                        or owner._owner_name != self._owner or owner._client is not None):
                    raise ValueError
                allowed = {_ACTOR: 2, _CONNECTORS: 2, _TAGS: 2, _URLS: 1}
                def get(path: str, table: str, name: str, *, actor: bool = False) -> Any:
                    if path not in allowed or counts.get(path, 0) >= allowed[path]:
                        raise ValueError
                    counts[path] = counts.get(path, 0) + 1
                    if sum(counts.values()) > 25 or owner._client is None:
                        raise ValueError
                    raw = bytearray()
                    try:
                        self.last_read_stage = "headers"
                        self.last_http_status = None
                        with owner._client.stream("GET", path, headers={"Accept-Encoding": "identity",
                                "Cache-Control": "no-cache, no-store"}) as response:
                            self.last_http_status = response.status_code
                            length = response.headers.get("Content-Length")
                            transfer = response.headers.get("Transfer-Encoding")
                            if (response.status_code != 200 or response.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/json"
                                    or response.headers.get("Content-Encoding", "identity") not in ("", "identity")
                                    or transfer is not None and (transfer.lower() != "chunked" or length is not None)
                                    or length is not None and (not length.isdecimal() or int(length) > 262144)):
                                raise ValueError
                            self.last_read_stage = "body"
                            for block in response.iter_bytes():
                                raw.extend(block)
                                if len(raw) > 262144:
                                    raise ValueError
                            if length is not None and len(raw) != int(length):
                                raise ValueError
                            self.last_read_stage = "json"
                            payload = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_nonfinite)
                            if type(payload) is not dict:
                                raise ValueError
                            self.last_read_stage = "product_frame"
                            result: Any
                            if actor:
                                if payload.get("serial") != self._serial:
                                    raise ValueError
                                result = _actor_context(raw, expected_name=self._owner)
                            else:
                                result = _frame(raw, self._serial, method="GET", path=table, name=name)
                            self.last_read_stage = "complete"
                            return result
                    finally:
                        _zeroize_mutable(raw)

                def connectors() -> list[dict[str, Any]]:
                    frame = get(_CONNECTORS, "endpoint-control", "fctems")
                    result = connector_projection(frame["results"])
                    if (frame.get("limit_reached", False) is not False
                            or type(frame.get("matched_count", len(result))) is not int
                            or frame.get("matched_count", len(result)) != len(result)):
                        raise ValueError
                    return result

                with owner.authenticated():
                    self._stage = "actor_before"
                    actor_before = get(_ACTOR, "", "", actor=True)
                    self._stage = "connectors_before"
                    before_connectors = connectors()
                    matches = [row for row in before_connectors if row["server"].casefold() == self._transport._config.hostname.casefold()
                        and row["https-port"] == self._transport._config.port]
                    if (len(matches) != 1 or matches[0]["pull-tags"] != "enable"
                            or not matches[0]["certificate-fingerprint"]):
                        raise ValueError
                    status_path = STATUS + "?" + urlencode({"ems_name": matches[0]["name"]})
                    allowed[status_path] = 2
                    self._stage = "status_before"
                    status = get(status_path, "endpoint-control", "ems")["results"]
                    if type(status) is not dict or status.get("ems_status") != "success":
                        raise ValueError
                    ems_serial = status.get("ems_serial")
                    if type(ems_serial) is not str:
                        raise ValueError
                    self._stage = "complete_mapping_before"
                    before = self._mapping(get(_TAGS, "firewall", "address"), ems_serial)
                    self._stage = "selected_root_scope"
                    prefixes = (ems_serial.casefold() + "_", "mac_" + ems_serial.casefold() + "_")
                    for encoded in before._rows:
                        row = json.loads(encoded)
                        if (row["type"] == "dynamic" and row["sub-type"] == "ems-tag"
                                and row["name"].casefold().startswith(prefixes)
                                and row.get("q_global_entry") is not False):
                            raise ValueError
                    self._stage = "reference_type"
                    reference_type = fpa_address_reference_type(get(_URLS, "web-ui", "object-urls"))
                    if len(before._owned_names) > 16:
                        raise ValueError
                    usage = {}
                    self._stage = "candidate_usage"
                    for candidate_name in before._owned_names:
                        path = _USAGE + urlencode({"mkey": candidate_name, "qtypes": json.dumps([reference_type], separators=(",", ":"))})
                        allowed[path] = 1
                        usage[candidate_name] = get(path, "system", "object")
                    before.require_zero_owned_references(usage)
                    self._stage = "complete_mapping_after"
                    after = self._mapping(get(_TAGS, "firewall", "address"), ems_serial)
                    after.require_zero_owned_references(usage)
                    self._stage = "status_after"
                    status_after = get(status_path, "endpoint-control", "ems")["results"]
                    if (after.digest != before.digest or status_after.get("ems_status") != "success"
                            or status_after.get("ems_serial") != ems_serial):
                        raise ValueError
                    self._stage = "connectors_after"
                    after_connectors = connectors()
                    before_configuration = [{key: value for key, value in row.items() if key != "q_ref"}
                                            for row in before_connectors]
                    self.connector_configuration_unchanged = before_configuration == [
                        {key: value for key, value in row.items() if key != "q_ref"} for row in after_connectors]
                    self.connector_counter_unchanged = [row["q_ref"] for row in before_connectors] == [
                        row["q_ref"] for row in after_connectors]
                    if after_connectors != before_connectors:
                        raise ValueError
                    self._stage = "actor_after"
                    if get(_ACTOR, "", "", actor=True) != actor_before:
                        raise ValueError
                self._stage = "owner_closure"
                if not owner.logout_verified or owner._client is not None:
                    raise ValueError
                self._pins()
                # Counters are compared inside each window. Persistent connector
                # identity excludes q_ref; every address reference stays bound.
                context = self._mac("source", {"namespace": self._namespace, "actor": actor_before,
                    "connectors": before_configuration,
                    "ems_serial": ems_serial, "reference_type": reference_type})
                if self._source is not None and self._source != context:
                    raise ValueError
                self._source = context
                now = self._now()
                observed = EmsTagFpaObservation(context, before, now, now + 60, "")
                object.__setattr__(observed, "signature", self._signature(observed))
                self._current = observed
                self._stage = "source_complete"
                return observed
        except Exception:
            self.failure_stage = self._stage
            self.close()
            raise ValueError(_ERROR) from None
        finally:
            self.metadata_get_count = sum(counts.values())
            self.owner_logout_verified = owner is not None and owner.logout_verified is True

    def check_current(self, observed: EmsTagFpaObservation) -> None:
        try:
            with self._lock:
                self._pins()
                now = self._now()
                if (type(observed) is not EmsTagFpaObservation or observed is not self._current
                        or observed.source_context_digest != self._source
                        or not observed.observed_at <= now < observed.expires_at
                        or observed.expires_at != observed.observed_at + 60
                        or not hmac.compare_digest(observed.signature, self._signature(observed))):
                    raise ValueError
        except Exception:
            raise ValueError(_ERROR) from None

    def bind_original_absence(self, observed: EmsTagFpaObservation) -> EmsTagFpaBinding:
        self.check_current(observed)
        if not observed.mapping.candidate_absent:
            raise ValueError(_ERROR)
        return EmsTagFpaBinding(observed.source_context_digest, observed.mapping.digest, self._key_digest)

    def require_original_scope(self, observed: EmsTagFpaObservation, binding: EmsTagFpaBinding, *, absent: bool) -> None:
        self.check_current(observed)
        if type(binding) is not EmsTagFpaBinding or type(absent) is not bool:
            raise ValueError(_ERROR)
        binding.__post_init__()
        if (binding.source_context_digest != observed.source_context_digest
                or binding.source_key_digest != self._key_digest
                or observed.mapping.without_owned_digest != binding.baseline_digest
                or absent and not observed.mapping.candidate_absent):
            raise ValueError(_ERROR)

    def close(self) -> None:
        with self._lock:
            self._closed = True
            _zeroize_mutable(self._key)


class EmsTagFpaAdmission(_OpaqueC3Object):
    """Bind only a fresh absence or the verified original's signed FPA inputs."""
    def __init__(self, source: EmsTagFpaSources, *, phase: Literal["create", "recover"],
            original: EmsTagOriginalCustody | None = None, original_binding_file: Path | None = None) -> None:
        try:
            if type(source) is not EmsTagFpaSources or phase not in ("create", "recover") or source._current is None:
                raise ValueError
            self.source, self.phase, self.original = source, phase, original
            self._source_pin, self._phase_pin, self._original_pin = source, phase, original
            if phase == "create":
                if original is not None or original_binding_file is not None:
                    raise ValueError
                binding = source.bind_original_absence(source._current)
            else:
                from .ems_tag_original_binding import load_original_fpa_binding
                if type(original) is not EmsTagOriginalCustody or original_binding_file is None:
                    raise ValueError
                binding = load_original_fpa_binding(original_binding_file, original._key_file, original=original)
                source.require_original_scope(source._current, binding, absent=False)
            self.binding = binding
            self._pin = _canonical(binding_fields(binding))
        except Exception:
            raise ValueError(_ERROR) from None

    def pins(self) -> None:
        if (self.source is not self._source_pin or self.phase != self._phase_pin
                or self.original is not self._original_pin):
            raise ValueError(_ERROR)
        self.source._pins()
        self.binding.__post_init__()
        if (self._pin != _canonical(binding_fields(self.binding))
                or self.source._source != self.binding.source_context_digest
                or self.source._key_digest != self.binding.source_key_digest):
            raise ValueError(_ERROR)

    def check(self, *, refresh: bool = False, after_effect: bool = False) -> EmsTagFpaObservation:
        self.pins()
        observed = self.source.observe() if refresh else self.source._current
        if observed is None:
            raise ValueError(_ERROR)
        absent = self.phase == ("recover" if after_effect else "create")
        self.source.require_original_scope(observed, self.binding, absent=absent)
        return observed


def binding_fields(binding: EmsTagFpaBinding) -> dict[str, str]:
    binding.__post_init__()
    return dict(source_context_digest=binding.source_context_digest, baseline_digest=binding.baseline_digest,
                source_key_digest=binding.source_key_digest)
