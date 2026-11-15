"""Private Source/credential-Secret/Target join and lease-time account guard.

No Tool, authorization or dispatch is added. Metadata preparation never loads
credentials. The existing provider alone loads its pair after M4 gates; the
loader below refuses a different account before releasing either owned buffer.
Retained snapshot state does not prove snapshot age or current account absence.
An explicit original-Run phase reuses these readers with original full Source
custody; the existing post-scan selection requirement remains unchanged.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import hmac
import ipaddress
import json
import secrets
import ssl
import time
import uuid
from pathlib import Path
from threading import RLock
from typing import TYPE_CHECKING, cast
from urllib.parse import quote, urlsplit

import httpx

from v4_planning.canonical import canonical_json
from v4_planning.material_provider import MaterialAccessDenied, MaterialBindingStatus, _OpaqueC3Object

from . import secret_bulk_import_metadata as m
from .discovery_review_http_transport import (
    _FIELDS, _nonfinite, _unique_pairs, project_unix_discovery_selection,
)
from .discovery_review_mcp_action import SELECTION_BINDING_CONTRACT, _load_review_binding
from .linux_onboarding_prepare import PROFILE_CONTRACT, PROFILE_VERSION
from .secret_create_central_lab_binding import _read_owner_only_file
from .secret_create_central_lab_provider import CentralLabSecretCreateResolverLoader
from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig, _redact_json_field_values, _zeroize_mutable,
)
from .secret_onboarding_projection_source import SecretOnboardingBinding
from .service_account_state_reader import _ca
from .target_api_dependency_reader import _private_http_logs
from .target_lifecycle_dependencies import _one, _spans
from .target_preservation_contract import _digest, capture_target_state

if TYPE_CHECKING:
    from .discovery_account_run_custody import AccountDiscoveryRunCustody
    from .discovery_source_create_custody import DiscoverySourceCreateCustody

_ERROR = "The protected Unix Discovery handoff is unavailable."
CONTRACT = "fortipam-build29-unix-discovery-onboarding-guard-private-v1"
ENV_PREFIX = "FORTIPAM_MCP_V4_SECRET_CREATE_LAB_AUTO_DISCOVERY_"
ORIGINAL_RUN_RELATION_CONTRACT = "fortipam-build29-original-run-reference-bracket-v1"
ORIGINAL_RUN_STABLE_RELATION_CONTRACT = "fortipam-build29-original-run-stable-reference-v1"


class UnixDiscoveryHandoffError(ValueError):
    """Fixed refusal without selectors, material or partial observations."""


def _profile_subject(profile: Mapping[str, object]) -> tuple[object, ...]:
    if (profile.get("contract") != PROFILE_CONTRACT or profile.get("version") != PROFILE_VERSION
            or profile.get("target_protocol") != "ssh"
            or profile.get("template_name") != "Unix Account (SSH Password)"):
        raise ValueError
    fields = ("folder_path", "secret_name", "template_name", "target_name", "target_protocol", "target_ipv4_address")
    for name in fields:
        m._text(profile[name])
    address = profile["target_ipv4_address"]
    if type(address) is not str or str(ipaddress.IPv4Address(address)) != address:
        raise ValueError
    target_name = profile["target_name"]
    if type(target_name) is not str or len(target_name) > 79 or target_name in {".", ".."} or any(char in target_name for char in "/\\?#%"):
        raise ValueError
    return tuple(profile[name] for name in fields)


@dataclass(frozen=True, slots=True, repr=False)
class UnixDiscoveryRelation(_OpaqueC3Object):
    relation_digest: str
    selected_account_unmanaged: bool


@dataclass(frozen=True, slots=True, repr=False)
class UnixDiscoveryOriginalRunRelation(_OpaqueC3Object):
    relation_digest: str
    native_fixture_or_activity_qualified: bool = False
    stable_reference_digest: str | None = None


class UnixDiscoveryOnboardingGuard(_OpaqueC3Object):
    """Fixed six-GET brackets; real source provenance remains acceptance-scoped."""

    def __init__(self, config: SecretMetadataHttpTransportConfig, *, selection_binding_path: Path,
            profile_path: Path, clock: Callable[[], float] = time.monotonic,
            client_factory: Callable[..., httpx.Client] = httpx.Client,
            original_run_enabled: bool = False) -> None:
        self._key = bytearray()
        selection, profile = bytearray(), bytearray()
        try:
            if (type(config) is not SecretMetadataHttpTransportConfig
                    or not callable(clock) or not callable(client_factory) or type(original_run_enabled) is not bool
                    or not selection_binding_path.is_absolute() or not profile_path.is_absolute()):
                raise ValueError
            config.__post_init__()
            parsed = urlsplit(config.base_url)
            if parsed.username is not None or parsed.password is not None:
                raise ValueError
            self._config, self._selection_path, self._profile_path = config, selection_binding_path, profile_path
            self._clock, self._factory = clock, client_factory
            selection = _read_owner_only_file(selection_binding_path)
            profile = _read_owner_only_file(profile_path)
            try:
                parsed_selection = json.loads(selection, object_pairs_hook=_unique_pairs, parse_constant=_nonfinite)
                self._request, self._account = _load_review_binding(selection_binding_path)
                if self._account is None:
                    raise ValueError
                # The path resolver reads independently. Its validated subject
                # must be the same record whose bytes are pinned, even on ABA.
                if (type(parsed_selection) is not dict
                        or type(parsed_selection.get("discovery_secret_id")) is not int
                        or parsed_selection != {"contract": SELECTION_BINDING_CONTRACT,
                            "source_name": self._request.source_name,
                            "discovery_secret_id": self._request.discovery_secret_id,
                            "selected_account": self._account}):
                    raise ValueError
                self._profile = json.loads(profile, object_pairs_hook=_unique_pairs, parse_constant=_nonfinite)
                if type(self._profile) is not dict:
                    raise ValueError
                self._subject = _profile_subject(self._profile)
                self.profile_digest = hashlib.sha256(canonical_json(self._profile).encode()).hexdigest()
                self._file_digests = (hashlib.sha256(selection).digest(), hashlib.sha256(profile).digest())
            finally:
                _zeroize_mutable(selection); _zeroize_mutable(profile)
            ca = _ca(config)
            self._tls = ssl.create_default_context() if ca is None else ssl.create_default_context(cadata=ca.decode("ascii"))
            self._tls.minimum_version = ssl.TLSVersion.TLSv1_2
            self._key.extend(secrets.token_bytes(32))
            self._source_path = ("/api/v2/cmdb/secret/discovery/" + quote(self._request.source_name, safe="") +
                "?format=" + quote(_FIELDS, safe="") + "&vdom=root")
            self._secret_path = ("/api/v2/cmdb/secret/database/" + str(self._request.discovery_secret_id) +
                "?format=id%7Ctarget%7Ctemplate%7Cuuid&with_meta=true&vdom=root")
            self._target_path = ("/api/v2/cmdb/secret/target/" + quote(str(self._profile["target_name"]), safe="") +
                "?with_meta=true&vdom=root")
            self._paths: tuple[str, ...] = (self._source_path, self._secret_path, self._target_path)
            self._original_source_path = ("/api/v2/cmdb/secret/discovery/" + quote(self._request.source_name, safe="") +
                "?vdom=root") if original_run_enabled else None
            if self._original_source_path is not None: self._paths += (self._original_source_path,)
            self._source = self._context()
            self._last = -1.0
            self._failed = self._closed = False
            self._lock = RLock()
        except Exception:
            _zeroize_mutable(self._key)
            raise UnixDiscoveryHandoffError(_ERROR) from None
        finally:
            _zeroize_mutable(selection); _zeroize_mutable(profile)

    def _context(self) -> str:
        self._config.__post_init__()
        self._request.__post_init__()
        current = []
        for path in (self._selection_path, self._profile_path):
            raw = _read_owner_only_file(path)
            try: current.append(hashlib.sha256(raw).digest())
            finally: _zeroize_mutable(raw)
        if (tuple(current) != self._file_digests or _profile_subject(self._profile) != self._subject
                or self.profile_digest != hashlib.sha256(canonical_json(self._profile).encode()).hexdigest()
                or not self._tls.check_hostname or self._tls.verify_mode != ssl.CERT_REQUIRED
                or self._tls.minimum_version != ssl.TLSVersion.TLSv1_2):
            raise ValueError
        ca = _ca(self._config)
        values: tuple[object, ...] = (CONTRACT, self._config.base_url, hashlib.sha256(self._config.bearer_token.encode()).hexdigest(),
            self._config.timeout_seconds, self._config.ca_file, None if ca is None else hashlib.sha256(ca).hexdigest(),
            tuple(value.hex() for value in current), self._request.source_name, self._request.discovery_secret_id,
            self._account, self._paths, self.profile_digest, hashlib.sha256(self._key).hexdigest(),
            id(self._factory), id(self._clock), id(self._tls))
        if self._original_source_path is not None: values += (ORIGINAL_RUN_RELATION_CONTRACT, self._original_source_path)
        return _digest(values)

    def _now(self) -> float:
        import math
        value = self._clock()
        if (self._failed or self._closed or type(value) not in (float, int) or not math.isfinite(value)
                or value < 0 or value < self._last or self._context() != self._source):
            raise ValueError
        self._last = float(value)
        return float(value)

    def check_inputs(self, *, selection_binding_path: Path, profile_path: Path) -> None:
        try:
            self._now()
            if selection_binding_path != self._selection_path or profile_path != self._profile_path:
                raise ValueError
        except Exception:
            raise UnixDiscoveryHandoffError(_ERROR) from None

    def check_ready(self) -> None:
        try:
            self._now()
        except Exception:
            raise UnixDiscoveryHandoffError(_ERROR) from None

    def check_transport(self, config: SecretMetadataHttpTransportConfig) -> None:
        self.check_ready()
        if config is not self._config:
            raise UnixDiscoveryHandoffError(_ERROR)

    def check_onboarding_binding(self, binding: SecretOnboardingBinding) -> None:
        try:
            self._now()
            if type(binding) is not SecretOnboardingBinding or tuple(getattr(binding, key) for key in (
                    "folder_path", "secret_name", "template_name", "target_name", "target_protocol", "target_ipv4_address")) != self._subject:
                raise ValueError
        except Exception:
            raise UnixDiscoveryHandoffError(_ERROR) from None

    def _get(self, client: httpx.Client, path: str, deadline: float) -> bytearray:
        raw = bytearray()
        def remaining() -> float:
            value = deadline - self._now()
            if value <= 0: raise ValueError
            return min(10.0, float(self._config.timeout_seconds), value)
        try:
            if path not in self._paths:
                raise ValueError
            with client.stream("GET", self._config.base_url.rstrip("/") + path,
                    headers={"Accept": "application/json", "Accept-Encoding": "identity", "Cache-Control": "no-store",
                        "Authorization": "Bearer " + self._config.bearer_token}, timeout=remaining()) as response:
                remaining()
                if (response.status_code != 200 or response.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json"
                        or response.headers.get("content-encoding", "identity").strip().lower() not in ("", "identity")):
                    raise ValueError
                iterator = response.iter_raw()
                while True:
                    remaining()
                    try: chunk = next(iterator)
                    except StopIteration: remaining(); break
                    remaining()
                    maximum = 262_144 if path in (self._source_path, self._original_source_path) else 1_048_576
                    if len(raw) + len(chunk) > maximum: raise ValueError
                    raw.extend(chunk)
            remaining()
            if path == self._secret_path: _redact_json_field_values(raw)
            _spans(raw)
            result, raw = raw, bytearray()
            return result
        finally:
            _zeroize_mutable(raw)

    def _secret(self, raw: bytearray, serial: str, *, fingerprint_key: bytearray | None = None) -> str:
        envelope = _spans(raw)
        for name, expected in dict(version="v7.0.0", build=29, path="secret", name="database",
                http_method="GET", http_status=200, status="OK", vdom="root", serial=serial).items():
            value = m._scalar(raw, envelope[name])
            if type(value) is not type(expected) or value != expected: raise ValueError
        if "action" in envelope:
            raise ValueError
        if "error" in envelope:
            error = m._scalar(raw, envelope["error"])
            if error is not None and (type(error) is not int or error != 0): raise ValueError
        if "limit_reached" in envelope and m._scalar(raw, envelope["limit_reached"]) is not False: raise ValueError
        fields = m._object_spans(raw, *_one(raw, envelope["results"]), frozenset({"id", "target", "template", "uuid"}))
        if set(fields) != {"id", "target", "template", "uuid"}: raise ValueError
        m._text(m._scalar(raw, fields["template"]), maximum=79)
        native_uuid = m._scalar(raw, fields["uuid"])
        if type(native_uuid) is not str or not uuid.UUID(native_uuid).int or str(uuid.UUID(native_uuid)) != native_uuid: raise ValueError
        identifier = m._scalar(raw, fields["id"])
        if (type(identifier) is not int or identifier != self._request.discovery_secret_id
                or m._scalar(raw, fields["target"]) != self._profile["target_name"]):
            raise ValueError
        # These nonmaterial identity tokens stay significant without interpreting
        # credential slots, TOTP, permission or any unselected Secret field.
        return _digest(tuple((name, self._mac(raw, fields[name], fingerprint_key=fingerprint_key)) for name in sorted(fields)))

    def _mac(self, raw: bytearray, span: tuple[int, int] | None = None, *, fingerprint_key: bytearray | None = None) -> str:
        with memoryview(raw)[slice(*(span or (0, len(raw))))] as view:
            digest = hmac.new(self._key if fingerprint_key is None else fingerprint_key,
                b"" if fingerprint_key is None else b"original-run-reference-field/v1\x00", hashlib.sha256)
            digest.update(view)
            return digest.hexdigest()

    def observe(self, *, require_unmanaged: bool = True) -> UnixDiscoveryRelation:
        raw_buffers: list[bytearray] = []
        with self._lock:
            try:
                if type(require_unmanaged) is not bool: raise ValueError
                started = self._now(); deadline = started + 30
                with _private_http_logs():
                    client = self._factory(verify=self._tls, timeout=10, follow_redirects=False, trust_env=False)
                    try:
                        with client:
                            source = self._get(client, self._source_path, deadline); raw_buffers.append(source)
                            account = self._account
                            if type(account) is not str: raise ValueError
                            decision = project_unix_discovery_selection(json.loads(source,
                                object_pairs_hook=_unique_pairs, parse_constant=_nonfinite), self._request, account)
                            unmanaged = decision["selected_account_unmanaged"] is True
                            if require_unmanaged and not unmanaged: raise ValueError
                            serial = m._text(m._scalar(source, _spans(source)["serial"]), maximum=128)
                            secret = self._get(client, self._secret_path, deadline); raw_buffers.append(secret)
                            secret_digest = self._secret(secret, serial)
                            target = self._get(client, self._target_path, deadline); raw_buffers.append(target)
                            first = capture_target_state(target, expected_name=str(self._profile["target_name"]),
                                expected_serial_digest=hashlib.sha256(serial.encode()).hexdigest())
                            if first.coordinates.address != self._profile["target_ipv4_address"]: raise ValueError
                            target = self._get(client, self._target_path, deadline); raw_buffers.append(target)
                            if capture_target_state(target, expected_name=first.name,
                                    expected_serial_digest=first.serial_digest) != first: raise ValueError
                            secret = self._get(client, self._secret_path, deadline); raw_buffers.append(secret)
                            if self._secret(secret, serial) != secret_digest: raise ValueError
                            last = self._get(client, self._source_path, deadline); raw_buffers.append(last)
                            if self._mac(source) != self._mac(last): raise ValueError
                    finally:
                        if not client.is_closed: client.close()
                if self._now() >= deadline or not client.is_closed: raise ValueError
                return UnixDiscoveryRelation(_digest((self._source, self._mac(source), secret_digest,
                    first.state_digest)), unmanaged)
            except Exception:
                self._failed = True
                _zeroize_mutable(self._key)
                raise UnixDiscoveryHandoffError(_ERROR) from None
            finally:
                for raw in raw_buffers: _zeroize_mutable(raw)

    def material_loader(self, loader: CentralLabSecretCreateResolverLoader,
            binding: SecretOnboardingBinding) -> CentralLabSecretCreateResolverLoader:
        self.check_onboarding_binding(binding)
        return _SelectedAccountLoader(self, loader, binding)

    def _reference_baseline(self, creation: DiscoverySourceCreateCustody, source_custody_digest: str,
            selected_account: str, fixture_birth_digest: str, stable_secret: str,
            target_digest: str, key: bytearray) -> str:
        ca = _ca(self._config)
        return hmac.new(key, b"original-run-reference-baseline/v1\x00" + canonical_json({
            "contract": ORIGINAL_RUN_STABLE_RELATION_CONTRACT,
            "source_custody": source_custody_digest, "source_parameters": creation._binding.parameters_digest,
            "requester": creation._plan.requester_digest, "device": creation._serial,
            "fixture_birth": fixture_birth_digest, "selected_account": selected_account,
            "profile": self.profile_digest, "origin": self._config.base_url,
            "ca_sha256": None if ca is None else hashlib.sha256(ca).hexdigest(),
            "secret_identity": stable_secret, "complete_target": target_digest,
        }).encode(), hashlib.sha256).hexdigest()

    def observe_original_run(self, creation: DiscoverySourceCreateCustody, *, selected_account: str,
            fixture_birth_digest: str, original_run: AccountDiscoveryRunCustody | None = None,
            reference_witness_key: bytearray | None = None) -> UnixDiscoveryOriginalRunRelation:
        """Bracket exact original Source content and the unchanged reference graph.

        Before Scan, require the original full unscanned row. After Scan, require
        the original positive reply/content pin, never a timestamp alone. These
        observations cannot qualify native fixture liveness, activity or recovery.
        """
        from .discovery_account_run_custody import AccountDiscoveryRunCustody
        from .discovery_source_create_custody import DiscoverySourceCreateCustody
        from v4_planning.models import require_digest
        raw_buffers: list[bytearray] = []
        stable_key = bytearray()
        with self._lock:
            try:
                started = self._now(); deadline = started + 30
                if (self._original_source_path is None or type(creation) is not DiscoverySourceCreateCustody
                        or creation._binding.request != self._request or creation._config is not self._config
                        or selected_account != self._account): raise ValueError
                require_digest(fixture_birth_digest, "original_run_fixture")
                if reference_witness_key is not None:
                    if type(reference_witness_key) is not bytearray or len(reference_witness_key) != 32 or reference_witness_key is self._key: raise ValueError
                    stable_key = bytearray(reference_witness_key)
                original = creation.inspect_original_state()
                if (not original.acknowledgement_qualified or original.original_outcome != "succeeded"
                        or original.original_verification != "verified"): raise ValueError
                if original_run is not None and (type(original_run) is not AccountDiscoveryRunCustody
                        or original_run._creation is not creation or original_run._selected != selected_account
                        or original_run._fixture != fixture_birth_digest): raise ValueError

                def source(raw: bytearray) -> None:
                    payload = json.loads(raw, object_pairs_hook=_unique_pairs, parse_constant=_nonfinite)
                    if original_run is None:
                        pin = creation.bind_scan_preservation(cast(Mapping[str, object], payload), selected_account,
                            fixture_birth_digest=fixture_birth_digest)
                        pin.close()
                    else:
                        original_run.inspect_scanned_state(self._request, payload)

                with _private_http_logs():
                    client = self._factory(verify=self._tls, timeout=10, follow_redirects=False, trust_env=False)
                    try:
                        with client:
                            first_source = self._get(client, self._original_source_path, deadline); raw_buffers.append(first_source)
                            source(first_source)
                            serial = m._text(m._scalar(first_source, _spans(first_source)["serial"]), maximum=128)
                            secret = self._get(client, self._secret_path, deadline); raw_buffers.append(secret)
                            secret_digest = self._secret(secret, serial)
                            stable_secret = self._secret(secret, serial, fingerprint_key=stable_key) if stable_key else None
                            target = self._get(client, self._target_path, deadline); raw_buffers.append(target)
                            first = capture_target_state(target, expected_name=str(self._profile["target_name"]),
                                expected_serial_digest=hashlib.sha256(serial.encode()).hexdigest())
                            if first.coordinates.address != self._profile["target_ipv4_address"]: raise ValueError
                            target = self._get(client, self._target_path, deadline); raw_buffers.append(target)
                            if capture_target_state(target, expected_name=first.name, expected_serial_digest=first.serial_digest) != first: raise ValueError
                            secret = self._get(client, self._secret_path, deadline); raw_buffers.append(secret)
                            if self._secret(secret, serial) != secret_digest: raise ValueError
                            if stable_key and self._secret(secret, serial, fingerprint_key=stable_key) != stable_secret: raise ValueError
                            last = self._get(client, self._original_source_path, deadline); raw_buffers.append(last)
                            source(last)
                            if self._mac(first_source) != self._mac(last): raise ValueError
                    finally:
                        if not client.is_closed: client.close()
                if self._now() >= deadline or not client.is_closed: raise ValueError
                # Source changes are validated above against their original
                # phase pin. Only the fixed reference graph must compare equal
                # across the permitted Source timestamp/results delta.
                stable_reference = None
                if stable_key:
                    if stable_secret is None: raise ValueError
                    stable_reference = self._reference_baseline(creation, original.custody_digest, selected_account,
                        fixture_birth_digest, stable_secret, first.state_digest, stable_key)
                return UnixDiscoveryOriginalRunRelation(_digest((ORIGINAL_RUN_RELATION_CONTRACT, self._source,
                    original.custody_digest, fixture_birth_digest, secret_digest, first.state_digest)),
                    stable_reference_digest=stable_reference)
            except Exception:
                self._failed = True
                _zeroize_mutable(self._key)
                raise UnixDiscoveryHandoffError(_ERROR) from None
            finally:
                for raw in raw_buffers: _zeroize_mutable(raw)
                _zeroize_mutable(stable_key)

    def observe_original_run_references(self, original_run: AccountDiscoveryRunCustody, *, reference_witness_key: bytearray) -> str:
        """Read only the fixed reference graph; never assert Source presence/absence.

        Recovery must bracket this observation with its own exact Source reads.
        The original successful Run and baseline remain mandatory.
        """
        from .discovery_account_run_custody import AccountDiscoveryRunCustody
        buffers: list[bytearray] = []; key = bytearray()
        with self._lock:
            try:
                deadline = self._now() + 30
                if (type(original_run) is not AccountDiscoveryRunCustody or self._original_source_path is None
                        or type(reference_witness_key) is not bytearray or len(reference_witness_key) != 32
                        or reference_witness_key is self._key): raise ValueError
                creation = original_run._creation
                if (creation._binding.request != self._request or creation._config is not self._config
                        or original_run._selected != self._account): raise ValueError
                original = original_run.inspect_original_state()
                if (original.original_outcome != "succeeded" or original.original_verification != "verified"
                        or not original.native_reply_valid or original.ongoing_requests != 0 or original.failed_requests != 0
                        or not original.original_configuration_preserved or original_run.inspect_reference_baseline() is None): raise ValueError
                key = bytearray(reference_witness_key)
                with _private_http_logs():
                    client = self._factory(verify=self._tls, timeout=10, follow_redirects=False, trust_env=False)
                    try:
                        with client:
                            raw = self._get(client, self._secret_path, deadline); buffers.append(raw)
                            serial = m._text(m._scalar(raw, _spans(raw)["serial"]), maximum=128)
                            if hashlib.sha256(serial.encode()).hexdigest() != creation._serial: raise ValueError
                            secret = self._secret(raw, serial, fingerprint_key=key)
                            raw = self._get(client, self._target_path, deadline); buffers.append(raw)
                            target = capture_target_state(raw, expected_name=str(self._profile["target_name"]), expected_serial_digest=creation._serial)
                            if target.coordinates.address != self._profile["target_ipv4_address"]: raise ValueError
                            raw = self._get(client, self._target_path, deadline); buffers.append(raw)
                            if capture_target_state(raw, expected_name=target.name, expected_serial_digest=creation._serial) != target: raise ValueError
                            raw = self._get(client, self._secret_path, deadline); buffers.append(raw)
                            if self._secret(raw, serial, fingerprint_key=key) != secret: raise ValueError
                    finally:
                        if not client.is_closed: client.close()
                if self._now() >= deadline or not client.is_closed: raise ValueError
                return self._reference_baseline(creation, creation.inspect_original_state().custody_digest, original_run._selected,
                    original_run._fixture, secret, target.state_digest, key)
            except Exception:
                self._failed = True; _zeroize_mutable(self._key)
                raise UnixDiscoveryHandoffError(_ERROR) from None
            finally:
                for raw in buffers: _zeroize_mutable(raw)
                _zeroize_mutable(key)

    def close(self) -> None:
        with self._lock:
            self._closed = True
            _zeroize_mutable(self._key)


class _SelectedAccountLoader(_OpaqueC3Object):
    def __init__(self, guard: UnixDiscoveryOnboardingGuard, loader: CentralLabSecretCreateResolverLoader,
            binding: SecretOnboardingBinding) -> None:
        self._guard, self._loader, self._binding = guard, loader, binding
        self._attempted = False

    def validate_prebound(self) -> MaterialBindingStatus:
        try:
            if self._attempted: return MaterialBindingStatus.UNAVAILABLE
            self._guard.check_onboarding_binding(self._binding)
            return self._loader.validate_prebound()
        except Exception:
            return MaterialBindingStatus.UNAVAILABLE

    def load_secret_create_material_once(self) -> tuple[bytearray, bytearray]:
        loaded = None
        try:
            if self._attempted: raise ValueError
            self._attempted = True
            self._guard.check_onboarding_binding(self._binding)
            self._guard.observe()
            loaded = self._loader.load_secret_create_material_once()
            if (type(loaded) is not tuple or len(loaded) != 2
                    or any(type(value) is not bytearray or not value for value in loaded)
                    or loaded[0] is loaded[1] or self._guard._account is None
                    or not hmac.compare_digest(loaded[0], self._guard._account.encode("utf-8"))):
                raise ValueError
            self._guard.check_onboarding_binding(self._binding)
            return loaded
        except Exception:
            if loaded is not None and type(loaded) in (tuple, list):
                for value in loaded:
                    if type(value) is bytearray: _zeroize_mutable(value)
            raise MaterialAccessDenied(_ERROR) from None


def guard_from_environment(environment: Mapping[str, str], config: SecretMetadataHttpTransportConfig
        ) -> UnixDiscoveryOnboardingGuard | None:
    """An explicit paired private selector narrows the existing Linux runtime."""
    names = (ENV_PREFIX + "SELECTION_BINDING_FILE", ENV_PREFIX + "PROFILE_FILE")
    if not any(name in environment for name in names):
        return None
    try:
        values = tuple(environment[name] for name in names)
        if any(type(value) is not str or not value or not Path(value).is_absolute() for value in values):
            raise ValueError
        return UnixDiscoveryOnboardingGuard(config, selection_binding_path=Path(values[0]), profile_path=Path(values[1]))
    except Exception:
        raise UnixDiscoveryHandoffError(_ERROR) from None
