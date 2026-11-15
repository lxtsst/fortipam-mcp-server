"""Protected, one-fixture BP002 creation provenance and baseline inspector.

The original create ledger stays reconciliation_required. A sealed independent
receipt binds its intact audit, one live creation event, current create
postcondition, complete non-material User state, and retained initial material.
This module has no MCP registration and cannot authorize a password reset.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat

from v4_planning import M4Outcome, M4Verification

from .local_user_reset_creation_audit_reader import FortiPamLocalUserResetCreationAuditReader
from .local_user_reset_fixture_create import (
    prepare_local_user_reset_fixture_create, verify_fixture_created_detail,
)
from .local_user_reset_fixture_preflight import _ACTOR, _DEFAULT, _SCHEMA, _actor_context
from .local_user_reset_fixture_transport import FortiPamLocalUserResetFixtureTransport
from .local_user_reset_http_transport import LocalUserResetBaseline, LocalUserResetBinding, _valid_password
from .local_user_reset_metadata_reader import (
    FortiPamLocalUserResetMetadataReader, LocalUserResetMetadataObservation,
)
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig, _zeroize_mutable

_RECEIPT = "creation-provenance.json"
_DOMAIN = b"bp002-retained-creation-provenance-build29/v1\0"
_ENABLED_RECEIPT = "enabled-provenance.json"
_ENABLED_DOMAIN = b"bp002-retained-enabled-provenance-build29/v1\0"
_AFTER_LOGIN_RECEIPT = "enabled-after-login-provenance.json"
_AFTER_LOGIN_DOMAIN = b"bp002-enabled-after-login-provenance-build29/v1\0"
_MATERIAL_DOMAIN = b"bp002-retained-initial-material/v1\0"
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_UNAVAILABLE = "The private Local User reset provenance is unavailable."


class LocalUserResetProvenanceError(RuntimeError):
    """Fixed failure with no private fixture or source details."""


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _owned_file(path: Path, *, maximum: int | None = None) -> os.stat_result:
    details = path.lstat()
    if (path.is_symlink() or not stat.S_ISREG(details.st_mode)
        or stat.S_IMODE(details.st_mode) != 0o600 or details.st_uid != os.getuid()
        or (maximum is not None and details.st_size > maximum)):
        raise ValueError
    return details


def _read_fixed_bytes(path: Path, *, length: int) -> bytearray:
    _owned_file(path, maximum=length)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    output = bytearray(length)
    try:
        details = os.fstat(descriptor)
        if (not stat.S_ISREG(details.st_mode) or stat.S_IMODE(details.st_mode) != 0o600
            or details.st_uid != os.getuid() or details.st_size != length
            or os.readv(descriptor, [output]) != length or os.read(descriptor, 1)):
            raise ValueError
        return output
    except Exception:
        _zeroize_mutable(output)
        raise
    finally:
        os.close(descriptor)


def _initial_material_metadata(directory: Path, created: int) -> os.stat_result:
    path = directory / "initial-password"
    details = _owned_file(path, maximum=256)
    if (not 8 <= details.st_size <= 256 or not created - 60 <= details.st_mtime <= created + 600):
        raise ValueError
    return details


def _initial_material_hmac(directory: Path, key: bytearray, created: int) -> str:
    details = _initial_material_metadata(directory, created)
    path = directory / "initial-password"
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    content = bytearray(256)
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_uid != os.getuid() or opened.st_ino != details.st_ino
            or opened.st_size != details.st_size):
            raise ValueError
        count = os.readv(descriptor, [content])
        if count != details.st_size or os.read(descriptor, 1):
            raise ValueError
        digest = hmac.new(key, _MATERIAL_DOMAIN, hashlib.sha256)
        digest.update(memoryview(content)[:count])
        return digest.hexdigest()
    finally:
        _zeroize_mutable(content)
        os.close(descriptor)


class FortiPamLocalUserResetProvenanceInspector:
    """Issue one sealed independent receipt, then fresh-read the same baseline."""

    def __init__(
        self, config: SecretMetadataHttpTransportConfig, *,
        fixture_directory: Path, api_principal: str,
        issue_enabled: bool = False,
    ) -> None:
        try:
            if type(issue_enabled) is not bool:
                raise ValueError
            directory = Path(fixture_directory)
            reader = FortiPamLocalUserResetCreationAuditReader(
                config, fixture_directory=directory, api_principal=api_principal,
            )
            if not directory.is_absolute():
                raise ValueError
            for name in ("execution.sqlite3", "execution.key", "initial-password"):
                _owned_file(directory / name)
            store = PersistentM4ExecutionStateStore(
                directory / "execution.sqlite3", directory / "execution.key",
            )
            username = reader._username
            fixture = FortiPamLocalUserResetFixtureTransport(
                config, username=username, api_principal=api_principal,
                material_directory=directory, enabled=False,
            )
            metadata = FortiPamLocalUserResetMetadataReader(config, username=username)
        except Exception:
            raise LocalUserResetProvenanceError(_UNAVAILABLE) from None
        self._directory, self._reader, self._store = directory, reader, store
        self._fixture, self._metadata = fixture, metadata
        self._username, self._principal = username, api_principal
        self._config, self._issue_enabled = config, issue_enabled
        self._directory_identity = reader._directory_identity

    def _identity(self) -> tuple[int, str]:
        identity, username, created = self._reader._binding()
        if identity != self._directory_identity or username != self._username:
            raise ValueError
        return created, username

    def _audit_digest(self) -> str:
        self._store.verify_ready()
        events = self._store.audit_events
        if (len(events) != 1 or events[0].authorization != "intent_bound"
            or events[0].outcome is not M4Outcome.RECONCILIATION_REQUIRED
            or events[0].verification is not M4Verification.UNKNOWN
            or not isinstance(events[0].digest_reference, str)
            or _DIGEST.fullmatch(events[0].digest_reference) is None):
            raise ValueError
        return events[0].digest_reference

    def _eligible(self, observation: LocalUserResetMetadataObservation) -> None:
        if type(observation) is not LocalUserResetMetadataObservation:
            raise ValueError
        user = observation.user
        if (user.username != self._username or user.status not in {"disable", "enable"}
            or user.is_local is not True or user.access_profile != "Guest"
            or user.sponsor_group != "" or user.schedule != ""
            or user.guest_auth != "disable" or user.reported_reference_count != 0
            or observation.usage_entry_count != 0
            or user.product_version != "7.0.0" or user.product_build != 29):
            raise ValueError

    def _current_user(self) -> LocalUserResetMetadataObservation:
        observation = self._metadata.read_observation()
        self._eligible(observation)
        return observation

    def _actor_is_current(self) -> None:
        content = self._reader._read("GET", _ACTOR)
        try:
            _actor_context(content, expected_name=self._principal)
        finally:
            _zeroize_mutable(content)

    def _created_detail_digest(self) -> str:
        schema = self._fixture._preflight._read(_SCHEMA)
        try:
            draft = prepare_local_user_reset_fixture_create(
                self._fixture._preflight._read(_DEFAULT), json.loads(schema),
                username=self._username, access_profile="Guest",
            )
            result = verify_fixture_created_detail(self._fixture._exchange("GET"), draft)
            if result.username != self._username or result.user_id <= 0:
                raise ValueError
            return result.readback_digest
        finally:
            _zeroize_mutable(schema)

    def _key(self) -> bytearray:
        return _read_fixed_bytes(self._directory / "execution.key", length=32)

    def _sealed_original(self, key: bytearray, *, created: int,
                         username: str, ledger_digest: str) -> tuple[dict[str, object], bytes]:
        path = self._directory / _RECEIPT
        details = _owned_file(path, maximum=4096)
        if not 0 < details.st_size <= 4096:
            raise ValueError
        document = json.loads(path.read_bytes())
        if not isinstance(document, dict) or set(document) != {"body", "mac"}:
            raise ValueError
        body, mac = document["body"], document["mac"]
        required = {"version", "username", "origin_digest", "actor_digest",
            "ledger_digest", "creation_event_digest", "creation_timestamp_ms",
            "lifecycle_observed_through_ms", "create_postcondition_digest",
            "full_user_digest", "initial_material_hmac"}
        if (not isinstance(body, dict) or set(body) != required
            or body["version"] != 1 or body["username"] != username
            or not isinstance(mac, str) or _DIGEST.fullmatch(mac) is None
            or any(not isinstance(body[field], str) or _DIGEST.fullmatch(body[field]) is None
                   for field in required - {"version", "username", "creation_timestamp_ms",
                                            "lifecycle_observed_through_ms"})
            or body["origin_digest"] != hashlib.sha256(self._config.base_url.encode()).hexdigest()
            or body["actor_digest"] != hashlib.sha256(self._principal.encode()).hexdigest()
            or body["ledger_digest"] != ledger_digest
            or type(body["creation_timestamp_ms"]) is not int
            or not (created - 60) * 1000 <= body["creation_timestamp_ms"] <= (created + 600) * 1000
            or type(body["lifecycle_observed_through_ms"]) is not int
            or body["lifecycle_observed_through_ms"] < body["creation_timestamp_ms"]):
            raise ValueError
        body_bytes = _canonical(body)
        if not hmac.compare_digest(mac, hmac.new(key, _DOMAIN + body_bytes, hashlib.sha256).hexdigest()):
            raise ValueError
        _initial_material_metadata(self._directory, created)
        return body, body_bytes

    def _sealed_enabled(self, key: bytearray, *, username: str,
                        original_digest: str) -> tuple[dict[str, object], bytes]:
        path = self._directory / _ENABLED_RECEIPT
        details = _owned_file(path, maximum=4096)
        if not 0 < details.st_size <= 4096:
            raise ValueError
        document = json.loads(path.read_bytes())
        if not isinstance(document, dict) or set(document) != {"body", "mac"}:
            raise ValueError
        body, mac = document["body"], document["mac"]
        if (not isinstance(body, dict) or set(body) != {"version", "username",
                "original_receipt_digest", "enabled_user_digest", "enable_marker_digest"}
            or body["version"] != 1 or body["username"] != username
            or body["original_receipt_digest"] != original_digest
            or not isinstance(body["enabled_user_digest"], str)
            or _DIGEST.fullmatch(body["enabled_user_digest"]) is None
            or not isinstance(body["enable_marker_digest"], str)
            or _DIGEST.fullmatch(body["enable_marker_digest"]) is None
            or not isinstance(mac, str) or _DIGEST.fullmatch(mac) is None):
            raise ValueError
        marker = self._directory / "enable-dispatch-once"
        _owned_file(marker, maximum=128)
        if body["enable_marker_digest"] != hashlib.sha256(marker.read_bytes()).hexdigest():
            raise ValueError
        body_bytes = _canonical(body)
        if not hmac.compare_digest(mac, hmac.new(key, _ENABLED_DOMAIN + body_bytes,
                                               hashlib.sha256).hexdigest()):
            raise ValueError
        return body, body_bytes

    def _sealed_after_login(self, key: bytearray, *, username: str,
                            prior_digest: str) -> tuple[dict[str, object], bytes]:
        path = self._directory / _AFTER_LOGIN_RECEIPT
        details = _owned_file(path, maximum=4096)
        if not 0 < details.st_size <= 4096:
            raise ValueError
        document = json.loads(path.read_bytes())
        if not isinstance(document, dict) or set(document) != {"body", "mac"}:
            raise ValueError
        body, mac = document["body"], document["mac"]
        if (not isinstance(body, dict) or set(body) != {"version", "username",
                "prior_enabled_receipt_digest", "stable_user_digest", "login_marker_digest"}
            or body["version"] != 1 or body["username"] != username
            or body["prior_enabled_receipt_digest"] != prior_digest
            or not isinstance(body["stable_user_digest"], str)
            or _DIGEST.fullmatch(body["stable_user_digest"]) is None
            or not isinstance(body["login_marker_digest"], str)
            or _DIGEST.fullmatch(body["login_marker_digest"]) is None
            or not isinstance(mac, str) or _DIGEST.fullmatch(mac) is None):
            raise ValueError
        marker = self._directory / "login-before-once"
        _owned_file(marker, maximum=128)
        if body["login_marker_digest"] != hashlib.sha256(marker.read_bytes()).hexdigest():
            raise ValueError
        body_bytes = _canonical(body)
        if not hmac.compare_digest(mac, hmac.new(key, _AFTER_LOGIN_DOMAIN + body_bytes,
                                               hashlib.sha256).hexdigest()):
            raise ValueError
        return body, body_bytes

    def issue(self) -> LocalUserResetBaseline:
        """Seal one independently verified fixture receipt; never replay create."""
        if not self._issue_enabled:
            raise LocalUserResetProvenanceError(_UNAVAILABLE)
        key: bytearray | None = None
        try:
            created, username = self._identity()
            receipt_path = self._directory / _RECEIPT
            if receipt_path.exists() or receipt_path.is_symlink():
                raise ValueError
            ledger_digest = self._audit_digest()
            creation = self._reader.read_creation_event()
            detail_digest = self._created_detail_digest()
            user = self._current_user()
            self._eligible(user)
            if self._audit_digest() != ledger_digest:
                raise ValueError
            key = self._key()
            material_hmac = _initial_material_hmac(self._directory, key, created)
            body = {
                "version": 1, "username": username,
                "origin_digest": hashlib.sha256(self._config.base_url.encode()).hexdigest(),
                "actor_digest": hashlib.sha256(self._principal.encode()).hexdigest(),
                "ledger_digest": ledger_digest,
                "creation_event_digest": creation.creation_event_digest,
                "creation_timestamp_ms": creation.creation_timestamp_ms,
                "lifecycle_observed_through_ms": creation.lifecycle_observed_through_ms,
                "create_postcondition_digest": detail_digest,
                "full_user_digest": user.user.nonmaterial_state_digest,
                "initial_material_hmac": material_hmac,
            }
            body_bytes = _canonical(body)
            mac = hmac.new(key, _DOMAIN + body_bytes, hashlib.sha256).hexdigest()
            receipt = _canonical({"body": body, "mac": mac})
            descriptor = os.open(receipt_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                os.fchmod(descriptor, 0o600)
                written = 0
                while written < len(receipt):
                    count = os.write(descriptor, memoryview(receipt)[written:])
                    if count <= 0:
                        raise ValueError
                    written += count
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            directory_fd = os.open(self._directory, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except Exception:
            raise LocalUserResetProvenanceError(_UNAVAILABLE) from None
        finally:
            if key is not None:
                _zeroize_mutable(key)
        return self.read_nonmaterial_baseline()

    def issue_enabled_transition(self) -> LocalUserResetBaseline:
        """Bind the same retained create receipt to one independently enabled User."""
        if not self._issue_enabled:
            raise LocalUserResetProvenanceError(_UNAVAILABLE)
        key: bytearray | None = None
        try:
            created, username = self._identity()
            path = self._directory / _ENABLED_RECEIPT
            if path.exists() or path.is_symlink():
                raise ValueError
            marker = self._directory / "enable-dispatch-once"
            marker_details = _owned_file(marker, maximum=128)
            original_details = _owned_file(self._directory / _RECEIPT, maximum=4096)
            if marker_details.st_mtime < original_details.st_mtime:
                raise ValueError
            ledger_digest = self._audit_digest()
            key = self._key()
            _, original_bytes = self._sealed_original(key, created=created,
                username=username, ledger_digest=ledger_digest)
            self._actor_is_current()
            user = self._current_user()
            if user.user.status != "enable" or not self._created_detail_digest():
                raise ValueError
            if self._audit_digest() != ledger_digest:
                raise ValueError
            body = {"version": 1, "username": username,
                "original_receipt_digest": hashlib.sha256(_DOMAIN + original_bytes).hexdigest(),
                "enabled_user_digest": user.user.nonmaterial_state_digest,
                "enable_marker_digest": hashlib.sha256(marker.read_bytes()).hexdigest()}
            body_bytes = _canonical(body)
            receipt = _canonical({"body": body,
                "mac": hmac.new(key, _ENABLED_DOMAIN + body_bytes, hashlib.sha256).hexdigest()})
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                os.fchmod(descriptor, 0o600)
                if os.write(descriptor, receipt) != len(receipt):
                    raise ValueError
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            directory_fd = os.open(self._directory, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except Exception:
            raise LocalUserResetProvenanceError(_UNAVAILABLE) from None
        finally:
            if key is not None:
                _zeroize_mutable(key)
        return self.read_nonmaterial_baseline()

    def issue_enabled_after_login(self) -> LocalUserResetBaseline:
        """Seal stable configuration state after the one verified test login."""
        if not self._issue_enabled:
            raise LocalUserResetProvenanceError(_UNAVAILABLE)
        key: bytearray | None = None
        try:
            created, username = self._identity()
            path = self._directory / _AFTER_LOGIN_RECEIPT
            if path.exists() or path.is_symlink():
                raise ValueError
            marker = self._directory / "login-before-once"
            marker_details = _owned_file(marker, maximum=128)
            enabled_details = _owned_file(self._directory / _ENABLED_RECEIPT, maximum=4096)
            if marker_details.st_mtime < enabled_details.st_mtime:
                raise ValueError
            ledger_digest = self._audit_digest()
            key = self._key()
            _, original_bytes = self._sealed_original(key, created=created,
                username=username, ledger_digest=ledger_digest)
            _, prior_bytes = self._sealed_enabled(key, username=username,
                original_digest=hashlib.sha256(_DOMAIN + original_bytes).hexdigest())
            self._actor_is_current()
            observation = self._current_user()
            if observation.user.status != "enable" or not self._created_detail_digest():
                raise ValueError
            if self._audit_digest() != ledger_digest:
                raise ValueError
            body = {"version": 1, "username": username,
                "prior_enabled_receipt_digest": hashlib.sha256(
                    _ENABLED_DOMAIN + prior_bytes).hexdigest(),
                "stable_user_digest": observation.user.nonmaterial_state_digest,
                "login_marker_digest": hashlib.sha256(marker.read_bytes()).hexdigest()}
            body_bytes = _canonical(body)
            receipt = _canonical({"body": body,
                "mac": hmac.new(key, _AFTER_LOGIN_DOMAIN + body_bytes, hashlib.sha256).hexdigest()})
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                os.fchmod(descriptor, 0o600)
                if os.write(descriptor, receipt) != len(receipt):
                    raise ValueError
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            directory_fd = os.open(self._directory, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except Exception:
            raise LocalUserResetProvenanceError(_UNAVAILABLE) from None
        finally:
            if key is not None:
                _zeroize_mutable(key)
        return self.read_nonmaterial_baseline()

    def read_nonmaterial_baseline(self) -> LocalUserResetBaseline:
        """Verify the seal and fresh full User state without another log search."""
        key: bytearray | None = None
        try:
            created, username = self._identity()
            ledger_digest = self._audit_digest()
            key = self._key()
            body, body_bytes = self._sealed_original(key, created=created,
                username=username, ledger_digest=ledger_digest)
            self._actor_is_current()
            observation = self._current_user()
            self._eligible(observation)
            digest = hashlib.sha256(_DOMAIN + body_bytes).hexdigest()
            if observation.user.status == "enable":
                enabled, enabled_bytes = self._sealed_enabled(key, username=username,
                    original_digest=digest)
                digest = hashlib.sha256(_ENABLED_DOMAIN + enabled_bytes).hexdigest()
                if (self._directory / _AFTER_LOGIN_RECEIPT).exists():
                    after_login, after_bytes = self._sealed_after_login(key,
                        username=username, prior_digest=digest)
                    if observation.user.nonmaterial_state_digest != after_login["stable_user_digest"]:
                        raise ValueError
                    digest = hashlib.sha256(_AFTER_LOGIN_DOMAIN + after_bytes).hexdigest()
                elif observation.user.nonmaterial_state_digest != enabled["enabled_user_digest"]:
                    raise ValueError
            elif observation.user.nonmaterial_state_digest != body["full_user_digest"]:
                raise ValueError
            if self._audit_digest() != ledger_digest:
                raise ValueError
            baseline = LocalUserResetBaseline(
                username=username, status=observation.user.status,
                is_local=observation.user.is_local,
                access_profile=observation.user.access_profile,
                sponsor_group=observation.user.sponsor_group,
                schedule=observation.user.schedule,
                guest_auth=observation.user.guest_auth,
                nonmaterial_state_digest=observation.user.nonmaterial_state_digest,
                fixture_creation_digest=digest,
                reported_reference_count=observation.user.reported_reference_count,
                usage_entry_count=observation.usage_entry_count,
                product_version=observation.user.product_version,
                product_build=observation.user.product_build,
            )
            LocalUserResetBinding(baseline)
            return baseline
        except Exception:
            raise LocalUserResetProvenanceError(_UNAVAILABLE) from None
        finally:
            if key is not None:
                _zeroize_mutable(key)

    def verify_initial_material_view(
        self, material: memoryview, *, expected_fixture_digest: str,
    ) -> bool:
        """Verify provider-owned C3 bytes only after the durable reset claim."""
        key: bytearray | None = None
        try:
            if (not _valid_password(material) or not 8 <= material.nbytes <= 256
                or type(expected_fixture_digest) is not str
                or _DIGEST.fullmatch(expected_fixture_digest) is None):
                raise ValueError
            created, username = self._identity()
            ledger_digest = self._audit_digest()
            key = self._key()
            body, body_bytes = self._sealed_original(key, created=created,
                username=username, ledger_digest=ledger_digest)
            digest = hashlib.sha256(_DOMAIN + body_bytes).hexdigest()
            if (self._directory / _ENABLED_RECEIPT).exists():
                _, enabled_bytes = self._sealed_enabled(key, username=username,
                    original_digest=digest)
                digest = hashlib.sha256(_ENABLED_DOMAIN + enabled_bytes).hexdigest()
                if (self._directory / _AFTER_LOGIN_RECEIPT).exists():
                    _, after_bytes = self._sealed_after_login(key,
                        username=username, prior_digest=digest)
                    digest = hashlib.sha256(_AFTER_LOGIN_DOMAIN + after_bytes).hexdigest()
            if not hmac.compare_digest(digest, expected_fixture_digest):
                raise ValueError
            material_digest = hmac.new(key, _MATERIAL_DOMAIN, hashlib.sha256)
            material_digest.update(material)
            if not hmac.compare_digest(str(body["initial_material_hmac"]), material_digest.hexdigest()):
                raise ValueError
            return True
        except Exception:
            raise LocalUserResetProvenanceError(_UNAVAILABLE) from None
        finally:
            if key is not None:
                _zeroize_mutable(key)
