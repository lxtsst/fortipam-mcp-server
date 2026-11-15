"""Inactive fixed admission policy boundary; no Reference issuer, route or provider.

Trusted composition supplies a separately issued policy, exact custody pins and
an independent human-owner eligibility verifier. A signed label, file digest or
caller-created binding alone grants no source access. This authorizes no action.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import fields
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import threading
import time
from typing import Any, TYPE_CHECKING

from v4_planning.material_provider import _OpaqueC3Object

from .secret_bulk_import_file import _read_owned, _wipe
from .secret_bulk_import_intake import BulkImportIntakeError, OwnerFileIntakeBinding, _ERROR

if TYPE_CHECKING:
    from .secret_bulk_import_reference_eligibility import ReferenceOwnerFileEligibility

CONTRACT = "fortipam-owner-file-intake-admission-policy-v1"
_DOMAIN = b"fortipam-owner-file-intake-admission/v1\0"
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_PURPOSE = "private-dependency-projection-only"
_FIELDS = frozenset({"contract", "purpose", "intent_digest", "owner_decision_digest", "issued_at", "expires_at"})
HumanOwnerVerifier = Callable[[OwnerFileIntakeBinding, str, int], object]


def _members(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in items:
        if name in result:
            raise ValueError
        result[name] = value
    return result


def _mac(key: bytearray, purpose: bytes, value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return hmac.new(key, _DOMAIN + purpose + b"\0" + raw, hashlib.sha256).hexdigest()


def _intent_digest(binding: OwnerFileIntakeBinding, key: bytearray) -> str:
    # Full source, identity, workload and lifetime binding stays private.
    value = {field.name: getattr(binding, field.name) for field in fields(binding)}
    value["path"] = str(binding.path)
    return _mac(key, b"intent", value)


def _publish_policy(path: Path, raw: bytearray, validate: Callable[[], None]) -> None:
    parent = descriptor = None
    created: tuple[int, int] | None = None
    complete = False
    try:
        parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
        for part in path.parent.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            previous, parent = parent, child
            os.close(previous)
        info = os.fstat(parent)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError
        descriptor = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=parent)
        info = os.fstat(descriptor)
        created = (info.st_dev, info.st_ino)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError
        offset = 0
        while offset < len(raw):
            with memoryview(raw)[offset:] as view:
                written = os.write(descriptor, view)
            if written <= 0:
                raise ValueError
            offset += written
        os.fsync(descriptor)
        validate()
        checked, _ = _read_owned(path)
        try:
            current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if (checked != raw or (current.st_dev, current.st_ino) != created
                    or os.fstat(descriptor).st_nlink != 1):
                raise ValueError
        finally:
            _wipe(checked)
        validate()
        os.fsync(parent)
        previous, descriptor = descriptor, None
        os.close(previous)
        previous, parent = parent, None
        os.close(previous)
        complete = True
    finally:
        try:
            if not complete and parent is not None and created is not None:
                try:
                    info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                    if (info.st_dev, info.st_ino) == created:
                        os.unlink(path.name, dir_fd=parent)
                except OSError:
                    pass
        finally:
            try:
                if descriptor is not None:
                    os.close(descriptor)
            finally:
                if parent is not None:
                    os.close(parent)


def issue_prebound_owner_file_policy_once(
    binding: OwnerFileIntakeBinding, *, policy_path: Path, key_path: Path, key_sha256: str,
    eligibility: ReferenceOwnerFileEligibility,
    clock: Callable[[], int] = lambda: int(time.time()),
    monotonic: Callable[[], float] = time.monotonic,
) -> str:
    """Trusted bootstrap only: seal a policy after an existing remote exact grant.

    Returns a private custody pin, not a permission or authentication receipt.
    This creates no Reference grant, global Owner role, source lease or action.
    """
    from .secret_bulk_import_reference_eligibility import ReferenceOwnerFileEligibility
    return _issue_prebound_policy_once(binding, policy_path=policy_path, key_path=key_path,
        key_sha256=key_sha256, eligibility=eligibility, clock=clock, monotonic=monotonic,
        eligibility_type=ReferenceOwnerFileEligibility, contract=CONTRACT, purpose=_PURPOSE)


def _issue_prebound_policy_once(
    binding: OwnerFileIntakeBinding, *, policy_path: Path, key_path: Path, key_sha256: str,
    eligibility: ReferenceOwnerFileEligibility, clock: Callable[[], int], monotonic: Callable[[], float],
    eligibility_type: type[ReferenceOwnerFileEligibility], contract: str, purpose: str,
) -> str:
    """Shared custody primitive; only fixed purpose-specific factories call it."""
    from .reference_authority_sidecar import UnixReferenceAuthorityClient
    from .secret_bulk_import_token_channel import _PinnedKey
    from v4_planning import canonical_digest
    from .secret_bulk_import_intake import _clock_sample

    key = raw = None
    try:
        if (type(binding) is not OwnerFileIntakeBinding or type(eligibility) is not eligibility_type
                or eligibility._binding != binding or type(eligibility._authority) is not UnixReferenceAuthorityClient
                or not all(isinstance(path, Path) and path.is_absolute() and '..' not in path.parts
                           for path in (policy_path, key_path))
                or len({path.parts[1:] for path in (binding.path, policy_path, key_path, eligibility._key.path)}) != 4
                or not callable(clock) or not callable(monotonic)):
            raise ValueError
        binding.__post_init__()
        now, started = clock(), _clock_sample(monotonic)
        if type(now) is not int or not binding.issued_at <= now < binding.expires_at <= binding.issued_at + 900:
            raise ValueError
        deadline, last_wall, last_mono = started + binding.expires_at - now, now, started
        decision = canonical_digest(eligibility._reference)
        pin = _PinnedKey(key_path, key_sha256)
        key = pin.load()

        def validate() -> None:
            nonlocal last_wall, last_mono
            wall, mono = clock(), _clock_sample(monotonic)
            if (type(wall) is not int or not last_wall <= wall < binding.expires_at
                    or not last_mono <= mono < deadline):
                raise ValueError
            last_wall, last_mono = wall, mono
            eligibility(binding, decision, wall)
            refreshed = pin.load()
            _wipe(refreshed)
            wall, mono = clock(), _clock_sample(monotonic)
            if (type(wall) is not int or not last_wall <= wall < binding.expires_at
                    or not last_mono <= mono < deadline):
                raise ValueError
            last_wall, last_mono = wall, mono

        validate()
        payload = dict(contract=contract, purpose=purpose, intent_digest=_intent_digest(binding, key),
                       owner_decision_digest=decision, issued_at=binding.issued_at, expires_at=binding.expires_at)
        raw = bytearray(json.dumps({'payload': payload, 'seal': _mac(key, b'policy', payload)},
                                   sort_keys=True, separators=(',', ':'), allow_nan=False).encode())
        if not 0 < len(raw) <= 16384:
            raise ValueError
        _publish_policy(policy_path, raw, validate)
        return hashlib.sha256(raw).hexdigest()
    except Exception:
        raise BulkImportIntakeError(_ERROR) from None
    finally:
        for buffer in (key, raw):
            if buffer is not None:
                _wipe(buffer)


class PinnedOwnerFileIntakeAuthority(_OpaqueC3Object):
    """Verify one externally granted intent without minting or renewing it."""

    __slots__ = ("_binding", "_policy", "_key", "_policy_digest", "_key_digest",
                 "_identities", "_human_owner_verifier", "_clock", "_last_now", "_lock")
    _display_name = "PinnedOwnerFileIntakeAuthority"
    _policy_contract = CONTRACT
    _policy_purpose = _PURPOSE

    def __init__(self, binding: OwnerFileIntakeBinding, *, policy_path: Path,
                 key_path: Path, policy_sha256: str, key_sha256: str,
                 human_owner_verifier: HumanOwnerVerifier | None = None,
                 clock: Callable[[], int] | None = None) -> None:
        try:
            if (type(binding) is not OwnerFileIntakeBinding
                    or not callable(human_owner_verifier)
                    or any(type(value) is not str or _DIGEST.fullmatch(value) is None
                           for value in (policy_sha256, key_sha256))
                    or not all(isinstance(path, Path) for path in (policy_path, key_path))):
                raise ValueError
            binding.__post_init__()
            # The custody reader always traverses from /, including // aliases.
            if len({path.parts[1:] for path in (binding.path, policy_path, key_path)}) != 3:
                raise ValueError
            self._binding, self._policy, self._key = binding, policy_path, key_path
            self._policy_digest, self._key_digest = policy_sha256, key_sha256
            self._human_owner_verifier = human_owner_verifier
            self._clock = clock if clock is not None else lambda: int(time.time())
            if not callable(self._clock):
                raise ValueError
            self._last_now = -1
            self._lock = threading.Lock()
            self._identities: tuple[tuple[int, ...], tuple[int, ...]] | None = None
            self._load()
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None

    def _load(self) -> dict[str, Any]:
        policy = key = None
        try:
            identities = self._identities
            policy, policy_identity = _read_owned(self._policy, identities[0] if identities else None)
            key, key_identity = _read_owned(self._key, identities[1] if identities else None)
            if (not 0 < len(policy) <= 16384 or not 32 <= len(key) <= 4096
                    or hashlib.sha256(policy).hexdigest() != self._policy_digest
                    or hashlib.sha256(key).hexdigest() != self._key_digest):
                raise ValueError
            value = json.loads(policy, object_pairs_hook=_members)
            if type(value) is not dict or set(value) != {"payload", "seal"}:
                raise ValueError
            payload = value["payload"]
            if (type(payload) is not dict or set(payload) != _FIELDS
                    or payload["contract"] != self._policy_contract or payload["purpose"] != self._policy_purpose
                    or type(value["seal"]) is not str
                    or not hmac.compare_digest(value["seal"], _mac(key, b"policy", payload))
                    or payload["intent_digest"] != _intent_digest(self._binding, key)
                    or type(payload["owner_decision_digest"]) is not str
                    or _DIGEST.fullmatch(payload["owner_decision_digest"]) is None
                    or type(payload["issued_at"]) is not int or type(payload["expires_at"]) is not int
                    or (payload["issued_at"], payload["expires_at"]) != (
                        self._binding.issued_at, self._binding.expires_at)
                    or not payload["issued_at"] < payload["expires_at"] <= payload["issued_at"] + 900):
                raise ValueError
            if identities is None:
                self._identities = (policy_identity, key_identity)
            return payload
        finally:
            if policy is not None:
                _wipe(policy)
            if key is not None:
                _wipe(key)

    def _now(self, supplied: int) -> int:
        now = self._clock()
        if (type(supplied) is not int or type(now) is not int
                or not 0 <= supplied <= now or now < self._last_now):
            raise ValueError
        self._last_now = now
        return now

    def verify(self, binding: OwnerFileIntakeBinding, *, now_epoch: int) -> None:
        acquired = False
        try:
            acquired = self._lock.acquire(blocking=False)
            if not acquired or type(binding) is not OwnerFileIntakeBinding or binding != self._binding:
                raise ValueError
            binding.__post_init__()
            now, grant = self._now(now_epoch), self._load()
            if not grant["issued_at"] <= now < grant["expires_at"]:
                raise ValueError
            verifier = self._human_owner_verifier
            if verifier is None or verifier(binding, grant["owner_decision_digest"], now) is not None:
                raise ValueError
            # Eligibility work cannot extend the grant or hide custody drift.
            now = self._now(now)
            if self._load() != grant or not grant["issued_at"] <= now < grant["expires_at"]:
                raise ValueError
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None
        finally:
            if acquired:
                self._lock.release()
