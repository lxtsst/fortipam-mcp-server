"""Private one-use BP002 material staging and lease from owner-only files.

This source does not stage a new password, authorize a reset, or register an MCP
operation by default. Its explicit staging function creates one protected
new-material file and a signed binding; the trusted client must bind only the
opaque receipt digest to authenticated intent. No material-derived digest may
enter the planner, MCP result or audit. The fixture inspector rechecks the
sealed creation evidence and current non-material User state.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import threading
from typing import Protocol

from .local_user_reset_http_transport import (
    LocalUserResetBaseline, LocalUserResetBinding,
    LocalUserResetMaterialLease,
)
from .secret_metadata_http_transport import _zeroize_mutable

_UNAVAILABLE = "The private Local User reset material source is unavailable."
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_MAX_MATERIAL = 256
_MANIFEST = "material-binding.json"
_MANIFEST_KEY = "material.key"
_TRANSITION = "current-login-transition.json"
_DOMAIN = b"bp002-reset-new-material-build29/v1\0"


class LocalUserResetMaterialSourceError(RuntimeError):
    """Fixed non-disclosing material-source failure."""


class LocalUserResetMaterialInspector(Protocol):
    def read_nonmaterial_baseline(self) -> LocalUserResetBaseline: ...

    def verify_initial_material_view(
        self, material: memoryview, *, expected_fixture_digest: str,
    ) -> bool: ...


def _directory_identity(path: Path) -> tuple[int, int]:
    details = path.lstat()
    if (not path.is_absolute() or path.is_symlink()
        or not stat.S_ISDIR(details.st_mode)
        or stat.S_IMODE(details.st_mode) != 0o700
        or details.st_uid != os.getuid()):
        raise ValueError
    return details.st_dev, details.st_ino


def _read_material(directory: Path, identity: tuple[int, int], name: str) -> tuple[bytearray, int]:
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptor: int | None = None
    material = bytearray(_MAX_MATERIAL)
    try:
        details = os.fstat(directory_fd)
        if ((details.st_dev, details.st_ino) != identity
            or stat.S_IMODE(details.st_mode) != 0o700 or details.st_uid != os.getuid()):
            raise ValueError
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
        file_details = os.fstat(descriptor)
        if (not stat.S_ISREG(file_details.st_mode)
            or stat.S_IMODE(file_details.st_mode) != 0o600
            or file_details.st_uid != os.getuid()
            or not 8 <= file_details.st_size <= _MAX_MATERIAL):
            raise ValueError
        count = os.readv(descriptor, [material])
        if count != file_details.st_size or os.read(descriptor, 1):
            raise ValueError
        return material, count
    except Exception:
        _zeroize_mutable(material)
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory_fd)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _write_once(directory: Path, identity: tuple[int, int], name: str, content: bytearray) -> None:
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptor: int | None = None
    try:
        details = os.fstat(directory_fd)
        if ((details.st_dev, details.st_ino) != identity
            or stat.S_IMODE(details.st_mode) != 0o700 or details.st_uid != os.getuid()):
            raise ValueError
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=directory_fd)
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(content):
            with memoryview(content)[offset:] as part:
                count = os.write(descriptor, part)
            if count <= 0:
                raise ValueError
            offset += count
        os.fsync(descriptor)
        os.fsync(directory_fd)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory_fd)


def _read_small(directory: Path, identity: tuple[int, int], name: str, limit: int) -> bytearray:
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptor: int | None = None
    value = bytearray(limit)
    try:
        details = os.fstat(directory_fd)
        if ((details.st_dev, details.st_ino) != identity
            or stat.S_IMODE(details.st_mode) != 0o700 or details.st_uid != os.getuid()):
            raise ValueError
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
        details = os.fstat(descriptor)
        if (not stat.S_ISREG(details.st_mode) or details.st_uid != os.getuid()
            or stat.S_IMODE(details.st_mode) != 0o600
            or not 1 <= details.st_size <= limit):
            raise ValueError
        count = os.readv(descriptor, [value])
        if count != details.st_size or os.read(descriptor, 1):
            raise ValueError
        del value[count:]
        return value
    except Exception:
        _zeroize_mutable(value)
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory_fd)


def _read_manifest(
    directory: Path, identity: tuple[int, int], fixture_digest: str,
) -> tuple[str, str]:
    key = receipt = None
    try:
        key = _read_small(directory, identity, _MANIFEST_KEY, 32)
        if len(key) != 32:
            raise ValueError
        receipt = _read_small(directory, identity, _MANIFEST, 1024)
        document = json.loads(receipt)
        if not isinstance(document, dict) or set(document) != {"body", "mac"}:
            raise ValueError
        body, mac = document["body"], document["mac"]
        if (not isinstance(body, dict)
            or set(body) != {"version", "fixture_digest", "material_digest", "nonce"}
            or body["version"] != 1 or body["fixture_digest"] != fixture_digest
            or any(type(body[name]) is not str or _DIGEST.fullmatch(body[name]) is None
                   for name in ("fixture_digest", "material_digest", "nonce"))
            or type(mac) is not str or _DIGEST.fullmatch(mac) is None):
            raise ValueError
        body_bytes = _canonical(body)
        if not hmac.compare_digest(mac, hmac.new(key, _DOMAIN + body_bytes, hashlib.sha256).hexdigest()):
            raise ValueError
        # The random nonce makes this persisted context binding non-resolvable.
        binding_digest = hashlib.sha256(_DOMAIN + _canonical(document)).hexdigest()
        return binding_digest, body["material_digest"]
    finally:
        if key is not None:
            _zeroize_mutable(key)
        if receipt is not None:
            _zeroize_mutable(receipt)


def stage_next_password_once(
    reset_directory: Path, *, fixture_directory: Path,
    binding: LocalUserResetBinding, enabled: bool = False,
) -> str:
    """Create one protected new material and return only an opaque binding digest."""
    key: bytearray | None = None
    material: bytearray | None = None
    receipt: bytearray | None = None
    try:
        transition = Path(fixture_directory) / _TRANSITION
        if transition.exists() or transition.is_symlink():
            raise ValueError
        if type(binding) is not LocalUserResetBinding or type(enabled) is not bool or not enabled:
            raise ValueError
        binding.__post_init__()
        directory = Path(reset_directory)
        identity = _directory_identity(directory)
        if _directory_identity(Path(fixture_directory)) == identity:
            raise ValueError
        if any((directory / name).exists() or (directory / name).is_symlink()
               for name in (_MANIFEST_KEY, "next-password", _MANIFEST)):
            raise ValueError
        key = bytearray(secrets.token_bytes(32))
        material = bytearray(b"Aa7!")
        alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        material.extend(alphabet[secrets.randbelow(len(alphabet))] for _ in range(28))
        body = {"version": 1, "fixture_digest": binding.expected.fixture_creation_digest,
                "material_digest": hashlib.sha256(material).hexdigest(),
                "nonce": secrets.token_hex(32)}
        body_bytes = _canonical(body)
        receipt = bytearray(_canonical({"body": body,
            "mac": hmac.new(key, _DOMAIN + body_bytes, hashlib.sha256).hexdigest()}))
        _write_once(directory, identity, _MANIFEST_KEY, key)
        _write_once(directory, identity, "next-password", material)
        _write_once(directory, identity, _MANIFEST, receipt)
        binding_digest = hashlib.sha256(_DOMAIN + receipt).hexdigest()
        if _read_manifest(directory, identity, binding.expected.fixture_creation_digest) != (
            binding_digest, body["material_digest"],
        ):
            raise ValueError
        return binding_digest
    except Exception:
        raise LocalUserResetMaterialSourceError(_UNAVAILABLE) from None
    finally:
        for value in (key, material, receipt):
            if value is not None:
                _zeroize_mutable(value)


def _read_current_login_selection(
    fixture: Path, binding: LocalUserResetBinding,
) -> tuple[Path, str, str]:
    """Resolve bounded owner records, not caller paths or execution authority."""
    buffers: list[bytearray] = []
    try:
        pointer = _read_small(fixture, _directory_identity(fixture), "current-login-binding.json", 4096)
        buffers.append(pointer)
        document = json.loads(pointer)
        if (type(document) is not dict
            or set(document) != {"username", "material_source", "acceptance_record",
                                 "verified_at", "identity_verified", "initial_password_is_historical"}
            or document["username"] != binding.expected.username
            or document["identity_verified"] is not True
            or document["initial_password_is_historical"] is not True
            or type(document["verified_at"]) is not int or document["verified_at"] <= 0
            or type(document["material_source"]) is not str):
            raise ValueError
        match = re.fullmatch(r"\.\./(reset(?:-[A-Za-z0-9][A-Za-z0-9._-]{0,95})?)/next-password",
                             document["material_source"])
        if match is None or document["acceptance_record"] != f"../{match.group(1)}/acceptance.json":
            raise ValueError
        current = fixture.parent / match.group(1)
        identity = _directory_identity(current)
        acceptance = _read_small(current, identity, "acceptance.json", 4096)
        buffers.append(acceptance)
        record = json.loads(acceptance)
        result = _read_small(current, identity, "result.json", 4096)
        buffers.append(result)
        outcome = json.loads(result)
        if (type(record) is not dict or type(outcome) is not dict
            or record.get("execution_outcome") != "succeeded" or outcome.get("outcome") != "succeeded"
            or record.get("authenticated_identity_verified") is not True
            or type(record.get("authenticated_status")) is not int or record["authenticated_status"] != 200
            or type(record.get("new_password_login_http_status")) is not int
            or record["new_password_login_http_status"] != 303
            or type(record.get("observed_at")) is not int or record["observed_at"] <= 0
            or document["verified_at"] < record["observed_at"]
            or record.get("execution_result_sha256") != hashlib.sha256(result).hexdigest()):
            raise ValueError
        manifest, _ = _read_manifest(current, identity, binding.expected.fixture_creation_digest)
        digest = hashlib.sha256(b"bp002-current-login-selection/v1\0" + manifest.encode("ascii"))
        for value in buffers:
            digest.update(len(value).to_bytes(4, "big"))
            digest.update(value)
        return current, manifest, digest.hexdigest()
    finally:
        for value in buffers:
            _zeroize_mutable(value)


class OwnerOnlyLocalUserResetMaterialSource:
    """Supply old/new writable buffers once after a fresh provenance check.

    A trusted caller may select a previously verified current reset source.
    Its signed manifest binds staged bytes to the fixture; it does not prove
    that a reset or login succeeded, or authorize a subsequent device write.
    """

    def __init__(
        self, *, fixture_directory: Path, reset_directory: Path,
        binding: LocalUserResetBinding, inspector: LocalUserResetMaterialInspector,
        expected_binding_digest: str, enabled: bool = False,
        current_reset_directory: Path | None = None,
        expected_current_binding_digest: str | None = None,
        _pending_login: bool = False,
    ) -> None:
        try:
            fixture = Path(fixture_directory)
            reset = Path(reset_directory)
            if (type(binding) is not LocalUserResetBinding
                or not callable(getattr(inspector, "read_nonmaterial_baseline", None))
                or not callable(getattr(inspector, "verify_initial_material_view", None))
                or type(expected_binding_digest) is not str
                or _DIGEST.fullmatch(expected_binding_digest) is None
                or type(enabled) is not bool or type(_pending_login) is not bool
                or (_pending_login and (enabled or current_reset_directory is None))):
                raise ValueError
            fixture_id = _directory_identity(fixture)
            reset_id = _directory_identity(reset)
            transition = fixture / _TRANSITION
            if not _pending_login and (transition.exists() or transition.is_symlink()):
                raise ValueError
            if fixture_id == reset_id:
                raise ValueError
            binding_digest, new_digest = _read_manifest(
                reset, reset_id, binding.expected.fixture_creation_digest,
            )
            if not hmac.compare_digest(binding_digest, expected_binding_digest):
                raise ValueError
            current = None
            current_id = None
            current_digest = None
            if current_reset_directory is not None:
                if (type(expected_current_binding_digest) is not str
                    or _DIGEST.fullmatch(expected_current_binding_digest) is None):
                    raise ValueError
                current = Path(current_reset_directory)
                current_id = _directory_identity(current)
                if current_id in {fixture_id, reset_id}:
                    raise ValueError
                current_binding, current_digest = _read_manifest(
                    current, current_id, binding.expected.fixture_creation_digest,
                )
                if not hmac.compare_digest(current_binding, expected_current_binding_digest):
                    raise ValueError
            elif expected_current_binding_digest is not None:
                raise ValueError
            elif ((fixture / "current-login-binding.json").exists()
                  or (fixture / "current-login-binding.json").is_symlink()):
                # A rotation marker prevents silent fallback to creation-time
                # credentials. Its contents never supply material authority.
                raise ValueError
        except Exception:
            raise LocalUserResetMaterialSourceError(_UNAVAILABLE) from None
        self._fixture, self._reset = fixture, reset
        self._fixture_id, self._reset_id = fixture_id, reset_id
        self._binding, self._inspector = binding, inspector
        self._staged_binding_digest = binding_digest
        self._current, self._current_id = current, current_id
        self._current_binding_digest = expected_current_binding_digest
        self._expected_current_digest = current_digest
        # Existing intent/context bindings include the selected old material as
        # well as the next material. A different old source needs fresh intent.
        self._binding_digest = (binding_digest if current is None else hashlib.sha256(
            b"bp002-reset-material-pair/v1\0" + _canonical({
                "current": expected_current_binding_digest, "next": binding_digest,
            }),
        ).hexdigest())
        self._expected_new_digest = new_digest
        self._current_selection_digest: str | None = None
        self._pending_transition: bytes | None = None
        self._enabled = enabled
        self._pending_login = _pending_login
        self._consumed, self._lock = _pending_login, threading.Lock()
        if _pending_login:
            content: bytearray | None = None
            try:
                if (reset.parent != fixture.parent
                    or re.fullmatch(r"reset(?:-[A-Za-z0-9][A-Za-z0-9._-]{0,95})?", reset.name) is None):
                    raise ValueError
                binding.__post_init__()
                selected, selected_manifest, selection = _read_current_login_selection(fixture, binding)
                if selected != current or selected_manifest != expected_current_binding_digest:
                    raise ValueError
                self._current_selection_digest = selection
                self._binding_digest = hashlib.sha256(b"bp002-current-login-material-pair/v1\0" + _canonical({
                    "material_pair": self._binding_digest, "current_record": selection,
                })).hexdigest()
                content = _read_small(fixture, fixture_id, _TRANSITION, 4096)
                expected = _canonical({"version": 1, "reset_directory": reset.name,
                    "current_selection_digest": selection, "staged_binding_digest": binding_digest,
                    "material_pair_digest": self._binding_digest})
                if not hmac.compare_digest(content, expected):
                    raise ValueError
                self._pending_transition = bytes(content)
                self._verify_current_selection()
                if (_directory_identity(fixture) != fixture_id or _directory_identity(reset) != reset_id
                    or _read_manifest(reset, reset_id, binding.expected.fixture_creation_digest) != (
                        binding_digest, new_digest)):
                    raise ValueError
            except Exception:
                raise LocalUserResetMaterialSourceError(_UNAVAILABLE) from None
            finally:
                if content is not None:
                    _zeroize_mutable(content)

    @classmethod
    def from_current_login_binding(
        cls, *, fixture_directory: Path, reset_directory: Path,
        binding: LocalUserResetBinding, inspector: LocalUserResetMaterialInspector,
        expected_binding_digest: str, enabled: bool = False,
    ) -> OwnerOnlyLocalUserResetMaterialSource:
        """Reuse owner-recorded successful material without granting execution.

        The protected records are local evidence, not a new authentication or
        authorization. The normal fresh baseline, intent and M4 guards remain
        required. This helper never falls back to the historical password.
        """
        try:
            if type(binding) is not LocalUserResetBinding:
                raise ValueError
            binding.__post_init__()
            current, manifest, selection = _read_current_login_selection(Path(fixture_directory), binding)
            source = cls(fixture_directory=fixture_directory, reset_directory=reset_directory,
                binding=binding, inspector=inspector, expected_binding_digest=expected_binding_digest,
                enabled=enabled, current_reset_directory=current, expected_current_binding_digest=manifest)
            source._current_selection_digest = selection
            source._binding_digest = hashlib.sha256(b"bp002-current-login-material-pair/v1\0" + _canonical({
                "material_pair": source._binding_digest, "current_record": selection,
            })).hexdigest()
            return source
        except Exception:
            raise LocalUserResetMaterialSourceError(_UNAVAILABLE) from None

    def __call__(self) -> LocalUserResetMaterialLease:
        with self._lock:
            if self._pending_login or not self._enabled or self._consumed:
                raise LocalUserResetMaterialSourceError(_UNAVAILABLE)
            self._consumed = True
        return LocalUserResetMaterialLease(self._load)

    @classmethod
    def from_pending_login_binding(
        cls, *, fixture_directory: Path, reset_directory: Path,
        binding: LocalUserResetBinding, inspector: LocalUserResetMaterialInspector,
        expected_binding_digest: str,
    ) -> OwnerOnlyLocalUserResetMaterialSource:
        """Reconstruct read-only bindings for separate verified login reconciliation.

        The exact pending marker remains in place. This source is disabled and
        permanently consumed: it cannot lease either password or reserve a
        dispatch. Execution and independent login evidence must still be
        verified by the private acceptance caller before promotion.
        """
        try:
            if type(binding) is not LocalUserResetBinding:
                raise ValueError
            binding.__post_init__()
            current, manifest, _ = _read_current_login_selection(Path(fixture_directory), binding)
            return cls(fixture_directory=fixture_directory, reset_directory=reset_directory,
                binding=binding, inspector=inspector, expected_binding_digest=expected_binding_digest,
                enabled=False, current_reset_directory=current, expected_current_binding_digest=manifest,
                _pending_login=True)
        except Exception:
            raise LocalUserResetMaterialSourceError(_UNAVAILABLE) from None

    def _verify_current_selection(self) -> None:
        """Recheck current-source records without acquiring password material."""
        try:
            transition = self._fixture / _TRANSITION
            pending = getattr(self, "_pending_transition", None)
            if transition.exists() or transition.is_symlink():
                if pending is None:
                    raise ValueError
                content = _read_small(self._fixture, self._fixture_id, _TRANSITION, 4096)
                try:
                    if not hmac.compare_digest(content, pending):
                        raise ValueError
                finally:
                    _zeroize_mutable(content)
            elif pending is not None:
                raise ValueError
            if self._current_selection_digest is not None:
                if _read_current_login_selection(self._fixture, self._binding) != (
                    self._current, self._current_binding_digest, self._current_selection_digest,
                ):
                    raise ValueError
            elif self._current is None and (
                (self._fixture / "current-login-binding.json").exists()
                or (self._fixture / "current-login-binding.json").is_symlink()
            ):
                raise ValueError
        except Exception:
            raise LocalUserResetMaterialSourceError(_UNAVAILABLE) from None

    def _reserve_transition_once(self) -> None:
        """Reserve the fixture before MCP dispatch until private login acceptance.

        A different run or a restarted source must not keep using the previous
        password after a successful or uncertain change. Only this live source
        may continue its already bound dispatch; the marker grants no authority.
        """
        content: bytearray | None = None
        try:
            with self._lock:
                if (self._pending_login or not self._enabled or self._consumed or self._pending_transition is not None
                    or self._current_selection_digest is None
                    or self._reset.parent != self._fixture.parent
                    or re.fullmatch(r"reset(?:-[A-Za-z0-9][A-Za-z0-9._-]{0,95})?", self._reset.name) is None
                    or _directory_identity(self._fixture) != self._fixture_id
                    or _directory_identity(self._reset) != self._reset_id):
                    raise ValueError
                self._verify_current_selection()
                if _read_manifest(self._reset, self._reset_id, self._binding.expected.fixture_creation_digest) != (
                    self._staged_binding_digest, self._expected_new_digest,
                ):
                    raise ValueError
                content = bytearray(_canonical({"version": 1, "reset_directory": self._reset.name,
                    "current_selection_digest": self._current_selection_digest,
                    "staged_binding_digest": self._staged_binding_digest,
                    "material_pair_digest": self._binding_digest}))
                _write_once(self._fixture, self._fixture_id, _TRANSITION, content)
                self._pending_transition = bytes(content)
                self._verify_current_selection()
        except Exception:
            raise LocalUserResetMaterialSourceError(_UNAVAILABLE) from None
        finally:
            if content is not None:
                _zeroize_mutable(content)

    def _load(self) -> tuple[memoryview, memoryview]:
        old: bytearray | None = None
        new: bytearray | None = None
        try:
            if self._pending_login:
                raise ValueError
            baseline = self._inspector.read_nonmaterial_baseline()
            if type(baseline) is not LocalUserResetBaseline:
                raise ValueError
            LocalUserResetBinding(baseline)
            if baseline != self._binding.expected:
                raise ValueError
            self._verify_current_selection()
            if (_directory_identity(self._fixture) != self._fixture_id
                or _directory_identity(self._reset) != self._reset_id):
                raise ValueError
            if _read_manifest(
                self._reset, self._reset_id, self._binding.expected.fixture_creation_digest,
            ) != (self._staged_binding_digest, self._expected_new_digest):
                raise ValueError
            if self._current is None:
                if ((self._fixture / "current-login-binding.json").exists()
                    or (self._fixture / "current-login-binding.json").is_symlink()):
                    raise ValueError
                old, old_length = _read_material(self._fixture, self._fixture_id, "initial-password")
                with memoryview(old)[:old_length] as old_view:
                    if self._inspector.verify_initial_material_view(
                        old_view, expected_fixture_digest=self._binding.expected.fixture_creation_digest,
                    ) is not True:
                        raise ValueError
            else:
                assert self._current_id is not None
                if (_directory_identity(self._current) != self._current_id
                    or _read_manifest(self._current, self._current_id,
                        self._binding.expected.fixture_creation_digest) != (
                            self._current_binding_digest, self._expected_current_digest)):
                    raise ValueError
                old, old_length = _read_material(self._current, self._current_id, "next-password")
                with memoryview(old)[:old_length] as old_view:
                    current_digest = hashlib.sha256(old_view).hexdigest()
                if not hmac.compare_digest(current_digest, self._expected_current_digest or ""):
                    raise ValueError
            new, new_length = _read_material(self._reset, self._reset_id, "next-password")
            with memoryview(new)[:new_length] as new_view:
                digest = hashlib.sha256(new_view).hexdigest()
            if (not hmac.compare_digest(digest, self._expected_new_digest)
                or hmac.compare_digest(memoryview(old)[:old_length], memoryview(new)[:new_length])):
                raise ValueError
            return memoryview(old)[:old_length], memoryview(new)[:new_length]
        except Exception:
            if old is not None:
                _zeroize_mutable(old)
            if new is not None:
                _zeroize_mutable(new)
            raise LocalUserResetMaterialSourceError(_UNAVAILABLE) from None
