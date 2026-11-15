"""Private durable original Target inputs; never identity or execution authority."""
from __future__ import annotations

from collections.abc import Callable
import hashlib
import os
from pathlib import Path
import secrets
import stat

from . import target_creation_http_transport as t
from .target_creation_evidence import _require_digest
from . import target_preservation_contract as c
from .ldap_server_http_transport import _Connection
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig, _zeroize_mutable
from .target_operation_records import _TargetOperationRecords
from .windows_target_owner_source import WindowsTargetOwnerSource

_ERROR = 'Protected Target creation inputs unavailable.'
_CONTRACT = 'fortipam-build29-target-creation-inputs-v1'
_BODY = 'original-request.bin'
_EXPECTED = 'expected-fields.bin'
_KEY = 'provenance-key.bin'
_CLAIM = 'provision.claim.json'
_MANIFEST = 'inputs.verified.json'


class TargetCreationInputsError(ValueError):
    """Fixed value-free error; partial provision must never be retried."""


def _file(info: os.stat_result, limit: int) -> None:
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
        or not 0 < info.st_size <= limit):
        raise ValueError


def _write_binary(directory: int, name: str, content: bytearray) -> None:
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    with os.fdopen(fd, 'wb') as stream:
        if stream.write(content) != len(content):
            raise ValueError
        stream.flush()
        os.fsync(stream.fileno())
        _file(os.fstat(stream.fileno()), len(content))
    os.fsync(directory)


def _read_binary(directory: int, name: str, limit: int) -> bytearray:
    raw = bytearray()
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        before = os.fstat(fd)
        _file(before, limit)
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = bytearray(before.st_size)
            if stream.readinto(raw) != len(raw) or stream.read(1):
                raise ValueError
        after = os.fstat(fd)
        _file(after, limit)
        current = os.stat(name, dir_fd=directory, follow_symlinks=False)
        _file(current, limit)
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            or (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino)):
            raise ValueError
        result, raw = raw, bytearray()
        return result
    finally:
        os.close(fd)
        _zeroize_mutable(raw)


class TargetCreationInputStore(_TargetOperationRecords):
    """Owner-only local storage; the caller must independently retain its digest.

    Request/key files are private plaintext, not encryption or a vault. No
    deletion, replacement, automatic repair or replay of partial input exists.
    """
    __slots__ = ('_directory', '_identity', '_namespace')

    def __init__(self, directory: Path) -> None:
        try:
            if (not isinstance(directory, Path) or not directory.is_absolute()
                or '..' in directory.parts
                or any(p.is_symlink() for p in (directory, *directory.parents))):
                raise ValueError
            info = directory.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
                raise ValueError
            self._directory, self._identity = directory, (info.st_dev, info.st_ino)
            self._namespace = t._digest((_CONTRACT, str(directory), self._identity))
        except Exception:
            raise TargetCreationInputsError(_ERROR) from None

    def _check_directory(self) -> None:
        info = self._directory.lstat()
        if ((info.st_dev, info.st_ino) != self._identity or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700
            or any(p.is_symlink() for p in self._directory.parents)):
            raise ValueError

    def provision(self, proposal: c.TargetState, body: bytearray, *,
                  expected_material: bytearray | None = None) -> str:
        """Consume the exact request and publish one externally retained input digest."""
        key = bytearray()
        try:
            c._checked_state(proposal)
            if expected_material is not None and type(expected_material) is not bytearray:
                raise ValueError
            material_digest = (None if expected_material is None
                               else hashlib.sha256(expected_material).hexdigest())
            serialization = t._verify_request(body, proposal,
                None if expected_material is None else bytearray(expected_material))
            body_digest = hashlib.sha256(body).hexdigest()
            with self._lock() as directory:
                self._check_directory()
                claim = {'namespace': self._namespace, 'proposal_digest': proposal.state_digest,
                         'body_digest': body_digest}
                if serialization is not None:
                    claim['serialization_digest'] = serialization
                self._write(directory, _CLAIM, claim)
                key = bytearray(secrets.token_bytes(32))
                _write_binary(directory, _BODY, body)
                if expected_material is not None:
                    _write_binary(directory, _EXPECTED, expected_material)
                _write_binary(directory, _KEY, key)
                value: dict[str, object] = {'namespace': self._namespace, 'proposal': t._snapshot(proposal),
                         'body_digest': body_digest, 'key_digest': hashlib.sha256(key).hexdigest(),
                         'claim_digest': t._digest(claim)}
                if serialization is not None:
                    value['serialization_digest'] = serialization
                    value['expected_material_digest'] = material_digest
                self._check_directory()
                self._write(directory, _MANIFEST, value)
                return t._digest(value)
        except Exception:
            raise TargetCreationInputsError(_ERROR) from None
        finally:
            if isinstance(body, bytearray):
                _zeroize_mutable(body)
            _zeroize_mutable(key)
            if isinstance(expected_material, bytearray):
                _zeroize_mutable(expected_material)

    def open_creator(self, config: SecretMetadataHttpTransportConfig, *, input_digest: str,
                     state_directory: Path, execution_enabled: bool = False,
                     recovery_enabled: bool = False, clock: Callable[[], int] | None = None,
                     connection_factory: Callable[..., _Connection] | None = None,
                     owner_read_source: WindowsTargetOwnerSource | None = None) -> t.TargetCreationHttpTransport:
        """Reload only pinned inputs; preserve the creator's independent default gates."""
        body, key, expected = bytearray(), bytearray(), bytearray()
        creator = None
        try:
            _require_digest(input_digest)
            if state_directory == self._directory:
                raise ValueError
            with self._lock() as directory:
                self._check_directory()
                value = self._read(directory, _MANIFEST)
                fields = {'namespace', 'proposal', 'body_digest', 'key_digest', 'claim_digest'}
                compiled = 'serialization_digest' in value
                if compiled:
                    fields |= {'serialization_digest', 'expected_material_digest'}
                if set(value) != fields or t._digest(value) != input_digest:
                    raise ValueError
                proposal = t._state(value['proposal'])
                claim = self._read(directory, _CLAIM)
                expected_claim = {'namespace': self._namespace, 'proposal_digest': proposal.state_digest,
                                  'body_digest': value['body_digest']}
                if compiled:
                    expected_claim['serialization_digest'] = value['serialization_digest']
                if claim != expected_claim or t._digest(claim) != value['claim_digest']:
                    raise ValueError
                body = _read_binary(directory, _BODY, t._LIMIT)
                key = _read_binary(directory, _KEY, 32)
                if (len(key) != 32 or hashlib.sha256(body).hexdigest() != value['body_digest']
                    or hashlib.sha256(key).hexdigest() != value['key_digest']):
                    raise ValueError
                if compiled:
                    expected = _read_binary(directory, _EXPECTED, t._LIMIT)
                    if hashlib.sha256(expected).hexdigest() != value['expected_material_digest']:
                        raise ValueError
                serialization = t._verify_request(body, proposal, bytearray(expected) if compiled else None)
                if serialization != value.get('serialization_digest'):
                    raise ValueError
                self._check_directory()
                creator = t.TargetCreationHttpTransport(config, proposal, body,
                    state_directory=state_directory, provenance_key=bytes(key),
                    execution_enabled=execution_enabled, recovery_enabled=recovery_enabled,
                    expected_material=expected if compiled else None,
                    clock=clock, connection_factory=connection_factory, owner_read_source=owner_read_source)
                self._check_directory()
                return creator
        except Exception:
            if creator is not None:
                creator.close()
            raise TargetCreationInputsError(_ERROR) from None
        finally:
            _zeroize_mutable(body)
            _zeroize_mutable(key)
            _zeroize_mutable(expected)
