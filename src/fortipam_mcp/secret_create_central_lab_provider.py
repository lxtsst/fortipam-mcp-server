"""Bounded central-lab C3 provider for accepted password Secret create paths.

The provider accepts one already-resolved opaque binding, one exact value-free
lease request, and one pre-bound resolver/loader.  It has no path, binding-ID,
environment-name, registry, list, or search input.  Material is loaded once,
kept only in provider-owned mutable buffers, and can be consumed only through
the action-specific FortiPAM 1.9.1 private transport bridge below.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import os
from pathlib import Path
import stat
import time
from typing import NoReturn, Protocol, SupportsIndex

from v4_planning.material_provider import (
    C3MaterialBinding,
    MaterialAccessDenied,
    MaterialBindingStatus,
    MaterialLease,
    MaterialLeaseCompletion,
    MaterialLeaseRequest,
    MaterialProviderClass,
    MaterialPurpose,
    MaterialRevocationReason,
)
from v4_planning.secret_create_adapter import (
    SECRET_CREATE_ACTION_ID,
    SECRET_CREATE_ACTION_VERSION,
    SecretCreateAdapterOutcome,
)

from .mutable_json_buffer import _take_mutable_prefix
from .secret_create_191_private_adapter import SecretCreate191Binding


MAX_SECRET_CREATE_LEASE_SECONDS = 60
_UNAVAILABLE = "The central lab Secret-create material provider is unavailable."
_MAX_SECRET_ENV_FILE_BYTES = 65_536
_MAX_SECRET_ENV_VARIABLE_NAME_BYTES = 128


class CentralLabSecretCreateResolverLoader(Protocol):
    """Pre-bound owner-side resolver for one credential-bindings-v1 entry.

    The implementation owns the central paths, binding ID, and the fixed
    username/password environment-variable names.  None are accepted here.
    Returned bytearrays transfer ownership to the provider and must not be
    retained by the loader.
    """

    def validate_prebound(self) -> MaterialBindingStatus: ...

    def load_secret_create_material_once(self) -> tuple[bytearray, bytearray]: ...


class OwnerOnlyCentralLabSecretCreateEnvFileLoader:
    """Load two pre-bound variables from one owner-only dotenv file.

    The credential-binding resolver supplies the absolute file path and fixed
    variable names. This loader never reads the binding YAML, process
    environment, or any sibling file, and it does not cache loaded material.
    """

    __slots__ = (
        "_password_variable_name",
        "_secret_env_path",
        "_username_variable_name",
    )

    def __init__(
        self,
        *,
        secret_env_path: Path,
        username_variable_name: str,
        password_variable_name: str,
    ) -> None:
        try:
            path = Path(secret_env_path)
            username_name = _validated_variable_name(username_variable_name)
            password_name = _validated_variable_name(password_variable_name)
            if not path.is_absolute() or username_name == password_name:
                raise ValueError
        except Exception:
            raise MaterialAccessDenied(_UNAVAILABLE) from None
        self._secret_env_path = path
        self._username_variable_name = username_name
        self._password_variable_name = password_name

    def validate_prebound(self) -> MaterialBindingStatus:
        """Check the protected file and both assignments without retaining values."""

        try:
            result = self._read_and_parse(extract_values=False)
        except Exception:
            return MaterialBindingStatus.UNAVAILABLE
        return (
            MaterialBindingStatus.AVAILABLE
            if result is None
            else MaterialBindingStatus.UNAVAILABLE
        )

    def load_secret_create_material_once(self) -> tuple[bytearray, bytearray]:
        """Return fresh mutable buffers; the provider owns their lifecycle."""

        try:
            result = self._read_and_parse(extract_values=True)
            if type(result) is not tuple:
                raise MaterialAccessDenied(_UNAVAILABLE)
            return result
        except Exception:
            raise MaterialAccessDenied(_UNAVAILABLE) from None

    def _read_and_parse(
        self,
        *,
        extract_values: bool,
    ) -> tuple[bytearray, bytearray] | None:
        content = _read_owner_only_secret_env_file(self._secret_env_path)
        try:
            return _parse_prebound_secret_env(
                content,
                self._username_variable_name,
                self._password_variable_name,
                extract_values=extract_values,
            )
        finally:
            _zeroize(content)


class SecretCreate191MaterialTransport(Protocol):
    """Internal action-specific transport that alone receives material views."""

    def _create_and_verify_with_material(
        self,
        binding: SecretCreate191Binding,
        request: MaterialLeaseRequest,
        username: memoryview,
        password: memoryview,
    ) -> SecretCreateAdapterOutcome: ...


class _CentralLabSecretCreateLease(MaterialLease):
    """Non-rendering handle; all material remains in its issuing provider."""

    __slots__ = ()


@dataclass(slots=True, repr=False)
class _LeaseRecord:
    username: bytearray
    password: bytearray
    consumed: bool = False
    cleared: bool = False

    def __repr__(self) -> str:
        return "<_LeaseRecord redacted>"

    __str__ = __repr__

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        del protocol
        raise MaterialAccessDenied(_UNAVAILABLE)

    def __copy__(self) -> NoReturn:
        raise MaterialAccessDenied(_UNAVAILABLE)

    def __deepcopy__(self, memo: object) -> NoReturn:
        del memo
        raise MaterialAccessDenied(_UNAVAILABLE)

    def clear(self) -> None:
        if self.cleared:
            return
        _zeroize(self.username)
        _zeroize(self.password)
        self.cleared = True


class CentralLabInventorySecretCreateProvider:
    """One-request provider for the FPA-BP-005 laboratory Secret create."""

    __slots__ = (
        "_binding",
        "_clock",
        "_lease",
        "_loader",
        "_load_attempted",
        "_record",
        "_request",
    )

    def __init__(
        self,
        resolver_loader: CentralLabSecretCreateResolverLoader,
        *,
        binding: C3MaterialBinding,
        request: MaterialLeaseRequest,
        clock: Callable[[], int] | None = None,
    ) -> None:
        selected_clock = clock or _epoch_seconds
        if (
            not isinstance(binding, C3MaterialBinding)
            or not isinstance(request, MaterialLeaseRequest)
            or request.action_id != SECRET_CREATE_ACTION_ID
            or request.action_version != SECRET_CREATE_ACTION_VERSION
            or request.provider_class
            is not MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE
            or request.purpose is not MaterialPurpose.INITIAL_ONBOARDING
            or request.expires_at - request.requested_at
            > MAX_SECRET_CREATE_LEASE_SECONDS
            or not callable(getattr(resolver_loader, "validate_prebound", None))
            or not callable(
                getattr(resolver_loader, "load_secret_create_material_once", None)
            )
            or not callable(selected_clock)
        ):
            raise MaterialAccessDenied(_UNAVAILABLE)
        self._binding = binding
        self._request = request
        self._loader = resolver_loader
        self._clock = selected_clock
        self._load_attempted = False
        self._lease: _CentralLabSecretCreateLease | None = None
        self._record: _LeaseRecord | None = None

    def validate_binding(
        self,
        binding: C3MaterialBinding,
        request: MaterialLeaseRequest,
    ) -> MaterialBindingStatus:
        """Return only a closed status; resolver details never escape."""

        if (
            binding is not self._binding
            or not isinstance(request, MaterialLeaseRequest)
            or request != self._request
        ):
            return MaterialBindingStatus.INCOMPATIBLE
        try:
            now_epoch = self._clock()
        except Exception:
            self._clear_active_record()
            return MaterialBindingStatus.UNAVAILABLE
        if type(now_epoch) is not int:
            self._clear_active_record()
            return MaterialBindingStatus.UNAVAILABLE
        if now_epoch >= request.expires_at:
            self._clear_active_record()
            return MaterialBindingStatus.EXPIRED
        if now_epoch < request.requested_at or self._load_attempted:
            return MaterialBindingStatus.UNAVAILABLE
        try:
            status = self._loader.validate_prebound()
        except Exception:
            return MaterialBindingStatus.UNAVAILABLE
        if not isinstance(status, MaterialBindingStatus):
            return MaterialBindingStatus.UNAVAILABLE
        return status

    def acquire_lease(
        self,
        binding: C3MaterialBinding,
        request: MaterialLeaseRequest,
    ) -> MaterialLease:
        """Load exactly once after the complete bound request validates."""

        if self.validate_binding(binding, request) is not MaterialBindingStatus.AVAILABLE:
            raise MaterialAccessDenied(_UNAVAILABLE)
        self._load_attempted = True
        loaded: object = None
        try:
            loaded = self._loader.load_secret_create_material_once()
            if (
                type(loaded) is not tuple
                or len(loaded) != 2
                or type(loaded[0]) is not bytearray
                or type(loaded[1]) is not bytearray
                or not _valid_env_file_value(loaded[0])
                or not _valid_env_file_value(loaded[1])
            ):
                raise MaterialAccessDenied(_UNAVAILABLE)
            record = _LeaseRecord(loaded[0], loaded[1])
            lease = _CentralLabSecretCreateLease()
            self._record = record
            self._lease = lease
            return lease
        except Exception:
            _clear_loaded_candidate(loaded)
            raise MaterialAccessDenied(_UNAVAILABLE) from None

    def release_lease(self, lease: MaterialLease) -> MaterialLeaseCompletion:
        """Clear the one issued lease and reject every terminal replay."""

        record = self._take_record(lease)
        record.clear()
        if self._expired():
            return MaterialLeaseCompletion.EXPIRED
        return MaterialLeaseCompletion.RELEASED

    def revoke_lease(
        self,
        lease: MaterialLease,
        *,
        reason: MaterialRevocationReason,
    ) -> MaterialLeaseCompletion:
        """Clear the one issued lease; a second revoke/release is denied."""

        if not isinstance(reason, MaterialRevocationReason):
            raise MaterialAccessDenied(_UNAVAILABLE)
        record = self._take_record(lease)
        record.clear()
        return MaterialLeaseCompletion.REVOKED

    def _consume_for_secret_create_transport(
        self,
        binding: SecretCreate191Binding,
        lease: MaterialLease,
        request: MaterialLeaseRequest,
        transport: SecretCreate191MaterialTransport,
    ) -> SecretCreateAdapterOutcome:
        """Use material once through the fixed private transport interface."""

        record = self._active_record(lease, request)
        operation = getattr(transport, "_create_and_verify_with_material", None)
        if not callable(operation):
            raise MaterialAccessDenied(_UNAVAILABLE)
        record.consumed = True
        username = memoryview(record.username).toreadonly()
        password = memoryview(record.password).toreadonly()
        try:
            outcome = operation(binding, request, username, password)
        finally:
            username.release()
            password.release()
            record.clear()
        if not isinstance(outcome, SecretCreateAdapterOutcome):
            return SecretCreateAdapterOutcome.RECONCILIATION_REQUIRED
        return outcome

    def _active_record(
        self,
        lease: MaterialLease,
        request: MaterialLeaseRequest,
    ) -> _LeaseRecord:
        record = self._record
        expired = self._expired()
        if (
            lease is not self._lease
            or request != self._request
            or record is None
            or record.consumed
            or record.cleared
            or expired
        ):
            if record is not None and expired:
                record.clear()
            raise MaterialAccessDenied(_UNAVAILABLE)
        return record

    def _take_record(self, lease: MaterialLease) -> _LeaseRecord:
        if lease is not self._lease or self._record is None:
            raise MaterialAccessDenied(_UNAVAILABLE)
        record = self._record
        self._record = None
        self._lease = None
        return record

    def _expired(self) -> bool:
        try:
            now_epoch = self._clock()
        except Exception:
            return True
        return type(now_epoch) is not int or now_epoch >= self._request.expires_at

    def _clear_active_record(self) -> None:
        if self._record is not None:
            self._record.clear()


class CentralLabSecretCreate191LeaseTransport:
    """Bridge an opaque lease to one fixed material-aware private transport."""

    __slots__ = ("_provider", "_transport")

    def __init__(
        self,
        provider: CentralLabInventorySecretCreateProvider,
        transport: SecretCreate191MaterialTransport,
    ) -> None:
        if not isinstance(provider, CentralLabInventorySecretCreateProvider) or not callable(
            getattr(transport, "_create_and_verify_with_material", None)
        ):
            raise MaterialAccessDenied(_UNAVAILABLE)
        self._provider = provider
        self._transport = transport

    def create_and_verify(
        self,
        binding: SecretCreate191Binding,
        lease: MaterialLease,
        request: MaterialLeaseRequest,
    ) -> SecretCreateAdapterOutcome:
        try:
            return self._provider._consume_for_secret_create_transport(
                binding,
                lease,
                request,
                self._transport,
            )
        except Exception:
            return SecretCreateAdapterOutcome.RECONCILIATION_REQUIRED


def _valid_env_file_value(value: bytearray) -> bool:
    return (
        0 < len(value) <= 4096
        and 0 not in value
        and 10 not in value
        and 13 not in value
    )


def _validated_variable_name(value: object) -> bytes:
    if type(value) is not str:
        raise ValueError
    encoded = value.encode("ascii")
    if (
        not encoded
        or len(encoded) > _MAX_SECRET_ENV_VARIABLE_NAME_BYTES
        or not _ascii_identifier(encoded)
    ):
        raise ValueError
    return encoded


def _read_owner_only_secret_env_file(path: Path) -> bytearray:
    if not hasattr(os, "O_NOFOLLOW"):
        raise MaterialAccessDenied(_UNAVAILABLE)
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    content = bytearray(_MAX_SECRET_ENV_FILE_BYTES + 1)
    descriptor = -1
    try:
        try:
            descriptor = os.open(path, flags)
            before = os.fstat(descriptor)
            if not _valid_secret_env_file_metadata(before):
                raise MaterialAccessDenied(_UNAVAILABLE)
            total = 0
            while total < len(content):
                target = memoryview(content)[total:]
                try:
                    count = os.readv(descriptor, [target])
                finally:
                    target.release()
                if count == 0:
                    break
                total += count
            after = os.fstat(descriptor)
            if (
                total != before.st_size
                or total > _MAX_SECRET_ENV_FILE_BYTES
                or not _same_secret_env_file(before, after)
            ):
                raise MaterialAccessDenied(_UNAVAILABLE)
            content = _take_mutable_prefix(content, total)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    except BaseException as error:
        _zeroize(content)
        if isinstance(error, Exception):
            raise MaterialAccessDenied(_UNAVAILABLE) from None
        raise
    return content


def _valid_secret_env_file_metadata(info: os.stat_result) -> bool:
    return (
        stat.S_ISREG(info.st_mode)
        and info.st_uid == os.getuid()
        and stat.S_IMODE(info.st_mode) == 0o600
        and 0 < info.st_size <= _MAX_SECRET_ENV_FILE_BYTES
    )


def _same_secret_env_file(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        _valid_secret_env_file_metadata(after)
        and before.st_dev == after.st_dev
        and before.st_ino == after.st_ino
        and before.st_size == after.st_size
        and before.st_mtime_ns == after.st_mtime_ns
    )


def _parse_prebound_secret_env(
    content: bytearray,
    username_name: bytes,
    password_name: bytes,
    *,
    extract_values: bool,
) -> tuple[bytearray, bytearray] | None:
    username: bytearray | None = None
    password: bytearray | None = None
    seen: set[bytes] = set()
    found_username = False
    found_password = False
    try:
        if not _is_valid_utf8(content) or 0 in content or 13 in content:
            raise MaterialAccessDenied(_UNAVAILABLE)
        start = 0
        while start < len(content):
            end = content.find(b"\n", start)
            if end < 0:
                end = len(content)
            if end == start or content[start] == 35:  # blank line or '#'
                start = end + 1
                continue
            equals = content.find(b"=", start, end)
            if equals <= start:
                raise MaterialAccessDenied(_UNAVAILABLE)
            name = bytes(content[start:equals])
            if not _ascii_identifier(name) or name in seen:
                raise MaterialAccessDenied(_UNAVAILABLE)
            seen.add(name)
            if name == username_name:
                value_start, value_end = _dotenv_value_range(
                    content, equals + 1, end
                )
                found_username = True
                if extract_values:
                    username = bytearray(content[value_start:value_end])
            elif name == password_name:
                value_start, value_end = _dotenv_value_range(
                    content, equals + 1, end
                )
                found_password = True
                if extract_values:
                    password = bytearray(content[value_start:value_end])
            start = end + 1
        if not found_username or not found_password:
            raise MaterialAccessDenied(_UNAVAILABLE)
        if not extract_values:
            return None
        if (
            type(username) is not bytearray
            or type(password) is not bytearray
            or not _valid_env_file_value(username)
            or not _valid_env_file_value(password)
        ):
            raise MaterialAccessDenied(_UNAVAILABLE)
        result = (username, password)
        username = None
        password = None
        return result
    except Exception:
        if username is not None:
            _zeroize(username)
        if password is not None:
            _zeroize(password)
        raise MaterialAccessDenied(_UNAVAILABLE) from None


def _dotenv_value_range(
    content: bytearray,
    start: int,
    end: int,
) -> tuple[int, int]:
    if start >= end:
        raise MaterialAccessDenied(_UNAVAILABLE)
    first = content[start]
    last = content[end - 1]
    if first in (34, 39):
        if end - start < 3 or last != first:
            raise MaterialAccessDenied(_UNAVAILABLE)
        start += 1
        end -= 1
    elif last in (34, 39):
        raise MaterialAccessDenied(_UNAVAILABLE)
    for index in range(start, end):
        value = content[index]
        if value < 0x20 or value == 0x7F:
            raise MaterialAccessDenied(_UNAVAILABLE)
        if first not in (34, 39) and value == 0x20:
            raise MaterialAccessDenied(_UNAVAILABLE)
    if (
        end <= start
        or end - start > 4096
        or content[start] == 0x20
        or content[end - 1] == 0x20
        or content[end - 1] == 0x5C
    ):
        raise MaterialAccessDenied(_UNAVAILABLE)
    return start, end


def _ascii_identifier(value: bytes) -> bool:
    if not value:
        return False
    first = value[0]
    if not (first == 95 or 65 <= first <= 90 or 97 <= first <= 122):
        return False
    return all(
        item == 95
        or 65 <= item <= 90
        or 97 <= item <= 122
        or 48 <= item <= 57
        for item in value[1:]
    )


def _is_valid_utf8(value: bytearray) -> bool:
    index = 0
    while index < len(value):
        first = value[index]
        if first <= 0x7F:
            index += 1
            continue
        if 0xC2 <= first <= 0xDF:
            width = 2
            second_min, second_max = 0x80, 0xBF
        elif 0xE0 <= first <= 0xEF:
            width = 3
            second_min = 0xA0 if first == 0xE0 else 0x80
            second_max = 0x9F if first == 0xED else 0xBF
        elif 0xF0 <= first <= 0xF4:
            width = 4
            second_min = 0x90 if first == 0xF0 else 0x80
            second_max = 0x8F if first == 0xF4 else 0xBF
        else:
            return False
        if index + width > len(value):
            return False
        second = value[index + 1]
        if not second_min <= second <= second_max:
            return False
        for continuation_index in range(index + 2, index + width):
            if not 0x80 <= value[continuation_index] <= 0xBF:
                return False
        index += width
    return True


def _clear_loaded_candidate(loaded: object) -> None:
    if type(loaded) is not tuple:
        return
    for item in loaded:
        if type(item) is bytearray:
            _zeroize(item)


def _zeroize(value: bytearray) -> None:
    value[:] = b"\x00" * len(value)
    try:
        value.clear()
    except BufferError:
        # A private transport may have created a child view. The overwrite has
        # already removed the material; resizing can wait for that view to die.
        pass


def _epoch_seconds() -> int:
    return int(time.time())


__all__ = [
    "CentralLabInventorySecretCreateProvider",
    "CentralLabSecretCreate191LeaseTransport",
    "CentralLabSecretCreateResolverLoader",
    "MAX_SECRET_CREATE_LEASE_SECONDS",
    "OwnerOnlyCentralLabSecretCreateEnvFileLoader",
    "SecretCreate191MaterialTransport",
]
