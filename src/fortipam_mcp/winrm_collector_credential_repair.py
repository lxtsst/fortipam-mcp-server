"""Private, one-shot repair of an existing WinRM collector username.

This unregistered candidate repairs one already-bound collector through a
complete ``Host``/``Username``/``Password`` field array.  It accepts neither
callers' selectors nor material: the binding and current-state reader remain
private, and the target username plus original password arrive together through
one protected mutable-material lease.

The PUT acknowledgement is deliberately status-only.  A separate protected
reader supplies the categorical post-write result and never returns field
content to this module's callers.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
import ipaddress
import re
import threading
from typing import Any, Protocol, cast
from urllib.parse import urlsplit

from v4_planning.material_provider import MaterialLease

from .mutable_json_buffer import _MutableJSONBuffer
from .secret_create_191_http_transport import _append_material, _append_text, _valid_material_view
from .secret_metadata_http_transport import COLLECTION_PATH, SecretMetadataHttpTransportConfig, _zeroize_mutable


_UNAVAILABLE = "The private WinRM collector credential repair is unavailable."
_MACHINE_USERNAME = re.compile(
    rb"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\\[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z",
    re.ASCII,
)
_UNQUALIFIED_USERNAME = re.compile(
    rb"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z",
    re.ASCII,
)


class CollectorCredentialRepairError(RuntimeError):
    """Stable non-disclosing failure for this private candidate."""


class CollectorCredentialRepairOutcome(str, Enum):
    GATE_CLOSED = "gate_closed"
    DRIFT_REJECTED = "drift_rejected"
    RECONCILIATION_REQUIRED = "reconciliation_required"
    VERIFIED = "verified"


class WinrmCollectorUsernameForm(str, Enum):
    """Exact private username shape authorized for one repair binding."""

    MACHINE_QUALIFIED = "machine_qualified"
    UNQUALIFIED_LOCAL = "unqualified_local"


@dataclass(frozen=True, slots=True, repr=False)
class WinrmCollectorCredentialRepairBinding:
    """Private identity and exact current field IDs for one collector."""

    secret_id: int
    secret_name: str
    folder_id: int
    template_name: str
    host: str
    host_field_id: int
    username_field_id: int
    password_field_id: int
    username_form: WinrmCollectorUsernameForm = (
        WinrmCollectorUsernameForm.MACHINE_QUALIFIED
    )

    def __post_init__(self) -> None:
        if (
            type(self.secret_id) is not int
            or type(self.folder_id) is not int
            or self.secret_id <= 0
            or self.folder_id <= 0
            or self.template_name != "Windows Machine"
            or not isinstance(self.username_form, WinrmCollectorUsernameForm)
            or not _selector(self.secret_name, 255)
            or not _canonical_ipv4(self.host)
            or any(type(value) is not int or value <= 0 or value > 2_147_483_647 for value in self.field_ids)
            or len(set(self.field_ids)) != 3
        ):
            raise CollectorCredentialRepairError(_UNAVAILABLE)

    @property
    def field_ids(self) -> tuple[int, int, int]:
        return self.host_field_id, self.username_field_id, self.password_field_id


class _RepairConnection(Protocol):
    def request(self, method: str, url: str, body: memoryview, headers: dict[str, str]) -> None: ...

    def getresponse(self) -> Any: ...

    def close(self) -> None: ...


class _OwnerSession(Protocol):
    def collector_credential_repair_connection(
        self, host: str, port: int, *, secret_id: int,
    ) -> _RepairConnection: ...


class WinrmCollectorCredentialRepairInspector(Protocol):
    """Protected reader: field content remains inside its implementation."""

    def read_prewrite(self) -> WinrmCollectorCredentialRepairBinding: ...

    def verify_prewrite_material(
        self,
        binding: WinrmCollectorCredentialRepairBinding,
        password: memoryview,
    ) -> bool: ...

    def verify_postwrite(
        self,
        binding: WinrmCollectorCredentialRepairBinding,
        username: memoryview,
        password: memoryview,
    ) -> bool: ...


class WinrmCollectorCredentialRepairGate:
    """Default-closed, consumed-before-dispatch gate for this one candidate."""

    __slots__ = ("_enabled", "_lock", "_reserved")

    def __init__(self, enabled: bool = False) -> None:
        if type(enabled) is not bool:
            raise CollectorCredentialRepairError(_UNAVAILABLE)
        self._enabled = enabled
        self._lock = threading.Lock()
        self._reserved = False

    @property
    def enabled(self) -> bool:
        with self._lock:
            return self._enabled and not self._reserved

    def reserve(self) -> _GateReservation:
        with self._lock:
            if not self._enabled or self._reserved:
                raise CollectorCredentialRepairError(_UNAVAILABLE)
            self._reserved = True
        return _GateReservation(self)


class _GateReservation:
    """One opaque reservation that becomes consumed immediately before PUT."""

    __slots__ = ("_gate", "_consumed")

    def __init__(self, gate: WinrmCollectorCredentialRepairGate) -> None:
        self._gate = gate
        self._consumed = False

    def consume(self) -> None:
        with self._gate._lock:
            if not self._gate._reserved or self._consumed:
                raise CollectorCredentialRepairError(_UNAVAILABLE)
            self._consumed = True


class _CredentialMaterial:
    """Mutable C3 material held only between one lease consume and disposal."""

    __slots__ = ("password", "username", "username_form")

    def __init__(
        self,
        username: memoryview,
        password: memoryview,
        username_form: WinrmCollectorUsernameForm,
    ) -> None:
        if not _valid_mutable_material_view(username) or not _valid_mutable_material_view(password):
            raise CollectorCredentialRepairError(_UNAVAILABLE)
        if not _username_matches_form(username, username_form):
            raise CollectorCredentialRepairError(_UNAVAILABLE)
        self.username = username
        self.password = password
        self.username_form = username_form

    def dispose(self) -> None:
        _dispose_material(self.username)
        _dispose_material(self.password)


class WinrmCollectorCredentialRepairMaterialLease(MaterialLease):
    """Private single-use lease for target username and original password."""

    __slots__ = ("_consumed", "_loader", "_username_form")

    def __init__(
        self,
        loader: Callable[[], tuple[memoryview, memoryview]],
        *,
        username_form: WinrmCollectorUsernameForm = (
            WinrmCollectorUsernameForm.MACHINE_QUALIFIED
        ),
    ) -> None:
        if not callable(loader) or not isinstance(
            username_form, WinrmCollectorUsernameForm
        ):
            raise CollectorCredentialRepairError(_UNAVAILABLE)
        self._loader = loader
        self._username_form = username_form
        self._consumed = False

    def _consume(self) -> _CredentialMaterial:
        if self._consumed:
            raise CollectorCredentialRepairError(_UNAVAILABLE)
        self._consumed = True
        username: memoryview | None = None
        password: memoryview | None = None
        try:
            username, password = self._loader()
            return _CredentialMaterial(username, password, self._username_form)
        except Exception:
            if isinstance(username, memoryview):
                _dispose_material(username)
            if isinstance(password, memoryview):
                _dispose_material(password)
            raise CollectorCredentialRepairError(_UNAVAILABLE) from None


class FortiPamWinrmCollectorCredentialRepairTransport:
    """Perform exactly one status-only PUT through a private connection."""

    def __init__(
        self,
        config: SecretMetadataHttpTransportConfig,
        *,
        owner_session: object,
    ) -> None:
        if (
            not isinstance(config, SecretMetadataHttpTransportConfig)
            or not callable(
            getattr(owner_session, "collector_credential_repair_connection", None)
            )
        ):
            raise CollectorCredentialRepairError(_UNAVAILABLE)
        self._config = config
        self._owner_session = cast(_OwnerSession, owner_session)

    def update(
        self,
        binding: WinrmCollectorCredentialRepairBinding,
        material: _CredentialMaterial,
        *,
        reservation: _GateReservation,
    ) -> None:
        if (
            not isinstance(binding, WinrmCollectorCredentialRepairBinding)
            or not isinstance(material, _CredentialMaterial)
            or not isinstance(reservation, _GateReservation)
        ):
            raise CollectorCredentialRepairError(_UNAVAILABLE)
        body = bytearray()
        connection: _RepairConnection | None = None
        body_view: memoryview | None = None
        response: Any = None
        try:
            body = _repair_body(binding, material.username, material.password)
            parsed = urlsplit(self._config.base_url)
            if parsed.hostname is None:
                raise ValueError
            # Consume before opening the connection: transport uncertainty is
            # reconciliation, never permission to resend this credential body.
            reservation.consume()
            connection = self._owner_session.collector_credential_repair_connection(
                parsed.hostname, parsed.port or 443, secret_id=binding.secret_id,
            )
            body_view = memoryview(body).toreadonly()
            connection.request(
                "PUT", f"{COLLECTION_PATH}/{binding.secret_id}", body_view,
                {
                    "Accept": "application/json",
                    "Connection": "close",
                    "Content-Type": "application/json",
                    "Content-Length": str(len(body)),
                    "User-Agent": "fortipam-mcp-v4-winrm-collector-credential-repair/1",
                },
            )
            response = connection.getresponse()
            # Never read or decode an update response: it can echo all fields.
            if type(response.status) is not int or response.status != 200:
                raise CollectorCredentialRepairError(_UNAVAILABLE)
        except CollectorCredentialRepairError:
            raise
        except Exception:
            raise CollectorCredentialRepairError(_UNAVAILABLE) from None
        finally:
            if response is not None:
                try:
                    response.close()
                except Exception:
                    pass
            if body_view is not None:
                body_view.release()
            _zeroize_mutable(body)
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass


class WinrmCollectorCredentialRepairWorkflow:
    """Bind one pre-write read, one consumed PUT and one categorical readback."""

    def __init__(
        self,
        binding: WinrmCollectorCredentialRepairBinding,
        inspector: WinrmCollectorCredentialRepairInspector,
        transport: FortiPamWinrmCollectorCredentialRepairTransport,
        gate: WinrmCollectorCredentialRepairGate,
        *,
        material_lease_provider: Callable[[], WinrmCollectorCredentialRepairMaterialLease],
    ) -> None:
        if (
            not isinstance(binding, WinrmCollectorCredentialRepairBinding)
            or not isinstance(transport, FortiPamWinrmCollectorCredentialRepairTransport)
            or not isinstance(gate, WinrmCollectorCredentialRepairGate)
            or not callable(getattr(inspector, "read_prewrite", None))
            or not callable(getattr(inspector, "verify_prewrite_material", None))
            or not callable(getattr(inspector, "verify_postwrite", None))
            or not callable(material_lease_provider)
        ):
            raise CollectorCredentialRepairError(_UNAVAILABLE)
        self._binding = binding
        self._inspector = inspector
        self._transport = transport
        self._gate = gate
        self._material_lease_provider = material_lease_provider

    def repair(self) -> CollectorCredentialRepairOutcome:
        material: _CredentialMaterial | None = None
        if not self._gate.enabled:
            return CollectorCredentialRepairOutcome.GATE_CLOSED
        try:
            prewrite = self._inspector.read_prewrite()
            if prewrite != self._binding:
                return CollectorCredentialRepairOutcome.DRIFT_REJECTED
            # Reserve before acquiring either C3 value. A failed material
            # acquisition keeps this Gate closed rather than permitting a retry.
            reservation = self._gate.reserve()
        except CollectorCredentialRepairError:
            return CollectorCredentialRepairOutcome.GATE_CLOSED
        except Exception:
            return CollectorCredentialRepairOutcome.DRIFT_REJECTED
        try:
            lease = self._material_lease_provider()
            if not isinstance(lease, WinrmCollectorCredentialRepairMaterialLease):
                raise ValueError
            material = lease._consume()
            if material.username_form is not self._binding.username_form:
                material.dispose()
                material = None
                raise ValueError
            if self._inspector.verify_prewrite_material(
                self._binding, material.password,
            ) is not True:
                material.dispose()
                material = None
                raise ValueError
        except Exception:
            return CollectorCredentialRepairOutcome.DRIFT_REJECTED
        try:
            self._transport.update(self._binding, material, reservation=reservation)
            return (
                CollectorCredentialRepairOutcome.VERIFIED
                if self._inspector.verify_postwrite(
                    self._binding, material.username, material.password,
                ) is True
                else CollectorCredentialRepairOutcome.RECONCILIATION_REQUIRED
            )
        except Exception:
            return CollectorCredentialRepairOutcome.RECONCILIATION_REQUIRED
        finally:
            if material is not None:
                material.dispose()


def _repair_body(
    binding: WinrmCollectorCredentialRepairBinding, username: memoryview, password: memoryview,
) -> bytearray:
    with _MutableJSONBuffer() as body:
        body.extend(b'{"id":')
        body.extend(str(binding.secret_id).encode("ascii"))
        body.extend(b',"name":')
        _append_text(body, binding.secret_name)
        body.extend(b',"folder":')
        body.extend(str(binding.folder_id).encode("ascii"))
        body.extend(b',"template":"Windows Machine","field":[{"id":')
        body.extend(str(binding.host_field_id).encode("ascii"))
        body.extend(b',"name":"Host","value":')
        _append_text(body, binding.host)
        body.extend(b'},{"id":')
        body.extend(str(binding.username_field_id).encode("ascii"))
        body.extend(b',"name":"Username","value":')
        _append_material(body, username)
        body.extend(b'},{"id":')
        body.extend(str(binding.password_field_id).encode("ascii"))
        body.extend(b',"name":"Password","value":')
        _append_material(body, password)
        body.extend(b'}]}')
        return body.finish()


def _selector(value: object, maximum: int) -> bool:
    return isinstance(value, str) and 0 < len(value) <= maximum and all(32 <= ord(char) <= 126 for char in value)


def _canonical_ipv4(value: object) -> bool:
    try:
        return isinstance(value, str) and str(ipaddress.IPv4Address(value)) == value
    except (ValueError, TypeError):
        return False


def _machine_username(value: object) -> bool:
    if not isinstance(value, memoryview) or not _valid_mutable_material_view(value):
        return False
    return _MACHINE_USERNAME.fullmatch(value) is not None


def _unqualified_username(value: object) -> bool:
    if not isinstance(value, memoryview) or not _valid_mutable_material_view(value):
        return False
    return _UNQUALIFIED_USERNAME.fullmatch(value) is not None


def _username_matches_form(
    value: object, username_form: WinrmCollectorUsernameForm,
) -> bool:
    if username_form is WinrmCollectorUsernameForm.MACHINE_QUALIFIED:
        return _machine_username(value)
    if username_form is WinrmCollectorUsernameForm.UNQUALIFIED_LOCAL:
        return _unqualified_username(value)
    return False


def _valid_mutable_material_view(value: object) -> bool:
    return isinstance(value, memoryview) and _valid_material_view(value) and not value.readonly


def _dispose_material(value: memoryview) -> None:
    try:
        value[:] = b"\x00" * value.nbytes
    except Exception:
        pass
    try:
        value.release()
    except Exception:
        pass


__all__ = [
    "CollectorCredentialRepairError",
    "CollectorCredentialRepairOutcome",
    "FortiPamWinrmCollectorCredentialRepairTransport",
    "WinrmCollectorCredentialRepairBinding",
    "WinrmCollectorCredentialRepairGate",
    "WinrmCollectorCredentialRepairMaterialLease",
    "WinrmCollectorCredentialRepairWorkflow",
    "WinrmCollectorUsernameForm",
]
