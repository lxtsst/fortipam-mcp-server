"""Unregistered, unqualified 7.0 build-29 reset candidate for one new fixture.

This private adapter has no runtime registration. Its in-process one-shot guard
is not durable authorization: the private execution runner must supply the
persistent claim, qualified authorization and source-qualified inspector.
Success means only backend_changed_metadata_preserved, never verified login.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
import hmac
import re
import threading
from typing import Literal, Protocol
from urllib.parse import urlsplit

from v4_planning.material_provider import C3MaterialBinding, MaterialLease

from .mutable_json_buffer import _MutableJSONBuffer, _take_mutable_prefix
from .secret_create_191_http_transport import _append_material, _append_text, _valid_material_view
from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig, _json_string_end, _json_value_end,
    _skip_json_space, _zeroize_mutable,
)

_UNAVAILABLE = "The private Local User reset candidate is unavailable."
_NAME = re.compile(r"mcp-v4-user-reset-[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_POLICY_PATH = "/api/v2/monitor/system/password-policy-conform/"
_CHANGE_PATH = "/api/v2/monitor/system/change-password"
_MAX_RESPONSE = 16_384
_Operation = Literal["policy_conform", "change_password"]


class LocalUserResetHttpTransportError(RuntimeError):
    """Fixed non-disclosing failure; never chain a material-bearing exception."""


class LocalUserResetHttpOutcome(str, Enum):
    GATE_CLOSED = "gate_closed"
    DRIFT_REJECTED = "drift_rejected"
    POLICY_REJECTED = "policy_rejected"
    RECONCILIATION_REQUIRED = "reconciliation_required"
    BACKEND_CHANGED_METADATA_PRESERVED = "backend_changed_metadata_preserved"


@dataclass(frozen=True, slots=True)
class LocalUserResetHttpResult:
    outcome: LocalUserResetHttpOutcome
    backend_changed: bool = False
    metadata_preserved: bool = False
    change_post_attempted: bool = False
    login_verified: bool = False


@dataclass(frozen=True, slots=True, repr=False)
class LocalUserResetBaseline(C3MaterialBinding):
    """Inspector-owned complete non-material state, represented by its digest.

The protected inspector must hash every non-material field, not just the
eligibility fields below. It must exclude passwords/history before hashing and
bind this observation to the exact target and verified product version.
It must also verify actual protected durable create/lifecycle evidence before
returning its fixture_creation_digest; a namespace or caller-supplied digest is
not proof that this is a new disposable fixture. The two counts are fresh,
explicit service-reported observations, not a complete global relationship
scan, proof of no incoming references, or permission to delete the user.
"""

    username: str
    status: str
    is_local: bool
    access_profile: str
    sponsor_group: str
    schedule: str
    guest_auth: str
    nonmaterial_state_digest: str
    fixture_creation_digest: str
    reported_reference_count: int
    usage_entry_count: int
    product_version: str
    product_build: int


@dataclass(frozen=True, slots=True, repr=False)
class LocalUserResetBinding(C3MaterialBinding):
    """Private exact new-fixture binding; never constructed from MCP input."""

    expected: LocalUserResetBaseline

    def __post_init__(self) -> None:
        state = self.expected
        if (
            type(state) is not LocalUserResetBaseline
            or not isinstance(state.username, str) or len(state.username) > 64
            or _NAME.fullmatch(state.username) is None
            or state.status not in {"enable", "disable"} or state.is_local is not True
            or not isinstance(state.access_profile, str) or not state.access_profile
            or state.access_profile.casefold() == "super_admin"
            or state.sponsor_group != "" or state.schedule != ""
            or not isinstance(state.guest_auth, str) or state.guest_auth not in {"enable", "disable"}
            or not isinstance(state.nonmaterial_state_digest, str)
            or _DIGEST.fullmatch(state.nonmaterial_state_digest) is None
            or not isinstance(state.fixture_creation_digest, str)
            or _DIGEST.fullmatch(state.fixture_creation_digest) is None
            or type(state.reported_reference_count) is not int or state.reported_reference_count != 0
            or type(state.usage_entry_count) is not int or state.usage_entry_count != 0
            or state.product_version != "7.0.0"
            or type(state.product_build) is not int or state.product_build != 29
        ):
            raise LocalUserResetHttpTransportError(_UNAVAILABLE)


class LocalUserResetInspector(Protocol):
    """Return a fresh, complete, protected observation of this fixed target."""

    def read_nonmaterial_baseline(self) -> LocalUserResetBaseline: ...


class _Response(Protocol):
    status: int

    def getheader(self, name: str, default: str = "") -> str: ...
    def readinto(self, buffer: memoryview) -> int: ...
    def close(self) -> None: ...


class _Connection(Protocol):
    def request(self, method: str, url: str, body: memoryview, headers: dict[str, str]) -> None: ...
    def getresponse(self) -> _Response: ...
    def close(self) -> None: ...


class LocalUserResetOwnerSession(Protocol):
    """Future Owner wrapper must pin origin, session, binding and operation.

It must enforce verified TLS, fixed paths, CSRF and session identity itself;
there is deliberately no default factory or arbitrary request relay here.
"""

    def local_user_reset_connection(
        self, host: str, port: int, *, binding: LocalUserResetBinding, operation: _Operation,
        dispatch_guard: Callable[[], None] | None = None,
    ) -> _Connection: ...


class LocalUserResetMaterialLease(MaterialLease):
    """Private one-use transfer of writable old/new password buffers."""

    __slots__ = ("_loader", "_lock", "_consumed")

    def __init__(self, loader: Callable[[], tuple[memoryview, memoryview]]) -> None:
        if not callable(loader):
            raise LocalUserResetHttpTransportError(_UNAVAILABLE)
        self._loader, self._lock, self._consumed = loader, threading.Lock(), False

    def _consume(self) -> tuple[memoryview, memoryview]:
        with self._lock:
            if self._consumed:
                raise LocalUserResetHttpTransportError(_UNAVAILABLE)
            self._consumed = True
        loaded: object = None
        try:
            loaded = self._loader()
            if not isinstance(loaded, tuple) or len(loaded) != 2:
                raise ValueError
            old, new = loaded
            if (
                not _valid_password(old) or not _valid_password(new)
                or old.obj is new.obj or hmac.compare_digest(old, new)
            ):
                raise ValueError
            return old, new
        except Exception:
            if isinstance(loaded, tuple):
                for value in loaded:
                    if isinstance(value, memoryview):
                        try:
                            _dispose_password(value)
                        except Exception:
                            # One invalid view cannot prevent clearing its peer.
                            pass
            raise LocalUserResetHttpTransportError(_UNAVAILABLE) from None


class FortiPamLocalUserResetHttpTransport:
    """One fixed two-POST candidate; no selector/material parameters to reset()."""

    def __init__(
        self, config: SecretMetadataHttpTransportConfig, *, binding: LocalUserResetBinding,
        inspector: LocalUserResetInspector, owner_session: LocalUserResetOwnerSession,
        material_lease_provider: Callable[[], LocalUserResetMaterialLease], enabled: bool = False,
    ) -> None:
        try:
            if not isinstance(config, SecretMetadataHttpTransportConfig):
                raise ValueError
            parsed = urlsplit(config.base_url)
            port = 443 if parsed.port is None else parsed.port
            if (
                parsed.scheme != "https" or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
                or not 1 <= port <= 65535
                or type(binding) is not LocalUserResetBinding or type(enabled) is not bool
                or not callable(getattr(inspector, "read_nonmaterial_baseline", None))
                or not callable(getattr(owner_session, "local_user_reset_connection", None))
                or not callable(material_lease_provider)
            ):
                raise ValueError
        except Exception:
            raise LocalUserResetHttpTransportError(_UNAVAILABLE) from None
        self._host, self._port = parsed.hostname, port
        self._binding, self._inspector, self._owner = binding, inspector, owner_session
        self._material_provider = material_lease_provider
        self._enabled, self._consumed, self._lock = enabled, False, threading.Lock()

    def _unchanged(self) -> bool:
        current = self._inspector.read_nonmaterial_baseline()
        if type(current) is not LocalUserResetBaseline:
            return False
        try:
            # Dataclass equality alone would equate False/0 and 0.0/0.
            LocalUserResetBinding(current)
        except LocalUserResetHttpTransportError:
            return False
        return current == self._binding.expected

    def reset(self) -> LocalUserResetHttpResult:
        """Exercise the private adapter; this alone is not a live executor."""
        return self._reset_with_dispatch_guard(lambda: None)

    def _reset_with_dispatch_guard(self, guard: Callable[[], None]) -> LocalUserResetHttpResult:
        """Use a runner-owned freshness/binding check, never a caller payload."""
        # Real material can dispatch only through the exact API-actor runner
        # after its durable claim and one-time authenticated intent verification.
        # Direct reset() and arbitrary guards stay closed.
        from .local_user_reset_material_source import OwnerOnlyLocalUserResetMaterialSource
        if isinstance(self._material_provider, OwnerOnlyLocalUserResetMaterialSource):
            from .local_user_reset_api_actor import LocalUserResetApiActor
            from .local_user_reset_execution import (
                FortiPamLocalUserResetExecution, LocalUserResetLabIntentVerifier,
            )
            runner = getattr(guard, "__self__", None)
            verifier = getattr(runner, "_verifier", None)
            actor = self._owner
            if (
                type(runner) is not FortiPamLocalUserResetExecution
                or type(verifier) is not LocalUserResetLabIntentVerifier
                or type(actor) is not LocalUserResetApiActor
                or not getattr(runner, "_claim_active", False)
                or not getattr(verifier, "_verified", False)
                or getattr(runner, "_transport", None) is not self
                or getattr(runner, "_dispatch_callback", None) is not guard
                or getattr(actor, "_runtime_guard", None) is not guard
                or not callable(getattr(actor, "_active", None))
                or not actor._active(actor._generation)
            ):
                return LocalUserResetHttpResult(LocalUserResetHttpOutcome.GATE_CLOSED)
        with self._lock:
            if not self._enabled or self._consumed or not callable(guard):
                return LocalUserResetHttpResult(LocalUserResetHttpOutcome.GATE_CLOSED)
            # Consume this instance before reads/material/first POST. A failed
            # attempt must not be retried; this does not replace a durable claim.
            self._consumed = True
        old: memoryview | None = None
        new: memoryview | None = None
        attempted = changed = False
        try:
            guard()
            if not self._unchanged():
                return LocalUserResetHttpResult(LocalUserResetHttpOutcome.DRIFT_REJECTED)
            guard()
            lease = self._material_provider()
            if type(lease) is not LocalUserResetMaterialLease:
                raise ValueError
            guard()
            old, new = lease._consume()
            if not self._post("policy_conform", old, new, guard):
                return LocalUserResetHttpResult(LocalUserResetHttpOutcome.POLICY_REJECTED)
            if not self._unchanged():
                return LocalUserResetHttpResult(LocalUserResetHttpOutcome.DRIFT_REJECTED)
            attempted = True
            changed = self._post("change_password", old, new, guard)
            if changed and self._unchanged():
                return LocalUserResetHttpResult(
                    LocalUserResetHttpOutcome.BACKEND_CHANGED_METADATA_PRESERVED,
                    backend_changed=True, metadata_preserved=True, change_post_attempted=True,
                )
        except Exception:
            # No exception detail, chained exception, response, or selector escapes.
            pass
        finally:
            if old is not None:
                _dispose_password(old)
            if new is not None:
                _dispose_password(new)
        return LocalUserResetHttpResult(
            LocalUserResetHttpOutcome.RECONCILIATION_REQUIRED,
            backend_changed=changed, change_post_attempted=attempted,
        )

    def _post(
        self, operation: _Operation, old: memoryview, new: memoryview,
        guard: Callable[[], None],
    ) -> bool:
        body = bytearray()
        builder = _MutableJSONBuffer()
        content = bytearray(_MAX_RESPONSE + 1)
        connection: _Connection | None = None
        response: _Response | None = None
        body_view: memoryview | None = None
        try:
            if operation not in {"policy_conform", "change_password"}:
                raise ValueError
            builder.extend(b'{"mkey":')
            _append_text(builder, self._binding.expected.username)
            if operation == "policy_conform":
                builder.extend(b',"apply_to":')
                _append_text(builder, "guest-admin" if self._binding.expected.guest_auth == "enable" else "admin")
                builder.extend(b',"password":')
            else:
                builder.extend(b',"new_password":')
            _append_material(builder, new)
            # The selected-other-user dialog has no old-password input. Keep
            # the verified original material in the private lease, but send
            # the same empty old_password field as the build-29 frontend.
            builder.extend(b',"old_password":""')
            builder.append(125)
            body = builder.finish()
            guard()
            connection = self._owner.local_user_reset_connection(
                self._host, self._port, binding=self._binding, operation=operation,
                dispatch_guard=guard,
            )
            body_view = memoryview(body).toreadonly()
            # A slow connection factory must not send an expired intent.
            guard()
            connection.request("POST", _POLICY_PATH if operation == "policy_conform" else _CHANGE_PATH,
                body_view, {"Accept": "application/json", "Content-Type": "application/json",
                            "Content-Length": str(len(body)), "Connection": "close"})
            response = connection.getresponse()
            if type(response.status) is not int or response.status != 200:
                raise ValueError
            if response.getheader("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
                raise ValueError
            total = 0
            while total < len(content):
                view = memoryview(content)[total:]
                try:
                    count = response.readinto(view)
                finally:
                    view.release()
                if type(count) is not int or not 0 <= count <= len(content) - total:
                    raise ValueError
                if count == 0:
                    break
                total += count
            if total > _MAX_RESPONSE:
                raise ValueError
            content = _take_mutable_prefix(content, total)
            return _response_flag(content, operation)
        except Exception:
            raise LocalUserResetHttpTransportError(_UNAVAILABLE) from None
        finally:
            builder.close()
            if body_view is not None:
                body_view.release()
            _zeroize_mutable(body)
            _zeroize_mutable(content)
            for resource in (response, connection):
                if resource is not None:
                    try:
                        resource.close()
                    except Exception:
                        pass


def _valid_password(value: object) -> bool:
    return (
        isinstance(value, memoryview) and isinstance(value.obj, bytearray)
        and not value.readonly and value.ndim == 1 and value.c_contiguous
        and value.format == "B" and _valid_material_view(value)
    )


def _dispose_password(value: memoryview) -> None:
    # Clear the entire provider-owned backing buffer, including rejected slices.
    try:
        try:
            owner = value.obj
        except ValueError:
            # A released view exposes no backing object. Its provider retains
            # responsibility for that inaccessible buffer, never its peer's.
            return
        if isinstance(owner, bytearray):
            _zeroize_mutable(owner)
        else:
            with memoryview(owner) as whole:
                if not whole.readonly:
                    with whole.cast("B") as raw:
                        raw[:] = b"\x00" * raw.nbytes
    finally:
        try:
            value.release()
        except ValueError:
            pass


def _response_flag(content: bytearray, operation: _Operation) -> bool:
    """Decode only fixed boolean tokens; unknown/echo members fail closed.

No whole-body JSON decoder can create immutable copies of echoed material.
    The build-29 policy response uses a fixed metadata envelope and an optional
    non-material ``msg`` result. The change response remains candidate-only.
"""
    start = _skip_json_space(content, 0)
    end = _json_value_end(content, start)
    if _skip_json_space(content, end) != len(content):
        raise ValueError
    wrapper = _members(content, start, end, {
        b'"results"', b'"action"', b'"build"', b'"http_method"', b'"mkey"',
        b'"name"', b'"path"', b'"serial"', b'"status"', b'"vdom"', b'"version"',
    })
    if b'"results"' not in wrapper:
        raise ValueError
    if len(wrapper) > 1:
        required = {b'"build"': b"29", b'"http_method"': b'"POST"',
                    b'"status"': b'"success"', b'"version"': b'"v7.0.0"'}
        for key, expected in required.items():
            if key not in wrapper:
                raise ValueError
            left, right = wrapper[key]
            with memoryview(content)[left:right] as actual:
                if actual != expected:
                    raise ValueError
    result_start, result_end = wrapper[b'"results"']
    allowed = ({b'"valid"', b'"reused"', b'"msg"'} if operation == "policy_conform"
               else {b'"changed"', b'"msg"'})
    fields = _members(content, result_start, result_end, allowed)
    flags: dict[bytes, bool] = {}
    for key, (left, right) in fields.items():
        if key == b'"msg"':
            if right - left > 1024:
                raise ValueError
            with memoryview(content)[left:right] as message:
                is_null = len(message) == 4 and all(message[index] == byte
                    for index, byte in enumerate(b"null"))
                if not is_null and (not message or message[0] != 34
                    or _json_string_end(content, left) + 1 != right):
                    raise ValueError
            continue
        with memoryview(content)[left:right] as token:
            if hmac.compare_digest(token, b"true"):
                flags[key] = True
            elif hmac.compare_digest(token, b"false"):
                flags[key] = False
            else:
                raise ValueError
    return (flags[b'"valid"'] is True and flags.get(b'"reused"', False) is False
            if operation == "policy_conform" else flags[b'"changed"'] is True)


def _members(content: bytearray, start: int, end: int, allowed: set[bytes]) -> dict[bytes, tuple[int, int]]:
    if end <= start or content[start] != 123 or content[end - 1] != 125:
        raise ValueError
    cursor = _skip_json_space(content, start + 1)
    fields: dict[bytes, tuple[int, int]] = {}
    while cursor < end - 1:
        key_end = _json_string_end(content, cursor)
        with memoryview(content)[cursor:key_end + 1] as raw_key:
            key = next((candidate for candidate in allowed if raw_key == candidate), None)
        if key is None or key in fields:
            raise ValueError
        separator = _skip_json_space(content, key_end + 1)
        if separator >= end or content[separator] != 58:
            raise ValueError
        left = _skip_json_space(content, separator + 1)
        right = _json_value_end(content, left)
        if right >= end:
            raise ValueError
        fields[key] = left, right
        cursor = _skip_json_space(content, right)
        if cursor == end - 1:
            break
        if cursor >= end or content[cursor] != 44:
            raise ValueError
        cursor = _skip_json_space(content, cursor + 1)
        if cursor >= end - 1:
            raise ValueError
    return fields
