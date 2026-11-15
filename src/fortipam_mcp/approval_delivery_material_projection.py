"""Private supplied-frame projection and one compilation, with no source IO.

Wire strings stay protected even when empty or masked. Re-emitting their decoded
UTF-8 bytes proves JSON-value continuity only, not backend material preservation,
source provenance, lease enforcement, full singleton custody or recovery rights.
"""
from __future__ import annotations

from collections.abc import Mapping
from contextlib import ExitStack
from threading import RLock
from typing import Any

from v4_planning.material_provider import _OpaqueC3Object

from . import approval_delivery_contract as request
from . import secret_bulk_import_metadata as metadata
from .approval_delivery_material_contract import (
    ApprovalDeliveryMaterialDraft, _LOCAL_MATERIAL_BYTES, _ROLES, _bindings,
    build_approval_delivery_material_body, prepare_material_approval_delivery,
)
from .approval_delivery_projection import _selected_current_fields
from .approval_delivery_schema import _integer
from .mutable_json_buffer import _MutableJSONBuffer
from .secret_metadata_http_transport import _zeroize_mutable

CONTRACT = "fortipam-build29-approval-email-material-projection-local/v1"
_ERROR = "The private approval-delivery material projection is unavailable."
_ESCAPES = {34: 34, 92: 92, 47: 47, 98: 8, 102: 12, 110: 10, 114: 13, 116: 9}


def _erase_owned(buffer: bytearray) -> None:
    try:
        _zeroize_mutable(buffer)
    except BaseException as error:
        # Do not require a second same-sized allocation after a failed wipe.
        for index in range(len(buffer)):
            buffer[index] = 0
        if isinstance(error, Exception):
            raise ValueError(_ERROR) from None
        raise


def _clear_buffers(buffers: Mapping[str, bytearray]) -> None:
    failure: BaseException | None = None
    for role in _ROLES:
        if role not in buffers:
            continue
        try:
            _erase_owned(buffers[role])
        except BaseException as error:
            if failure is None:
                failure = error
    if failure is not None:
        raise failure


def _hex4(token: memoryview, at: int) -> int:
    value = 0
    for index in range(at, at + 4):
        digit = token[index]
        value = value * 16 + (digit - 48 if digit <= 57 else digit - 87 if digit >= 97 else digit - 55)
    return value


def _decode_material(token: memoryview) -> bytearray:
    """Unescape one validated JSON string into owned mutable UTF-8 only."""
    metadata._validate_string(token)
    with _MutableJSONBuffer() as decoded:
        cursor, count = 1, 0
        while cursor < len(token) - 1:
            byte = token[cursor]
            cursor += 1
            if byte != 92:
                decoded.append(byte)
                count += 1
            else:
                escape = token[cursor]
                cursor += 1
                if escape != 117:
                    decoded.append(_ESCAPES[escape])
                    count += 1
                else:
                    code = _hex4(token, cursor)
                    cursor += 4
                    if 0xD800 <= code <= 0xDBFF:
                        if (cursor + 6 > len(token) - 1 or token[cursor] != 92 or token[cursor + 1] != 117):
                            raise ValueError
                        low = _hex4(token, cursor + 2)
                        if not 0xDC00 <= low <= 0xDFFF:
                            raise ValueError
                        code = 0x10000 + ((code - 0xD800) << 10) + low - 0xDC00
                        cursor += 6
                    elif 0xDC00 <= code <= 0xDFFF:
                        raise ValueError
                    if code < 0x80:
                        decoded.append(code); width = 1
                    elif code < 0x800:
                        decoded.append(0xC0 | code >> 6)
                        decoded.append(0x80 | code & 63); width = 2
                    elif code < 0x10000:
                        decoded.append(0xE0 | code >> 12)
                        decoded.append(0x80 | code >> 6 & 63)
                        decoded.append(0x80 | code & 63); width = 3
                    else:
                        decoded.append(0xF0 | code >> 18)
                        decoded.append(0x80 | code >> 12 & 63)
                        decoded.append(0x80 | code >> 6 & 63)
                        decoded.append(0x80 | code & 63); width = 4
                    count += width
            if count > _LOCAL_MATERIAL_BYTES:
                raise ValueError
        return decoded.finish()


class ApprovalDeliveryMaterialProjection(_OpaqueC3Object):
    """Own three bounded buffers until close or one private compilation.

    This physical lifetime is data disposal, not a provider lease or operation
    replay ledger. No material getter, resolver, transport or MCP method exists.
    """
    __slots__ = ("_values", "_bindings", "_buffers", "_used", "_closed", "_lock")
    _values: tuple[tuple[str, Any], ...]
    _bindings: tuple[str, ...]
    _buffers: dict[str, bytearray]
    _used: bool
    _closed: bool
    _lock: RLock

    def __new__(cls, *args: object, **kwargs: object) -> ApprovalDeliveryMaterialProjection:
        del args, kwargs
        raise ValueError(_ERROR)

    def __enter__(self) -> ApprovalDeliveryMaterialProjection:
        if self._closed:
            raise ValueError(_ERROR)
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _prepare_request(self, values: Mapping[str, Any], *, enabled: bool) -> ApprovalDeliveryMaterialDraft:
        with self._lock:
            if self._closed or self._used:
                raise ValueError(_ERROR)
            return prepare_material_approval_delivery(values, enabled=enabled,
                material_binding_digests=dict(zip(_ROLES, self._bindings, strict=True)))

    def _compile_once(self, draft: ApprovalDeliveryMaterialDraft) -> bytearray:
        with self._lock:
            body = bytearray()
            try:
                try:
                    if self._closed or self._used:
                        raise ValueError
                    self._used = True
                    with ExitStack() as stack:
                        views = {role: stack.enter_context(memoryview(self._buffers[role]).toreadonly()) for role in _ROLES}
                        body = build_approval_delivery_material_body(draft,
                            username=views["username"], credential=views["credential"], client_secret=views["client-secret"],
                            material_binding_digests=dict(zip(_ROLES, self._bindings, strict=True)))
                    if self._closed:
                        raise ValueError
                finally:
                    self.close()
            except BaseException as error:
                _erase_owned(body)
                if isinstance(error, Exception):
                    raise ValueError(_ERROR) from None
                raise
            return body

    def close(self) -> None:
        with self._lock:
            self._closed = True
            _clear_buffers(self._buffers)

    def summary(self) -> dict[str, object]:
        values = dict(self._values)
        protocol = values["approval-email-protocol"]
        enabled = bool(values["server"]) if protocol == "ms-graph" else bool(values["server"] or values["email-pulling-server"])
        return dict(contract=CONTRACT, protocol=protocol, ui_enabled_inference=enabled,
            model_field_count=14, protected_slot_count=3, closed=self._closed,
            material_values_decoded_to_strings_or_hashed=False,
            native_current_response_contract_qualified=False, backend_masking_or_material_preservation_qualified=False,
            material_binding_is_provenance=False, provider_lease_or_operation_replay_protection=False,
            whole_setting_baseline_verified=False, partial_put_merge_qualified=False,
            restore_authorized=False, execution_authorized=False, device_contacted=False)


def project_material_approval_delivery(raw: bytearray, *, expected_serial: str,
        material_binding_digests: Mapping[str, str]) -> ApprovalDeliveryMaterialProjection:
    """Consume one supplied frame, clear input, retain only three private buffers.

    Bindings are caller-provided private facts. No actual source, HTTP metadata,
    authentication continuity, effective permission or backend semantics is
    attested by this parser. Unrelated values are never decoded or hashed.
    """
    buffers: dict[str, bytearray] = {}
    published = input_cleared = False
    try:
        # Allocate the three dictionary entries before any C3 result transfers.
        buffers = {role: bytearray() for role in _ROLES}
        bindings = _bindings(material_binding_digests)
        selected = _selected_current_fields(raw, expected_serial=expected_serial)
        # Classify all protected values before decoding any nonmaterial scalar.
        for role in _ROLES:
            with memoryview(raw)[slice(*selected[role])] as token:
                metadata._validate_string(token)
        for role in _ROLES:
            with memoryview(raw)[slice(*selected[role])] as token:
                buffers[role] = _decode_material(token)
        values: dict[str, Any] = {}
        for key in request._FIELDS:
            if key in request._MATERIAL:
                continue
            span = selected[key]
            if key in ("port", "check-interval"):
                values[key] = _integer(raw, span)
            else:
                if raw[span[0]] != 34:
                    raise ValueError
                values[key] = metadata._scalar(raw, span)
        checked = request._checked_nonmaterial(values)
        result = object.__new__(ApprovalDeliveryMaterialProjection)
        result._values, result._bindings = tuple(checked.items()), bindings
        result._buffers, result._used, result._closed = buffers, False, False
        result._lock = RLock()
        _erase_owned(raw)
        input_cleared = True
        published = True
        return result
    except Exception:
        raise ValueError(_ERROR) from None
    finally:
        try:
            if not input_cleared and type(raw) is bytearray:
                _erase_owned(raw)
        finally:
            if not published:
                _clear_buffers(buffers)
