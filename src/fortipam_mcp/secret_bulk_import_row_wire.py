"""Inactive build-29 import wire encoder and fixed blank-default projection.

No product dispatcher, field-value readback, defaults selector or Tool exists.
An exact defaults snapshot is conversion data, not an actor/permission receipt.
The product adapter must freshly bind this digest and child ACKs before writing.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import hmac
import json
import math
import threading
from typing import Iterator, cast

from v4_planning.material_provider import _OpaqueC3Object

from . import secret_bulk_import_metadata as m
from .secret_bulk_import_dependencies import ImportRowDependency, ImportTemplate
from .secret_bulk_import_file import _wipe
from .secret_bulk_import_intake import BulkImportIntakeError, _ERROR
from .secret_bulk_import_row_adapter import _OriginalRowUseContext
from .secret_bulk_import_row_conversion import _Build29OriginalRowConversion
from .mutable_json_buffer import _MutableJSONBuffer
from .secret_create_191_http_transport import _append_text
from .secret_metadata_http_transport import (
    _SECRET_CREATE_191_REQUIRED_DEFAULTS, _skip_json_space, _json_value_end, _json_string_end,
)

# Exact top-level keys of the pinned module59089 unparse return object.
_WIRE_KEYS = (
    'folder', 'template', 'id', 'name', 'target',
    'target-privilege-account', 'server-info', 'associated-secret', 'auto-association', 'account-prefix',
    'launch-with', 'instruction-profile', 'description', 'field', 'proxy',
    'tunnel-encryption', 'block-clipboard', 'secret-auth', 'secret-auth-server', 'secret-auth-duration',
    'secret-auth-owner-exempt', 'av-scan', 'av-profile', 'dlp-status', 'dlp-sensor',
    'recording', 'cert-expiry-log', 'password-changer', 'credential-expire-notification', 'credential-expiry-after',
    'pwd-chg-use-policy-default', 'pwd-chg-sch-frequency', 'pwd-chg-sch-interval', 'pwd-chg-sch-month-type', 'pwd-chg-sch-month-day',
    'pwd-chg-sch-week-day', 'pwd-chg-sch-start-date', 'password-reconciliation', 'reconcile-secret-id', 'reconcile-method',
    'password-heartbeat', 'heartbeat-use-policy-default', 'heartbeat-interval', 'heartbeat-start-time', 'checkout',
    'checkin-pwd-change', 'checkout-duration-renew', 'checkout-renew-times', 'checkout-duration', 'force-checkout-idle-time',
    'checkin-script', 'checkout-script', 'need-approval', 'need-approval-job', 'bypass-approval',
    'approval-profile', 'totp-setting', 'ssh-service-status', 'ssh-service-port', 'ssh-filter',
    'ssh-filter-profile', 'ssh-algorithm', 'bypass-ssh-filter-for-owner', 'rsa-sign-algo', 'ssh-auto-password',
    'sudo-prompt', 'ssh-switch-account', 'rdp-service-status', 'rdp-service-port', 'rdp-security-level',
    'rdp-restricted-admin-mode', 'rdp-auto-totp', 'keyboard-layout', 'rdp-event-filter', 'rdp-event-filter-profile',
    'rdp-nla-kerberos', 'winappfilter', 'winappfilter-profile', 'rdp-remote-app', 'rdp-remote-app-profile',
    'rdp-remote-app-owner-exempt', 'rdp-tcp-forward', 'vnc-service-status', 'vnc-service-port', 'display-num',
    'samba-service-status', 'samba-service-port', 'sftp-service-status', 'sftp-service-port', 'telnet-service-status',
    'telnet-service-port', 'http-service-status', 'allow-viewer-launch-web', 'inherit-permission', 'user-permission',
    'group-permission', 'inherit-folder-ztna', 'ztna-tags-match-logic', 'ztna-ems-tag', 'address-blacklist',
    'address-whitelist', 'dependency',
)
_ARRAY_KEYS = frozenset({'field', 'user-permission', 'group-permission', 'ztna-ems-tag',
                        'address-blacklist', 'address-whitelist', 'dependency'})
_SCALAR_KEYS = frozenset(_WIRE_KEYS) - _ARRAY_KEYS - {'totp-setting'}
_TARGET_KINDS = frozenset({'target-address', 'domain', 'url', 'service-address'})
_TOTP = b'{"status":"disable","shared-key":"","generate-by":"manual","fortitoken-access-code":""}'
_READBACK_ARRAYS = _ARRAY_KEYS - {'field'}
_READBACK_FIELDS = (_SCALAR_KEYS - {'description'}) | _READBACK_ARRAYS
_DETAIL_SCALAR_DEFAULTS: dict[str, str | int] = {
    'account-prefix': '', 'cert-expiry-log': 'enable', 'launch-with': 'associate',
    'password-reconciliation': 'disable', 'reconcile-secret-id': 0,
    'reconcile-method': 'reconcile-after-fail', 'secret-auth-owner-exempt': 'disable',
    'secret-auth-server': '', 'ssh-auto-password': 'disable', 'sudo-prompt': '',
    'ssh-service-port': 0, 'rdp-service-port': 0, 'vnc-service-port': 0,
    'samba-service-port': 0, 'sftp-service-port': 0, 'telnet-service-port': 0,
}
_DETAIL_REQUIRED_FIELDS = _READBACK_FIELDS - frozenset(_DETAIL_SCALAR_DEFAULTS)
# Use the fixed native detail route and minimize by projecting owned bytes, not
# by trusting server-side format filtering (which native reads may ignore).
_READBACK_QUERY = 'vdom=root'


def _detail_spans(content: bytearray, span: tuple[int, int]) -> dict[str, tuple[int, int]]:
    """Accept only the observed identical native clipboard pair, never last-win.

    A build29 detail returned block-clipboard twice with identical literal enum
    tokens. Other selected duplicates, a third occurrence, conflicting values
    or an escaped duplicate key remain ambiguous and reject.
    """
    selected = m._object_spans(content, *span, (_READBACK_FIELDS | {'q_origin_key'}) - {'block-clipboard'})
    cursor = _skip_json_space(content, span[0] + 1)
    clipboard: list[tuple[tuple[int, int], tuple[int, int]]] = []
    while cursor < span[1] - 1:
        key_end = _json_string_end(content, cursor) + 1
        key = m._selected_key(content, cursor, key_end, frozenset({'block-clipboard'}))
        separator = _skip_json_space(content, key_end)
        left = _skip_json_space(content, separator + 1)
        right = _json_value_end(content, left)
        if key is not None:
            clipboard.append(((cursor, key_end), (left, right)))
            if len(clipboard) > 2:
                raise ValueError
        cursor = _skip_json_space(content, right)
        if cursor == span[1] - 1:
            break
        cursor = _skip_json_space(content, cursor + 1)
    if len(clipboard) == 2 and (
            not all(_matches_token(content, key, (b'"block-clipboard"',)) for key, _ in clipboard)
            or not any(all(_matches_token(content, value, (token,)) for _, value in clipboard)
                       for token in (b'"enable"', b'"disable"'))):
        raise ValueError
    if clipboard:
        selected['block-clipboard'] = clipboard[0][1]
    return selected


def _effective_detail_scalar(content: bytearray, selected: dict[str, tuple[int, int]], key: str) -> object:
    """Only16 observed omissions use pinned native parse/unparse fallbacks.

    This never supplies the expected request's value for a missing response key.
    A missing explicit port22 consequently resolves to0 and fails comparison.
    """
    if key in selected:
        return m._scalar(content, selected[key])
    return _DETAIL_SCALAR_DEFAULTS[key]


def _native_controls(defaults: _Build29SecretWireDefaults) -> dict[str, str | int]:
    values = dict(defaults.scalars)
    # Exact scalar fallbacks of module59089 parse -> unparse. Metadata-only
    # permission/timezone helpers are not implemented or qualified here.
    fallback: dict[str, str | int] = {
        'launch-with': 'associate', 'proxy': 'enable', 'block-clipboard': 'disable',
        'secret-auth-owner-exempt': 'disable', 'recording': 'disable', 'cert-expiry-log': 'enable',
        'password-reconciliation': 'disable', 'reconcile-secret-id': 0,
        'reconcile-method': 'reconcile-after-fail', 'rsa-sign-algo': 'ssh-rsa',
        'ssh-auto-password': 'disable', 'sudo-prompt': '', 'ssh-switch-account': 'enable',
        'ssh-algorithm': 'compatible', 'rdp-security-level': 'best-effort',
        'rdp-restricted-admin-mode': 'disable', 'rdp-auto-totp': 'disable', 'keyboard-layout': 'en-us',
        'rdp-remote-app-owner-exempt': 'disable', 'rdp-nla-kerberos': 'disable', 'rdp-tcp-forward': 'disable',
        'ztna-tags-match-logic': 'or', 'account-prefix': '', 'password-changer': 'disable',
        'password-heartbeat': 'disable', 'checkout': 'disable', 'checkin-pwd-change': 'disable',
        'checkout-duration-renew': 'disable',
    }
    for key, value in fallback.items():
        values[key] = values[key] or value
    for status, profile in (('av-scan', 'av-profile'), ('dlp-status', 'dlp-sensor'),
            ('ssh-filter', 'ssh-filter-profile'), ('rdp-event-filter', 'rdp-event-filter-profile'),
            ('winappfilter', 'winappfilter-profile'), ('rdp-remote-app', 'rdp-remote-app-profile')):
        if values[status] != 'enable':
            values[profile] = ''
        values[status] = 'enable' if values[profile] != '' else 'disable'
    values['bypass-approval'] = 'disable'
    return values


def _matches_token(content: bytearray, span: tuple[int, int], tokens: tuple[bytes, ...]) -> bool:
    start, end = span
    return any(end - start == len(token) and all(content[start + index] == value
               for index, value in enumerate(token)) for token in tokens)


@dataclass(frozen=True, slots=True, repr=False)
class _Build29SecretWireDefaults(_OpaqueC3Object):
    scalars: tuple[tuple[str, str | int], ...]
    serial_digest: str

    def __post_init__(self) -> None:
        if (type(self.scalars) is not tuple or len(self.scalars) != len(_SCALAR_KEYS)
                or type(self.serial_digest) is not str or m._DIGEST.fullmatch(self.serial_digest) is None):
            raise BulkImportIntakeError(_ERROR)
        names = set()
        for entry in self.scalars:
            if type(entry) is not tuple or len(entry) != 2:
                raise BulkImportIntakeError(_ERROR)
            name, value = entry
            if (type(name) is not str or name not in _SCALAR_KEYS or name in names
                    or type(value) not in {str, int}
                    or type(value) is str and (len(value.encode('utf-8')) > 4096 or '\x00' in value)
                    or type(value) is int and not 0 <= value <= 2**31 - 1):
                raise BulkImportIntakeError(_ERROR)
            names.add(name)
        controls = dict(self.scalars)
        for key, expected in {**_SECRET_CREATE_191_REQUIRED_DEFAULTS, 'id': 0, 'folder': 0,
                'name': '', 'template': '', 'target': '', 'description': '', 'associated-secret': 0,
                'auto-association': 'disable', 'inherit-permission': 'enable'}.items():
            if type(controls.get(key)) is not type(expected) or controls.get(key) != expected:
                raise BulkImportIntakeError(_ERROR)
        if controls['inherit-folder-ztna'] not in {'enable', 'disable'}:
            raise BulkImportIntakeError(_ERROR)

    def digest(self) -> str:
        self.__post_init__()
        raw = json.dumps([self.serial_digest, sorted(self.scalars)], separators=(',', ':'), allow_nan=False).encode()
        return hashlib.sha256(raw).hexdigest()


def _project_build29_secret_wire_defaults(content: bytearray, *, serial_digest: str) -> _Build29SecretWireDefaults:
    """Project one fixed default response; never decode default material leaves."""
    try:
        if (type(content) is not bytearray or not 0 < len(content) <= 1048576
                or type(serial_digest) is not str or m._DIGEST.fullmatch(serial_digest) is None):
            raise ValueError
        start = _skip_json_space(content, 0)
        end = _json_value_end(content, start)
        if _skip_json_space(content, end) != len(content):
            raise ValueError
        m._validate_json(content, start, end, depth=0, budget=[50000])
        envelope = m._object_spans(content, start, end, m._ENVELOPE_FIELDS)
        for key, expected in {'version': 'v7.0.0', 'build': 29, 'path': 'secret', 'name': 'database',
                             'http_method': 'GET', 'status': 'success', 'http_status': 200, 'vdom': 'root'}.items():
            value = m._scalar(content, envelope[key])
            if type(value) is not type(expected) or value != expected:
                raise ValueError
        serial = m._scalar(content, envelope['serial'])
        if type(serial) is not str or not hmac.compare_digest(hashlib.sha256(serial.encode()).hexdigest(), serial_digest):
            raise ValueError
        if 'error' in envelope:
            error = m._scalar(content, envelope['error'])
            if error is not None and (type(error) is not int or error != 0):
                raise ValueError
        span = envelope['results']
        if content[span[0]] == 91:
            records = m._array(content, span, 1)
            if len(records) != 1:
                raise ValueError
            span = records[0]
        selected = m._object_spans(content, *span, frozenset(_WIRE_KEYS))
        if set(selected) != set(_WIRE_KEYS):
            raise ValueError
        for key in _ARRAY_KEYS:
            if m._array(content, selected[key], 1):
                raise ValueError
        totp = m._object_spans(content, *selected['totp-setting'], frozenset({'status', 'shared-key', 'is-ftk', 'fortitoken-access-code'}))
        if (m._scalar(content, totp['status']) != 'disable'
                or not _matches_token(content, totp['shared-key'], (b'""',))
                or 'fortitoken-access-code' in totp and not _matches_token(content, totp['fortitoken-access-code'], (b'""',))
                or 'is-ftk' in totp and not _matches_token(content, totp['is-ftk'], (b'false', b'0', b'null'))):
            raise ValueError
        controls: list[tuple[str, str | int]] = []
        for key in _WIRE_KEYS:
            if key in _SCALAR_KEYS:
                scalar = m._scalar(content, selected[key])
                if type(scalar) not in {str, int}:
                    raise ValueError
                controls.append((key, cast(str | int, scalar)))
        return _Build29SecretWireDefaults(tuple(controls), serial_digest)
    except Exception:
        raise BulkImportIntakeError(_ERROR) from None
    finally:
        if type(content) is bytearray:
            _wipe(content)


def _compare_build29_detail(content: bytearray, *, metadata: tuple[tuple[str, str | int], ...],
                            serial_digest: str, expected_secret_id: int) -> bool:
    """Fixed C2 comparison shared with the isolated action worker; no authority."""
    try:
        if (type(expected_secret_id) is not int or not 0 < expected_secret_id <= 2**31 - 1
                or len(metadata) != len(_SCALAR_KEYS - {'description'})
                or {key for key, _ in metadata} != _SCALAR_KEYS - {'description'}):
            raise ValueError
        expected = dict(metadata)
        expected['id'] = expected_secret_id
        if type(content) is not bytearray or not 0 < len(content) <= 1048576:
            raise ValueError
        start = _skip_json_space(content, 0)
        end = _json_value_end(content, start)
        if _skip_json_space(content, end) != len(content):
            raise ValueError
        m._validate_json(content, start, end, depth=0, budget=[50000])
        envelope = m._object_spans(content, start, end, m._ENVELOPE_FIELDS | {'action'})
        for key, value in {'version': 'v7.0.0', 'build': 29, 'path': 'secret', 'name': 'database',
                          'http_method': 'GET', 'status': 'OK', 'http_status': 200, 'vdom': 'root'}.items():
            observed = m._scalar(content, envelope[key])
            if type(observed) is not type(value) or observed != value:
                raise ValueError
        serial = m._scalar(content, envelope['serial'])
        if (type(serial) is not str or not hmac.compare_digest(
                hashlib.sha256(serial.encode()).hexdigest(), serial_digest)):
            raise ValueError
        if 'action' in envelope and m._scalar(content, envelope['action']) != '':
            raise ValueError
        if 'error' in envelope:
            error = m._scalar(content, envelope['error'])
            if error is not None and (type(error) is not int or error != 0):
                raise ValueError
        span = envelope['results']
        if content[span[0]] == 91:
            records = m._array(content, span, 1)
            if len(records) != 1:
                raise ValueError
            span = records[0]
        selected = _detail_spans(content, span)
        if not _DETAIL_REQUIRED_FIELDS <= selected.keys():
            raise ValueError
        if 'q_origin_key' in selected:
            origin = m._scalar(content, selected['q_origin_key'])
            if type(origin) is not int or origin != expected_secret_id:
                raise ValueError
        for key in _READBACK_ARRAYS:
            if m._array(content, selected[key], 1):
                raise ValueError
        for key, value in expected.items():
            observed = _effective_detail_scalar(content, selected, key)
            if type(observed) is not type(value) or observed != value:
                raise ValueError
        return True
    except Exception:
        raise BulkImportIntakeError(_ERROR) from None
    finally:
        if type(content) is bytearray:
            _wipe(content)


def _original_product_metadata(defaults: _Build29SecretWireDefaults, dependency: ImportRowDependency,
                               template: ImportTemplate, *, target_name: str | None,
                               associated_secret_id: int | None) -> tuple[tuple[tuple[str, str | int], ...], tuple[str, ...]]:
    """Project fixed C2 after original graph validation; this grants no authority."""
    values = _native_controls(defaults)
    values.update(name=dependency.name, folder=dependency.folder_id,
        template=template.name, **{'inherit-permission': 'enable',
            'launch-with': 'associate' if associated_secret_id is not None else 'itself'})
    if target_name is not None:
        values['target'] = target_name
    if associated_secret_id is not None:
        values['associated-secret'] = associated_secret_id
    for service, port in dependency.services:
        values[f'{service}-service-status'] = 'up'
        if port is not None:
            values[f'{service}-service-port'] = port
    names = tuple(sorted((field.name for field in template.fields
        if target_name is None or field.kind not in _TARGET_KINDS),
        key=lambda name: name.encode('utf-16-be')))
    metadata = tuple((key, values[key]) for key in _WIRE_KEYS if key in _SCALAR_KEYS - {'description'})
    return metadata, names

class _Build29OriginalRowWireEncoder(_OpaqueC3Object):
    """One exact converted row, prebound native defaults and owned wire bytes."""

    def __init__(self, converter: _Build29OriginalRowConversion, defaults: _Build29SecretWireDefaults,
                 *, expected_defaults_digest: str, expected_serial_digest: str) -> None:
        if (type(converter) is not _Build29OriginalRowConversion or type(defaults) is not _Build29SecretWireDefaults
                or defaults.digest() != expected_defaults_digest or defaults.serial_digest != expected_serial_digest):
            raise BulkImportIntakeError(_ERROR)
        self._converter, self._defaults, self._digest = converter, defaults, expected_defaults_digest
        self._active_metadata: tuple[tuple[str, str | int], ...] | None = None
        self._active_deadline: float | None = None
        self._active_thread: int | None = None
        self._readback_used = False

    def _product_metadata(self) -> tuple[tuple[tuple[str, str | int], ...], tuple[str, ...]]:
        """Compile fixed C2 expectations from the original graph, without C3.

        The caller still needs original dispatch ownership and an independently
        authorized product workload. This projection grants neither.
        """
        converter = self._converter
        converter._verify_graph()
        if self._defaults.digest() != self._digest:
            raise BulkImportIntakeError(_ERROR)
        return _original_product_metadata(self._defaults, converter._dependency, converter._template,
            target_name=converter._target, associated_secret_id=converter._associated)

    def _inspect_detail_once(self, context: _OriginalRowUseContext, content: bytearray,
                             *, expected_secret_id: int, deadline: float) -> bool:
        """Compare only99 fixed C2 fields during this original wire handoff.

        The supplied ID is ACK data, not verified original-child ownership. This
        comparison proves no field material, description or TOTP postcondition
        and cannot turn an HTTP acknowledgement into VERIFIED_CREATED.
        """
        try:
            if (type(context) is not _OriginalRowUseContext or context != self._converter._context
                    or self._active_metadata is None or self._active_deadline is None
                    or self._active_thread != threading.get_ident() or self._readback_used
                    or type(expected_secret_id) is not int or not 0 < expected_secret_id <= 2**31 - 1
                    or type(deadline) not in {int, float} or not math.isfinite(deadline)
                    or deadline > self._active_deadline):
                raise ValueError
            self._converter._check(deadline)
            self._readback_used = True
            _compare_build29_detail(content, metadata=self._active_metadata,
                serial_digest=self._defaults.serial_digest, expected_secret_id=expected_secret_id)
            self._converter._check(deadline)
            return True
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None
        finally:
            if type(content) is bytearray:
                _wipe(content)

    @contextmanager
    def _serialize_once(self, context: _OriginalRowUseContext, columns: tuple[memoryview, ...],
                        *, deadline: float) -> Iterator[memoryview]:
        body = bytearray()
        builder = _MutableJSONBuffer()
        try:
            if self._defaults.digest() != self._digest:
                raise ValueError
            with self._converter._convert_once(context, columns, deadline=deadline) as dto:
                raw = dto.obj
                if type(raw) is not bytearray:
                    raise ValueError
                selected = m._object_spans(raw, 0, len(raw), frozenset(_WIRE_KEYS))
                fields = m._array(raw, selected['field'], 64)
                ordered = []
                for span in fields:
                    field = m._object_spans(raw, *span, frozenset({'name', 'type', 'value'}))
                    name, kind = m._scalar(raw, field['name']), m._scalar(raw, field['type'])
                    if type(name) is not str or type(kind) is not str:
                        raise ValueError
                    if self._converter._target is None or kind not in _TARGET_KINDS:
                        ordered.append((name.encode('utf-16-be'), field))
                ordered.sort(key=lambda pair: pair[0])
                defaults = _native_controls(self._defaults)
                builder.append(123)
                for index, key in enumerate(_WIRE_KEYS):
                    self._converter._check(deadline)
                    if index:
                        builder.append(44)
                    _append_text(builder, key)
                    builder.append(58)
                    if key == 'field':
                        builder.append(91)
                        for position, (_, field) in enumerate(ordered):
                            if position:
                                builder.append(44)
                            builder.extend(b'{"name":')
                            builder.extend(dto[slice(*field['name'])])
                            builder.extend(b',"value":')
                            builder.extend(dto[slice(*field['value'])])
                            builder.append(125)
                        builder.append(93)
                    elif key in selected:
                        builder.extend(dto[slice(*selected[key])])
                    elif key == 'totp-setting':
                        builder.extend(_TOTP)
                    elif key in _ARRAY_KEYS:
                        builder.extend(b'[]')
                    else:
                        builder.extend(json.dumps(defaults[key], ensure_ascii=False, separators=(',', ':')).encode())
                builder.append(125)
                body = builder.finish()
                self._converter._check(deadline)
                self._converter._bridge._verify()
                spans = m._object_spans(body, 0, len(body), _READBACK_FIELDS)
                self._active_metadata = tuple((key, cast(str | int, m._scalar(body, spans[key])))
                    for key in _WIRE_KEYS if key in _SCALAR_KEYS and key != 'description')
                if self._active_metadata != self._product_metadata()[0]:
                    raise ValueError
                self._active_deadline, self._active_thread = deadline, threading.get_ident()
                with self._converter._borrow_body(body, deadline) as view:
                    yield view
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None
        finally:
            builder.close()
            self._active_metadata = self._active_deadline = self._active_thread = None
            _wipe(body)
