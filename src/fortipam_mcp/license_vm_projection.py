"""Byte-only minimization of a provided build29 license-status frame.

Only the VM scalars consumed by the retained frontend are classified. Status
symbols, deployment/HA, entitlement and the complete native schema are unknown.
This module performs no GET, polling, FortiGuard update or license operation.
An optional in-memory string-symbol comparison remains partial and unqualified.
"""
from __future__ import annotations

from dataclasses import dataclass
import hmac
import json

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object

from . import secret_bulk_import_metadata as metadata
from .approval_delivery_schema import _members, _known, _integer
from .mutable_json_buffer import _clear_mutable_group, _erase_transfer_storage
from .secret_metadata_http_transport import _json_value_end, _skip_json_space

CONTRACT = "fortipam-build29-license-vm-provided-frame-local/v1"
STATUS_PATH = "/api/v2/monitor/license/status"
MAIN_SHA256 = "0c2bf35bb5cde1a5154012d6bf2f529d8d59e782a35aebe0bd29976ca9da434f"
CHUNK_SHA256 = "841c2d7595337b59a665f6cd011590160fdc74488e4f4bdc26d2a2f478a9c4ae"
_ERROR = "The private license VM projection is unavailable."
MAX_BYTES = 1024 * 1024
_FIELDS = ("valid", "expires", "cpu_used", "cpu_max", "mem_used", "mem_max",
    "vmx_instance_used", "vmx_instance_max", "enabled_users", "licensed_users")
_EXPECTED = dict(version=b'"v7.0.0"', build=b'29', http_method=b'"GET"', http_status=b'200',
    path=b'"license"', name=b'"status"')


@dataclass(frozen=True, slots=True, repr=False, init=False)
class LicenseVmProjection(_OpaqueC3Object):
    _shape: str
    _serial_digest: str
    _values: tuple[tuple[str, bool | int | None], ...]
    _status_present: bool
    _unselected_fields: int
    _symbol_matches: tuple[str, ...] | None
    _static_symbols_provided: bool

    def __init__(self) -> None:
        raise ValueError(_ERROR)

    @property
    def digest(self) -> str:
        # Only classified scalars enter this PARTIAL digest. Unknown status,
        # license material, identities and unrelated subtrees are never hashed.
        values = {name: str(value) if type(value) is int else value for name, value in self._values}
        content = dict(contract=CONTRACT, main=MAIN_SHA256, chunk=CHUNK_SHA256,
            serial=self._serial_digest, shape=self._shape, values=values, status_present=self._status_present)
        if self._static_symbols_provided:
            content['provided_symbol_matches'] = self._symbol_matches
        return canonical_digest(content)

    def summary(self) -> dict[str, object]:
        public: dict[str, object] = dict(contract=CONTRACT, vm_node_shape=self._shape,
            classified_field_count=len(self._values), nullable_field_count=sum(value is None for _, value in self._values),
            unselected_vm_field_count=self._unselected_fields, status_field_present=self._status_present,
            status_enum_classified=False, private_values_returned=False, complete_vm_schema_verified=False,
            deployment_or_ha_verified=False, entitlement_verified=False, native_response_contract_verified=False,
            authoritative_current_state_observed=False, post_boot_license_verified=False,
            installation_authorized=False, device_contacted=False)
        if self._static_symbols_provided:
            public.update(status_enum_classified=self._symbol_matches is not None and len(self._symbol_matches) == 1,
                static_symbol_table_provided=True, status_string_compared=self._symbol_matches is not None,
                status_symbol_matches=list(self._symbol_matches or ()),
                status_symbol_ambiguous=self._symbol_matches is not None and len(self._symbol_matches) > 1,
                native_status_mapping_qualified=False)
        return public


def project_provided_license_vm(raw: bytearray, *, expected_serial: str,
        static_symbols: bytearray | None = None) -> LicenseVmProjection:
    """Consume and wipe one caller-owned mutable frame, including interruptions.

    This is a strict local scalar profile, not an upstream schema/type claim.
    Missing/null VM nodes do not identify a physical appliance. Nullable scalar
    presence is preserved; no default/zero/boolean coercion supplies readiness.
    """
    try:
        if (type(raw) is not bytearray or not 0 < len(raw) <= MAX_BYTES
                or type(expected_serial) is not str or not 0 < len(expected_serial) <= 128
                or static_symbols is not None and (type(static_symbols) is not bytearray or static_symbols is raw)): raise ValueError
        start = _skip_json_space(raw, 0); end = _json_value_end(raw, start)
        if _skip_json_space(raw, end) != len(raw): raise ValueError
        metadata._validate_json(raw, start, end, depth=0, budget=[50000])
        root, _ = _members(raw, (start, end), frozenset(_EXPECTED) | {"serial", "status", "results", "error", "action"})
        for name, expected in {**_EXPECTED, "serial": json.dumps(expected_serial, ensure_ascii=True).encode("ascii")}.items():
            with memoryview(raw)[slice(*root[name])] as token:
                if not hmac.compare_digest(token, expected): raise ValueError
        if _known(raw, root["status"], ("success", "OK")) is None: raise ValueError
        for name, literals in (("error", (b"0", b"null")), ("action", (b'""',))):
            if name in root:
                with memoryview(raw)[slice(*root[name])] as token:
                    if not any(hmac.compare_digest(token, literal) for literal in literals): raise ValueError
        results, _ = _members(raw, root["results"], frozenset({"vm"}))
        shape, status_present, unselected = "absent", False, 0
        status_span: tuple[int, int] | None = None
        values: list[tuple[str, bool | int | None]] = []
        if "vm" in results:
            left, right = results["vm"]
            with memoryview(raw)[left:right] as token: is_null = hmac.compare_digest(token, b"null")
            shape = "null" if is_null else "object"
            if not is_null:
                selected, count = _members(raw, (left, right), frozenset(_FIELDS) | {"status"})
                status_present, unselected = "status" in selected, count-len(selected)
                status_span = selected.get('status')
                for name in _FIELDS:
                    if name not in selected: continue
                    span = selected[name]
                    with memoryview(raw)[slice(*span)] as token:
                        if hmac.compare_digest(token, b"null"): value: bool | int | None = None
                        elif name == "valid":
                            if hmac.compare_digest(token, b"true"): value = True
                            elif hmac.compare_digest(token, b"false"): value = False
                            else: raise ValueError
                        else:
                            value = _integer(raw, span)
                            if value < 0: raise ValueError
                    values.append((name, value))
        matches = None
        if static_symbols is not None:
            from .license_status_symbols import _match_provided_status
            matches = _match_provided_status(raw, status_span, static_symbols)
        projection = object.__new__(LicenseVmProjection)
        attributes = dict(_shape=shape, _serial_digest=canonical_digest(dict(serial=expected_serial)),
            _values=tuple(values), _status_present=status_present, _unselected_fields=unselected,
            _symbol_matches=matches, _static_symbols_provided=static_symbols is not None)
        for name, attribute in attributes.items(): object.__setattr__(projection, name, attribute)
        return projection
    except Exception: raise ValueError(_ERROR) from None
    finally:
        _clear_mutable_group((raw, static_symbols), _erase_transfer_storage)


def license_vm_projection_boundary() -> dict[str, object]:
    return dict(contract=CONTRACT, method="GET", path=STATUS_PATH, source_kind="retained_build29_frontend_consumption",
        main_sha256=MAIN_SHA256, chunk_sha256=CHUNK_SHA256, classified_fields=list(_FIELDS),
        build_status_symbols_retained=False, polling_helper_can_trigger_fortiguard_update=True,
        frontend_polling_helper_invoked=False, native_schema_qualified=False,
        private_status_values_decoded_or_hashed=False, http_transport_registered=False,
        execution_authorized=False, device_contacted=False)
