"""Minimize provided fweb_build JSON to compiled VM status integer symbols.

The retained build29 loader merges this static JSON at root and consumers use
BUILD.SYMBOLS. Unknown fields/values are byte-validated without string decoding
or hashing. Value-free JSON kinds diagnose unclassified selected symbols;
they do not extend the local integer profile or qualify a native schema.
"""
from __future__ import annotations

from collections.abc import Iterator
from itertools import zip_longest
import zlib

from . import secret_bulk_import_metadata as metadata
from .approval_delivery_schema import _integer
from .license_vm_projection import MAIN_SHA256, CHUNK_SHA256
from .mutable_json_buffer import _erase_transfer_storage
from .secret_metadata_http_transport import _json_string_end, _json_value_end, _skip_json_space

CONTRACT = "fortipam-build29-license-status-static-symbols-local/v1"
BUILD_PATH = "/api/v2/static/fweb_build.json"
MAX_BYTES = 1024 * 1024
_ERROR = "The private license status symbols are unavailable."
_NAMES = (
    "LICENSE_STATUS_NO_LICENSE", "LICENSE_STATUS_PENDING", "LICENSE_STATUS_UNAVAILABLE",
    "LICENSE_STATUS_VM_VALID", "LICENSE_STATUS_VM_EXPIRED", "LICENSE_STATUS_VM_INVALID",
    "LICENSE_STATUS_VM_EVAL", "LICENSE_STATUS_VM_EVAL_EXPIRED", "LICENSE_STATUS_VM_EXPIRES_SOON",
    "LICENSE_STATUS_VM_PENDING", "LICENSE_STATUS_VM_VALIDATION_OVERDUE",
)
_VALUE_KINDS = {34: "string", 123: "object", 91: "array", 110: "null", 116: "boolean", 102: "boolean"}


def _validate_container(raw: bytearray, span: tuple[int, int], budget: list[int], *,
        skip: tuple[int, int] | None = None) -> int:
    """Validate the two wide static maps; nested unknown values keep old bounds.

    BUILD.SYMBOLS is not a CMDB row. Only these fixed root/maps may have up to
    8192 entries; existing byte validation retains its normal nested limits.
    """
    start, end = span
    if raw[start] != 123 or raw[end - 1] != 125:
        raise ValueError
    budget[0] -= 1
    if budget[0] < 0:
        raise ValueError
    cursor, count = _skip_json_space(raw, start + 1), 0
    while cursor < end - 1:
        count += 1
        if count > 8192:
            raise ValueError
        key_end = _json_string_end(raw, cursor) + 1
        metadata._validate_json(raw, cursor, key_end, depth=1, budget=budget)
        colon = _skip_json_space(raw, key_end)
        if raw[colon] != 58:
            raise ValueError
        left = _skip_json_space(raw, colon + 1)
        right = _json_value_end(raw, left)
        if (left, right) != skip:
            metadata._validate_json(raw, left, right, depth=1, budget=budget)
        cursor = _skip_json_space(raw, right)
        if cursor == end - 1:
            break
        if raw[cursor] != 44:
            raise ValueError
        cursor = _skip_json_space(raw, cursor + 1)
        if cursor >= end - 1:
            raise ValueError
    return count


def consume_license_status_symbols(raw: bytearray) -> dict[str, object]:
    """Consume/wipe a provided static map; only selected integers may escape."""
    try:
        fields, count = _provided_fields(raw)
        values: dict[str, int | None] = {}
        kinds: dict[str, str] = {}
        kind_counts: dict[str, int] = {}
        for name in _NAMES:
            if name not in fields:
                continue
            left, right = fields[name]
            # The entire value has already passed byte-level JSON validation.
            # Only its fixed JSON kind escapes; strings are never decoded.
            kind = _VALUE_KINDS.get(raw[left], "number")
            kinds[name] = kind
            kind_counts[kind] = kind_counts.get(kind, 0) + 1
            try:
                values[name] = _integer(raw, (left, right))
            except ValueError:
                # A non-integer/oversized symbol may be a different native type;
                # never decode or hash it, coerce it or invent an enum value.
                values[name] = None
        classified = sum(value is not None for value in values.values())
        return dict(contract=CONTRACT, source_path=BUILD_PATH, main_sha256=MAIN_SHA256, chunk_sha256=CHUNK_SHA256,
            selected_symbol_count=len(values), classified_integer_count=classified,
            unclassified_selected_count=len(values) - classified, unselected_symbol_count=count - len(values),
            symbols=values, complete_selected_integer_table=classified == len(_NAMES),
            selected_value_kinds=kinds, selected_value_kind_counts=kind_counts, value_kind_diagnostics_only=True,
            local_integer_profile_only=True, unselected_values_decoded_or_hashed=False,
            native_source_build_verified=False, native_status_mapping_qualified=False,
            current_license_read=False, installation_authorized=False, configuration_written=False, device_contacted=False)
    except Exception:
        raise ValueError(_ERROR) from None
    finally:
        if type(raw) is bytearray:
            _erase_transfer_storage(raw)


def _provided_fields(raw: bytearray) -> tuple[dict[str, tuple[int, int]], int]:
    if type(raw) is not bytearray or not 0 < len(raw) <= MAX_BYTES: raise ValueError
    start = _skip_json_space(raw, 0); end = _json_value_end(raw, start)
    if _skip_json_space(raw, end) != len(raw): raise ValueError
    root = metadata._object_spans(raw, start, end, frozenset({"SYMBOLS"}))
    symbols = root["SYMBOLS"]
    budget = [50000]
    _validate_container(raw, (start, end), budget, skip=symbols)
    count = _validate_container(raw, symbols, budget)
    return metadata._object_spans(raw, *symbols, frozenset(_NAMES)), count


def _string_octets(raw: bytearray, span: tuple[int, int]) -> Iterator[int]:
    """Compare validated JSON strings without text, byte copies or hashes.

    Escape/surrogate handling follows the existing private Terraform string
    comparer; emit integer UTF-8 octets instead of material fingerprints.
    """
    left, right = span
    if raw[left] != 34 or raw[right - 1] != 34: raise ValueError
    cursor = left + 1
    escapes = {34: 34, 92: 92, 47: 47, 98: 8, 102: 12, 110: 10, 114: 13, 116: 9}
    def codepoint(at: int) -> int:
        value = 0
        for index in range(at, at + 4):
            byte = raw[index]
            value = value * 16 + (byte - 48 if byte <= 57 else byte - 87 if byte >= 97 else byte - 55)
        return value
    while cursor < right - 1:
        value = raw[cursor]; cursor += 1
        if value != 92:
            yield value
            continue
        escape = raw[cursor]; cursor += 1
        if escape != 117:
            yield escapes[escape]
            continue
        value = codepoint(cursor); cursor += 4
        if 0xD800 <= value <= 0xDBFF:
            if cursor + 6 > right - 1 or raw[cursor] != 92 or raw[cursor + 1] != 117: raise ValueError
            low = codepoint(cursor + 2)
            if not 0xDC00 <= low <= 0xDFFF: raise ValueError
            value = 0x10000 + ((value - 0xD800) << 10) + low - 0xDC00
            cursor += 6
        elif 0xDC00 <= value <= 0xDFFF:
            raise ValueError
        if value < 0x80:
            yield value
        elif value < 0x800:
            yield 0xC0 | value >> 6; yield 0x80 | value & 63
        elif value < 0x10000:
            yield 0xE0 | value >> 12; yield 0x80 | value >> 6 & 63; yield 0x80 | value & 63
        else:
            yield 0xF0 | value >> 18; yield 0x80 | value >> 12 & 63
            yield 0x80 | value >> 6 & 63; yield 0x80 | value & 63


def _match_provided_status(raw: bytearray, span: tuple[int, int] | None,
        symbols: bytearray) -> tuple[str, ...] | None:
    fields, _ = _provided_fields(symbols)
    if len(fields) != len(_NAMES): raise ValueError
    for selected in fields.values():
        # Fully consume even unmatched strings to reject unpaired surrogates.
        for _ in _string_octets(symbols, selected): pass
    if span is None or raw[span[0]] != 34: return None
    matches = []
    for name in _NAMES:
        difference = 0
        for left, right in zip_longest(_string_octets(raw, span), _string_octets(symbols, fields[name]), fillvalue=-1):
            difference |= left ^ right
        if difference == 0: matches.append(name)
    return tuple(matches)


def _decode_static_symbols(raw: bytearray, encoding: str) -> bytearray:
    """Use the accepted bounded static-source gzip/deflate algorithm."""
    if encoding in ('', 'identity'): return raw
    if encoding == 'gzip': decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    elif encoding == 'deflate': decoder = zlib.decompressobj()
    else: raise ValueError
    decoded = bytearray()
    try:
        decoded.extend(decoder.decompress(raw, MAX_BYTES + 1))
        if len(decoded) > MAX_BYTES or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail: raise ValueError
        return decoded
    except BaseException:
        _erase_transfer_storage(decoded)
        raise
