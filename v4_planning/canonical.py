"""Canonical value handling for the repository-only V4 planning model.

The functions in this module accept bounded C0-C2 values only.  They never
load credentials, contact a product, or serialize arbitrary Python objects.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import TypeAlias
import unicodedata


Scalar: TypeAlias = None | bool | int | str
CanonicalValue: TypeAlias = Scalar | list["CanonicalValue"] | dict[str, "CanonicalValue"]

_MAX_STRING_LENGTH = 256
_MAX_SEQUENCE_LENGTH = 64
_MAX_MAPPING_LENGTH = 64
_MAX_DEPTH = 8
_CANONICAL_PROFILE = "m2-canonical-v1"


class CanonicalValueError(ValueError):
    """Raised when an input cannot enter a canonical V4 digest."""


def normalize(value: object, *, depth: int = 0) -> CanonicalValue:
    """Return a JSON-compatible, bounded, deterministically ordered value."""

    if depth > _MAX_DEPTH:
        raise CanonicalValueError("Canonical value nesting is too deep.")
    if value is None or type(value) is bool:
        return value  # type: ignore[return-value]
    if type(value) is int:
        if not -(2**31) <= value <= 2**31 - 1:
            raise CanonicalValueError("Canonical integer is out of bounds.")
        return value
    if type(value) is str:
        normalized = unicodedata.normalize("NFC", value)
        if (
            not normalized
            or len(normalized) > _MAX_STRING_LENGTH
            or any(unicodedata.category(character).startswith("C") for character in normalized)
        ):
            raise CanonicalValueError("Canonical string is empty, unsafe, or too long.")
        return normalized
    if isinstance(value, Mapping):
        if len(value) > _MAX_MAPPING_LENGTH:
            raise CanonicalValueError("Canonical mapping is too large.")
        result: dict[str, CanonicalValue] = {}
        for key in sorted(value):
            if type(key) is not str or not key or len(key) > 64:
                raise CanonicalValueError("Canonical mapping key is invalid.")
            result[key] = normalize(value[key], depth=depth + 1)
        return result
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if len(value) > _MAX_SEQUENCE_LENGTH:
            raise CanonicalValueError("Canonical sequence is too large.")
        return [normalize(item, depth=depth + 1) for item in value]
    raise CanonicalValueError("Canonical value type is not allowed.")


def canonical_json(value: object) -> str:
    """Serialize one bounded canonical value with stable JSON settings."""

    return json.dumps(
        normalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def canonical_digest(value: object) -> str:
    """Return the SHA-256 digest of one bounded canonical value."""

    bound = {"canonical_profile": _CANONICAL_PROFILE, "value": normalize(value)}
    return hashlib.sha256(canonical_json(bound).encode("utf-8")).hexdigest()
