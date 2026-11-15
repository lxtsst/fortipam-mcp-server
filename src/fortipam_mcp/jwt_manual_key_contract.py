"""I/O-free native manual JWT-key request candidate, without device authority.

Only a public RSA SubjectPublicKeyInfo value is accepted. This module neither
generates keys nor proves backend acceptance, ownership, isolation or login.
"""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import re
from typing import NoReturn

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from v4_planning.material_provider import C3MaterialBinding

CONTRACT = "fortipam-700-build29-manual-jwt-public-key-private-v1"
DEFAULT_FIELDS = frozenset({"name", "type", "key", "jwks-url", "check-interval", "ca",
                            "claim", "oidc-discovery-url", "last-check-time", "last-update-time"})
WIRE_FIELDS = frozenset({"name", "type", "key", "jwks-url", "check-interval", "ca", "claim"})
_NAME = re.compile(r"mcp-v4-jwt-[a-z0-9][a-z0-9-]{0,23}\Z")
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_UNAVAILABLE = "The private manual JWT public-key contract is unavailable."


class JwtManualKeyContractError(RuntimeError):
    """Value-free refusal without key content, identifiers or current state."""


def _fail() -> NoReturn:
    raise JwtManualKeyContractError(_UNAVAILABLE)


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def _require_digest(value: str) -> None:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        _fail()


class _Private(C3MaterialBinding):
    __slots__ = ()

    def __setattr__(self, name: str, value: object) -> None:
        _fail()

    def __delattr__(self, name: str) -> None:
        _fail()


class JwtManualPublicKey(_Private):
    """A canonical public SPKI only; RSA parameters bound to this candidate."""

    __slots__ = ("_pem", "digest")
    _pem: bytes
    digest: str

    def __init__(self, pem: bytes) -> None:
        if (type(pem) is not bytes or not 0 < len(pem) <= 2047
                or not pem.startswith(b"-----BEGIN PUBLIC KEY-----\n")
                or not pem.endswith(b"\n-----END PUBLIC KEY-----\n")):
            _fail()
        try:
            key = serialization.load_pem_public_key(pem)
            if (not isinstance(key, rsa.RSAPublicKey) or key.key_size not in {2048, 3072, 4096}
                    or key.public_numbers().e != 65537):
                _fail()
            canonical = key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            if canonical != pem:
                _fail()
        except (TypeError, ValueError, UnsupportedAlgorithm):
            _fail()
        object.__setattr__(self, "_pem", pem)
        object.__setattr__(self, "digest", hashlib.sha256(pem).hexdigest())


def _default_digest(defaults: Mapping[str, object]) -> str:
    if not isinstance(defaults, Mapping) or set(defaults) != DEFAULT_FIELDS:
        _fail()
    if any(type(defaults[k]) is not str or defaults[k] != ""
           for k in ("name", "jwks-url", "oidc-discovery-url", "ca")):
        _fail()
    if (type(defaults["type"]) is not str or defaults["type"] != "manually" or type(defaults["check-interval"]) is not int
            or defaults["check-interval"] != 24):
        _fail()
    if any(type(defaults[k]) is not list or defaults[k] != [] for k in ("key", "claim")):
        _fail()
    for key in ("last-check-time", "last-update-time"):
        value = defaults[key]
        if type(value) is not str or len(value) > 128 or re.search(r"[\x00-\x1f\x7f]", value):
            _fail()
    return _digest(dict(defaults))


class JwtManualCreatePlan(_Private):
    """One distinct name, public key and immutable source/default fingerprints."""

    __slots__ = ("_name", "_key", "_default_digest", "_schema_digest", "_serial_digest", "digest")
    _name: str
    _key: JwtManualPublicKey
    _default_digest: str
    _schema_digest: str
    _serial_digest: str
    digest: str

    def __init__(self, name: str, nonce: str, key: JwtManualPublicKey, defaults: Mapping[str, object], *,
                 schema_digest: str, serial_digest: str) -> None:
        if type(name) is not str or len(name) > 35 or _NAME.fullmatch(name) is None:
            _fail()
        if type(key) is not JwtManualPublicKey:
            _fail()
        for value in (nonce, schema_digest, serial_digest):
            _require_digest(value)
        default_digest = _default_digest(defaults)
        values: dict[str, object] = {"_name": name, "_key": key, "_default_digest": default_digest,
            "_schema_digest": schema_digest, "_serial_digest": serial_digest,
            "digest": _digest({"contract": CONTRACT, "name": name, "nonce": nonce,
                "public_key_digest": key.digest, "default_digest": default_digest,
                "schema_digest": schema_digest, "serial_digest": serial_digest})}
        for field, item in values.items():
            object.__setattr__(self, field, item)


def build_jwt_manual_create_body(plan: JwtManualCreatePlan, defaults: Mapping[str, object], *,
                                 schema_digest: str, serial_digest: str) -> bytearray:
    """Compile the seven native JSON fields; callers must erase the buffer."""
    if type(plan) is not JwtManualCreatePlan:
        _fail()
    _require_digest(schema_digest)
    _require_digest(serial_digest)
    if (_default_digest(defaults) != plan._default_digest or schema_digest != plan._schema_digest
            or serial_digest != plan._serial_digest):
        _fail()
    # Native defaults contain no q_origin_key; JSON.stringify omits undefined.
    body = {"name": plan._name, "type": "manually", "key": [{"key-name": plan._key._pem.decode("ascii")}],
            "jwks-url": "", "check-interval": 24, "ca": "", "claim": []}
    return bytearray(json.dumps(body, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode())


__all__ = ["CONTRACT", "DEFAULT_FIELDS", "WIRE_FIELDS", "JwtManualKeyContractError",
           "JwtManualPublicKey", "JwtManualCreatePlan", "build_jwt_manual_create_body"]
