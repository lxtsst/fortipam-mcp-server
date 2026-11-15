"""Private-key exclusion, native serialization and create-context drift tests."""
from __future__ import annotations

import copy
import json
import pickle

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
import pytest

from fortipam_mcp.jwt_manual_key_contract import (
    WIRE_FIELDS, JwtManualCreatePlan, JwtManualKeyContractError, JwtManualPublicKey, build_jwt_manual_create_body,
)
from v4_planning.material_provider import MaterialAccessDenied

CONTEXT = {"schema_digest": "a" * 64, "serial_digest": "b" * 64}


def defaults() -> dict[str, object]:
    return {"name": "", "type": "manually", "key": [], "jwks-url": "", "check-interval": 24,
            "ca": "", "claim": [], "oidc-discovery-url": "", "last-check-time": "synthetic-never",
            "last-update-time": "synthetic-never"}


@pytest.fixture(scope="module")
def synthetic_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def public_pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def plan(key: rsa.RSAPrivateKey, current: dict[str, object] | None = None) -> JwtManualCreatePlan:
    return JwtManualCreatePlan("mcp-v4-jwt-synthetic", "c" * 64, JwtManualPublicKey(public_pem(key)),
                               defaults() if current is None else current, **CONTEXT)


def test_manual_native_body_contains_only_public_spki_and_seven_fields(synthetic_key: rsa.RSAPrivateKey) -> None:
    current = defaults()
    raw = build_jwt_manual_create_body(plan(synthetic_key, current), current, **CONTEXT)
    try:
        body = json.loads(raw)
        assert set(body) == WIRE_FIELDS and len(body) == 7
        assert body["key"] == [{"key-name": public_pem(synthetic_key).decode()}]
        assert body["type"] == "manually" and body["check-interval"] == 24
        assert body["ca"] == body["jwks-url"] == "" and body["claim"] == []
        assert "q_origin_key" not in body and "oidc-discovery-url" not in body
        assert current == defaults()
    finally:
        raw[:] = b"\0" * len(raw)


@pytest.mark.parametrize("kind", ["private_pkcs8", "private_rsa", "public_pkcs1", "two_public_keys", "trailing_data", "crlf", "ec", "weak_rsa"])
def test_private_unsupported_or_noncanonical_material_never_enters_plan(synthetic_key: rsa.RSAPrivateKey, kind: str) -> None:
    pem = public_pem(synthetic_key)
    if kind.startswith("private"):
        format = (serialization.PrivateFormat.PKCS8 if kind == "private_pkcs8"
                  else serialization.PrivateFormat.TraditionalOpenSSL)
        pem = synthetic_key.private_bytes(serialization.Encoding.PEM, format, serialization.NoEncryption())
    elif kind == "public_pkcs1":
        pem = synthetic_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1)
    elif kind == "two_public_keys":
        pem += pem
    elif kind == "trailing_data":
        pem += b"unexpected"
    elif kind == "crlf":
        pem = pem.replace(b"\n", b"\r\n")
    elif kind == "ec":
        pem = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    else:
        pem = public_pem(rsa.generate_private_key(public_exponent=65537, key_size=1024))
    with pytest.raises(JwtManualKeyContractError, match="^The private manual JWT public-key contract is unavailable.$"):
        JwtManualPublicKey(pem)


@pytest.mark.parametrize("field,value", [("type", "jwks"), ("jwks-url", "https://synthetic.invalid/keys"),
    ("ca", "synthetic-ca"), ("key", [{"key-name": "unexpected"}]), ("claim", [{"claim-name": "iss"}]),
    ("check-interval", True), ("check-interval", 25), ("last-check-time", "changed"),
    ("last-update-time", "changed"), ("unknown", "unexpected")])
def test_default_drift_cannot_become_the_new_plan(synthetic_key: rsa.RSAPrivateKey, field: str, value: object) -> None:
    current = defaults()
    prepared = plan(synthetic_key, current)
    current[field] = value
    with pytest.raises(JwtManualKeyContractError):
        build_jwt_manual_create_body(prepared, current, **CONTEXT)


@pytest.mark.parametrize("field", tuple(CONTEXT))
def test_device_or_schema_drift_refuses_body(synthetic_key: rsa.RSAPrivateKey, field: str) -> None:
    context = dict(CONTEXT, **{field: "d" * 64})
    with pytest.raises(JwtManualKeyContractError):
        build_jwt_manual_create_body(plan(synthetic_key), defaults(), **context)


def test_name_limit_and_opaque_immutable_carriers(synthetic_key: rsa.RSAPrivateKey) -> None:
    key = JwtManualPublicKey(public_pem(synthetic_key))
    name = "mcp-v4-jwt-" + "a" * 24
    assert len(name) == 35
    p = JwtManualCreatePlan(name, "c" * 64, key, defaults(), **CONTEXT)
    for invalid in (name + "b", "existing-shared-key", "mcp-v4-jwt-../name"):
        with pytest.raises(JwtManualKeyContractError):
            JwtManualCreatePlan(invalid, "c" * 64, key, defaults(), **CONTEXT)
    for item in (key, p):
        assert "PUBLIC KEY" not in repr(item) and name not in repr(item)
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(MaterialAccessDenied):
                operation(item)
        with pytest.raises(JwtManualKeyContractError):
            setattr(item, "digest", "f" * 64)
