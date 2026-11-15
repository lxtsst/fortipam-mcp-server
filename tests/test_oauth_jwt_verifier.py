"""Exercise JWT claims and algorithm checks against the installed dependency."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
import time

from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
import pytest

from fortipam_mcp.http_server import OAuthJwtTokenVerifier


@pytest.fixture(scope="module")
def signing_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.mark.parametrize("case", ["valid", "audience", "issuer", "expired", "signature", "algorithm"])
def test_jwt_verifier_enforces_token_boundary(signing_key: rsa.RSAPrivateKey, case: str) -> None:
    issuer = "https://identity.example.com"
    audience = "https://mcp.example.com/mcp"
    verifier = OAuthJwtTokenVerifier(
        issuer=issuer, jwks_url=f"{issuer}/jwks", audience=audience, algorithms=("RS256",)
    )
    verifier._jwks_client.get_signing_key_from_jwt = lambda token: SimpleNamespace(
        key=signing_key.public_key()
    )
    claims = {"iss": issuer, "aud": audience, "exp": int(time.time()) + 300,
              "sub": "synthetic-user", "client_id": "synthetic-client", "scope": "fortipam:read"}
    if case == "audience":
        claims["aud"] = "https://other.example.com/mcp"
    elif case == "issuer":
        claims["iss"] = "https://other.example.com"
    elif case == "expired":
        claims["exp"] = int(time.time()) - 300
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048) if case == "signature" else signing_key
    token = (jwt.encode(claims, "synthetic-test-key-with-32-characters", algorithm="HS256")
             if case == "algorithm" else jwt.encode(claims, key, algorithm="RS256"))
    result = asyncio.run(verifier.verify_token(token))
    if case == "valid":
        assert result is not None
        assert result.resource == audience
        assert result.scopes == ["fortipam:read"]
    else:
        assert result is None
