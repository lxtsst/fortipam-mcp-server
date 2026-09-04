"""Fail-closed authorization adapter for object-level diagnostic operations.

This module deliberately accepts only an SDK-validated ``AccessToken``.  It
does not parse bearer tokens, JWTs, HTTP headers, form fields, MCP arguments,
or OS credentials.  The resulting principal contains no source identifiers;
it carries only a fixed class and a keyed namespace digest suitable for
authorization and audit correlation.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
from collections.abc import Mapping
from typing import NoReturn

from mcp.server.auth.provider import AccessToken

REQUIRED_DIAGNOSTIC_SCOPE = "fortipam:diagnostic"
DIAGNOSTIC_PRINCIPAL_CLASS = "http_oauth_authenticated_human"
MIN_NAMESPACE_HMAC_KEY_BYTES = 32
MAX_TEXT_BYTES = 256
MAX_TOKEN_BYTES = 8192

_DENIED_MESSAGE = "diagnostic authorization denied"
_STDIO_DENIED_MESSAGE = "stdio diagnostic authorization denied"
_MISSING = object()


class DiagnosticAuthorizationError(ValueError):
    """Stable, non-disclosing failure for diagnostic authorization."""


class StdioDiagnosticAuthorizationDenied(PermissionError):
    """Raised because stdio has no authenticated human principal boundary."""


@dataclass(frozen=True, slots=True)
class DiagnosticPrincipal:
    """The only principal data allowed beyond the authorization boundary."""

    principal_class: str
    namespace_digest: str

    def __post_init__(self) -> None:
        if self.principal_class != DIAGNOSTIC_PRINCIPAL_CLASS:
            raise DiagnosticAuthorizationError(_DENIED_MESSAGE)
        if (
            type(self.namespace_digest) is not str
            or len(self.namespace_digest) != hashlib.sha256().digest_size * 2
            or any(character not in "0123456789abcdef" for character in self.namespace_digest)
        ):
            raise DiagnosticAuthorizationError(_DENIED_MESSAGE)


def principal_from_access_token(
    access_token: AccessToken,
    *,
    expected_resource: str,
    namespace_hmac_key: bytes,
) -> DiagnosticPrincipal:
    """Derive a bounded principal from an already verified SDK token.

    Expiration and signature validation are the responsibility of the SDK
    verifier that produced ``access_token``.  We only require a well-formed
    expiration field and never compare it with a local clock.  The current
    MCP ``AccessToken`` type currently carries issuer data in its validated
    ``claims["iss"]`` mapping.  A token without a dedicated issuer field or
    validated claims issuer is rejected; it must never silently downgrade to
    an issuer-less namespace.
    """

    if not isinstance(access_token, AccessToken):
        raise DiagnosticAuthorizationError(_DENIED_MESSAGE)
    _validate_namespace_key(namespace_hmac_key)
    resource = _validated_text(expected_resource)

    token = _attribute(access_token, "token")
    _validated_text(token, maximum_bytes=MAX_TOKEN_BYTES)
    client_id = _validated_text(_attribute(access_token, "client_id"))
    subject = _validated_text(_attribute(access_token, "subject"))
    token_resource = _validated_text(_attribute(access_token, "resource"))
    if token_resource != resource:
        raise DiagnosticAuthorizationError(_DENIED_MESSAGE)

    _validated_scopes(_attribute(access_token, "scopes"))

    # The verifier establishes freshness.  Requiring a typed positive value
    # prevents an unverified/static token-shaped object from being accepted,
    # without reimplementing bearer/JWT expiry validation here.
    expires_at = _attribute(access_token, "expires_at")
    if type(expires_at) is not int or expires_at <= 0:
        raise DiagnosticAuthorizationError(_DENIED_MESSAGE)

    issuer = _required_issuer(access_token)
    namespace_digest = _namespace_digest(
        namespace_hmac_key,
        issuer=issuer,
        client_id=client_id,
        subject=subject,
        resource=token_resource,
    )
    return DiagnosticPrincipal(
        principal_class=DIAGNOSTIC_PRINCIPAL_CLASS,
        namespace_digest=namespace_digest,
    )


def deny_stdio_diagnostics() -> NoReturn:
    """Explicitly deny V3 diagnostic authorization over stdio."""

    raise StdioDiagnosticAuthorizationDenied(_STDIO_DENIED_MESSAGE)


def _attribute(value: object, name: str) -> object:
    try:
        result = getattr(value, name, _MISSING)
    except Exception:
        raise DiagnosticAuthorizationError(_DENIED_MESSAGE) from None
    if result is _MISSING:
        raise DiagnosticAuthorizationError(_DENIED_MESSAGE)
    return result


def _validated_text(value: object, *, maximum_bytes: int = MAX_TEXT_BYTES) -> str:
    if type(value) is not str or not value or not value.strip():
        raise DiagnosticAuthorizationError(_DENIED_MESSAGE)
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        raise DiagnosticAuthorizationError(_DENIED_MESSAGE) from None
    if len(encoded) > maximum_bytes or any(ord(character) < 0x20 for character in value):
        raise DiagnosticAuthorizationError(_DENIED_MESSAGE)
    return value


def _validated_scope(value: object) -> str:
    scope = _validated_text(value)
    if any(character.isspace() for character in scope):
        raise DiagnosticAuthorizationError(_DENIED_MESSAGE)
    return scope


def _validated_scopes(value: object) -> tuple[str, ...]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, (list, tuple)):
        raise DiagnosticAuthorizationError(_DENIED_MESSAGE)
    scopes = tuple(_validated_scope(item) for item in value)
    if len(set(scopes)) != len(scopes) or REQUIRED_DIAGNOSTIC_SCOPE not in scopes:
        raise DiagnosticAuthorizationError(_DENIED_MESSAGE)
    return tuple(sorted(scopes))


def _validate_namespace_key(value: object) -> None:
    if type(value) is not bytes or len(value) < MIN_NAMESPACE_HMAC_KEY_BYTES:
        raise DiagnosticAuthorizationError(_DENIED_MESSAGE)


def _required_issuer(access_token: object) -> str:
    issuer = _attribute_or_missing(access_token, "issuer")
    if issuer is _MISSING:
        # The installed MCP AccessToken currently carries validated issuer
        # data in its claims mapping rather than a dedicated field.  Read only
        # that SDK-provided field; never decode the raw bearer/JWT token.
        claims = _attribute_or_missing(access_token, "claims")
        if not isinstance(claims, Mapping):
            raise DiagnosticAuthorizationError(_DENIED_MESSAGE)
        issuer = claims.get("iss", _MISSING)
    if issuer is _MISSING or issuer is None:
        raise DiagnosticAuthorizationError(_DENIED_MESSAGE)
    return _validated_text(issuer)


def _attribute_or_missing(value: object, name: str) -> object:
    try:
        return getattr(value, name, _MISSING)
    except Exception:
        raise DiagnosticAuthorizationError(_DENIED_MESSAGE) from None


def _namespace_digest(
    key: bytes,
    *,
    issuer: str,
    client_id: str,
    subject: str,
    resource: str,
) -> str:
    fields = ("v1", issuer, client_id, subject, resource)
    payload = bytearray()
    for field in fields:
        encoded = field.encode("utf-8")
        payload.extend(len(encoded).to_bytes(4, "big"))
        payload.extend(encoded)
    return hmac.new(key, bytes(payload), hashlib.sha256).hexdigest()


__all__ = [
    "DIAGNOSTIC_PRINCIPAL_CLASS",
    "DiagnosticAuthorizationError",
    "DiagnosticPrincipal",
    "REQUIRED_DIAGNOSTIC_SCOPE",
    "StdioDiagnosticAuthorizationDenied",
    "deny_stdio_diagnostics",
    "principal_from_access_token",
]
