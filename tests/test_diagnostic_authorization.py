"""Tests for the fail-closed diagnostic authorization adapter."""

from __future__ import annotations

from typing import Any, cast

import pytest

from mcp.server.auth.provider import AccessToken
from fortipam_mcp.diagnostic_authorization import (
    DIAGNOSTIC_PRINCIPAL_CLASS,
    DiagnosticAuthorizationError,
    DiagnosticPrincipal,
    StdioDiagnosticAuthorizationDenied,
    deny_stdio_diagnostics,
    principal_from_access_token,
)


KEY = b"k" * 32
RESOURCE = "https://mcp.example.test/fpamcp"
SUBJECT = "human-alpha"
CLIENT = "client-alpha"
_MISSING = object()


def _token(
    *,
    subject: str = SUBJECT,
    client_id: str = CLIENT,
    resource: str = RESOURCE,
    scopes: list[str] | None = None,
    token: str = "opaque-validated-token",
    expires_at: int | None = 2_000_000_000,
    issuer: str | None = "https://issuer.example.test",
) -> AccessToken:
    return AccessToken(
        token=token,
        client_id=client_id,
        scopes=["fortipam:diagnostic"] if scopes is None else scopes,
        expires_at=expires_at,
        resource=resource,
        subject=subject,
        claims={} if issuer is None else {"iss": issuer},
    )


def _mutate_token(**changes: Any) -> AccessToken:
    """Create an SDK instance with deliberately unvalidated test fields."""

    return _token().model_copy(update=changes)


def _principal(
    token: AccessToken | object = _MISSING,
    *,
    expected_resource: str = RESOURCE,
    namespace_hmac_key: bytes = KEY,
) -> DiagnosticPrincipal:
    source = _token() if token is _MISSING else cast(AccessToken, token)
    return principal_from_access_token(
        source,
        expected_resource=expected_resource,
        namespace_hmac_key=namespace_hmac_key,
    )


def test_returns_only_fixed_class_and_hmac_namespace() -> None:
    principal = _principal()

    assert principal.principal_class == DIAGNOSTIC_PRINCIPAL_CLASS
    assert len(principal.namespace_digest) == 64
    assert set(principal.namespace_digest) <= set("0123456789abcdef")
    rendered = repr(principal)
    assert SUBJECT not in rendered
    assert CLIENT not in rendered
    assert RESOURCE not in rendered
    with pytest.raises((AttributeError, TypeError)):
        principal.namespace_digest = "0" * 64  # type: ignore[misc]


def test_subject_client_and_resource_are_isolated_but_scope_order_is_not_identity() -> None:
    baseline = _principal()
    assert (
        _principal(_token(subject="human-beta")).namespace_digest
        != baseline.namespace_digest
    )
    assert (
        _principal(_token(client_id="client-beta")).namespace_digest
        != baseline.namespace_digest
    )
    other_resource = "https://other.example.test/mcp"
    assert (
        _principal(
            _token(resource=other_resource),
            expected_resource=other_resource,
        ).namespace_digest
        != baseline.namespace_digest
    )
    assert _principal(
        _token(scopes=["fortipam:diagnostic", "fortipam:other"])
    ).namespace_digest == baseline.namespace_digest


def test_claims_issuer_is_bound_without_leaking_it() -> None:
    first = _token(issuer="issuer-a")
    second = _token(issuer="issuer-b")

    one = _principal(first)
    two = _principal(second)
    assert one.namespace_digest != two.namespace_digest
    assert "issuer-a" not in repr(one)
    assert "issuer-b" not in repr(two)


@pytest.mark.parametrize(
    "bad_token",
    [
        "static-bearer",
        None,
        object(),
    ],
)
def test_non_sdk_or_static_token_shaped_input_fails_closed(bad_token: object) -> None:
    with pytest.raises(DiagnosticAuthorizationError) as caught:
        _principal(bad_token)
    assert str(caught.value) == "diagnostic authorization denied"
    assert SUBJECT not in repr(caught.value)
    assert CLIENT not in repr(caught.value)
    assert RESOURCE not in repr(caught.value)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"namespace_hmac_key": b"short"},
        {"namespace_hmac_key": True},
        {"namespace_hmac_key": bytearray(b"k" * 32)},
        {"expected_resource": ""},
        {"expected_resource": "x" * 257},
        {"expected_resource": True},
    ],
)
def test_invalid_key_and_boundary_inputs_fail_closed(kwargs: dict[str, Any]) -> None:
    with pytest.raises(DiagnosticAuthorizationError) as caught:
        principal_from_access_token(
            _token(),
            expected_resource=kwargs.get("expected_resource", RESOURCE),
            namespace_hmac_key=kwargs.get("namespace_hmac_key", KEY),
        )
    assert str(caught.value) == "diagnostic authorization denied"
    assert "x" * 257 not in repr(caught.value)


def test_resource_and_scope_mismatch_fail_closed() -> None:
    with pytest.raises(DiagnosticAuthorizationError):
        _principal(_token(resource="https://other.example.test/mcp"))
    with pytest.raises(DiagnosticAuthorizationError):
        _principal(_token(scopes=["fortipam:read"]))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("subject", True),
        ("client_id", True),
        ("resource", True),
        ("subject", "s" * 257),
        ("client_id", "c" * 257),
        ("resource", "r" * 257),
        ("scopes", ["fortipam:diagnostic", True]),
        ("scopes", ["fortipam:diagnostic", "s" * 257]),
    ],
)
def test_identity_field_types_and_sizes_fail_closed(field: str, value: Any) -> None:
    with pytest.raises(DiagnosticAuthorizationError) as caught:
        principal_from_access_token(
            _mutate_token(**{field: value}),
            expected_resource=RESOURCE,
            namespace_hmac_key=KEY,
        )
    assert str(caught.value) == "diagnostic authorization denied"


def test_missing_claims_issuer_fails_closed() -> None:
    with pytest.raises(DiagnosticAuthorizationError) as caught:
        _principal(_token(issuer=None))
    assert str(caught.value) == "diagnostic authorization denied"


def test_stdio_has_an_explicit_deny_boundary() -> None:
    with pytest.raises(StdioDiagnosticAuthorizationDenied) as caught:
        deny_stdio_diagnostics()
    assert str(caught.value) == "stdio diagnostic authorization denied"


def test_invalid_manual_principal_cannot_be_constructed() -> None:
    with pytest.raises(DiagnosticAuthorizationError):
        DiagnosticPrincipal("arbitrary", "0" * 64)
    with pytest.raises(DiagnosticAuthorizationError):
        DiagnosticPrincipal(DIAGNOSTIC_PRINCIPAL_CLASS, "raw-namespace")
