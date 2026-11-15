"""Inactive fixed two-resource issuer candidate; no file route or authority.

Only trusted composition may construct this issuer. Both resources reuse one
authorization-service-owned store and authenticated human. The private intake
workload must not mount that store. This does not qualify deployed separation,
human Owner eligibility, policy issuance or permission to read file material.
Normal HTTP startup selects this candidate only through the explicitly enabled,
fixed private issuer runtime; default startup remains single-resource.
"""

from __future__ import annotations

import asyncio
from contextvars import ContextVar
from dataclasses import replace
import time
from urllib.parse import parse_qs, urlsplit

from mcp.server.auth.provider import (
    AccessToken, AuthorizationCode, AuthorizationParams,
    RefreshToken, RegistrationError, TokenError, TokenVerifier,
)
from mcp.server.auth.settings import ClientRegistrationOptions
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .local_oauth import (
    LOCAL_PLANNING_SCOPE, LOCAL_SCOPE, LOCAL_SCOPES,
    LocalOAuthConfigurationError, LocalOAuthProvider, LocalOAuthSettings,
)
from .secret_bulk_import_intake import _INTAKE_SCOPE

_REQUEST_RESOURCE: ContextVar[str | None] = ContextVar("owner_file_intake_oauth_resource", default=None)
_REVOCATION_LOOKUP: ContextVar[bool] = ContextVar("owner_file_intake_revocation_lookup", default=False)


class _IntakeIssuer(LocalOAuthProvider):
    def _access_token_lifetime(self) -> int:
        return 900


class OwnerFileIntakeOAuthCandidate(LocalOAuthProvider):
    """One issuer, two exact resources, disjoint registration and verification."""

    def __init__(self, settings: LocalOAuthSettings, *, intake_resource: str) -> None:
        try:
            if type(settings) is not LocalOAuthSettings or type(intake_resource) is not str:
                raise ValueError
            parsed, primary, issuer = (urlsplit(value) for value in (
                intake_resource, settings.resource, settings.issuer))
            if (type(intake_resource) is not str or intake_resource != intake_resource.strip()
                    or parsed.scheme != "https" or primary.scheme != "https" or issuer.scheme != "https"
                    or not parsed.hostname or parsed.netloc != primary.netloc or parsed.netloc != issuer.netloc
                    or parsed.username or parsed.password or parsed.query or parsed.fragment
                    or not parsed.path or parsed.path == "/" or "%" in parsed.path
                    or any(ord(char) <= 32 or ord(char) >= 127 for char in intake_resource)
                    or any(part in {".", "..", ""} for part in parsed.path.split("/")[1:])
                    or parsed.path == primary.path
                    or parsed.path == issuer.path or parsed.path.startswith(issuer.path.rstrip("/") + "/")
                    or settings.insecure_private_ip_lab or settings.scope != LOCAL_SCOPE
                    or LOCAL_PLANNING_SCOPE not in settings.available_scopes
                    or set(settings.available_scopes) - set(LOCAL_SCOPES)
                    or set(settings.default_scopes) - set(settings.available_scopes)):
                raise ValueError
        except Exception:
            raise LocalOAuthConfigurationError("Private intake OAuth composition unavailable.") from None
        super().__init__(settings)
        self._intake = _IntakeIssuer(replace(
            settings, resource=intake_resource, scope=_INTAKE_SCOPE,
            available_scopes=(_INTAKE_SCOPE,), default_scopes=(_INTAKE_SCOPE,),
        ))

    def _registration_options(self) -> ClientRegistrationOptions:
        options = super()._registration_options()
        options.valid_scopes = [*self.settings.available_scopes, _INTAKE_SCOPE]
        return options

    def _validate_client_registration(self, client: OAuthClientInformationFull) -> None:
        scopes = (client.scope or "").split()
        if _INTAKE_SCOPE in scopes:
            if scopes != [_INTAKE_SCOPE] or client.grant_types != ["authorization_code"]:
                raise RegistrationError(error="invalid_client_metadata",
                                        error_description="Private intake requires a dedicated code-only client.")
            self._intake._validate_client_registration(client)
        else:
            super()._validate_client_registration(client)

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        if params.resource == self._intake.settings.resource:
            return await self._intake.authorize(client, params)
        return await super().authorize(client, params)

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        resource = authorization_code.resource
        if _REQUEST_RESOURCE.get() != resource:
            raise TokenError(error="invalid_grant", error_description="The requested resource does not match.")
        if resource == self._intake.settings.resource:
            self._validate_client_registration(client)
            if authorization_code.scopes != [_INTAKE_SCOPE]:
                raise TokenError(error="invalid_scope", error_description="Private intake scope unavailable.")
            return await self._intake.exchange_authorization_code(client, authorization_code)
        if resource != self.settings.resource:
            raise TokenError(error="invalid_grant", error_description="The resource is unavailable.")
        return await super().exchange_authorization_code(client, authorization_code)

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str,
    ) -> RefreshToken | None:
        loaded = await super().load_refresh_token(client, refresh_token)
        if loaded is not None and getattr(loaded, "resource", None) != self.settings.resource:
            return None
        return loaded

    async def load_access_token(self, token: str) -> AccessToken | None:
        loaded = await super().load_access_token(token)
        if loaded is None and _REVOCATION_LOOKUP.get():
            return await self._load_intake_access_token(token)
        return loaded

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str],
    ) -> OAuthToken:
        if (_REQUEST_RESOURCE.get() != self.settings.resource
                or getattr(refresh_token, "resource", None) != self.settings.resource):
            raise TokenError(error="invalid_grant", error_description="Private intake cannot refresh.")
        return await super().exchange_refresh_token(client, refresh_token, scopes)

    def authorization_routes(self) -> list[Route]:
        routes = super().authorization_routes()
        path = urlsplit(self.settings.issuer).path.rstrip("/") + "/token"
        revoke = urlsplit(self.settings.issuer).path.rstrip("/") + "/revoke"
        for route in routes:
            if route.path == path:
                # Preserve the SDK's ASGI endpoint and CORS/preflight behavior.
                route.app = self._bound_token_endpoint(route.app)
            elif route.path == revoke:
                route.app = self._bound_token_endpoint(route.app, revocation=True)
        return routes

    def _bound_token_endpoint(self, endpoint: ASGIApp, *, revocation: bool = False) -> ASGIApp:
        async def bound(scope: Scope, receive: Receive, send: Send) -> None:
            if scope["method"] != "POST":
                await endpoint(scope, receive, send)
                return
            context = None
            revocation_context = None
            body = bytearray()
            try:
                request = Request(scope)
                lengths = request.headers.getlist("content-length")
                if len(lengths) != 1:
                    raise ValueError
                length = lengths[0]
                if (not length.isascii() or not length.isdigit() or len(length) > 5
                        or not 0 < int(length) <= 16384
                        or request.headers.get("content-type", "").split(";", 1)[0] != "application/x-www-form-urlencoded"):
                    raise ValueError
                async with asyncio.timeout(10):
                    for _ in range(256):
                        message = await receive()
                        if message["type"] != "http.request":
                            raise ValueError
                        chunk = message.get("body", b"")
                        if len(body) + len(chunk) > int(length):
                            raise ValueError
                        body.extend(chunk)
                        if not message.get("more_body", False):
                            break
                    else:
                        raise ValueError
                if len(body) != int(length):
                    raise ValueError
                form = parse_qs(body.decode("ascii"), keep_blank_values=True,
                                strict_parsing=True, max_num_fields=8, errors="strict")
                if revocation:
                    if (set(form) - {'token', 'token_type_hint', 'client_id', 'client_secret'}
                            or any(len(values) != 1 for values in form.values())
                            or not form.get('token', [''])[0] or not form.get('client_id', [''])[0]
                            or form.get('token_type_hint', ['access_token'])[0] not in {'access_token', 'refresh_token'}):
                        raise ValueError
                    # SDK authenticates the client and compares its identity
                    # before revoking. Only that fixed endpoint may look up both
                    # resources; normal MCP verification still excludes intake.
                    revocation_context = _REVOCATION_LOOKUP.set(True)
                else:
                    resources = form.get("resource", [])
                    if (len(resources) != 1
                            or resources[0] not in (self.settings.resource, self._intake.settings.resource)):
                        raise ValueError
                    context = _REQUEST_RESOURCE.set(resources[0])
            except Exception:
                response = JSONResponse({"error": "invalid_request" if revocation else "invalid_target",
                    "error_description": "The request is unavailable." if revocation else "The resource is unavailable."},
                                        status_code=400, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})
                try:
                    await response(scope, receive, send)
                finally:
                    body[:] = b"\x00" * len(body)
                return
            except BaseException:
                body[:] = b"\x00" * len(body)
                raise
            try:
                delivered = False

                async def replay() -> Message:
                    nonlocal delivered
                    if delivered:
                        return await receive()
                    delivered = True
                    return {"type": "http.request", "body": bytes(body), "more_body": False}

                await endpoint(scope, replay, send)
            finally:
                if context is not None:
                    _REQUEST_RESOURCE.reset(context)
                if revocation_context is not None:
                    _REVOCATION_LOOKUP.reset(revocation_context)
                body[:] = b"\x00" * len(body)

        return bound

    def _permission_description(self, scopes: object) -> str:
        if scopes == [_INTAKE_SCOPE]:
            return "private file dependency projection; separate Owner authorization required"
        return super()._permission_description(scopes)

    async def _load_intake_access_token(self, token: str) -> AccessToken | None:
        loaded = await self._intake.load_access_token(token)
        if (loaded is None or loaded.scopes != [_INTAKE_SCOPE]
                or type(loaded.expires_at) is not int or loaded.expires_at <= int(time.time())):
            return None
        return loaded


class OwnerFileIntakeTokenVerifier(TokenVerifier):
    """Issuer-side fixed-resource verifier, not a remote introspection route.

    Trusted transport to a distinct workload remains unqualified. Never give the
    intake workload direct access to the issuer's authentication database.
    """

    def __init__(self, issuer: OwnerFileIntakeOAuthCandidate) -> None:
        if type(issuer) is not OwnerFileIntakeOAuthCandidate:
            raise LocalOAuthConfigurationError("Private intake OAuth composition unavailable.")
        self._issuer = issuer

    async def verify_token(self, token: str) -> AccessToken | None:
        return await self._issuer._load_intake_access_token(token)
