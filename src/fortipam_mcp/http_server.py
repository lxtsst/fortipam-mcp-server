"""Hardened Streamable HTTP entrypoint for the read-only FortiPAM MCP server."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from fnmatch import fnmatchcase
import os
from pathlib import Path
import secrets
import ssl
from typing import Any, Mapping
from urllib.parse import urlsplit

from mcp.server.auth.provider import AccessToken
from mcp.server.auth.provider import ProviderTokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import AnyHttpUrl

from .approval_service import (
    CONTROLLED_OPERATION_PREFIX,
    ApprovalServiceConfigurationError,
    ApprovalServiceSettings,
    LocalApprovalService,
    approval_settings_from_environment,
)
from .diagnostic_service import (
    DIAGNOSTIC_DB_ENV,
    DIAGNOSTIC_HMAC_KEY_FILE_ENV,
    DIAGNOSTIC_PREFIX,
    DiagnosticServiceError,
    DiagnosticServiceSettings,
    diagnostic_settings_from_environment,
)
from .env import EnvironmentFileError, load_prefixed_environment_file
from .local_oauth import (
    LocalOAuthConfigurationError,
    LocalOAuthProvider,
    LocalOAuthSettings,
    local_oauth_settings_from_environment,
)
from .runtime_profile import (
    RUNTIME_PROFILE_ENV,
    RuntimeProfile,
    RuntimeProfileError,
    load_runtime_profile,
)
from .server import FortiPamMcpServer

HTTP_PREFIX = "FORTIPAM_MCP_HTTP_"
HTTP_ENV_FILE_VARIABLE = f"{HTTP_PREFIX}ENV_FILE"
DEFAULT_PATH = "/mcp"
DEFAULT_PORT = 8000
DEFAULT_SCOPE = "fortipam:read"
SAFE_JWT_ALGORITHMS = frozenset(
    {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"}
)


class HttpConfigurationError(ValueError):
    """Raised when the remote MCP listener would be unsafe or incomplete."""


@dataclass(frozen=True, slots=True)
class HttpServerSettings:
    """Validated Streamable HTTP settings without secret disclosure."""

    host: str
    port: int
    path: str
    auth_mode: str
    bearer_token: str | None
    allowed_hosts: tuple[str, ...]
    allowed_origins: tuple[str, ...]
    public_url: str | None
    oauth_issuer: str | None
    oauth_jwks_url: str | None
    oauth_audience: str | None
    oauth_required_scopes: tuple[str, ...]
    oauth_algorithms: tuple[str, ...]
    local_oauth: LocalOAuthSettings | None
    diagnostic: DiagnosticServiceSettings | None
    controlled_operation: ApprovalServiceSettings | None
    runtime_profile: RuntimeProfile

    @classmethod
    def from_environment(
        cls,
        environment: Mapping[str, str] | None = None,
    ) -> "HttpServerSettings":
        """Load and validate remote transport configuration."""

        env = os.environ if environment is None else environment
        try:
            runtime_profile = load_runtime_profile(env)
        except RuntimeProfileError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        host = _value(env, "HOST") or "127.0.0.1"
        port = _port(_value(env, "PORT"))
        path = _path(_value(env, "PATH") or DEFAULT_PATH)
        auth_mode = (_value(env, "AUTH_MODE") or "bearer").lower()
        if auth_mode not in {"none", "bearer", "oauth", "local_oauth"}:
            raise HttpConfigurationError(
                "FORTIPAM_MCP_HTTP_AUTH_MODE must be none, bearer, oauth, or local_oauth."
            )

        allowed_hosts = _csv(_value(env, "ALLOWED_HOSTS"))
        if not allowed_hosts:
            if _is_loopback(host):
                allowed_hosts = (f"127.0.0.1:{port}", f"localhost:{port}")
            else:
                raise HttpConfigurationError(
                    "Non-loopback HTTP listeners require explicit allowed hosts."
                )

        bearer_token = _value(env, "BEARER_TOKEN")
        public_url = _optional_https_url(_value(env, "PUBLIC_URL"), "public URL")
        oauth_issuer = _optional_https_url(
            _value(env, "OAUTH_ISSUER"), "OAuth issuer"
        )
        oauth_jwks_url = _optional_https_url(
            _value(env, "OAUTH_JWKS_URL"), "OAuth JWKS URL"
        )
        oauth_audience = _optional_https_url(
            _value(env, "OAUTH_AUDIENCE"), "OAuth audience"
        )
        oauth_required_scopes = _csv(_value(env, "OAUTH_REQUIRED_SCOPES")) or (
            DEFAULT_SCOPE,
        )
        oauth_algorithms = _csv(_value(env, "OAUTH_ALGORITHMS")) or ("RS256",)
        if set(oauth_algorithms) - SAFE_JWT_ALGORITHMS:
            raise HttpConfigurationError(
                "OAuth algorithms must use an approved asymmetric JWT algorithm."
            )

        if auth_mode == "none" and not _is_loopback(host):
            raise HttpConfigurationError(
                "Unauthenticated Streamable HTTP is restricted to loopback."
            )
        if auth_mode == "bearer" and (bearer_token is None or len(bearer_token) < 32):
            raise HttpConfigurationError(
                "Bearer mode requires a token containing at least 32 characters."
            )
        if auth_mode == "oauth":
            missing = [
                label
                for label, value in (
                    ("PUBLIC_URL", public_url),
                    ("OAUTH_ISSUER", oauth_issuer),
                    ("OAUTH_JWKS_URL", oauth_jwks_url),
                    ("OAUTH_AUDIENCE", oauth_audience),
                )
                if value is None
            ]
            if missing:
                raise HttpConfigurationError(
                    "OAuth mode requires complete public URL, issuer, JWKS, and audience settings."
                )
            if public_url != oauth_audience:
                raise HttpConfigurationError(
                    "OAuth audience must exactly match the canonical MCP public URL."
                )
            if urlsplit(public_url).path != path:
                raise HttpConfigurationError(
                    "The public URL path must match the configured MCP endpoint path."
                )

        local_oauth: LocalOAuthSettings | None = None
        if auth_mode == "local_oauth":
            if public_url is None:
                raise HttpConfigurationError(
                    "Local OAuth mode requires the canonical MCP public URL."
                )
            if urlsplit(public_url).path != path:
                raise HttpConfigurationError(
                    "The public URL path must match the configured MCP endpoint path."
                )
            try:
                local_oauth = local_oauth_settings_from_environment(
                    env,
                    prefix=HTTP_PREFIX,
                    public_url=public_url,
                )
            except LocalOAuthConfigurationError as exc:
                raise HttpConfigurationError(str(exc)) from exc

        diagnostic: DiagnosticServiceSettings | None = None
        diagnostic_requested = any(
            _exact_value(env, name) is not None
            for name in (DIAGNOSTIC_DB_ENV, DIAGNOSTIC_HMAC_KEY_FILE_ENV)
        )
        if diagnostic_requested and auth_mode not in {"oauth", "local_oauth"}:
            raise HttpConfigurationError(
                "Diagnostic state requires HTTP OAuth authentication."
            )
        if auth_mode in {"oauth", "local_oauth"}:
            assert public_url is not None
            try:
                diagnostic = diagnostic_settings_from_environment(
                    env,
                    expected_resource=public_url,
                )
            except DiagnosticServiceError as exc:
                raise HttpConfigurationError(str(exc)) from exc

        try:
            controlled_operation = approval_settings_from_environment(env)
        except ApprovalServiceConfigurationError as exc:
            raise HttpConfigurationError(str(exc)) from exc
        if controlled_operation is not None and auth_mode != "local_oauth":
            raise HttpConfigurationError(
                "Controlled-operation approval requires embedded local OAuth."
            )

        return cls(
            host=host,
            port=port,
            path=path,
            auth_mode=auth_mode,
            bearer_token=bearer_token,
            allowed_hosts=allowed_hosts,
            allowed_origins=_csv(_value(env, "ALLOWED_ORIGINS")),
            public_url=public_url,
            oauth_issuer=oauth_issuer,
            oauth_jwks_url=oauth_jwks_url,
            oauth_audience=oauth_audience,
            oauth_required_scopes=oauth_required_scopes,
            oauth_algorithms=oauth_algorithms,
            local_oauth=local_oauth,
            diagnostic=diagnostic,
            controlled_operation=controlled_operation,
            runtime_profile=runtime_profile,
        )


class StaticBearerMiddleware:
    """Require one deployment token without exposing it to the MCP server."""

    def __init__(self, app: Any, *, token: str, protected_path: str) -> None:
        self._app = app
        self._token = token
        self._protected_path = protected_path

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Any,
        send: Any,
    ) -> None:
        if scope.get("type") != "http" or scope.get("path") != self._protected_path:
            await self._app(scope, receive, send)
            return
        headers = {
            key.lower(): value
            for key, value in scope.get("headers", ())
            if isinstance(key, bytes) and isinstance(value, bytes)
        }
        authorization = headers.get(b"authorization", b"").decode(
            "latin-1", errors="ignore"
        )
        scheme, separator, supplied = authorization.partition(" ")
        valid = (
            separator == " "
            and scheme.lower() == "bearer"
            and bool(supplied)
            and secrets.compare_digest(supplied, self._token)
        )
        if not valid:
            body = b'{"error":"unauthorized"}'
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode("ascii")),
                        (b"www-authenticate", b'Bearer realm="fortipam-mcp"'),
                        (b"cache-control", b"no-store"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return
        await self._app(scope, receive, send)


class AllowedHostMiddleware:
    """Apply the configured Host allowlist to MCP and embedded auth routes."""

    def __init__(self, app: Any, *, allowed_hosts: tuple[str, ...]) -> None:
        self._app = app
        self._allowed_hosts = tuple(host.lower() for host in allowed_hosts)

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Any,
        send: Any,
    ) -> None:
        if scope.get("type") != "http":
            await self._app(scope, receive, send)
            return
        headers = {
            key.lower(): value
            for key, value in scope.get("headers", ())
            if isinstance(key, bytes) and isinstance(value, bytes)
        }
        host = headers.get(b"host", b"").decode("latin-1", errors="ignore").lower()
        if not host or not any(fnmatchcase(host, pattern) for pattern in self._allowed_hosts):
            body = b'{"error":"untrusted_host"}'
            await send(
                {
                    "type": "http.response.start",
                    "status": 421,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode("ascii")),
                        (b"cache-control", b"no-store"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return
        await self._app(scope, receive, send)


class OAuthJwtTokenVerifier:
    """Validate IdP JWT access tokens as MCP resource-server credentials."""

    def __init__(
        self,
        *,
        issuer: str,
        jwks_url: str,
        audience: str,
        algorithms: tuple[str, ...],
    ) -> None:
        import jwt
        import truststore

        self._jwt = jwt
        self._issuer = issuer
        self._audience = audience
        self._algorithms = algorithms
        ssl_context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self._jwks_client = jwt.PyJWKClient(
            jwks_url,
            cache_keys=True,
            lifespan=300,
            timeout=10,
            ssl_context=ssl_context,
        )

    async def verify_token(self, token: str) -> AccessToken | None:
        """Return validated access metadata or a non-disclosing failure."""

        try:
            signing_key = await asyncio.to_thread(
                self._jwks_client.get_signing_key_from_jwt,
                token,
            )
            claims = self._jwt.decode(
                token,
                signing_key.key,
                algorithms=list(self._algorithms),
                audience=self._audience,
                issuer=self._issuer,
                options={"require": ["exp", "iss", "aud"]},
            )
        except Exception:
            return None
        scopes = _token_scopes(claims)
        client_id = str(claims.get("client_id") or claims.get("azp") or "unknown")
        subject = claims.get("sub")
        expires_at = claims.get("exp")
        return AccessToken(
            token=token,
            client_id=client_id,
            scopes=list(scopes),
            expires_at=int(expires_at) if isinstance(expires_at, int) else None,
            resource=self._audience,
            subject=str(subject) if subject is not None else None,
            claims=dict(claims),
        )


def create_http_app(settings: HttpServerSettings) -> Any:
    """Create the hardened ASGI app for one validated transport configuration."""

    auth_settings: AuthSettings | None = None
    token_verifier: Any = None
    custom_http_routes: list[Any] = []
    if settings.auth_mode == "oauth":
        assert settings.oauth_issuer is not None
        assert settings.oauth_jwks_url is not None
        assert settings.oauth_audience is not None
        assert settings.public_url is not None
        auth_settings = AuthSettings(
            issuer_url=AnyHttpUrl(settings.oauth_issuer),
            resource_server_url=AnyHttpUrl(settings.public_url),
            required_scopes=list(settings.oauth_required_scopes),
        )
        token_verifier = OAuthJwtTokenVerifier(
            issuer=settings.oauth_issuer,
            jwks_url=settings.oauth_jwks_url,
            audience=settings.oauth_audience,
            algorithms=settings.oauth_algorithms,
        )
    if settings.auth_mode == "local_oauth":
        assert settings.local_oauth is not None
        assert settings.public_url is not None
        provider = LocalOAuthProvider(settings.local_oauth)
        auth_settings = AuthSettings(
            issuer_url=AnyHttpUrl(settings.local_oauth.issuer),
            resource_server_url=AnyHttpUrl(settings.public_url),
            required_scopes=[settings.local_oauth.scope],
        )
        token_verifier = ProviderTokenVerifier(provider)
        custom_http_routes.extend(provider.authorization_routes())
        if settings.controlled_operation is not None:
            approval_service = LocalApprovalService(
                provider,
                settings.controlled_operation,
            )
            custom_http_routes.extend(approval_service.routes())

    server = FortiPamMcpServer(
        auth_settings=auth_settings,
        token_verifier=token_verifier,
        custom_http_routes=custom_http_routes,
        diagnostic_settings=settings.diagnostic,
        runtime_profile=settings.runtime_profile,
    )
    transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=list(settings.allowed_hosts),
        allowed_origins=list(settings.allowed_origins),
    )
    app: Any = server.mcp.streamable_http_app(
        streamable_http_path=settings.path,
        json_response=True,
        stateless_http=True,
        max_request_body_size=1_048_576,
        transport_security=transport_security,
        host=settings.host,
    )
    if settings.auth_mode == "bearer":
        assert settings.bearer_token is not None
        app = StaticBearerMiddleware(
            app,
            token=settings.bearer_token,
            protected_path=settings.path,
        )
    return AllowedHostMiddleware(app, allowed_hosts=settings.allowed_hosts)


def main() -> None:
    """Run the Streamable HTTP server from validated environment settings."""

    import uvicorn

    try:
        load_http_runtime_environment()
        settings = HttpServerSettings.from_environment()
    except (EnvironmentFileError, HttpConfigurationError) as exc:
        raise SystemExit(str(exc)) from None
    app = create_http_app(settings)
    config = uvicorn.Config(
        app,
        host=settings.host,
        port=settings.port,
        log_level="warning",
        access_log=False,
        server_header=False,
    )
    asyncio.run(uvicorn.Server(config).serve())


def load_http_runtime_environment() -> bool:
    """Load an owner-only HTTP settings file without disclosing its location."""

    configured = os.environ.get(HTTP_ENV_FILE_VARIABLE)
    if not configured:
        return False
    path = os.path.expanduser(configured)
    if not os.path.isfile(path):
        raise HttpConfigurationError("The configured HTTP environment file was not found.")
    environment_path = Path(path)
    load_prefixed_environment_file(environment_path, HTTP_PREFIX)
    load_prefixed_environment_file(environment_path, RUNTIME_PROFILE_ENV)
    load_prefixed_environment_file(environment_path, DIAGNOSTIC_PREFIX)
    load_prefixed_environment_file(environment_path, CONTROLLED_OPERATION_PREFIX)
    return True


def _value(environment: Mapping[str, str], suffix: str) -> str | None:
    raw = environment.get(f"{HTTP_PREFIX}{suffix}")
    if raw is None:
        return None
    value = raw.strip()
    return value or None


def _exact_value(environment: Mapping[str, str], name: str) -> str | None:
    raw = environment.get(name)
    if raw is None:
        return None
    value = raw.strip()
    return value or None


def _port(raw: str | None) -> int:
    if raw is None:
        return DEFAULT_PORT
    try:
        port = int(raw)
    except ValueError as exc:
        raise HttpConfigurationError("HTTP port must be numeric.") from exc
    if not 1 <= port <= 65535:
        raise HttpConfigurationError("HTTP port is outside the valid range.")
    return port


def _path(raw: str) -> str:
    if (
        not raw.startswith("/")
        or raw == "/"
        or raw.endswith("/")
        or "?" in raw
        or "#" in raw
        or "\\" in raw
        or any(segment in {".", ".."} for segment in raw.split("/"))
    ):
        raise HttpConfigurationError(
            "The MCP HTTP path must be one absolute path without traversal or a trailing slash."
        )
    return raw


def _csv(raw: str | None) -> tuple[str, ...]:
    if raw is None:
        return ()
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def _optional_https_url(raw: str | None, label: str) -> str | None:
    if raw is None:
        return None
    parsed = urlsplit(raw)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise HttpConfigurationError(f"The {label} must be an HTTPS URL.")
    return raw.rstrip("/")


def _is_loopback(host: str) -> bool:
    return host.lower() in {"127.0.0.1", "::1", "localhost"}


def _token_scopes(claims: Mapping[str, Any]) -> tuple[str, ...]:
    raw_scope = claims.get("scope")
    if isinstance(raw_scope, str):
        return tuple(item for item in raw_scope.split() if item)
    raw_scp = claims.get("scp")
    if isinstance(raw_scp, list):
        return tuple(str(item) for item in raw_scp if str(item))
    return ()


if __name__ == "__main__":
    main()
