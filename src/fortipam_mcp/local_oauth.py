"""Embedded OAuth 2.1 authorization service for a single local operator.

The MCP SDK owns the protocol endpoints and validation. This module provides
the local login, durable client registration, one-time authorization codes,
opaque access tokens, rotating refresh tokens, and revocation state.
"""

from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass
import getpass
from hashlib import scrypt, sha256
from html import escape
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import time
from typing import Any, Mapping
from urllib.parse import urlsplit

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    IdentityAssertionParams,
    RefreshToken,
    RegistrationError,
    TokenError,
    construct_redirect_uri,
)
from mcp.server.auth.handlers.metadata import MetadataHandler
from mcp.server.auth.routes import build_metadata, cors_middleware, create_auth_routes
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import AnyHttpUrl
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route

LOCAL_SCOPE = "fortipam:read"
LOCAL_DIAGNOSTIC_SCOPE = "fortipam:diagnostic"
LOCAL_OPERATION_SCOPE = "fortipam:operate"
LOCAL_SCOPES = (LOCAL_SCOPE, LOCAL_DIAGNOSTIC_SCOPE, LOCAL_OPERATION_SCOPE)
LOCAL_DEFAULT_SCOPES = (LOCAL_SCOPE, LOCAL_DIAGNOSTIC_SCOPE)
PASSWORD_SCHEME = "scrypt-v1"
PASSWORD_N = 2**15
PASSWORD_R = 8
PASSWORD_P = 1
PASSWORD_DKLEN = 32
PASSWORD_MAXMEM = 64 * 1024 * 1024
AUTHORIZATION_REQUEST_LIFETIME = 300
AUTHORIZATION_CODE_LIFETIME = 60
ACCESS_TOKEN_LIFETIME = 3600
REFRESH_TOKEN_LIFETIME = 30 * 24 * 3600
LOGIN_FAILURE_WINDOW = 900
LOGIN_LOCK_SECONDS = 300
MAX_LOGIN_FAILURES = 5
MAX_REGISTERED_CLIENTS = 32
CSRF_COOKIE = "fortipam_mcp_oauth_csrf"


class LocalOAuthConfigurationError(ValueError):
    """Raised when embedded OAuth state or credentials would be unsafe."""


@dataclass(frozen=True, slots=True)
class LocalOAuthSettings:
    """Validated settings for the embedded authorization service."""

    issuer: str
    resource: str
    database_path: Path
    username: str
    password_hash: str
    scope: str = LOCAL_SCOPE
    available_scopes: tuple[str, ...] = LOCAL_SCOPES
    default_scopes: tuple[str, ...] = LOCAL_DEFAULT_SCOPES


class StoredRefreshToken(RefreshToken):
    """Refresh token metadata retained by the local provider."""

    resource: str
    family_id: str


class LocalOAuthProvider:
    """SQLite-backed OAuth provider with a local password login."""

    def __init__(self, settings: LocalOAuthSettings) -> None:
        self.settings = settings
        self._validate_storage()
        self._initialize_database()
        self._bootstrap_operator()

    @property
    def login_path(self) -> str:
        """Return the authorization-service-local login path."""

        return f"{urlsplit(self.settings.issuer).path.rstrip('/')}/login"

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        """Load one dynamically registered OAuth client."""

        row = self._fetchone(
            "SELECT client_json FROM oauth_clients WHERE client_id = ?",
            (client_id,),
        )
        if row is None:
            return None
        try:
            return OAuthClientInformationFull.model_validate(json.loads(row["client_json"]))
        except (json.JSONDecodeError, ValueError):
            return None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        """Persist one constrained OAuth client registration."""

        self._validate_client_registration(client_info)
        encoded = json.dumps(
            client_info.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        )
        now = int(time.time())
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            count = connection.execute(
                "SELECT COUNT(*) FROM oauth_clients"
            ).fetchone()[0]
            if count >= MAX_REGISTERED_CLIENTS:
                raise RegistrationError(
                    error="invalid_client_metadata",
                    error_description="The local client registration limit was reached.",
                )
            connection.execute(
                "INSERT INTO oauth_clients(client_id, client_json, created_at) VALUES(?, ?, ?)",
                (client_info.client_id, encoded, now),
            )

    async def authorize(
        self,
        client: OAuthClientInformationFull,
        params: AuthorizationParams,
    ) -> str:
        """Create a pending login and consent request."""

        if params.resource != self.settings.resource:
            raise AuthorizeError(
                error="invalid_target",
                error_description="The resource must identify this MCP server.",
            )
        registered = set((client.scope or "").split())
        requested = params.scopes or [
            scope for scope in self.settings.default_scopes if scope in registered
        ]
        if (
            not requested
            or len(requested) != len(set(requested))
            or set(requested) - set(self.settings.available_scopes)
            or set(requested) - registered
            or self.settings.scope not in requested
        ):
            raise AuthorizeError(
                error="invalid_scope",
                error_description="The requested FortiPAM scope set is unavailable.",
            )
        scopes = [
            scope for scope in self.settings.available_scopes if scope in requested
        ]
        request_id = _random_token()
        now = int(time.time())
        with self._connect() as connection:
            self._prune(connection, now)
            connection.execute(
                """
                INSERT INTO pending_authorizations(
                    request_hash, client_id, scopes_json, code_challenge,
                    redirect_uri, redirect_explicit, resource, state,
                    csrf_hash, expires_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)
                """,
                (
                    _digest(request_id),
                    client.client_id,
                    json.dumps(scopes),
                    params.code_challenge,
                    str(params.redirect_uri),
                    int(params.redirect_uri_provided_explicitly),
                    params.resource,
                    params.state,
                    now + AUTHORIZATION_REQUEST_LIFETIME,
                ),
            )
        return f"{self.settings.issuer.rstrip('/')}/login?request_id={request_id}"

    async def load_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: str,
    ) -> AuthorizationCode | None:
        """Load an unexpired, unconsumed authorization code by digest."""

        row = self._fetchone(
            """
            SELECT * FROM authorization_codes
            WHERE code_hash = ? AND client_id = ? AND consumed_at IS NULL
            """,
            (_digest(authorization_code), client.client_id),
        )
        if row is None or row["expires_at"] < int(time.time()):
            return None
        return AuthorizationCode(
            code=authorization_code,
            scopes=json.loads(row["scopes_json"]),
            expires_at=float(row["expires_at"]),
            client_id=row["client_id"],
            code_challenge=row["code_challenge"],
            redirect_uri=row["redirect_uri"],
            redirect_uri_provided_explicitly=bool(row["redirect_explicit"]),
            resource=row["resource"],
            subject=row["subject"],
        )

    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        """Consume one code and issue an access/refresh token family."""

        now = int(time.time())
        family_id = secrets.token_hex(16)
        access_token = _random_token()
        refresh_token = _random_token()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            consumed = connection.execute(
                """
                UPDATE authorization_codes SET consumed_at = ?
                WHERE code_hash = ? AND client_id = ? AND consumed_at IS NULL
                    AND expires_at >= ?
                """,
                (
                    now,
                    _digest(authorization_code.code),
                    client.client_id,
                    now,
                ),
            )
            if consumed.rowcount != 1:
                raise TokenError(
                    error="invalid_grant",
                    error_description="The authorization code is no longer valid.",
                )
            self._insert_token(
                connection,
                access_token,
                "access",
                client.client_id,
                authorization_code.scopes,
                now + ACCESS_TOKEN_LIFETIME,
                authorization_code.resource or self.settings.resource,
                authorization_code.subject or self.settings.username,
                family_id,
            )
            issue_refresh = "refresh_token" in client.grant_types
            if issue_refresh:
                self._insert_token(
                    connection,
                    refresh_token,
                    "refresh",
                    client.client_id,
                    authorization_code.scopes,
                    now + REFRESH_TOKEN_LIFETIME,
                    authorization_code.resource or self.settings.resource,
                    authorization_code.subject or self.settings.username,
                    family_id,
                )
        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_LIFETIME,
            scope=" ".join(authorization_code.scopes),
            refresh_token=refresh_token if issue_refresh else None,
        )

    async def load_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: str,
    ) -> RefreshToken | None:
        """Load a live refresh token without storing its raw value."""

        row = self._load_token(refresh_token, "refresh", client.client_id)
        if row is None:
            return None
        return StoredRefreshToken(
            token=refresh_token,
            client_id=row["client_id"],
            scopes=json.loads(row["scopes_json"]),
            expires_at=row["expires_at"],
            subject=row["subject"],
            resource=row["resource"],
            family_id=row["family_id"],
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        """Rotate a refresh-token family and issue a fresh access token."""

        if not isinstance(refresh_token, StoredRefreshToken):
            raise TokenError(
                error="invalid_grant",
                error_description="The refresh token metadata is invalid.",
            )
        if any(scope not in refresh_token.scopes for scope in scopes):
            raise TokenError(
                error="invalid_scope",
                error_description="The refresh request cannot expand its original scope.",
            )
        now = int(time.time())
        new_access = _random_token()
        new_refresh = _random_token()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                """
                SELECT token_hash FROM oauth_tokens
                WHERE token_hash = ? AND token_type = 'refresh'
                    AND client_id = ? AND revoked_at IS NULL AND expires_at >= ?
                """,
                (_digest(refresh_token.token), client.client_id, now),
            ).fetchone()
            if current is None:
                raise TokenError(
                    error="invalid_grant",
                    error_description="The refresh token is no longer valid.",
                )
            connection.execute(
                "UPDATE oauth_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL",
                (now, refresh_token.family_id),
            )
            self._insert_token(
                connection,
                new_access,
                "access",
                client.client_id,
                scopes,
                now + ACCESS_TOKEN_LIFETIME,
                refresh_token.resource,
                refresh_token.subject or self.settings.username,
                refresh_token.family_id,
            )
            self._insert_token(
                connection,
                new_refresh,
                "refresh",
                client.client_id,
                scopes,
                now + REFRESH_TOKEN_LIFETIME,
                refresh_token.resource,
                refresh_token.subject or self.settings.username,
                refresh_token.family_id,
            )
        return OAuthToken(
            access_token=new_access,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_LIFETIME,
            scope=" ".join(scopes),
            refresh_token=new_refresh,
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        """Verify one opaque access token for the MCP auth middleware."""

        row = self._load_token(token, "access")
        if row is None or row["resource"] != self.settings.resource:
            return None
        return AccessToken(
            token=token,
            client_id=row["client_id"],
            scopes=json.loads(row["scopes_json"]),
            expires_at=row["expires_at"],
            resource=row["resource"],
            subject=row["subject"],
            claims={"iss": self.settings.issuer},
        )

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        """Revoke the complete token family for one supplied token."""

        now = int(time.time())
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT family_id FROM oauth_tokens WHERE token_hash = ?",
                (_digest(token.token),),
            ).fetchone()
            if row is not None:
                connection.execute(
                    "UPDATE oauth_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL",
                    (now, row["family_id"]),
                )

    async def exchange_identity_assertion(
        self,
        client: OAuthClientInformationFull,
        params: IdentityAssertionParams,
    ) -> OAuthToken:
        """Reject enterprise identity assertions in the local-only provider."""

        del client, params
        raise TokenError(
            error="unsupported_grant_type",
            error_description="Identity assertion grants are not enabled.",
        )

    async def login(self, request: Request) -> Response:
        """Render or process the local login and consent page."""

        if request.method == "GET":
            return self._render_login(request)
        return await self._process_login(request)

    async def authenticate_operator(self, username: str, password: str) -> bool:
        """Authenticate the local operator with the shared lockout policy."""

        return await asyncio.to_thread(
            self._verify_and_record_login,
            username,
            password,
        )

    def authorization_routes(self) -> list[Route]:
        """Return path-prefixed SDK OAuth routes plus the local login route."""

        issuer = AnyHttpUrl(self.settings.issuer)
        registration_options = ClientRegistrationOptions(
            enabled=True,
            client_secret_expiry_seconds=30 * 24 * 3600,
            valid_scopes=list(self.settings.available_scopes),
            default_scopes=list(self.settings.default_scopes),
        )
        revocation_options = RevocationOptions(enabled=True)
        routes = create_auth_routes(
            provider=self,
            issuer_url=issuer,
            client_registration_options=registration_options,
            revocation_options=revocation_options,
        )
        issuer_path = urlsplit(self.settings.issuer).path.rstrip("/")
        rewritten: list[Route] = []
        for route in routes:
            if route.path == "/.well-known/oauth-authorization-server":
                metadata = build_metadata(
                    issuer,
                    None,
                    registration_options,
                    revocation_options,
                )
                metadata.token_endpoint_auth_methods_supported = [
                    "none",
                    "client_secret_post",
                    "client_secret_basic",
                ]
                rewritten.append(
                    Route(
                        f"{route.path}{issuer_path}",
                        endpoint=cors_middleware(
                            MetadataHandler(metadata).handle,
                            ["GET", "OPTIONS"],
                        ),
                        methods=["GET", "OPTIONS"],
                    )
                )
                continue
            else:
                path = f"{issuer_path}{route.path}"
            rewritten.append(
                Route(
                    path,
                    endpoint=route.endpoint,
                    methods=sorted(route.methods or ()),
                )
            )
        rewritten.append(
            Route(self.login_path, endpoint=self.login, methods=["GET", "POST"])
        )
        return rewritten

    def _render_login(
        self,
        request: Request,
        *,
        error: str | None = None,
        request_id: str | None = None,
        status_code: int = 200,
    ) -> Response:
        request_id = request_id or request.query_params.get("request_id", "")
        pending = self._pending(request_id)
        if pending is None:
            return _html_page(
                "Authorization request expired",
                "Return to the MCP client and start the connection again.",
                status_code=400,
            )
        csrf_token = _random_token()
        with self._connect() as connection:
            connection.execute(
                "UPDATE pending_authorizations SET csrf_hash = ? WHERE request_hash = ?",
                (_digest(csrf_token), _digest(request_id)),
            )
        client = self._client_display(pending["client_id"])
        message = (
            f'<p role="alert">{escape(error)}</p>' if error else ""
        )
        body = f"""
<h1>Authorize FortiPAM MCP</h1>
<p>Client: <strong>{escape(client)}</strong></p>
<p>Permission: {escape(_scope_description(json.loads(pending["scopes_json"])))}</p>
{message}
<form method="post" action="{escape(self.login_path)}">
  <input type="hidden" name="request_id" value="{escape(request_id)}">
  <input type="hidden" name="csrf_token" value="{escape(csrf_token)}">
  <label>Username <input name="username" autocomplete="username" required></label><br>
  <label>Password <input type="password" name="password" autocomplete="current-password" required></label><br>
  <button type="submit" name="action" value="allow">Allow read-only access</button>
  <button type="submit" name="action" value="deny" formnovalidate>Deny</button>
</form>
"""
        response = _html_page(
            "Authorize FortiPAM MCP",
            body,
            raw_body=True,
            status_code=status_code,
        )
        response.set_cookie(
            CSRF_COOKIE,
            csrf_token,
            max_age=AUTHORIZATION_REQUEST_LIFETIME,
            secure=True,
            httponly=True,
            samesite="lax",
            path=self.login_path,
        )
        return response

    async def _process_login(self, request: Request) -> Response:
        content_length = request.headers.get("content-length")
        if content_length and (not content_length.isdigit() or int(content_length) > 8192):
            return _html_page("Invalid request", "The submitted form is too large.", status_code=400)
        expected_origin = _origin(self.settings.issuer)
        supplied_origin = request.headers.get("origin")
        if supplied_origin and supplied_origin != expected_origin:
            return _html_page("Invalid request", "The request origin was rejected.", status_code=400)
        form = await request.form()
        request_id = _form_value(form, "request_id")
        csrf_token = _form_value(form, "csrf_token")
        pending = self._pending(request_id)
        cookie_token = request.cookies.get(CSRF_COOKIE, "")
        valid_csrf = (
            pending is not None
            and bool(csrf_token)
            and bool(cookie_token)
            and secrets.compare_digest(csrf_token, cookie_token)
            and pending["csrf_hash"] is not None
            and secrets.compare_digest(_digest(csrf_token), pending["csrf_hash"])
        )
        if not valid_csrf or pending is None:
            return _html_page("Invalid request", "The authorization request was rejected.", status_code=400)

        action = _form_value(form, "action")
        if action == "deny":
            self._delete_pending(request_id)
            response = RedirectResponse(
                construct_redirect_uri(
                    pending["redirect_uri"],
                    error="access_denied",
                    error_description="The local operator denied access.",
                    state=pending["state"],
                    iss=self.settings.issuer,
                ),
                status_code=302,
                headers={"Cache-Control": "no-store"},
            )
            self._clear_csrf_cookie(response)
            return response
        if action != "allow":
            return self._render_login(
                request,
                error="The authorization choice was invalid.",
                request_id=request_id,
                status_code=400,
            )

        username = _form_value(form, "username")
        password = _form_value(form, "password")
        accepted = await self.authenticate_operator(username, password)
        if not accepted:
            return self._render_login(
                request,
                error="Login failed. Try again later.",
                request_id=request_id,
                status_code=401,
            )

        code = _random_token()
        now = int(time.time())
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                "SELECT * FROM pending_authorizations WHERE request_hash = ? AND expires_at >= ?",
                (_digest(request_id), now),
            ).fetchone()
            if current is None:
                return _html_page(
                    "Authorization request expired",
                    "Return to the MCP client and start the connection again.",
                    status_code=400,
                )
            connection.execute(
                """
                INSERT INTO authorization_codes(
                    code_hash, client_id, scopes_json, code_challenge,
                    redirect_uri, redirect_explicit, resource, subject,
                    expires_at, consumed_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    _digest(code),
                    current["client_id"],
                    current["scopes_json"],
                    current["code_challenge"],
                    current["redirect_uri"],
                    current["redirect_explicit"],
                    current["resource"],
                    self.settings.username,
                    now + AUTHORIZATION_CODE_LIFETIME,
                ),
            )
            connection.execute(
                "DELETE FROM pending_authorizations WHERE request_hash = ?",
                (_digest(request_id),),
            )
        response = RedirectResponse(
            construct_redirect_uri(
                pending["redirect_uri"],
                code=code,
                state=pending["state"],
                iss=self.settings.issuer,
            ),
            status_code=302,
            headers={"Cache-Control": "no-store"},
        )
        self._clear_csrf_cookie(response)
        return response

    def _validate_storage(self) -> None:
        path = self.settings.database_path
        if not path.is_absolute():
            raise LocalOAuthConfigurationError("The local OAuth database path must be absolute.")
        parent = path.parent
        if not parent.is_dir() or parent.is_symlink():
            raise LocalOAuthConfigurationError("The local OAuth database directory is unavailable.")
        parent_mode = stat.S_IMODE(parent.stat().st_mode)
        if parent_mode & 0o077:
            raise LocalOAuthConfigurationError(
                "The local OAuth database directory must be owner-only (mode 700)."
            )
        if path.exists():
            if path.is_symlink() or not path.is_file():
                raise LocalOAuthConfigurationError("The local OAuth database path is unsafe.")
            if stat.S_IMODE(path.stat().st_mode) & 0o077:
                raise LocalOAuthConfigurationError(
                    "The local OAuth database must be owner-only (mode 600)."
                )

    def _initialize_database(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS oauth_clients (
                    client_id TEXT PRIMARY KEY,
                    client_json TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS local_users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    failure_count INTEGER NOT NULL DEFAULT 0,
                    first_failure_at INTEGER,
                    locked_until INTEGER
                );
                CREATE TABLE IF NOT EXISTS pending_authorizations (
                    request_hash TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL,
                    scopes_json TEXT NOT NULL,
                    code_challenge TEXT NOT NULL,
                    redirect_uri TEXT NOT NULL,
                    redirect_explicit INTEGER NOT NULL,
                    resource TEXT NOT NULL,
                    state TEXT,
                    csrf_hash TEXT,
                    expires_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS authorization_codes (
                    code_hash TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL,
                    scopes_json TEXT NOT NULL,
                    code_challenge TEXT NOT NULL,
                    redirect_uri TEXT NOT NULL,
                    redirect_explicit INTEGER NOT NULL,
                    resource TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    consumed_at INTEGER
                );
                CREATE TABLE IF NOT EXISTS oauth_tokens (
                    token_hash TEXT PRIMARY KEY,
                    token_type TEXT NOT NULL CHECK(token_type IN ('access', 'refresh')),
                    client_id TEXT NOT NULL,
                    scopes_json TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    resource TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    family_id TEXT NOT NULL,
                    revoked_at INTEGER
                );
                CREATE INDEX IF NOT EXISTS oauth_tokens_family_idx
                    ON oauth_tokens(family_id);
                """
            )
        os.chmod(self.settings.database_path, 0o600)

    def _bootstrap_operator(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO local_users(username, password_hash)
                VALUES(?, ?)
                ON CONFLICT(username) DO UPDATE SET password_hash = excluded.password_hash
                """,
                (self.settings.username, self.settings.password_hash),
            )

    def _validate_client_registration(self, client: OAuthClientInformationFull) -> None:
        requested_scopes = (client.scope or "").split()
        if (
            not requested_scopes
            or len(requested_scopes) != len(set(requested_scopes))
            or self.settings.scope not in requested_scopes
            or set(requested_scopes) - set(self.settings.available_scopes)
        ):
            raise RegistrationError(
                error="invalid_client_metadata",
                error_description="The requested FortiPAM scope set is unavailable.",
            )
        if set(client.grant_types) - {"authorization_code", "refresh_token"}:
            raise RegistrationError(
                error="invalid_client_metadata",
                error_description="Only authorization_code and refresh_token grants are allowed.",
            )
        if set(client.response_types) != {"code"}:
            raise RegistrationError(
                error="invalid_client_metadata",
                error_description="Only the code response type is allowed.",
            )
        if client.token_endpoint_auth_method not in {
            "none",
            "client_secret_basic",
            "client_secret_post",
        }:
            raise RegistrationError(
                error="invalid_client_metadata",
                error_description="The requested token authentication method is unsupported.",
            )
        redirect_uris = client.redirect_uris or []
        if not redirect_uris or len(redirect_uris) > 8:
            raise RegistrationError(
                error="invalid_redirect_uri",
                error_description="One to eight exact redirect URIs are required.",
            )
        for redirect_uri in redirect_uris:
            parsed = urlsplit(str(redirect_uri))
            loopback = parsed.hostname in {"127.0.0.1", "::1", "localhost"}
            if (
                parsed.username
                or parsed.password
                or parsed.fragment
                or not parsed.hostname
                or (parsed.scheme != "https" and not (parsed.scheme == "http" and loopback))
            ):
                raise RegistrationError(
                    error="invalid_redirect_uri",
                    error_description="Redirect URIs must use HTTPS or an HTTP loopback address.",
                )

    def _verify_and_record_login(self, username: str, password: str) -> bool:
        now = int(time.time())
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM local_users WHERE username = ?",
                (self.settings.username,),
            ).fetchone()
            if row is None:
                return False
            if row["locked_until"] and row["locked_until"] > now:
                return False
            first_failure = row["first_failure_at"]
            failure_count = row["failure_count"]
            if first_failure is None or first_failure < now - LOGIN_FAILURE_WINDOW:
                failure_count = 0
                first_failure = now
            valid_username = secrets.compare_digest(
                username.encode("utf-8"),
                self.settings.username.encode("utf-8"),
            )
            valid_password = verify_local_password(password, row["password_hash"])
            valid = valid_username and valid_password
            if valid:
                connection.execute(
                    """
                    UPDATE local_users SET failure_count = 0,
                        first_failure_at = NULL, locked_until = NULL
                    WHERE username = ?
                    """,
                    (self.settings.username,),
                )
                return True
            failure_count += 1
            locked_until = now + LOGIN_LOCK_SECONDS if failure_count >= MAX_LOGIN_FAILURES else None
            connection.execute(
                """
                UPDATE local_users SET failure_count = ?, first_failure_at = ?, locked_until = ?
                WHERE username = ?
                """,
                (failure_count, first_failure, locked_until, self.settings.username),
            )
            return False

    def _pending(self, request_id: str) -> sqlite3.Row | None:
        if not request_id:
            return None
        return self._fetchone(
            "SELECT * FROM pending_authorizations WHERE request_hash = ? AND expires_at >= ?",
            (_digest(request_id), int(time.time())),
        )

    def _delete_pending(self, request_id: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM pending_authorizations WHERE request_hash = ?",
                (_digest(request_id),),
            )

    def _client_display(self, client_id: str) -> str:
        row = self._fetchone(
            "SELECT client_json FROM oauth_clients WHERE client_id = ?",
            (client_id,),
        )
        if row is None:
            return "Unknown client"
        try:
            data = json.loads(row["client_json"])
        except json.JSONDecodeError:
            return "Unknown client"
        name = data.get("client_name")
        return str(name) if name else client_id

    def _load_token(
        self,
        token: str,
        token_type: str,
        client_id: str | None = None,
    ) -> sqlite3.Row | None:
        parameters: list[object] = [_digest(token), token_type, int(time.time())]
        query = """
            SELECT * FROM oauth_tokens
            WHERE token_hash = ? AND token_type = ? AND revoked_at IS NULL AND expires_at >= ?
        """
        if client_id is not None:
            query += " AND client_id = ?"
            parameters.append(client_id)
        return self._fetchone(query, tuple(parameters))

    def _insert_token(
        self,
        connection: sqlite3.Connection,
        token: str,
        token_type: str,
        client_id: str,
        scopes: list[str],
        expires_at: int,
        resource: str,
        subject: str,
        family_id: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO oauth_tokens(
                token_hash, token_type, client_id, scopes_json, expires_at,
                resource, subject, family_id, revoked_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, NULL)
            """,
            (
                _digest(token),
                token_type,
                client_id,
                json.dumps(scopes),
                expires_at,
                resource,
                subject,
                family_id,
            ),
        )

    def _fetchone(self, query: str, parameters: tuple[object, ...]) -> sqlite3.Row | None:
        with self._connect() as connection:
            row: sqlite3.Row | None = connection.execute(query, parameters).fetchone()
            return row

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.settings.database_path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @staticmethod
    def _prune(connection: sqlite3.Connection, now: int) -> None:
        connection.execute("DELETE FROM pending_authorizations WHERE expires_at < ?", (now,))
        connection.execute("DELETE FROM authorization_codes WHERE expires_at < ?", (now,))
        connection.execute("DELETE FROM oauth_tokens WHERE expires_at < ?", (now,))

    def _clear_csrf_cookie(self, response: Response) -> None:
        response.delete_cookie(
            CSRF_COOKIE,
            path=self.login_path,
            secure=True,
            httponly=True,
            samesite="lax",
        )


def local_oauth_settings_from_environment(
    environment: Mapping[str, str],
    *,
    prefix: str,
    public_url: str,
) -> LocalOAuthSettings:
    """Load embedded OAuth settings from a prefixed environment mapping."""

    issuer = _environment_value(environment, prefix, "LOCAL_OAUTH_ISSUER")
    if issuer is None:
        issuer = f"{public_url.rstrip('/')}/oauth"
    parsed_issuer = urlsplit(issuer)
    parsed_resource = urlsplit(public_url)
    if (
        parsed_issuer.scheme != "https"
        or parsed_issuer.netloc != parsed_resource.netloc
        or not parsed_issuer.path
        or parsed_issuer.path == "/"
        or parsed_issuer.query
        or parsed_issuer.fragment
        or parsed_issuer.username
        or parsed_issuer.password
        or not parsed_issuer.path.startswith(f"{parsed_resource.path.rstrip('/')}/")
        or any(segment in {".", ".."} for segment in parsed_issuer.path.split("/"))
    ):
        raise LocalOAuthConfigurationError(
            "The local OAuth issuer must be a path-based HTTPS URL on the MCP public host."
        )
    database = _environment_value(environment, prefix, "LOCAL_OAUTH_DB")
    username = _environment_value(environment, prefix, "LOCAL_OAUTH_USERNAME")
    password_hash = _environment_value(environment, prefix, "LOCAL_OAUTH_PASSWORD_HASH")
    missing = [
        label
        for label, value in (
            ("LOCAL_OAUTH_DB", database),
            ("LOCAL_OAUTH_USERNAME", username),
            ("LOCAL_OAUTH_PASSWORD_HASH", password_hash),
        )
        if value is None
    ]
    if missing:
        raise LocalOAuthConfigurationError(
            "Local OAuth requires a database path, username, and password hash."
        )
    assert database is not None
    assert username is not None
    assert password_hash is not None
    if not (1 <= len(username) <= 64) or any(character.isspace() for character in username):
        raise LocalOAuthConfigurationError(
            "The local OAuth username must contain 1-64 non-whitespace characters."
        )
    _parse_password_hash(password_hash)
    return LocalOAuthSettings(
        issuer=issuer.rstrip("/"),
        resource=public_url,
        database_path=Path(database).expanduser(),
        username=username,
        password_hash=password_hash,
    )


def hash_local_password(password: str, *, salt: bytes | None = None) -> str:
    """Create the only accepted owner password hash format."""

    if len(password) < 14:
        raise LocalOAuthConfigurationError(
            "The local OAuth password must contain at least 14 characters."
        )
    chosen_salt = salt or secrets.token_bytes(16)
    derived = scrypt(
        password.encode("utf-8"),
        salt=chosen_salt,
        n=PASSWORD_N,
        r=PASSWORD_R,
        p=PASSWORD_P,
        dklen=PASSWORD_DKLEN,
        maxmem=PASSWORD_MAXMEM,
    )
    return "$".join(
        (
            PASSWORD_SCHEME,
            str(PASSWORD_N),
            str(PASSWORD_R),
            str(PASSWORD_P),
            _b64(chosen_salt),
            _b64(derived),
        )
    )


def verify_local_password(password: str, encoded: str) -> bool:
    """Verify a local operator password without disclosing parsing failures."""

    try:
        salt, expected = _parse_password_hash(encoded)
        actual = scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=PASSWORD_N,
            r=PASSWORD_R,
            p=PASSWORD_P,
            dklen=PASSWORD_DKLEN,
            maxmem=PASSWORD_MAXMEM,
        )
    except (LocalOAuthConfigurationError, ValueError):
        return False
    return secrets.compare_digest(actual, expected)


def _scope_description(scopes: object) -> str:
    if not isinstance(scopes, list) or any(type(scope) is not str for scope in scopes):
        return "invalid scope request"
    labels = ["read-only FortiPAM posture and local advisory knowledge"]
    if LOCAL_DIAGNOSTIC_SCOPE in scopes:
        labels.append("fixed local diagnostic state")
    if LOCAL_OPERATION_SCOPE in scopes:
        labels.append("controlled-operation authorization (no device action is enabled)")
    return "; ".join(labels)


def password_hash_main() -> None:
    """Interactively create a deployment password verifier."""

    password = getpass.getpass("Local OAuth password: ")
    confirmation = getpass.getpass("Confirm local OAuth password: ")
    if not secrets.compare_digest(
        password.encode("utf-8"), confirmation.encode("utf-8")
    ):
        raise SystemExit("The passwords did not match.")
    try:
        encoded = hash_local_password(password)
    except LocalOAuthConfigurationError as exc:
        raise SystemExit(str(exc)) from None
    print(encoded)


def _parse_password_hash(encoded: str) -> tuple[bytes, bytes]:
    parts = encoded.split("$")
    if len(parts) != 6 or parts[:4] != [
        PASSWORD_SCHEME,
        str(PASSWORD_N),
        str(PASSWORD_R),
        str(PASSWORD_P),
    ]:
        raise LocalOAuthConfigurationError("The local OAuth password hash format is invalid.")
    try:
        salt = _unb64(parts[4])
        expected = _unb64(parts[5])
    except ValueError as exc:
        raise LocalOAuthConfigurationError(
            "The local OAuth password hash format is invalid."
        ) from exc
    if len(salt) != 16 or len(expected) != PASSWORD_DKLEN:
        raise LocalOAuthConfigurationError("The local OAuth password hash format is invalid.")
    return salt, expected


def _html_page(
    title: str,
    body: str,
    *,
    status_code: int = 200,
    raw_body: bool = False,
) -> HTMLResponse:
    content = body if raw_body else f"<h1>{escape(title)}</h1><p>{escape(body)}</p>"
    response = HTMLResponse(
        f"<!doctype html><html lang=\"en\"><meta charset=\"utf-8\">"
        f"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        f"<title>{escape(title)}</title><body>{content}</body></html>",
        status_code=status_code,
    )
    response.headers.update(
        {
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
            "Content-Security-Policy": "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        }
    )
    return response


def _random_token() -> str:
    return secrets.token_urlsafe(32)


def _digest(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.b64decode(value + padding, altchars=b"-_", validate=True)


def _origin(url: str) -> str:
    parsed = urlsplit(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _form_value(form: Any, name: str) -> str:
    value = form.get(name)
    return value if isinstance(value, str) else ""


def _environment_value(
    environment: Mapping[str, str],
    prefix: str,
    suffix: str,
) -> str | None:
    raw = environment.get(f"{prefix}{suffix}")
    if raw is None:
        return None
    value = raw.strip()
    return value or None
