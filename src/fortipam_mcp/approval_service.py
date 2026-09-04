"""Local human approval route for future controlled FortiPAM operations.

The route can decide only approvals that were already issued by the closed
controlled-operation store. It cannot create an approval, register an action,
or call a FortiPAM transport.
"""

from __future__ import annotations

from dataclasses import dataclass
from html import escape
from pathlib import Path
import secrets
from typing import Any, Mapping
from urllib.parse import urlsplit

from starlette.requests import Request
from starlette.responses import HTMLResponse, Response
from starlette.routing import Route

from .controlled_operation_store import (
    ControlledOperationStateStore,
    ControlledOperationStoreError,
    PersistentControlledOperationEngineStore,
)
from .controlled_operations import (
    ActionRegistry,
    ApprovalRejected,
    ControlledOperationEngine,
    DenyAllControlledOperationAdapter,
)
from .local_oauth import LocalOAuthProvider


CONTROLLED_OPERATION_PREFIX = "FORTIPAM_MCP_CONTROLLED_OPERATION_"
CONTROLLED_OPERATION_DB_ENV = f"{CONTROLLED_OPERATION_PREFIX}DB"
CONTROLLED_OPERATION_HMAC_KEY_FILE_ENV = (
    f"{CONTROLLED_OPERATION_PREFIX}HMAC_KEY_FILE"
)
APPROVAL_CSRF_COOKIE = "fortipam_mcp_operation_csrf"
APPROVAL_FORM_LIMIT = 8192


class ApprovalServiceConfigurationError(ValueError):
    """Raised when the local approval boundary is incomplete or unsafe."""


@dataclass(frozen=True, slots=True)
class ApprovalServiceSettings:
    """Owner-only persistent state paths for the local approval service."""

    database_path: Path
    hmac_key_path: Path


def approval_settings_from_environment(
    environment: Mapping[str, str],
) -> ApprovalServiceSettings | None:
    """Return complete approval settings or fail closed on a partial pair."""

    database = _value(environment, CONTROLLED_OPERATION_DB_ENV)
    key = _value(environment, CONTROLLED_OPERATION_HMAC_KEY_FILE_ENV)
    if database is None and key is None:
        return None
    if database is None or key is None:
        raise ApprovalServiceConfigurationError(
            "Controlled-operation state requires both database and HMAC key paths."
        )
    database_path = Path(database).expanduser()
    key_path = Path(key).expanduser()
    if not database_path.is_absolute() or not key_path.is_absolute():
        raise ApprovalServiceConfigurationError(
            "Controlled-operation state paths must be absolute."
        )
    return ApprovalServiceSettings(database_path, key_path)


class LocalApprovalService:
    """Password-authenticated CSRF-protected decision route.

    V3.0 intentionally has no product action registry. Consequently, a normal
    deployment has no pending approvals; the route exists so the trust boundary
    can be accepted independently before any device action is admitted.
    """

    def __init__(
        self,
        provider: LocalOAuthProvider,
        settings: ApprovalServiceSettings,
    ) -> None:
        self._provider = provider
        try:
            self.store = ControlledOperationStateStore(
                settings.database_path,
                settings.hmac_key_path,
            )
        except ControlledOperationStoreError as exc:
            raise ApprovalServiceConfigurationError(str(exc)) from exc
        self.engine = ControlledOperationEngine(
            ActionRegistry((), ()),
            DenyAllControlledOperationAdapter(),
            self.store,
            PersistentControlledOperationEngineStore(self.store),
        )
        issuer_path = urlsplit(provider.settings.issuer).path.rstrip("/")
        self.path = f"{issuer_path}/approval"
        resource = urlsplit(provider.settings.resource)
        self._origin = f"{resource.scheme}://{resource.netloc}"

    def routes(self) -> list[Route]:
        return [Route(self.path, endpoint=self.handle, methods=["GET", "POST"])]

    async def handle(self, request: Request) -> Response:
        if request.method == "GET":
            return self._render_form()
        return await self._process(request)

    def _render_form(
        self,
        *,
        message: str | None = None,
        status_code: int = 200,
    ) -> Response:
        csrf_token = secrets.token_urlsafe(32)
        notice = (
            f'<p role="status">{escape(message)}</p>' if message is not None else ""
        )
        body = f"""
<h1>FortiPAM controlled-operation approval</h1>
<p>V3.0 enables the local approval boundary, but no FortiPAM device action is registered.</p>
<p>Only a reference and nonce issued by this server can be decided.</p>
{notice}
<form method="post" action="{escape(self.path)}">
  <input type="hidden" name="csrf_token" value="{escape(csrf_token)}">
  <label>Approval reference <input name="approval_reference" autocomplete="off" required></label><br>
  <label>Approval nonce <input type="password" name="approval_nonce" autocomplete="off" required></label><br>
  <label>Username <input name="username" autocomplete="username" required></label><br>
  <label>Password <input type="password" name="password" autocomplete="current-password" required></label><br>
  <button type="submit" name="action" value="approve">Approve once</button>
  <button type="submit" name="action" value="deny">Deny</button>
</form>
"""
        response = _html_page(body, status_code=status_code)
        response.set_cookie(
            APPROVAL_CSRF_COOKIE,
            csrf_token,
            max_age=300,
            secure=True,
            httponly=True,
            samesite="strict",
            path=self.path,
        )
        return response

    async def _process(self, request: Request) -> Response:
        content_length = request.headers.get("content-length")
        if content_length and (
            not content_length.isdigit() or int(content_length) > APPROVAL_FORM_LIMIT
        ):
            return _html_page("<h1>Approval rejected</h1>", status_code=400)
        origin = request.headers.get("origin")
        if origin is not None and origin != self._origin:
            return _html_page("<h1>Approval rejected</h1>", status_code=400)
        form = await request.form()
        csrf_token = _form_value(form, "csrf_token")
        csrf_cookie = request.cookies.get(APPROVAL_CSRF_COOKIE, "")
        if (
            not csrf_token
            or not csrf_cookie
            or not secrets.compare_digest(csrf_token, csrf_cookie)
        ):
            return _html_page("<h1>Approval rejected</h1>", status_code=400)
        action = _form_value(form, "action")
        if action not in {"approve", "deny"}:
            return self._render_form(message="Approval rejected.", status_code=400)
        username = _form_value(form, "username")
        password = _form_value(form, "password")
        if not await self._provider.authenticate_operator(username, password):
            return self._render_form(message="Approval rejected.", status_code=401)
        approval_reference = _form_value(form, "approval_reference")
        approval_nonce = _form_value(form, "approval_nonce")
        try:
            if action == "approve":
                self.store.approve(
                    approval_reference,
                    approval_nonce,
                    self._provider.settings.username,
                )
            else:
                self.store.deny(
                    approval_reference,
                    approval_nonce,
                    self._provider.settings.username,
                )
        except (ApprovalRejected, ControlledOperationStoreError):
            return self._render_form(message="Approval rejected.", status_code=400)
        response = _html_page(
            "<h1>Decision recorded</h1><p>The one-time approval state was updated.</p>"
        )
        response.delete_cookie(
            APPROVAL_CSRF_COOKIE,
            path=self.path,
            secure=True,
            httponly=True,
            samesite="strict",
        )
        return response


def _html_page(body: str, *, status_code: int = 200) -> HTMLResponse:
    response = HTMLResponse(
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        f"<title>FortiPAM approval</title><body>{body}</body></html>",
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


def _form_value(form: Any, name: str) -> str:
    value = form.get(name)
    return value if isinstance(value, str) else ""


def _value(environment: Mapping[str, str], name: str) -> str | None:
    raw = environment.get(name)
    if raw is None:
        return None
    value = raw.strip()
    return value or None
