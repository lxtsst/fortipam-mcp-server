"""Local-OAuth human intent confirmation for the V4 plan-only profile.

The browser route can only affirm or deny one exact persisted Final Intent
Summary after password reauthentication. It never approves a plan, accesses
C3 material, contacts FortiPAM, or authorizes execution.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from hashlib import sha256
from html import escape
from pathlib import Path
import secrets
import time
from typing import Any, Protocol
from urllib.parse import urlsplit

from starlette.requests import Request
from starlette.responses import HTMLResponse, Response
from starlette.routing import Route

from v4_planning import (
    AuthenticatedRequester,
    FinalIntentSummary,
    ObjectClass,
    VerifiedConfirmationInteraction,
)
from v4_planning.models import SummaryState
from v4_planning.confirmation import (
    PLAN_CONFIRMATION_SCOPE,
    build_challenge,
    build_invalidation,
    build_reauthentication,
)
from v4_planning.confirmation_persistence import (
    PersistentIntentConfirmationError,
    PersistentIntentConfirmationStore,
)
from v4_planning.store import ProtectedStoreError

from .local_oauth import LocalOAuthProvider


V4_CONFIRMATION_DB_ENV = "FORTIPAM_MCP_V4_PLAN_CONFIRMATION_DB"
V4_CONFIRMATION_STORE_HMAC_KEY_FILE_ENV = (
    "FORTIPAM_MCP_V4_PLAN_CONFIRMATION_STORE_HMAC_KEY_FILE"
)
V4_CONFIRMATION_RECEIPT_HMAC_KEY_FILE_ENV = (
    "FORTIPAM_MCP_V4_PLAN_CONFIRMATION_RECEIPT_HMAC_KEY_FILE"
)
CONFIRMATION_CSRF_COOKIE = "fortipam_mcp_v4_confirmation_csrf"
CONFIRMATION_REAUTH_COOKIE = "fortipam_mcp_v4_confirmation_reauth"
CONFIRMATION_FORM_LIMIT = 8192
CONFIRMATION_CHALLENGE_LIFETIME = 300
CONFIRMATION_REAUTH_LIFETIME = 120
_DISPLAY_FIELD_ALLOWLIST = {
    ObjectClass.APPROVAL_PROFILE_BINDING.value: frozenset({
        "exists", "profile_mode", "profile_ref",
    }),
    ObjectClass.SECRET_APPROVAL_BINDING.value: frozenset({
        "exists", "approval_profile_attached", "interactive_approval_required",
        "job_approval_required", "owner_bypass_allowed", "owned_original_baseline_verified",
    }),
    ObjectClass.ACCESS_GRANT.value: frozenset({"exists", "permission", "subject_class"}),
    ObjectClass.CLASSIFICATION_BINDING.value: frozenset({"exists"}),
    ObjectClass.FOLDER_BINDING.value: frozenset({"exists", "folder_ref"}),
    ObjectClass.FOLDER_POLICY_BINDING.value: frozenset({"exists", "policy_profile_ref"}),
    ObjectClass.LAUNCHER_BINDING.value: frozenset({"exists", "launcher_profile_ref"}),
    ObjectClass.POLICY_BINDING.value: frozenset({"exists", "policy_profile_ref"}),
    ObjectClass.PUBLIC_FOLDER.value: frozenset({"enabled", "exists"}),
    ObjectClass.SECRET_METADATA.value: frozenset({"exists", "inherit_permission"}),
    ObjectClass.TARGET.value: frozenset({"exists", "protocol", "connectivity_profile_ref"}),
    ObjectClass.TEMPLATE_BINDING.value: frozenset({"compatibility", "exists", "template_ref"}),
    ObjectClass.DOMAIN_TARGET_BINDING.value: frozenset({
        "exists", "profile_ref", "target_relation_matches",
    }),
    ObjectClass.DOMAIN_SECRET_METADATA.value: frozenset({
        "exists", "inherit_permission", "non_privileged_account", "services_disabled",
        "target_association_matches",
    }),
    ObjectClass.DISCOVERY_SOURCE_METADATA.value: frozenset({
        "exists", "source_type", "account_discovery", "domain_secret_ref",
        "periodic_scanning_disabled", "auto_onboarding_disabled", "existing_secret_method",
        "no_scan_timestamp",
    }),
    ObjectClass.WEB_SECRET_METADATA.value: frozenset({
        "exists", "inherit_permission", "session_recording",
    }),
    ObjectClass.WEB_TARGET_BINDING.value: frozenset({
        "exists", "profile_ref", "target_relation_matches",
    }),
    ObjectClass.TARGET_BOUND_WEB_SECRET_METADATA.value: frozenset({
        "exists", "inherit_permission", "session_recording", "http_service_enabled",
        "proxy_mode_enabled", "target_association_matches",
    }),
    ObjectClass.WEB_SECRET_SERVICE_BINDING.value: frozenset({"exists", "http_service_enabled"}),
    ObjectClass.RDP_EVENT_FILTER_BINDING.value: frozenset({"exists", "profile_ref"}),
    ObjectClass.SECRET_SESSION_CONTROLS_BINDING.value: frozenset({
        "exists", "recording_enabled", "clipboard_blocking_enabled", "rdp_event_filter_enabled",
        "rdp_event_filter_profile_matches", "profile_ref",
    }),
    ObjectClass.WINRM_COLLECTOR_METADATA.value: frozenset({
        "exists", "inherit_permission", "privileged_account", "owner_only_folder",
        "rdp_service_enabled", "recording_enabled", "rdp_event_filter_enabled",
        "rdp_event_filter_profile_matches", "non_rdp_services_disabled", "target_association_matches",
    }),
}


class V4ConfirmationHttpError(RuntimeError):
    """Stable failure for an incomplete or denied confirmation transport."""


@dataclass(frozen=True, slots=True)
class V4ConfirmationSettings:
    """Owner-only state paths for the local confirmation transport."""

    database_path: Path
    store_hmac_key_path: Path
    receipt_hmac_key_path: Path


class SummaryReader(Protocol):
    """Read one exact, integrity-verified planning Summary."""

    def get_summary(self, summary_ref: str, revision: int) -> FinalIntentSummary: ...


def confirmation_settings_from_environment(
    environment: Mapping[str, str],
) -> V4ConfirmationSettings | None:
    """Return complete confirmation settings or reject partial configuration."""

    values = tuple(
        _value(environment, name)
        for name in (
            V4_CONFIRMATION_DB_ENV,
            V4_CONFIRMATION_STORE_HMAC_KEY_FILE_ENV,
            V4_CONFIRMATION_RECEIPT_HMAC_KEY_FILE_ENV,
        )
    )
    if all(value is None for value in values):
        return None
    if any(value is None for value in values):
        raise V4ConfirmationHttpError(
            "V4 confirmation requires database, store HMAC key, and receipt HMAC key paths."
        )
    paths = tuple(Path(value).expanduser() for value in values if value is not None)
    if len(paths) != 3 or any(not path.is_absolute() for path in paths):
        raise V4ConfirmationHttpError(
            "V4 confirmation state paths must be absolute."
        )
    if len(set(paths)) != 3:
        raise V4ConfirmationHttpError(
            "V4 confirmation state and key paths must be distinct."
        )
    return V4ConfirmationSettings(*paths)


class LocalIntentConfirmationService:
    """Issue, render, record, and consume exact human intent decisions."""

    def __init__(
        self,
        provider: LocalOAuthProvider,
        settings: V4ConfirmationSettings,
        summary_reader: SummaryReader,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._provider = provider
        self._summary_reader = summary_reader
        self._clock = clock or (lambda: int(time.time()))
        try:
            self.store = PersistentIntentConfirmationStore(
                settings.database_path,
                settings.store_hmac_key_path,
                settings.receipt_hmac_key_path,
                clock=self._clock,
            )
        except PersistentIntentConfirmationError as exc:
            raise V4ConfirmationHttpError(str(exc)) from exc
        issuer = provider.settings.issuer.rstrip("/")
        issuer_parts = urlsplit(issuer)
        resource_parts = urlsplit(provider.settings.resource)
        self._route_path = f"{issuer_parts.path.rstrip('/')}/v4/confirm/{{challenge_token}}"
        self._url_prefix = f"{issuer}/v4/confirm"
        self._origin = f"{resource_parts.scheme}://{resource_parts.netloc}"

    def routes(self) -> list[Route]:
        return [Route(self._route_path, self.handle, methods=["GET", "POST"])]

    def issue(
        self,
        summary: FinalIntentSummary,
        requester: AuthenticatedRequester,
        *,
        principal_namespace_digest: str,
        now_epoch: int,
    ) -> str:
        """Persist one challenge and return its one-time browser URL."""

        if (
            requester.digest != summary.requester_digest
            or summary.state is not SummaryState.AWAITING_CONFIRMATION
            or now_epoch < summary.created_at
            or now_epoch >= summary.expires_at
        ):
            raise V4ConfirmationHttpError("Confirmation challenge could not be issued.")
        token = secrets.token_urlsafe(32)
        challenge = build_challenge(
            challenge_ref=f"intent-challenge-{secrets.token_hex(16)}",
            challenge_token_digest=_digest(token),
            requester_digest=requester.digest,
            principal_namespace_digest=principal_namespace_digest,
            audience_ref=summary.audience_ref,
            summary_ref=summary.summary_ref,
            summary_revision=summary.revision,
            summary_digest=summary.summary_digest,
            required_scope=PLAN_CONFIRMATION_SCOPE,
            issued_at=now_epoch,
            expires_at=min(
                summary.expires_at,
                now_epoch + CONFIRMATION_CHALLENGE_LIFETIME,
            ),
        )
        try:
            self.store.put_challenge(challenge)
        except PersistentIntentConfirmationError as exc:
            raise V4ConfirmationHttpError(
                "Confirmation challenge could not be issued."
            ) from exc
        return f"{self._url_prefix}/{token}"

    def verify(
        self,
        requester: AuthenticatedRequester,
        *,
        principal_namespace_digest: str,
        summary_ref: str,
        summary_revision: int,
        now_epoch: int,
    ) -> VerifiedConfirmationInteraction:
        """Verify a browser decision without consuming it before planning commits."""

        try:
            challenge = self.store.get_challenge_for_summary(
                summary_ref=summary_ref,
                summary_revision=summary_revision,
                requester_digest=requester.digest,
                principal_namespace_digest=principal_namespace_digest,
            )
            receipt = self.store.get_receipt_for_challenge(challenge.challenge_ref)
        except PersistentIntentConfirmationError as exc:
            raise V4ConfirmationHttpError(
                "Trusted human confirmation is unavailable."
            ) from exc
        if (
            now_epoch < receipt.issued_at
            or now_epoch >= receipt.expires_at
            or receipt.requester_digest != requester.digest
            or receipt.principal_namespace_digest != principal_namespace_digest
            or receipt.summary_ref != summary_ref
            or receipt.summary_revision != summary_revision
            or receipt.summary_digest != challenge.summary_digest
        ):
            raise V4ConfirmationHttpError("Trusted human confirmation is unavailable.")
        return VerifiedConfirmationInteraction(
            interaction_ref=receipt.interaction_ref,
            interaction_type="authenticated_human_confirmation",
            nonce_digest=receipt.nonce_digest,
            requester_digest=receipt.requester_digest,
            audience_ref=receipt.audience_ref,
            summary_ref=receipt.summary_ref,
            summary_revision=receipt.summary_revision,
            summary_digest=receipt.summary_digest,
            decision=receipt.decision,
            confirmed_at=receipt.issued_at,
            expires_at=receipt.expires_at,
        )

    def claim(
        self,
        requester: AuthenticatedRequester,
        *,
        principal_namespace_digest: str,
        summary_ref: str,
        summary_revision: int,
        now_epoch: int,
    ) -> None:
        """Idempotently mark one exact verified decision as MCP-consumed."""

        try:
            challenge = self.store.get_challenge_for_summary(
                summary_ref=summary_ref,
                summary_revision=summary_revision,
                requester_digest=requester.digest,
                principal_namespace_digest=principal_namespace_digest,
            )
            receipt = self.store.get_receipt_for_challenge(challenge.challenge_ref)
            self.store.claim_receipt(
                receipt.receipt_ref,
                claim_ref=f"intent-claim-{secrets.token_hex(16)}",
                now_epoch=now_epoch,
                requester_digest=requester.digest,
                principal_namespace_digest=principal_namespace_digest,
                summary_ref=summary_ref,
                summary_revision=summary_revision,
                summary_digest=challenge.summary_digest,
            )
        except PersistentIntentConfirmationError as exc:
            raise V4ConfirmationHttpError(
                "Trusted human confirmation is unavailable."
            ) from exc

    async def handle(self, request: Request) -> Response:
        token = request.path_params.get("challenge_token", "")
        if not _valid_token(token):
            return _page("Confirmation unavailable", status_code=404)
        try:
            challenge = self.store.get_challenge_by_token_digest(_digest(token))
        except PersistentIntentConfirmationError:
            return _page("Confirmation unavailable", status_code=404)
        now_epoch = self._now()
        if now_epoch < challenge.issued_at or now_epoch >= challenge.expires_at:
            return _page("Confirmation expired", status_code=410)
        if request.method == "GET":
            return self._render_reauthentication(request.url.path)
        return await self._process(request, challenge)

    async def _process(self, request: Request, challenge: Any) -> Response:
        if not _valid_form_request(request, self._origin):
            return _page("Confirmation rejected", status_code=400)
        form = await request.form()
        if not _valid_csrf(request, form):
            return _page("Confirmation rejected", status_code=400)
        action = _form_value(form, "action")
        if action == "review":
            return await self._reauthenticate(request, form, challenge)
        if action not in {"affirm", "deny"}:
            return _page("Confirmation rejected", status_code=400)
        return self._record_decision(request, challenge, action)

    async def _reauthenticate(
        self,
        request: Request,
        form: Any,
        challenge: Any,
    ) -> Response:
        username = _form_value(form, "username")
        password = _form_value(form, "password")
        if not await self._provider.authenticate_operator(username, password):
            return self._render_reauthentication(
                request.url.path,
                message="Authentication failed.",
                status_code=401,
            )
        now_epoch = self._now()
        session_token = secrets.token_urlsafe(32)
        reauthentication = build_reauthentication(
            reauthentication_ref=f"intent-reauth-{secrets.token_hex(16)}",
            reauthentication_session_digest=_digest(session_token),
            challenge_ref=challenge.challenge_ref,
            challenge_digest=challenge.record_digest,
            principal_namespace_digest=challenge.principal_namespace_digest,
            required_scope=PLAN_CONFIRMATION_SCOPE,
            authenticated_at=now_epoch,
            expires_at=min(
                challenge.expires_at,
                now_epoch + CONFIRMATION_REAUTH_LIFETIME,
            ),
        )
        try:
            summary = self._summary(challenge)
            self.store.put_reauthentication(reauthentication)
        except (PersistentIntentConfirmationError, V4ConfirmationHttpError):
            return _page("Confirmation unavailable", status_code=409)
        response = self._render_summary(request.url.path, summary)
        response.set_cookie(
            CONFIRMATION_REAUTH_COOKIE,
            session_token,
            max_age=max(1, reauthentication.expires_at - now_epoch),
            secure=True,
            httponly=True,
            samesite="strict",
            path=request.url.path,
        )
        return response

    def _record_decision(
        self,
        request: Request,
        challenge: Any,
        decision: str,
    ) -> Response:
        session_token = request.cookies.get(CONFIRMATION_REAUTH_COOKIE, "")
        try:
            reauthentication = self.store.get_reauthentication_for_challenge(
                challenge.challenge_ref
            )
            summary = self._summary(challenge)
        except (PersistentIntentConfirmationError, V4ConfirmationHttpError):
            return _page("Confirmation unavailable", status_code=409)
        now_epoch = self._now()
        if (
            not session_token
            or not secrets.compare_digest(
                _digest(session_token),
                reauthentication.reauthentication_session_digest,
            )
            or now_epoch < reauthentication.authenticated_at
            or now_epoch >= reauthentication.expires_at
        ):
            return _page("Reauthentication required", status_code=401)
        receipt = self.store.create_receipt(
            receipt_ref=f"intent-receipt-{secrets.token_hex(16)}",
            challenge_ref=challenge.challenge_ref,
            challenge_digest=challenge.record_digest,
            reauthentication_ref=reauthentication.reauthentication_ref,
            reauthentication_digest=reauthentication.record_digest,
            requester_digest=challenge.requester_digest,
            principal_namespace_digest=challenge.principal_namespace_digest,
            audience_ref=challenge.audience_ref,
            summary_ref=summary.summary_ref,
            summary_revision=summary.revision,
            summary_digest=summary.summary_digest,
            decision=decision,
            interaction_ref=f"human-interaction-{secrets.token_hex(16)}",
            nonce_digest=_digest(secrets.token_urlsafe(32)),
            required_scope=PLAN_CONFIRMATION_SCOPE,
            issued_at=now_epoch,
            expires_at=min(summary.expires_at, reauthentication.expires_at),
            one_time=True,
            execution_authorized=False,
        )
        invalidation = None
        if decision == "deny":
            invalidation = build_invalidation(
                invalidation_ref=f"summary-invalidation-{secrets.token_hex(16)}",
                receipt_ref=receipt.receipt_ref,
                receipt_digest=receipt.receipt_digest,
                summary_ref=summary.summary_ref,
                summary_revision=summary.revision,
                summary_digest=summary.summary_digest,
                requester_digest=summary.requester_digest,
                reason_code="requester_denied",
                invalidated_at=now_epoch,
            )
        try:
            self.store.put_receipt(receipt, invalidation=invalidation)
        except PersistentIntentConfirmationError:
            return _page("Confirmation unavailable", status_code=409)
        response = _page(
            "Decision recorded",
            body="The exact intent decision was recorded for one-time MCP consumption.",
        )
        _delete_confirmation_cookies(response, request.url.path)
        return response

    def _summary(self, challenge: Any) -> FinalIntentSummary:
        try:
            summary = self._summary_reader.get_summary(
                challenge.summary_ref,
                challenge.summary_revision,
            )
        except ProtectedStoreError as exc:
            raise V4ConfirmationHttpError("Confirmation Summary is unavailable.") from exc
        if (
            summary.summary_digest != challenge.summary_digest
            or summary.requester_digest != challenge.requester_digest
            or summary.audience_ref != challenge.audience_ref
            or self.store.summary_is_invalidated(summary.summary_ref, summary.revision)
        ):
            raise V4ConfirmationHttpError("Confirmation Summary is unavailable.")
        return summary

    def _render_reauthentication(
        self,
        path: str,
        *,
        message: str | None = None,
        status_code: int = 200,
    ) -> Response:
        csrf = secrets.token_urlsafe(32)
        notice = f'<p role="alert">{escape(message)}</p>' if message else ""
        body = f"""
<p>Reauthenticate before viewing the exact administrative intent.</p>
{notice}
<form method="post" action="{escape(path)}">
  <input type="hidden" name="csrf_token" value="{escape(csrf)}">
  <label>Username <input name="username" autocomplete="username" required></label><br>
  <label>Password <input type="password" name="password" autocomplete="current-password" required></label><br>
  <button type="submit" name="action" value="review">Review exact intent</button>
</form>
"""
        response = _page("FortiPAM V4 intent confirmation", body=body, status_code=status_code)
        response.set_cookie(
            CONFIRMATION_CSRF_COOKIE,
            csrf,
            max_age=CONFIRMATION_CHALLENGE_LIFETIME,
            secure=True,
            httponly=True,
            samesite="strict",
            path=path,
        )
        return response

    def _render_summary(self, path: str, summary: FinalIntentSummary) -> Response:
        csrf = secrets.token_urlsafe(32)
        body = _summary_html(summary, path=path, csrf_token=csrf)
        response = _page("Confirm exact FortiPAM administrative intent", body=body)
        response.set_cookie(
            CONFIRMATION_CSRF_COOKIE,
            csrf,
            max_age=CONFIRMATION_REAUTH_LIFETIME,
            secure=True,
            httponly=True,
            samesite="strict",
            path=path,
        )
        return response

    def _now(self) -> int:
        value = self._clock()
        if type(value) is not int:
            raise V4ConfirmationHttpError("Trusted confirmation clock is invalid.")
        return value


def _summary_html(
    summary: FinalIntentSummary,
    *,
    path: str,
    csrf_token: str,
) -> str:
    changes = "".join(_change_html(change.as_dict()) for change in summary.object_changes)
    return f"""
<p>Summary: <code>{escape(summary.summary_ref)}</code>, revision {summary.revision}</p>
<p>Outcome: <code>{escape(summary.outcome_code)}</code></p>
<p>Environment and scope: <code>[server-bound references]</code></p>
<h2>Current / Proposed / Expected</h2>{changes}
{_list_html("Unchanged boundary", summary.unchanged_boundary)}
{_list_html("Facts", summary.facts)}
{_list_html("Assumptions", summary.assumptions)}
{_list_html("Unresolved gaps", summary.unresolved_gaps)}
{_list_html("Risks and external effects", (summary.risk_class, *summary.external_effects))}
{_list_html("Verification", summary.verification_codes)}
{_list_html("Stop conditions", summary.stop_codes)}
<p>Maintenance: <code>{escape(summary.maintenance_class)}</code>; Reversibility: <code>{escape(summary.reversibility_class)}</code></p>
<form method="post" action="{escape(path)}">
  <input type="hidden" name="csrf_token" value="{escape(csrf_token)}">
  <button type="submit" name="action" value="affirm">Confirm this exact intent</button>
  <button type="submit" name="action" value="deny">Deny</button>
</form>
"""


def _change_html(change: Mapping[str, Any]) -> str:
    object_class = escape(str(change.get("object_class", "unknown")))
    change_kind = escape(str(change.get("change_kind", "unknown")))
    return (
        f"<section><h3>{object_class}: {change_kind}</h3>"
        + _field_table("Current", change.get("current_fields"), object_class)
        + _field_table("Proposed", change.get("projected_changes"), object_class)
        + _field_table("Expected", change.get("expected_fields"), object_class)
        + "</section>"
    )


def _field_table(title: str, value: object, object_class: str) -> str:
    fields = value if isinstance(value, Mapping) else {}
    allowed = _DISPLAY_FIELD_ALLOWLIST.get(object_class, frozenset())
    rows = "".join(
        f"<tr><th>{escape(str(key))}</th><td>{escape(_display_field(item))}</td></tr>"
        for key, item in sorted(fields.items(), key=lambda pair: str(pair[0]))
        if type(key) is str and key in allowed
    )
    return f"<h4>{escape(title)}</h4><table>{rows}</table>"


def _display_field(value: object) -> str:
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is str and len(value.encode("utf-8")) <= 512:
        return value
    return "[unsupported value excluded]"


def _list_html(title: str, values: tuple[str, ...]) -> str:
    items = "".join(f"<li><code>{escape(value)}</code></li>" for value in values)
    return f"<h2>{escape(title)}</h2><ul>{items}</ul>"


def _valid_form_request(request: Request, expected_origin: str) -> bool:
    content_length = request.headers.get("content-length")
    content_type = (
        request.headers.get("content-type", "")
        .split(";", 1)[0]
        .strip()
        .lower()
    )
    return (
        content_length is not None
        and content_length.isdigit()
        and 0 < int(content_length) <= CONFIRMATION_FORM_LIMIT
        and content_type == "application/x-www-form-urlencoded"
        and request.headers.get("origin") == expected_origin
    )


def _valid_csrf(request: Request, form: Any) -> bool:
    supplied = _form_value(form, "csrf_token")
    cookie = request.cookies.get(CONFIRMATION_CSRF_COOKIE, "")
    return bool(supplied and cookie and secrets.compare_digest(supplied, cookie))


def _form_value(form: Any, name: str) -> str:
    value = form.get(name)
    return value if isinstance(value, str) else ""


def _valid_token(value: object) -> bool:
    return (
        type(value) is str
        and 32 <= len(value) <= 128
        and all(character.isalnum() or character in "-_" for character in value)
    )


def _digest(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def _page(
    title: str,
    *,
    body: str | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    content = body if body is not None else f"<p>{escape(title)}</p>"
    response = HTMLResponse(
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\">"
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{escape(title)}</title><body><h1>{escape(title)}</h1>{content}</body></html>",
        status_code=status_code,
    )
    response.headers.update(
        {
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
            "Content-Security-Policy": "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
        }
    )
    return response


def _delete_confirmation_cookies(response: Response, path: str) -> None:
    for name in (CONFIRMATION_CSRF_COOKIE, CONFIRMATION_REAUTH_COOKIE):
        response.delete_cookie(
            name,
            path=path,
            secure=True,
            httponly=True,
            samesite="strict",
        )


def _value(environment: Mapping[str, str], name: str) -> str | None:
    raw = environment.get(name)
    if raw is None:
        return None
    value = raw.strip()
    return value or None


__all__ = [
    "LocalIntentConfirmationService",
    "SummaryReader",
    "V4ConfirmationHttpError",
    "V4ConfirmationSettings",
    "confirmation_settings_from_environment",
]
