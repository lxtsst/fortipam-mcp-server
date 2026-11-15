"""Fixed REST update for noncredential controls on one verified Secret.

The caller establishes existing-object identity and pre-write state.  This
transport sends changed, Policy-mutable controls with the unchanged parent Folder
ID and Template from the protected pre-write projection. It never reads or emits
Secret field values, and does not retry a PUT.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
import http.client
import json
import logging
import re
from typing import Any
from urllib.parse import urlsplit

from .rdp_event_filter_ssh_transport import RDP_EVENT_FILTER_NAME_PREFIX
from .secret_metadata_http_transport import (
    COLLECTION_PATH,
    MAX_RESPONSE_BYTES,
    SecretMetadataHttpTransportConfig,
    SecretSessionControlsFolderPolicy,
    SecretSessionControlsProjectionInspection,
    _redact_json_field_values,
    _ssl_context,
    _zeroize_mutable,
)


_PROFILE_NAME = re.compile(
    rf"{re.escape(RDP_EVENT_FILTER_NAME_PREFIX)}[A-Za-z0-9][A-Za-z0-9._-]{{0,38}}\Z"
)
_UNAVAILABLE = "FortiPAM V4 Secret session-controls transport is unavailable."
_LOGGER = logging.getLogger(__name__)
_MAX_DIAGNOSTIC_TEXT = 512
_DIAGNOSTIC_TERMS = re.compile(
    r"\b(?:missing|required|parameter|field|id|name|folder|template|uuid|syntax|unsupported|"
    r"permission|csrf|parse|json|invalid|token|body|secret|duplicate)\b",
    re.IGNORECASE | re.ASCII,
)
_REQUIRED_FIELD = re.compile(
    r"(?:missing required (?:field|parameter):? (?P<q1>['\"]?)(?P<f1>id|name|folder|template|uuid|field)(?P=q1)"
    r"|(?:field|parameter) (?P<q2>['\"]?)(?P<f2>id|name|folder|template|uuid|field)(?P=q2) is required)\.?",
    re.IGNORECASE | re.ASCII,
)
_ERROR_CATEGORIES = {
    "permission denied": "permission_denied",
    "access denied": "permission_denied",
    "invalid csrf token": "csrf_rejected",
    "missing csrf token": "csrf_rejected",
    "csrf token invalid": "csrf_rejected",
    "csrf token missing": "csrf_rejected",
    "missing required data": "required_data_missing",
    "invalid data": "invalid_data",
    "invalid request data": "invalid_data",
    "conflict": "conflict",
    "entry already exists": "conflict",
}


class SecretSessionControlsHttpTransportError(RuntimeError):
    """Stable non-disclosing failure for the fixed Secret control update."""


class FortiPamSecretSessionControlsHttpTransport:
    """Apply a fixed Policy-aware difference from a protected pre-write read."""

    def __init__(
        self,
        config: SecretMetadataHttpTransportConfig,
        *,
        connection_factory: Callable[..., Any] | None = None,
    ) -> None:
        if not isinstance(config, SecretMetadataHttpTransportConfig):
            raise SecretSessionControlsHttpTransportError(_UNAVAILABLE)
        self._config = config
        self._connection_factory = connection_factory

    def enable_controls(
        self, secret_id: int, rdp_event_filter_profile_name: str, *,
        prewrite: SecretSessionControlsProjectionInspection,
    ) -> None:
        safe_id = _secret_id(secret_id)
        safe_profile = _profile_name(rdp_event_filter_profile_name)
        changes = _mutable_control_changes(prewrite, safe_profile)
        # Validate a nonempty authorized delta before adding the routing envelope.
        # These are the original identity values bound by the runtime pre-write
        # digest; callers cannot supply a destination Folder, name, or Template.
        body: dict[str, str | int] = {
            **changes,
            "id": safe_id,
            "name": prewrite.original_name,
            "folder": prewrite.folder_policy.folder_id,
            "template": prewrite.original_template,
        }
        self._put(safe_id, body)

    def _put(self, secret_id: int, body: Mapping[str, str | int]) -> None:
        parsed = urlsplit(self._config.base_url)
        if parsed.hostname is None:
            raise SecretSessionControlsHttpTransportError(_UNAVAILABLE)
        request_content = bytearray(
            json.dumps(body, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        )
        response_content = bytearray(MAX_RESPONSE_BYTES + 1)
        connection: Any = None
        response: Any = None
        stage = "connection"
        diagnostic_status: int | None = None
        diagnostic_error: int | None = None
        diagnostic_category, diagnostic_field = "unclassified", "none"
        diagnostic_text: tuple[bool, bool, tuple[str, ...]] = (False, False, ())
        payload: object = None
        raw_error: object = None
        try:
            factory = self._connection_factory or http.client.HTTPSConnection
            connection = factory(
                parsed.hostname,
                parsed.port or 443,
                timeout=self._config.timeout_seconds,
                context=_ssl_context(self._config),
            )
            stage = "request"
            connection.request(
                "PUT",
                f"{COLLECTION_PATH}/{secret_id}",
                body=request_content,
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {self._config.bearer_token}",
                    "Connection": "close",
                    "Content-Type": "application/json",
                    "Content-Length": str(len(request_content)),
                    "User-Agent": "fortipam-mcp-v4-secret-session-controls/1",
                },
            )
            stage = "response_headers"
            response = connection.getresponse()
            raw_status = response.status
            if type(raw_status) is int and 100 <= raw_status <= 599:
                diagnostic_status = raw_status
            status = int(response.status)
            stage = "response_content_type"
            content_type = response.getheader("content-type", "")
            if not isinstance(content_type, str) or "json" not in content_type.lower():
                raise SecretSessionControlsHttpTransportError(_UNAVAILABLE)
            stage = "response_read"
            total = _read_bounded(response, response_content)
            del response_content[total:]
            stage = "response_redaction"
            _redact_json_field_values(response_content)
            stage = "response_json"
            try:
                payload = json.loads(response_content)
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise SecretSessionControlsHttpTransportError(_UNAVAILABLE) from None
            if isinstance(payload, Mapping):
                raw_error = payload.get("error")
                if type(raw_error) is int and -2_147_483_648 <= raw_error < 0:
                    diagnostic_error = raw_error
            stage = "http_status" if status != 200 else "vendor_status"
            if status != 200 or not _successful_response(payload):
                diagnostic_category, diagnostic_field = _classify_error(payload)
                diagnostic_text = _diagnostic_text_evidence(payload)
                raise SecretSessionControlsHttpTransportError(_UNAVAILABLE)
        except SecretSessionControlsHttpTransportError:
            _log_failure(stage, diagnostic_status, diagnostic_error, diagnostic_category, diagnostic_field, diagnostic_text)
            raise
        except TimeoutError:
            _log_failure("timeout", diagnostic_status, diagnostic_error)
            raise SecretSessionControlsHttpTransportError(_UNAVAILABLE) from None
        except Exception:
            _log_failure(stage, diagnostic_status, diagnostic_error)
            raise SecretSessionControlsHttpTransportError(_UNAVAILABLE) from None
        finally:
            payload = raw_error = None
            _zeroize_mutable(request_content)
            _zeroize_mutable(response_content)
            if response is not None:
                try:
                    response.close()
                except Exception:
                    pass
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass


def _log_failure(
    stage: str, status: int | None, error: int | None,
    category: str = "unclassified", required_field: str = "none",
    text_evidence: tuple[bool, bool, tuple[str, ...]] = (False, False, ()),
) -> None:
    # All arguments originate from fixed stages or strict numeric allowlists.
    # Never attach exception information or product response text.
    _LOGGER.warning(
        "Secret session-controls PUT failed: stage=%s http_status=%s vendor_error=%s category=%s required_field=%s error_text_present=%s cli_error_text_present=%s diagnostic_terms=%s",
        stage, status, error, category, required_field, *text_evidence,
    )


def _diagnostic_text_evidence(payload: object) -> tuple[bool, bool, tuple[str, ...]]:
    """Return only bounded-string presence and sorted fixed vocabulary hits.

    Presence means a nonempty string of at most 512 characters. Terms are
    structural diagnostic hints, not causal classification, authorization,
    or instructions for constructing request bodies. Unknown text is discarded.
    """
    if not isinstance(payload, Mapping):
        return False, False, ()
    present: list[bool] = []
    terms: set[str] = set()
    for key in ("error", "cli_error"):
        value = payload.get(key)
        if type(value) is str and 0 < len(value) <= _MAX_DIAGNOSTIC_TEXT:
            present.append(True)
            terms.update(match.group().lower() for match in _DIAGNOSTIC_TERMS.finditer(value))
        else:
            present.append(False)
    return present[0], present[1], tuple(sorted(terms))


def _classify_error(payload: object) -> tuple[str, str]:
    """Classify bounded exact syntax; never return vendor text or unknown keys.

    These are conservative text recognizers, not a product error-code catalog.
    Unrecognized wording, multiple different findings and oversized messages
    cannot supply a diagnostic category or a suggested request-body field.
    """
    if not isinstance(payload, Mapping):
        return "unclassified", "none"
    findings: set[tuple[str, str]] = set()
    for key in ("error", "cli_error"):
        value = payload.get(key)
        if type(value) is not str or not 0 < len(value) <= _MAX_DIAGNOSTIC_TEXT:
            continue
        # Do not trim arbitrary response lines or match substrings containing
        # names, selectors, values, or additional diagnostic text.
        match = _REQUIRED_FIELD.fullmatch(value)
        if match is not None:
            field = (match.group("f1") or match.group("f2")).lower()
            findings.add(("required_data_missing", field))
        else:
            category = _ERROR_CATEGORIES.get(value.removesuffix(".").lower())
            if category is not None:
                findings.add((category, "none"))
    if len(findings) != 1:
        return "unclassified", "none"
    return next(iter(findings))


def _mutable_control_changes(
    prewrite: SecretSessionControlsProjectionInspection, profile: str,
) -> dict[str, str]:
    if not isinstance(prewrite, SecretSessionControlsProjectionInspection) or not isinstance(
        prewrite.folder_policy, SecretSessionControlsFolderPolicy,
    ):
        raise SecretSessionControlsHttpTransportError(_UNAVAILABLE)
    policy = prewrite.folder_policy
    # Forced event-filter policy additionally governs its profile. This bounded
    # adapter supports only not-set; it never infers a forced profile binding.
    if policy.rdp_event_filter != "not-set":
        raise SecretSessionControlsHttpTransportError(_UNAVAILABLE)
    body: dict[str, str] = {}
    for field, current, control in (
        ("recording", prewrite.recording_enabled, policy.recording),
        ("block-clipboard", prewrite.clipboard_blocking_enabled, policy.block_clipboard),
        ("rdp-event-filter", prewrite.rdp_event_filter_enabled, policy.rdp_event_filter),
    ):
        if type(current) is not bool or control not in {"enable", "not-set"}:
            raise SecretSessionControlsHttpTransportError(_UNAVAILABLE)
        if control == "enable" and not current:
            raise SecretSessionControlsHttpTransportError(_UNAVAILABLE)
        if not current:
            body[field] = "enable"
    if type(prewrite.rdp_event_filter_profile_matches) is not bool:
        raise SecretSessionControlsHttpTransportError(_UNAVAILABLE)
    if not prewrite.rdp_event_filter_profile_matches:
        body["rdp-event-filter-profile"] = profile
    if not body:
        raise SecretSessionControlsHttpTransportError(_UNAVAILABLE)
    return body


def _read_bounded(response: Any, content: bytearray) -> int:
    total = 0
    while total < len(content):
        view = memoryview(content)[total:]
        try:
            count = response.readinto(view)
        finally:
            view.release()
        if not isinstance(count, int) or count < 0:
            raise SecretSessionControlsHttpTransportError(_UNAVAILABLE)
        if count == 0:
            break
        total += count
    if total > MAX_RESPONSE_BYTES:
        raise SecretSessionControlsHttpTransportError(_UNAVAILABLE)
    return total


def _successful_response(payload: object) -> bool:
    """Accept only the documented HTTP success shape without server text."""

    if not isinstance(payload, Mapping):
        return False
    if payload.get("http_status") not in {None, 200}:
        return False
    if payload.get("status") not in {None, "success"}:
        return False
    return payload.get("error") in {None, 0, "0"}


def _secret_id(value: int) -> int:
    if type(value) is not int or value <= 0 or value > 2_147_483_647:
        raise SecretSessionControlsHttpTransportError(_UNAVAILABLE)
    return value


def _profile_name(value: str) -> str:
    if not isinstance(value, str) or _PROFILE_NAME.fullmatch(value) is None:
        raise SecretSessionControlsHttpTransportError(_UNAVAILABLE)
    return value


__all__ = [
    "FortiPamSecretSessionControlsHttpTransport",
    "SecretSessionControlsHttpTransportError",
]
