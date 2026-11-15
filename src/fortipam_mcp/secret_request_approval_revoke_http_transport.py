"""Private build-29 Launcher withdrawal source qualification, default closed.

This fixed lab candidate is not an accepted withdrawal workflow or a public
runtime action. Original creation continuity and explicit lab authority belong
to the protected caller; current metadata cannot manufacture either. Unknown
ACK/post-change semantics always remain reconciliation-required.
"""

from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from datetime import datetime
import hashlib
import hmac
import json
import math
import time
import os
from pathlib import Path
import stat
import threading
from typing import Any, Literal
from urllib.parse import quote, urlsplit

import httpx

from .local_user_reset_fixture_preflight import _actor_context
from .local_user_reset_metadata_reader import _monitor_results
from .local_user_reset_projection import _object_spans
from .secret_approval_build29_http_transport import (
    _normalize_one_native_metadata_duplicate, _redact_material_members, _validate_ack_json,
)
from .secret_approval_build29_metadata_reader import _unique_raw_field_span
from .secret_metadata_http_transport import (
    MAX_RESPONSE_BYTES, SecretMetadataHttpTransportConfig, _json_value_end,
    _record, _redact_json_field_values, _skip_json_space, _ssl_context, _zeroize_mutable,
)
from .secret_request_approval_revoke_contract import (
    compile_secret_request_approval_revoke_body, secret_request_approval_revoke_url,
)
from .secret_request_approval_revoke_detail_contract import (
    SecretRequestApprovalRevokeDetailBinding, SecretRequestApprovalRevokeDetailWitness,
    SecretRequestApprovalRevokeRelationWitness, _reject_raw_duplicates,
    qualify_secret_request_approval_revoke_get_detail,
    qualify_secret_request_approval_revoke_secret_profile_relation,
)
from .secret_request_approval_revoke_ack_contract import qualify_secret_request_approval_revoke_ack
from .secret_request_approval_revoke_post_contract import qualify_secret_request_approval_revoke_post_state
from .secret_request_http_transport import _server_date

_UNAVAILABLE = "The fixed Launcher withdrawal source qualification is unavailable."
_CLAIM_CONTRACT = "secret-request-approval-revoke-build29-lab-source-claim-v1"
_STATE = "/api/v2/monitor/web-ui/state"


class SecretRequestApprovalRevokeHttpTransportError(RuntimeError):
    """Stable categorical failure; no private values or upstream exception text."""

    def __init__(self, *, stage: str = "preflight") -> None:
        super().__init__(_UNAVAILABLE)
        self.stage = stage


@dataclass(frozen=True, slots=True, repr=False)
class SecretRequestApprovalRevokeInspection:
    detail: SecretRequestApprovalRevokeDetailWitness
    relation: SecretRequestApprovalRevokeRelationWitness


@dataclass(frozen=True, slots=True, repr=False)
class SecretRequestApprovalRevokePrivateSource:
    """Only bounded, duplicate-free and predecode-redacted private JSON bytes."""

    request_metadata: bytes | None
    secret_metadata: bytes | None
    profile_metadata: bytes | None
    request_date: datetime | None
    last_read_date: datetime | None


@dataclass(frozen=True, slots=True, repr=False)
class SecretRequestApprovalRevokeSourceQualificationResult:
    dispatch_consumed: bool
    http_status_class: str
    reviewer_logout_verified: bool
    ack_source_safe: bool
    private_ack_http_status: int | None
    private_ack_metadata: bytes | None
    private_post_source: SecretRequestApprovalRevokePrivateSource | None
    failure_stage: str
    source_qualification_only: Literal[True] = True
    reconciliation_required: Literal[True] = True
    ack_contract_qualified: bool = False
    post_contract_qualified: bool = False


@dataclass(frozen=True, slots=True)
class SecretRequestApprovalRevokeReadback:
    """Categorical device result only, never a runtime execution authorization.

    A qualified withdrawal is not backend session-denial evidence. The caller
    must supply original creation continuity and server-side authorization.
    """

    dispatch_consumed: bool
    http_accepted: bool
    pending_and_metadata_preserved: bool
    reviewer_logout_verified: bool
    reconciliation_required: bool


@dataclass(frozen=True, slots=True)
class SecretRequestApprovalRevokeDiagnostics:
    """Original categorical evidence only; no sources or replay authority."""

    dispatch_consumed: bool
    http_status_class: str
    ack_http_status: int | None
    ack_source_safe: bool
    ack_contract_qualified: bool
    post_contract_qualified: bool
    reviewer_logout_verified: bool
    failure_stage: str


class FortiPamSecretRequestApprovalRevokeHttpTransport:
    """One explicit lab DELETE after exact current inspection and durable claim.

    The binding is supplied from this attempt's protected create result and
    precreate parent relation. No API accepts arbitrary routes or derives the
    original Profile from current metadata. Safe private source is never a
    public/MCP result, successful readback, or dispatch authorization.
    This candidate alone requires the original reviewer to be the bound local
    enabled super_admin Owner; it does not define all product reviewers' Roles.
    """

    def __init__(
        self, config: SecretMetadataHttpTransportConfig,
        binding: SecretRequestApprovalRevokeDetailBinding,
        credentials: Callable[[], tuple[str, str]], *, claim_path: Path,
        hmac_key: bytes, execution_enabled: bool = False,
        client_factory: Callable[..., Any] = httpx.Client,
    ) -> None:
        try:
            if (type(config) is not SecretMetadataHttpTransportConfig
                    or type(binding) is not SecretRequestApprovalRevokeDetailBinding
                    or not callable(credentials) or not callable(client_factory)
                    or type(hmac_key) is not bytes or len(hmac_key) < 32
                    or type(execution_enabled) is not bool or not isinstance(claim_path, Path)):
                raise ValueError
            self._config, self._binding = config, binding
            self._credentials, self._factory = credentials, client_factory
            self._claim, self._key, self._enabled = claim_path, hmac_key, execution_enabled
            self._tls = _ssl_context(config)
            self._lock = threading.Lock()
            self._withdrawal_diagnostics: SecretRequestApprovalRevokeDiagnostics | None = None
            self._check_parent()
        except Exception:
            raise SecretRequestApprovalRevokeHttpTransportError() from None

    def _check_parent(self) -> None:
        info = self._claim.parent.lstat()
        if (not self._claim.is_absolute() or self._claim.name in {"", ".", ".."}
                or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError

    def _unconsumed(self) -> None:
        self._check_parent()
        if os.path.lexists(self._claim):
            raise ValueError

    def _reserve(self, inspection: SecretRequestApprovalRevokeInspection, body: Mapping[str, object]) -> None:
        self._unconsumed()
        directory = os.open(self._claim.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(directory)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o700):
                raise ValueError
            exact = json.dumps({"contract": _CLAIM_CONTRACT, "origin": self._config.base_url,
                                "binding": asdict(self._binding), "inspection": asdict(inspection),
                                "method": "DELETE", "body": body}, sort_keys=True,
                               separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            claim = {"contract": _CLAIM_CONTRACT, "retry_allowed": False,
                     "intent_binding_hmac": hmac.new(self._key, exact, hashlib.sha256).hexdigest()}
            descriptor = os.open(self._claim.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=directory)
            with os.fdopen(descriptor, "w") as file:
                json.dump(claim, file, sort_keys=True, separators=(",", ":"))
                file.flush()
                os.fsync(file.fileno())
            os.fsync(directory)
        finally:
            os.close(directory)

    @staticmethod
    def _safe_source(response: Any, *, kind: str) -> tuple[bytes, datetime | None]:
        raw = bytearray()
        try:
            if (response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                    != "application/json"):
                raise ValueError
            for chunk in response.iter_bytes():
                if len(raw) + len(chunk) > MAX_RESPONSE_BYTES:
                    raise ValueError
                raw.extend(chunk)
            start = _skip_json_space(raw, 0)
            end = _json_value_end(raw, start)
            if _skip_json_space(raw, end) != len(raw):
                raise ValueError
            _validate_ack_json(raw, start, end)
            if kind == "secret":
                _normalize_one_native_metadata_duplicate(raw)
                start, end = _skip_json_space(raw, 0), _json_value_end(raw, _skip_json_space(raw, 0))
            _reject_raw_duplicates(raw, start, end)
            if kind == "profile":
                left, right = _unique_raw_field_span(raw)
                if (raw[left] != 91 or raw[right - 1] != 93
                        or _skip_json_space(raw, left + 1) != right - 1):
                    raise ValueError
            _redact_json_field_values(raw)
            _redact_material_members(raw)
            if kind == "profile":
                left, right = _unique_raw_field_span(raw)
                raw[left:right] = b"[]"
            # Return protected bytes, not a generic decoded response. Qualifiers
            # will perform their own strict duplicate-free value decoding.
            return bytes(raw), _server_date(response.headers.get("date"))
        finally:
            _zeroize_mutable(raw)

    def _sources(self, client: Any, *, partial: bool = False) -> SecretRequestApprovalRevokePrivateSource:
        paths = (
            ("request", f"/api/v2/cmdb/secret/request/{self._binding.request_id}?with_meta=true&vdom=root"),
            ("secret", f"/api/v2/cmdb/secret/database/{self._binding.secret_id}?with_meta=true&vdom=root"),
            ("profile", "/api/v2/cmdb/secret/approval-profile/"
             + quote(self._binding.approval_profile_name, safe="") + "?with_meta=true&vdom=root"),
        )
        sources: list[bytes | None] = []
        request_date = None
        last_read_date = None
        for kind, path in paths:
            try:
                with client.stream("GET", path, headers={"Accept": "application/json",
                        "Cache-Control": "no-cache, no-store"}) as response:
                    if type(response.status_code) is not int or response.status_code != 200:
                        raise ValueError
                    source, date = self._safe_source(response, kind=kind)
                sources.append(source)
                if kind == "request":
                    request_date = date
                if kind == "profile":
                    last_read_date = date
            except Exception:
                if not partial:
                    raise
                sources.append(None)
        return SecretRequestApprovalRevokePrivateSource(sources[0], sources[1], sources[2], request_date, last_read_date)

    def _reviewer_role(self, client: Any) -> None:
        """Reuse isolated Folder _creation_owner_role's fixed Owner contract.

        Actor context alone proves no Role. This scoped read uses the same
        authenticated client and pins the Role envelope to the binding's serial.
        """
        owner = self._binding.original_reviewer
        route = "/api/v2/cmdb/system/admin/" + quote(owner, safe="") + "?format=name%7Caccprofile%7Cstatus%7Cremote-auth%7Cwildcard"
        with client.stream("GET", route, headers={"Accept": "application/json",
                "Cache-Control": "no-cache, no-store"}) as response:
            if type(response.status_code) is not int or response.status_code != 200:
                raise ValueError
            safe, _ = self._safe_source(response, kind="role")
        raw = bytearray(safe)
        try:
            role = json.loads(raw)
        finally:
            _zeroize_mutable(raw)
        envelope = {"version": "v7.0.0", "build": 29, "http_method": "GET", "http_status": 200,
                    "vdom": "root", "path": "system", "name": "admin", "serial": self._binding.source_serial}
        if (type(role) is not dict
                or any(type(role.get(key)) is not type(value) or role.get(key) != value
                       for key, value in envelope.items())
                or role.get("status") not in {"OK", "success"}
                or "action" in role and (type(role["action"]) is not str or role["action"] != "")
                or "error" in role and (type(role["error"]) is not int or role["error"] != 0)
                or role.get("limit_reached", False) is not False
                or any(key in role for key in ("next_idx", "next_index", "total", "total_count"))
                or any(type(role[key]) is not int or role[key] != 1
                       for key in ("size", "matched_count") if key in role)):
            raise ValueError
        row = _record(role)
        expected = {"name": owner, "accprofile": "super_admin", "status": "enable",
                    "remote-auth": "disable", "wildcard": "disable"}
        if (not isinstance(row, Mapping) or not set(expected) <= set(row)
                or not set(row) <= set(expected) | {"q_origin_key"}
                or any(type(row.get(key)) is not type(value) or row.get(key) != value
                       for key, value in expected.items())
                or "q_origin_key" in row and row["q_origin_key"] != owner
                or "mkey" in role and (type(role["mkey"]) is not str or role["mkey"] != owner)):
            raise ValueError

    def _inspection(self, source: SecretRequestApprovalRevokePrivateSource) -> SecretRequestApprovalRevokeInspection:
        if any(value is None for value in (source.request_metadata, source.secret_metadata, source.profile_metadata)):
            raise ValueError
        assert source.request_metadata is not None and source.secret_metadata is not None and source.profile_metadata is not None
        detail = qualify_secret_request_approval_revoke_get_detail(
            source.request_metadata, binding=self._binding, authenticated_reviewer=self._binding.original_reviewer,
            server_time=source.request_date,
        )
        relation = qualify_secret_request_approval_revoke_secret_profile_relation(
            source.secret_metadata, source.profile_metadata, binding=self._binding,
            authenticated_reviewer=self._binding.original_reviewer,
        )
        # Reuse the same Date/window predicate after the final fixed read, so
        # expiry during Secret/Profile reads cannot be hidden by the earlier Date.
        qualify_secret_request_approval_revoke_get_detail(
            source.request_metadata, binding=self._binding, authenticated_reviewer=self._binding.original_reviewer,
            server_time=source.last_read_date,
        )
        return SecretRequestApprovalRevokeInspection(detail, relation)

    def inspect(self) -> SecretRequestApprovalRevokeInspection:
        result = self._run(execute=False, expected=None)
        assert isinstance(result, SecretRequestApprovalRevokeInspection)
        return result

    def execute(self, expected: SecretRequestApprovalRevokeInspection) -> SecretRequestApprovalRevokeSourceQualificationResult:
        result = self._run(execute=True, expected=expected)
        assert isinstance(result, SecretRequestApprovalRevokeSourceQualificationResult)
        return result

    def withdraw_and_readback(
        self, expected: SecretRequestApprovalRevokeInspection, *, authorization_expires_at: float | None = None,
    ) -> SecretRequestApprovalRevokeReadback:
        """Execute once and return no protected sources to a workflow adapter.

        This private interface retains the same closed-by-default execution Gate
        and consumed claim. It does not register an MCP action or accept a caller
        assertion of original creation continuity as execution authority.
        """
        result = self._run(execute=True, expected=expected, authorization_expires_at=authorization_expires_at)
        assert isinstance(result, SecretRequestApprovalRevokeSourceQualificationResult)
        if self._withdrawal_diagnostics is None:
            self._withdrawal_diagnostics = SecretRequestApprovalRevokeDiagnostics(
                dispatch_consumed=result.dispatch_consumed,
                http_status_class=result.http_status_class,
                ack_http_status=result.private_ack_http_status,
                ack_source_safe=result.ack_source_safe,
                ack_contract_qualified=result.ack_contract_qualified,
                post_contract_qualified=result.post_contract_qualified,
                reviewer_logout_verified=result.reviewer_logout_verified,
                failure_stage=result.failure_stage,
            )
        qualified = (
            result.dispatch_consumed and result.ack_contract_qualified
            and result.post_contract_qualified and result.reviewer_logout_verified
            and result.failure_stage == "none"
        )
        return SecretRequestApprovalRevokeReadback(
            dispatch_consumed=result.dispatch_consumed,
            http_accepted=result.ack_contract_qualified,
            pending_and_metadata_preserved=result.post_contract_qualified,
            reviewer_logout_verified=result.reviewer_logout_verified,
            reconciliation_required=not qualified,
        )

    @property
    def withdrawal_diagnostics(self) -> SecretRequestApprovalRevokeDiagnostics | None:
        """Retain the original result across consumed-attempt refusals.

        Trusted acceptance may persist this minimized evidence before shutdown.
        It never changes the readback, workflow outcome or dispatch claim.
        """
        return self._withdrawal_diagnostics

    def _run(self, *, execute: bool, expected: SecretRequestApprovalRevokeInspection | None,
             authorization_expires_at: float | None = None,
             ) -> SecretRequestApprovalRevokeInspection | SecretRequestApprovalRevokeSourceQualificationResult:
        with self._lock:
            stage = "gate"
            consumed = logged_out = login_attempted = False
            status_class, ack, post = "none", None, None
            ack_http_status = None
            ack_qualified = post_qualified = False
            inspection = None
            failed = False
            failure_stage = "none"
            try:
                if authorization_expires_at is not None and (
                        type(authorization_expires_at) not in (int, float)
                        or not math.isfinite(authorization_expires_at)
                        or time.time() >= authorization_expires_at):
                    raise ValueError
                if execute and (self._enabled is not True or type(expected) is not SecretRequestApprovalRevokeInspection):
                    raise ValueError
                stage = "claim_preflight"
                self._unconsumed()
                with self._factory(base_url=self._config.base_url, verify=self._tls,
                        timeout=self._config.timeout_seconds, follow_redirects=False, trust_env=False) as client:
                    try:
                        stage = "login_page"
                        page = client.get("/remote/login?lang=en")
                        if page.status_code != 200 or len(page.content) > MAX_RESPONSE_BYTES or 'action="/XX/YY/ZZ/AUTH"' not in page.text:
                            raise ValueError
                        stage = "credential_provider"
                        username, password = self._credentials()
                        if username != self._binding.original_reviewer or type(password) is not str or not password:
                            raise ValueError
                        stage = "login"
                        login_attempted = True
                        auth = client.post("/XX/YY/ZZ/AUTH", data={"username": username, "password": password,
                            "magic": "0", "4Tredir": "/", "4Tmthd": "0"})
                        del username, password
                        location = auth.headers.get("location", "")
                        parsed = urlsplit(location)
                        if (auth.status_code != 303 or not location.startswith("/") or location.startswith("//")
                                or parsed.scheme or parsed.netloc or parsed.path.startswith("/api/") or len(location) > 2048):
                            raise ValueError
                        client.get(location)
                        stage = "reviewer_identity"
                        with client.stream("GET", _STATE) as response:
                            if response.status_code != 200:
                                raise ValueError
                            safe, _ = self._safe_source(response, kind="state")
                        raw = bytearray(safe)
                        try:
                            _actor_context(raw, expected_name=self._binding.original_reviewer)
                            left, right = _monitor_results(raw, expected_route="web-ui/state")
                            state = _object_spans(raw, left, right)
                            left, right = state["ccsrf_token_cookie_name"]
                            if not 2 < right - left <= 258:
                                raise ValueError
                            cookie_name = json.loads(raw[left:right])
                        finally:
                            _zeroize_mutable(raw)
                        stage = "csrf"
                        if (type(cookie_name) is not str or not cookie_name
                                or len(cookie_name.encode("utf-8")) > 128
                                or any(ord(c) < 33 or ord(c) > 126 for c in cookie_name)):
                            raise ValueError
                        csrf = client.cookies.get(cookie_name)
                        if type(csrf) is str:
                            csrf = csrf.strip('"')
                        if type(csrf) is not str or not csrf or any(ord(c) < 33 or ord(c) > 126 for c in csrf):
                            raise ValueError
                        stage = "reviewer_role"
                        self._reviewer_role(client)
                        stage = "current_source"
                        pre_source = self._sources(client)
                        inspection = self._inspection(pre_source)
                        if execute:
                            stage = "drift"
                            if inspection != expected:
                                raise ValueError
                            body = compile_secret_request_approval_revoke_body(request_id=self._binding.request_id)
                            stage = "authorization_deadline"
                            if authorization_expires_at is not None and time.time() >= authorization_expires_at:
                                raise ValueError
                            stage = "claim_reserve"
                            self._reserve(inspection, body)
                            consumed = True
                            stage = "authorization_deadline"
                            if authorization_expires_at is not None and time.time() >= authorization_expires_at:
                                raise ValueError
                            stage = "delete"
                            try:
                                with client.stream("DELETE", secret_request_approval_revoke_url(self._binding.request_id),
                                        json=body, headers={"X-Requested-With": "XMLHttpRequest", "X-CSRFTOKEN": csrf,
                                                           "Accept": "application/json"}) as response:
                                    status = response.status_code
                                    status_class = f"{status // 100}xx" if type(status) is int and 100 <= status <= 599 else "invalid"
                                    if type(status) is int and 100 <= status <= 599:
                                        ack_http_status = status
                                    stage = "ack_source"
                                    ack, _ = self._safe_source(response, kind="ack")
                            except Exception:
                                # One ambiguous dispatch remains consumed, never resent.
                                failed = True
                                failure_stage = stage
                            stage = "post_source"
                            post = self._sources(client, partial=True)
                            # Independent source facts only: neither flag opens a
                            # runtime Gate, clears reconciliation or permits replay.
                            try:
                                if ack is None or ack_http_status is None:
                                    raise ValueError
                                qualify_secret_request_approval_revoke_ack(
                                    ack, http_status=ack_http_status, binding=self._binding,
                                    authenticated_reviewer=self._binding.original_reviewer,
                                )
                                ack_qualified = True
                            except Exception:
                                pass
                            try:
                                if (pre_source.request_metadata is None or post.request_metadata is None
                                        or post.secret_metadata is None or post.profile_metadata is None):
                                    raise ValueError
                                if (post.request_date is None or post.last_read_date is None
                                        or post.last_read_date < post.request_date):
                                    raise ValueError
                                qualify_secret_request_approval_revoke_post_state(
                                    pre_source.request_metadata, post.request_metadata,
                                    binding=self._binding,
                                    authenticated_reviewer=self._binding.original_reviewer,
                                    pre_server_time=pre_source.request_date,
                                    post_server_time=post.request_date,
                                )
                                qualify_secret_request_approval_revoke_post_state(
                                    pre_source.request_metadata, post.request_metadata,
                                    binding=self._binding,
                                    authenticated_reviewer=self._binding.original_reviewer,
                                    pre_server_time=pre_source.request_date,
                                    post_server_time=post.last_read_date,
                                )
                                relation = qualify_secret_request_approval_revoke_secret_profile_relation(
                                    post.secret_metadata, post.profile_metadata, binding=self._binding,
                                    authenticated_reviewer=self._binding.original_reviewer,
                                )
                                if relation != inspection.relation:
                                    raise ValueError
                                post_qualified = True
                            except Exception:
                                pass
                    except Exception:
                        failed = True
                        failure_stage = stage
                    finally:
                        if login_attempted:
                            retained_cookies = httpx.Cookies(client.cookies)
                            try:
                                exit_response = client.get("/logout")
                                client.cookies.clear()
                                client.cookies.update(retained_cookies)
                                revoked = client.get(_STATE)
                                logged_out = (exit_response.status_code in {200, 302, 303}
                                              and revoked.status_code in {401, 403})
                            except Exception:
                                logged_out = False
                            finally:
                                retained_cookies.clear()
                                client.cookies.clear()
                if not consumed:
                    if failed or not logged_out or inspection is None:
                        raise ValueError
                    return inspection
                return SecretRequestApprovalRevokeSourceQualificationResult(
                    consumed, status_class, logged_out, ack is not None, ack_http_status, ack, post,
                    failure_stage if failed else ("none" if logged_out else "logout"),
                    ack_contract_qualified=ack_qualified, post_contract_qualified=post_qualified,
                )
            except Exception:
                if consumed:
                    return SecretRequestApprovalRevokeSourceQualificationResult(
                        True, status_class, logged_out, ack is not None, ack_http_status, ack, post, stage,
                    )
                raise SecretRequestApprovalRevokeHttpTransportError(stage=stage) from None
