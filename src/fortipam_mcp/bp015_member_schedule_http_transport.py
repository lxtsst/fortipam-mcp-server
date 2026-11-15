"""Fixed BP015 Sponsored Group member and Schedule lifecycle for FortiPAM 7.0.

The build-29 frontend saves Sponsored Group membership by updating an existing
``system/admin`` record.  This transport is deliberately limited to one fixed
local laboratory administrator and one existing Schedule.  A
disabled member remains observable but is not assignment eligible.  The
transport issues at most one assignment PUT and one rollback PUT, reconciles
both through exact readback, and never returns identities or raw product
responses.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import hmac
import json
import re
from typing import Any, Final, Literal
from urllib.parse import quote, urlencode

from .bp015_sponsored_group_http_transport import (
    GROUP_COLLECTION_PATH,
    MEMBER_COLLECTION_PATH,
    _collection_records,
    _group_filter_body,
    _member_filter_body,
)
from .schedule_assign_http_transport import (
    _existing_user_projection,
    _mapping_digest,
    _user_is_local,
)
from .secret_metadata_http_transport import (
    MAX_RESPONSE_BYTES,
    SecretMetadataHttpTransportConfig,
    _ssl_context,
)


FIXED_MEMBER_NAME: Final = "mcp-v4-user-b57"
FIXED_SCHEDULE_NAME: Final = "always"
_ADMIN_PATH: Final = "/api/v2/cmdb/system/admin"
_SCHEDULE_PATH: Final = "/api/v2/cmdb/firewall.schedule/recurring"
_GROUP_NAME = re.compile(r"mcp-v4-bp015-[A-Za-z0-9][A-Za-z0-9._-]{0,47}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_UNAVAILABLE: Final = "FortiPAM BP015 member Schedule transport is unavailable."
_EXPERIMENTAL_WRITE_DISABLED: Final = True


class BP015MemberScheduleHttpTransportError(RuntimeError):
    """Stable, non-disclosing failure for the fixed member/Schedule transport."""


@dataclass(frozen=True, slots=True, repr=False)
class BP015MemberScheduleInspection:
    group_exists: bool
    member_exists: bool
    member_enabled: bool
    member_disabled: bool
    member_local: bool
    member_sponsored_user_role: bool
    relationship_unassigned: bool
    relationship_assigned_exact: bool
    schedule_exists: bool
    member_relation_count: int
    member_state_digest: str
    member_non_relationship_digest: str
    schedule_state_digest: str
    inspection_digest: str

    @property
    def eligible(self) -> bool:
        return all(
            (
                self.group_exists,
                self.member_exists,
                self.member_enabled,
                self.member_local,
                self.relationship_unassigned,
                self.schedule_exists,
                self.member_relation_count == 0,
            )
        )

    def __repr__(self) -> str:
        return "<BP015MemberScheduleInspection categorical>"


@dataclass(frozen=True, slots=True, repr=False)
class BP015MemberScheduleReadback:
    write_category: Literal["accepted", "ambiguous"]
    member_relation_exact: bool
    sponsor_group_matches: bool
    schedule_matches: bool
    member_enabled: bool
    member_local: bool
    member_sponsored_user_role: bool
    unrelated_state_preserved: bool
    schedule_state_preserved: bool
    assigned_state_digest: str
    readback_digest: str

    @property
    def verified(self) -> bool:
        return all(
            (
                self.member_relation_exact,
                self.sponsor_group_matches,
                self.schedule_matches,
                self.member_enabled,
                self.member_local,
                self.unrelated_state_preserved,
                self.schedule_state_preserved,
            )
        )

    def __repr__(self) -> str:
        return "<BP015MemberScheduleReadback categorical>"


@dataclass(frozen=True, slots=True, repr=False)
class BP015MemberScheduleRollbackReadback:
    write_category: Literal["accepted", "ambiguous"]
    member_relation_zero: bool
    relationship_unassigned: bool
    original_member_state_restored: bool
    schedule_state_preserved: bool
    rollback_digest: str

    @property
    def verified(self) -> bool:
        return all(
            (
                self.member_relation_zero,
                self.relationship_unassigned,
                self.original_member_state_restored,
                self.schedule_state_preserved,
            )
        )

    def __repr__(self) -> str:
        return "<BP015MemberScheduleRollbackReadback categorical>"


@dataclass(frozen=True, slots=True, repr=False)
class BP015RetainedRecoveryAssessment:
    retained_relation_exact: bool
    member_enabled: bool
    member_disabled: bool
    frontend_member_loader_includes: bool
    member_editor_classification: Literal[
        "sponsored_user", "sponsor_admin", "unavailable"
    ]
    documented_disabled_user_visibility: bool
    documented_selected_user_edit_action: bool
    saved_build29_transport_preserves_status: bool
    saved_build29_transport_projects_relationship_fields: bool
    current_build_disabled_edit_form_verified: bool
    current_build_edit_source_sponsor_locked: bool
    sponsor_assignment_clear_required: bool
    relationship_removal_contract_proven: bool
    automatic_execution_allowed: bool
    assessment_digest: str

    @property
    def requires_recovery_contract(self) -> bool:
        return (
            self.retained_relation_exact
            and self.saved_build29_transport_preserves_status
            and self.saved_build29_transport_projects_relationship_fields
            and self.current_build_edit_source_sponsor_locked
            and self.sponsor_assignment_clear_required
            and not self.relationship_removal_contract_proven
            and not self.automatic_execution_allowed
        )

    def __repr__(self) -> str:
        return "<BP015RetainedRecoveryAssessment categorical>"


class FortiPamBP015MemberScheduleHttpTransport:
    """Bind and roll back the one fixed member/Schedule relationship."""

    def __init__(
        self,
        config: SecretMetadataHttpTransportConfig,
        *,
        client_factory: Callable[..., Any] | None = None,
    ) -> None:
        if not isinstance(config, SecretMetadataHttpTransportConfig):
            raise BP015MemberScheduleHttpTransportError(_UNAVAILABLE)
        self._config = config
        self._client_factory = client_factory
        self._assign_attempted = False
        self._rollback_attempted = False
        self._bound_group: str | None = None
        self._original_member_digest: str | None = None
        self._unrelated_digest: str | None = None
        self._schedule_digest: str | None = None
        self._assigned_member_digest: str | None = None

    def inspect(self, group_name: str) -> BP015MemberScheduleInspection:
        group = _group_name(group_name)
        member = self._read_detail(_member_path(), "system", "admin", FIXED_MEMBER_NAME)
        schedule = self._read_detail(
            _schedule_path(), "firewall.schedule", "recurring", FIXED_SCHEDULE_NAME
        )
        group_records = self._read_collection(
            GROUP_COLLECTION_PATH, _group_filter_body(group), "user", "group"
        )
        relations = self._read_collection(
            MEMBER_COLLECTION_PATH, _member_filter_body(group), "system", "admin"
        )
        member_digest = _mapping_digest(member)
        unrelated_digest = _non_relationship_digest(member)
        schedule_digest = _mapping_digest(schedule)
        categorical: dict[str, object] = {
            "group_exists": len(group_records) == 1
            and group_records[0].get("name") == group,
            "member_exists": member is not None,
            "member_enabled": member is not None and member.get("status") == "enable",
            "member_disabled": member is not None and member.get("status") == "disable",
            "member_local": member is not None and _user_is_local(member),
            "member_sponsored_user_role": member is not None
            and member.get("accprofile") == "pam_standard_user",
            "relationship_unassigned": member is not None
            and member.get("sponsor-group") in {None, ""}
            and member.get("schedule") in {None, ""},
            "relationship_assigned_exact": member is not None
            and member.get("sponsor-group") == group
            and member.get("schedule") == FIXED_SCHEDULE_NAME,
            "schedule_exists": schedule is not None,
            "member_relation_count": len(relations),
            "member_state_digest": member_digest,
            "member_non_relationship_digest": unrelated_digest,
            "schedule_state_digest": schedule_digest,
        }
        return BP015MemberScheduleInspection(
            **categorical, inspection_digest=_digest(categorical)  # type: ignore[arg-type]
        )

    def assess_retained_recovery(
        self, group_name: str
    ) -> BP015RetainedRecoveryAssessment:
        """Classify the retained relation without granting recovery authority."""

        current = self.inspect(group_name)
        retained_exact = all(
            (
                current.group_exists,
                current.member_exists,
                current.member_enabled != current.member_disabled,
                current.member_local,
                current.relationship_assigned_exact,
                current.schedule_exists,
                current.member_relation_count == 1,
            )
        )
        if not retained_exact:
            branch: Literal[
                "sponsored_user", "sponsor_admin", "unavailable"
            ] = "unavailable"
        elif current.member_sponsored_user_role:
            branch = "sponsored_user"
        else:
            branch = "sponsor_admin"
        categorical: dict[str, object] = {
            "retained_relation_exact": retained_exact,
            "member_enabled": retained_exact and current.member_enabled,
            "member_disabled": retained_exact and current.member_disabled,
            "frontend_member_loader_includes": retained_exact
            and current.member_enabled,
            "member_editor_classification": branch,
            "documented_disabled_user_visibility": retained_exact
            and current.member_disabled,
            "documented_selected_user_edit_action": retained_exact,
            "saved_build29_transport_preserves_status": retained_exact,
            "saved_build29_transport_projects_relationship_fields": retained_exact,
            "current_build_disabled_edit_form_verified": False,
            # Current build-29 UserEdit source disables sponsor-group for every
            # existing user. getRawValue() preserves it through buildEntry().
            # See docs/API_SOURCES.md for the authenticated static-source digest.
            "current_build_edit_source_sponsor_locked": retained_exact,
            "sponsor_assignment_clear_required": retained_exact,
            "relationship_removal_contract_proven": False,
            "automatic_execution_allowed": False,
        }
        return BP015RetainedRecoveryAssessment(
            **categorical, assessment_digest=_digest(categorical)  # type: ignore[arg-type]
        )

    def assign_and_readback(
        self,
        group_name: str,
        *,
        expected_member_state_digest: str,
        expected_member_non_relationship_digest: str,
        expected_schedule_state_digest: str,
    ) -> BP015MemberScheduleReadback:
        if _EXPERIMENTAL_WRITE_DISABLED or self._assign_attempted:
            raise BP015MemberScheduleHttpTransportError(_UNAVAILABLE)
        group = _group_name(group_name)
        expected_member = _digest_value(expected_member_state_digest)
        expected_unrelated = _digest_value(expected_member_non_relationship_digest)
        expected_schedule = _digest_value(expected_schedule_state_digest)
        current = self.inspect(group)
        if (
            not current.eligible
            or not hmac.compare_digest(current.member_state_digest, expected_member)
            or not hmac.compare_digest(
                current.member_non_relationship_digest, expected_unrelated
            )
            or not hmac.compare_digest(current.schedule_state_digest, expected_schedule)
        ):
            raise BP015MemberScheduleHttpTransportError(_UNAVAILABLE)
        member = self._read_detail(_member_path(), "system", "admin", FIXED_MEMBER_NAME)
        if member is None or not hmac.compare_digest(_mapping_digest(member), expected_member):
            raise BP015MemberScheduleHttpTransportError(_UNAVAILABLE)
        body = _existing_user_projection(member)
        body["sponsor-group"] = group
        body["schedule"] = FIXED_SCHEDULE_NAME
        self._assign_attempted = True
        category = self._put_once(group, body)
        updated = self._read_detail(_member_path(), "system", "admin", FIXED_MEMBER_NAME)
        schedule = self._read_detail(
            _schedule_path(), "firewall.schedule", "recurring", FIXED_SCHEDULE_NAME
        )
        relations = self._read_collection(
            MEMBER_COLLECTION_PATH, _member_filter_body(group), "system", "admin"
        )
        assigned_digest = _mapping_digest(updated)
        categorical: dict[str, object] = {
            "write_category": category,
            "member_relation_exact": len(relations) == 1
            and relations[0].get("name") == FIXED_MEMBER_NAME,
            "sponsor_group_matches": updated is not None
            and updated.get("sponsor-group") == group,
            "schedule_matches": updated is not None
            and updated.get("schedule") == FIXED_SCHEDULE_NAME,
            "member_enabled": updated is not None and updated.get("status") == "enable",
            "member_local": updated is not None and _user_is_local(updated),
            "member_sponsored_user_role": updated is not None
            and updated.get("accprofile") == "pam_standard_user",
            "unrelated_state_preserved": updated is not None
            and hmac.compare_digest(_non_relationship_digest(updated), expected_unrelated),
            "schedule_state_preserved": schedule is not None
            and hmac.compare_digest(_mapping_digest(schedule), expected_schedule),
            "assigned_state_digest": assigned_digest,
        }
        result = BP015MemberScheduleReadback(
            **categorical, readback_digest=_digest(categorical)  # type: ignore[arg-type]
        )
        if result.verified:
            self._bound_group = group
            self._original_member_digest = expected_member
            self._unrelated_digest = expected_unrelated
            self._schedule_digest = expected_schedule
            self._assigned_member_digest = assigned_digest
        return result

    def rollback_and_readback(self) -> BP015MemberScheduleRollbackReadback:
        group = self._bound_group
        if (
            group is None
            or self._rollback_attempted
            or self._original_member_digest is None
            or self._unrelated_digest is None
            or self._schedule_digest is None
            or self._assigned_member_digest is None
        ):
            raise BP015MemberScheduleHttpTransportError(_UNAVAILABLE)
        current = self._read_detail(_member_path(), "system", "admin", FIXED_MEMBER_NAME)
        relations = self._read_collection(
            MEMBER_COLLECTION_PATH, _member_filter_body(group), "system", "admin"
        )
        if (
            current is None
            or not hmac.compare_digest(
                _mapping_digest(current), self._assigned_member_digest
            )
            or current.get("sponsor-group") != group
            or current.get("schedule") != FIXED_SCHEDULE_NAME
            or len(relations) != 1
            or relations[0].get("name") != FIXED_MEMBER_NAME
        ):
            raise BP015MemberScheduleHttpTransportError(_UNAVAILABLE)
        body = _existing_user_projection(current)
        body["sponsor-group"] = ""
        body["schedule"] = ""
        self._rollback_attempted = True
        category = self._put_once(group, body)
        restored = self._read_detail(_member_path(), "system", "admin", FIXED_MEMBER_NAME)
        schedule = self._read_detail(
            _schedule_path(), "firewall.schedule", "recurring", FIXED_SCHEDULE_NAME
        )
        remaining = self._read_collection(
            MEMBER_COLLECTION_PATH, _member_filter_body(group), "system", "admin"
        )
        categorical: dict[str, object] = {
            "write_category": category,
            "member_relation_zero": remaining == [],
            "relationship_unassigned": restored is not None
            and restored.get("sponsor-group") in {None, ""}
            and restored.get("schedule") in {None, ""},
            "original_member_state_restored": restored is not None
            and hmac.compare_digest(
                _mapping_digest(restored), self._original_member_digest
            ),
            "schedule_state_preserved": schedule is not None
            and hmac.compare_digest(_mapping_digest(schedule), self._schedule_digest),
        }
        result = BP015MemberScheduleRollbackReadback(
            **categorical, rollback_digest=_digest(categorical)  # type: ignore[arg-type]
        )
        if result.verified:
            self._bound_group = None
        return result

    def _read_detail(
        self, path: str, expected_path: str, expected_name: str, key: str
    ) -> Mapping[str, object] | None:
        status, payload = self._request("GET", path, None, override=False)
        if status != 200 or not isinstance(payload, Mapping):
            raise BP015MemberScheduleHttpTransportError(_UNAVAILABLE)
        if (
            payload.get("status") != "success"
            or payload.get("http_method") != "GET"
            or payload.get("http_status") != 200
            or payload.get("version") != "v7.0.0"
            or payload.get("build") != 29
            or payload.get("path") != expected_path
            or payload.get("name") != expected_name
        ):
            raise BP015MemberScheduleHttpTransportError(_UNAVAILABLE)
        results = payload.get("results")
        record: object = results[0] if isinstance(results, list) and len(results) == 1 else results
        if not isinstance(record, Mapping) or record.get("name") != key:
            raise BP015MemberScheduleHttpTransportError(_UNAVAILABLE)
        return record

    def _read_collection(
        self,
        path: str,
        body: Mapping[str, object],
        expected_path: str,
        expected_name: str,
    ) -> list[Mapping[str, object]]:
        status, payload = self._request("POST", path, body, override=True)
        try:
            return _collection_records(
                payload, status, path=expected_path, name=expected_name
            )
        except Exception as exc:
            raise BP015MemberScheduleHttpTransportError(_UNAVAILABLE) from exc

    def _put_once(
        self, group_name: str, body: Mapping[str, object]
    ) -> Literal["accepted", "ambiguous"]:
        # The User CMDB save layer overwrites the Group-edit extras with the
        # current login principal's Sponsor Group.  The protected API principal
        # is not a Sponsored Admin, so its exact frontend-equivalent context is
        # the empty value; the target relationship remains only in the body.
        path = f"{_member_path()}?{urlencode({'sponsor-group': ''})}"
        try:
            status, payload = self._request("PUT", path, body, override=False)
        except BP015MemberScheduleHttpTransportError:
            return "ambiguous"
        return "accepted" if status == 200 and _put_envelope(payload) else "ambiguous"

    def _request(
        self,
        method: Literal["GET", "POST", "PUT"],
        path: str,
        body: Mapping[str, object] | None,
        *,
        override: bool,
    ) -> tuple[int, object]:
        try:
            import httpx

            factory = self._client_factory or httpx.Client
            headers = {
                "Accept": "application/json",
                "Authorization": f"Bearer {self._config.bearer_token}",
                "User-Agent": "fortipam-mcp-v4-bp015-member-schedule/1",
            }
            if override:
                headers["X-HTTP-Method-Override"] = "GET"
            with factory(
                verify=_ssl_context(self._config),
                timeout=self._config.timeout_seconds,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                response = client.request(
                    method,
                    f"{self._config.base_url}{path}",
                    headers=headers,
                    json=body,
                )
        except Exception as exc:
            raise BP015MemberScheduleHttpTransportError(_UNAVAILABLE) from exc
        content_type = response.headers.get("content-type", "")
        if "json" not in content_type.lower() or len(response.content) > MAX_RESPONSE_BYTES:
            raise BP015MemberScheduleHttpTransportError(_UNAVAILABLE)
        try:
            return int(response.status_code), json.loads(response.content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BP015MemberScheduleHttpTransportError(_UNAVAILABLE) from exc


def _member_path() -> str:
    return f"{_ADMIN_PATH}/{quote(FIXED_MEMBER_NAME, safe='')}"


def _schedule_path() -> str:
    return f"{_SCHEDULE_PATH}/{quote(FIXED_SCHEDULE_NAME, safe='')}"


def _group_name(value: str) -> str:
    if not isinstance(value, str) or _GROUP_NAME.fullmatch(value) is None:
        raise BP015MemberScheduleHttpTransportError(_UNAVAILABLE)
    return value


def _digest_value(value: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise BP015MemberScheduleHttpTransportError(_UNAVAILABLE)
    return value


def _non_relationship_digest(record: Mapping[str, object] | None) -> str:
    if record is None:
        return _digest({"absent": True})
    return _digest(
        {
            key: value
            for key, value in record.items()
            if key not in {"sponsor-group", "schedule"}
        }
    )


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest()


def _put_envelope(payload: object) -> bool:
    return (
        isinstance(payload, Mapping)
        and payload.get("status") == "success"
        and payload.get("http_method") == "PUT"
        and payload.get("http_status") == 200
        and payload.get("version") == "v7.0.0"
        and payload.get("build") == 29
        and payload.get("path") == "system"
        and payload.get("name") == "admin"
    )


__all__ = [
    "BP015MemberScheduleHttpTransportError",
    "BP015MemberScheduleInspection",
    "BP015MemberScheduleReadback",
    "BP015MemberScheduleRollbackReadback",
    "BP015RetainedRecoveryAssessment",
    "FIXED_MEMBER_NAME",
    "FIXED_SCHEDULE_NAME",
    "FortiPamBP015MemberScheduleHttpTransport",
]
