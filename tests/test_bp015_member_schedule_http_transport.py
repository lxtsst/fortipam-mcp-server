from __future__ import annotations

import json
from typing import Any, cast

import pytest

import fortipam_mcp.bp015_member_schedule_http_transport as module
from fortipam_mcp.bp015_member_schedule_http_transport import (
    BP015MemberScheduleHttpTransportError,
    FIXED_MEMBER_NAME,
    FIXED_SCHEDULE_NAME,
    FortiPamBP015MemberScheduleHttpTransport,
)
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig


GROUP = "mcp-v4-bp015-slice-01"


class _Response:
    def __init__(self, payload: object, status: int = 200) -> None:
        self.status_code = status
        self.content = json.dumps(payload).encode()
        self.headers = {"content-type": "application/json"}


class _Client:
    def __init__(self, responses: list[_Response], calls: list[dict[str, object]], **_: object) -> None:
        self.responses = responses
        self.calls = calls

    def __enter__(self) -> _Client:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def request(self, method: str, url: str, **kwargs: object) -> _Response:
        self.calls.append({"method": method, "url": url, **kwargs})
        return self.responses.pop(0)


def _config() -> SecretMetadataHttpTransportConfig:
    return SecretMetadataHttpTransportConfig(
        base_url="https://fpa.example.test",
        bearer_token="unit-test-token",
        timeout_seconds=10,
        ca_file=None,
    )


def _member(
    group: str = "", schedule: str = "", *, status: str = "enable"
) -> dict[str, object]:
    return {
        "id": 57,
        "name": FIXED_MEMBER_NAME,
        "display-name": "fixture",
        "wildcard": "disable",
        "remote-auth": "disable",
        "accprofile": "pam_standard_user",
        "schedule": schedule,
        "sponsor-group": group,
        "status": status,
    }


def _schedule() -> dict[str, object]:
    return {"name": FIXED_SCHEDULE_NAME, "start": "00:00", "end": "00:00", "day": "all"}


def _detail(record: dict[str, object], path: str, name: str) -> dict[str, object]:
    return {
        "build": 29,
        "http_method": "GET",
        "http_status": 200,
        "name": name,
        "path": path,
        "results": [record],
        "status": "success",
        "version": "v7.0.0",
    }


def _collection(records: list[object], path: str, name: str) -> dict[str, object]:
    payload: dict[str, object] = {
        "build": 29,
        "http_method": "POST",
        "http_status": 200,
        "name": name,
        "path": path,
        "results": records,
        "status": "OK" if path == "user" else "success",
        "version": "v7.0.0",
    }
    if path == "system":
        payload.update({"matched_count": len(records), "next_idx": 3 if records else 0, "size": 7})
    return payload


def _put_success() -> dict[str, object]:
    return {
        "build": 29,
        "http_method": "PUT",
        "http_status": 200,
        "name": "admin",
        "path": "system",
        "status": "success",
        "version": "v7.0.0",
    }


def _inspect_responses(member: dict[str, object] | None = None) -> list[_Response]:
    return [
        _Response(_detail(member or _member(), "system", "admin")),
        _Response(_detail(_schedule(), "firewall.schedule", "recurring")),
        _Response(_collection([{"name": GROUP}], "user", "group")),
        _Response(_collection([], "system", "admin")),
    ]


def _retained_responses(member: dict[str, object]) -> list[_Response]:
    return [
        _Response(_detail(member, "system", "admin")),
        _Response(_detail(_schedule(), "firewall.schedule", "recurring")),
        _Response(_collection([{"name": GROUP}], "user", "group")),
        _Response(_collection([member], "system", "admin")),
    ]


def _transport(monkeypatch: pytest.MonkeyPatch, responses: list[_Response]) -> tuple[FortiPamBP015MemberScheduleHttpTransport, list[dict[str, object]]]:
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(module, "_ssl_context", lambda _: object())

    def factory(**kwargs: object) -> _Client:
        return _Client(responses, calls, **kwargs)

    return FortiPamBP015MemberScheduleHttpTransport(_config(), client_factory=factory), calls


def test_inspection_is_exact_categorical_and_non_disclosing(monkeypatch: pytest.MonkeyPatch) -> None:
    transport, calls = _transport(monkeypatch, _inspect_responses())

    result = transport.inspect(GROUP)

    assert result.eligible is True
    assert result.member_sponsored_user_role is True
    assert len(result.member_state_digest) == 64
    assert FIXED_MEMBER_NAME not in repr(result)
    assert GROUP not in repr(result)
    assert [call["method"] for call in calls] == ["GET", "GET", "POST", "POST"]
    assert calls[2]["headers"]["X-HTTP-Method-Override"] == "GET"  # type: ignore[index]


def test_disabled_member_is_observed_but_not_assignment_eligible(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport, calls = _transport(
        monkeypatch, _inspect_responses(_member(status="disable"))
    )

    result = transport.inspect(GROUP)

    assert result.member_disabled is True
    assert result.member_enabled is False
    assert result.eligible is False
    assert not any(call["method"] == "PUT" for call in calls)


def test_guest_member_is_observed_as_enabled_sponsor_admin_candidate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    member = _member()
    member["accprofile"] = "guest"
    transport, calls = _transport(monkeypatch, _inspect_responses(member))

    result = transport.inspect(GROUP)

    assert result.member_enabled is True
    assert result.member_sponsored_user_role is False
    assert result.eligible is True
    assert not any(call["method"] == "PUT" for call in calls)


def test_retained_recovery_assessment_rejects_existing_user_edit_clear_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    retained = _member(GROUP, FIXED_SCHEDULE_NAME, status="disable")
    retained["accprofile"] = "mcp-v4-role-example"
    transport, calls = _transport(monkeypatch, _retained_responses(retained))

    result = transport.assess_retained_recovery(GROUP)

    assert result.retained_relation_exact is True
    assert result.member_editor_classification == "sponsor_admin"
    assert result.documented_disabled_user_visibility is True
    assert result.documented_selected_user_edit_action is True
    assert result.saved_build29_transport_preserves_status is True
    assert result.saved_build29_transport_projects_relationship_fields is True
    assert result.current_build_disabled_edit_form_verified is False
    assert result.current_build_edit_source_sponsor_locked is True
    assert result.sponsor_assignment_clear_required is True
    assert result.relationship_removal_contract_proven is False
    assert result.automatic_execution_allowed is False
    assert result.requires_recovery_contract is True
    assert not any(call["method"] == "PUT" for call in calls)
    assert FIXED_MEMBER_NAME not in repr(result)
    assert GROUP not in repr(result)


@pytest.mark.parametrize(
    ("accprofile", "expected_branch"),
    [
        ("pam_standard_user", "sponsored_user"),
        ("guest", "sponsor_admin"),
    ],
)
def test_retained_recovery_classifies_exact_sponsored_user_role(
    monkeypatch: pytest.MonkeyPatch, accprofile: str, expected_branch: str
) -> None:
    retained = _member(GROUP, FIXED_SCHEDULE_NAME, status="disable")
    retained["accprofile"] = accprofile
    transport, calls = _transport(monkeypatch, _retained_responses(retained))

    result = transport.assess_retained_recovery(GROUP)

    assert result.member_editor_classification == expected_branch
    assert result.requires_recovery_contract is True
    assert result.automatic_execution_allowed is False
    assert not any(call["method"] == "PUT" for call in calls)


def test_assign_and_rollback_use_one_put_each_and_restore_exact_state(monkeypatch: pytest.MonkeyPatch) -> None:
    original = _member()
    assigned = _member(GROUP, FIXED_SCHEDULE_NAME)
    responses = _inspect_responses(original) + _inspect_responses(original) + [
        _Response(_detail(original, "system", "admin")),
        _Response(_put_success()),
        _Response(_detail(assigned, "system", "admin")),
        _Response(_detail(_schedule(), "firewall.schedule", "recurring")),
        _Response(_collection([assigned], "system", "admin")),
        _Response(_detail(assigned, "system", "admin")),
        _Response(_collection([assigned], "system", "admin")),
        _Response(_put_success()),
        _Response(_detail(original, "system", "admin")),
        _Response(_detail(_schedule(), "firewall.schedule", "recurring")),
        _Response(_collection([], "system", "admin")),
    ]
    transport, calls = _transport(monkeypatch, responses)
    inspection = transport.inspect(GROUP)
    monkeypatch.setattr(module, "_EXPERIMENTAL_WRITE_DISABLED", False)

    assigned_result = transport.assign_and_readback(
        GROUP,
        expected_member_state_digest=inspection.member_state_digest,
        expected_member_non_relationship_digest=inspection.member_non_relationship_digest,
        expected_schedule_state_digest=inspection.schedule_state_digest,
    )
    rollback = transport.rollback_and_readback()

    assert assigned_result.verified is True
    assert assigned_result.member_sponsored_user_role is True
    assert rollback.verified is True
    puts = [call for call in calls if call["method"] == "PUT"]
    assert len(puts) == 2
    assert cast(str, puts[0]["url"]).endswith(
        f"/api/v2/cmdb/system/admin/{FIXED_MEMBER_NAME}?sponsor-group="
    )
    first_body = cast(dict[str, object], puts[0]["json"])
    second_body = cast(dict[str, object], puts[1]["json"])
    assert first_body["sponsor-group"] == GROUP
    assert first_body["schedule"] == FIXED_SCHEDULE_NAME
    assert second_body["sponsor-group"] == ""
    assert second_body["schedule"] == ""
    assert "password" not in first_body


def test_drift_and_second_write_are_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    transport, calls = _transport(monkeypatch, _inspect_responses())
    inspection = transport.inspect(GROUP)
    monkeypatch.setattr(module, "_EXPERIMENTAL_WRITE_DISABLED", False)

    with pytest.raises(BP015MemberScheduleHttpTransportError, match="unavailable"):
        transport.assign_and_readback(
            GROUP,
            expected_member_state_digest="0" * 64,
            expected_member_non_relationship_digest=inspection.member_non_relationship_digest,
            expected_schedule_state_digest=inspection.schedule_state_digest,
        )

    assert not any(call["method"] == "PUT" for call in calls)


def test_unsafe_group_and_unbound_rollback_are_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    transport, _ = _transport(monkeypatch, [])
    with pytest.raises(BP015MemberScheduleHttpTransportError, match="unavailable"):
        transport.inspect("unsafe/group")
    with pytest.raises(BP015MemberScheduleHttpTransportError, match="unavailable"):
        transport.rollback_and_readback()


def test_live_write_is_fail_closed_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    transport, calls = _transport(monkeypatch, _inspect_responses())
    inspection = transport.inspect(GROUP)

    with pytest.raises(BP015MemberScheduleHttpTransportError, match="unavailable"):
        transport.assign_and_readback(
            GROUP,
            expected_member_state_digest=inspection.member_state_digest,
            expected_member_non_relationship_digest=(
                inspection.member_non_relationship_digest
            ),
            expected_schedule_state_digest=inspection.schedule_state_digest,
        )

    assert not any(call["method"] == "PUT" for call in calls)
