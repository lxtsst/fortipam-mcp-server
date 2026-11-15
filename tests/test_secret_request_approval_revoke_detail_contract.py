from copy import deepcopy
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timedelta, timezone
import json
from typing import Any

import pytest

from fortipam_mcp.secret_metadata_http_transport import MAX_RESPONSE_BYTES
from fortipam_mcp.secret_request_approval_revoke_detail_contract import (
    SecretRequestApprovalRevokeDetailBinding,
    SecretRequestApprovalRevokeDetailContractError,
    SecretRequestApprovalRevokeDetailWitness,
    SecretRequestApprovalRevokeRelationWitness,
    qualify_secret_request_approval_revoke_get_detail,
    qualify_secret_request_approval_revoke_secret_profile_relation,
)

_NOW = datetime(2026, 10, 8, 12, tzinfo=timezone.utc)
_BINDING = SecretRequestApprovalRevokeDetailBinding(
    request_id=19, secret_id=7, requester="synthetic-requester",
    approval_profile_name="synthetic-original-profile", original_reviewer="synthetic-reviewer",
    source_serial="SYNTHETIC29",
)


class _Clock(datetime):
    @classmethod
    def now(cls, tz: Any = None) -> "_Clock":
        value = cls.fromtimestamp(_NOW.timestamp(), timezone.utc)
        return value.astimezone(tz) if tz is not None else value.replace(tzinfo=None)


@pytest.fixture(autouse=True)
def fixed_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("fortipam_mcp.secret_request_http_transport.datetime", _Clock)


def _payload() -> dict[str, Any]:
    return {
        "version": "v7.0.0", "build": 29, "http_method": "GET", "http_status": 200,
        "status": "success", "path": "secret", "name": "request", "vdom": "root",
        "mkey": "19", "serial": "SYNTHETIC29", "revision": "synthetic-revision",
        "results": [{"id": 19, "q_origin_key": 19, "secret-id": 7,
                     "user": "synthetic-requester", "request-type": "launcher", "job-name": "",
                     "approval-profile": "synthetic-original-profile", "final-status": "approved",
                     "tier1-status": "approved", "start-time": "2026-10-08 19:50:00",
                     "expiration-time": "2026-10-08 20:10:00", "timezone": "Asia/Shanghai",
                     "tier1": [{"name": "synthetic-reviewer", "q_origin_key": "synthetic-reviewer",
                                "status": "approved", "comments": "opaque", "update-time": "opaque-not-date"}],
                     "tier2": [], "tier3": [], "comments": "preserved request comments",
                     "opaque-metadata": {"description": "synthetic preserved native metadata"}}],
    }


def _encode(payload: object) -> bytes:
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _qualify(payload: object, *, reviewer: str = "synthetic-reviewer",
             date: datetime | None = _NOW) -> SecretRequestApprovalRevokeDetailWitness:
    return qualify_secret_request_approval_revoke_get_detail(
        _encode(payload), binding=_BINDING, authenticated_reviewer=reviewer, server_time=date,
    )


def _relation_payloads() -> tuple[dict[str, Any], dict[str, Any]]:
    # Qualified build-29 native envelopes differ between database and Profile.
    common = {"version": "v7.0.0", "build": 29, "http_method": "GET", "http_status": 200,
              "path": "secret", "vdom": "root", "serial": "SYNTHETIC29"}
    secret = {**common, "status": "OK", "name": "database",
              "results": [{"id": 7, "q_origin_key": 7, "need-approval": "enable",
                           "bypass-approval": "disable", "approval-profile": "synthetic-original-profile",
                           "opaque-metadata": {"description": "preserved secret metadata"}}]}
    profile = {**common, "status": "success", "name": "approval-profile",
               "mkey": "synthetic-original-profile", "revision": "opaque-revision",
               "results": [{"name": "synthetic-original-profile", "q_origin_key": "synthetic-original-profile",
                            "type": "single", "first-num": 1,
                            "first-user": [{"name": "synthetic-reviewer", "q_origin_key": "synthetic-reviewer"}],
                            "first-group": [], "second-user": [], "second-group": [],
                            "third-user": [], "third-group": [], "self-approval": "disable",
                            "auto-approval-schedule": "", "max-allowed-duration": 0,
                            "remote-group-email": "disable", "email-template": "",
                            "approver-perm-req": "none", "field": [],
                            "opaque-metadata": "preserved profile metadata"}]}
    return secret, profile


def _qualify_relation(secret: object, profile: object, *, reviewer: str = "synthetic-reviewer",
                      binding: SecretRequestApprovalRevokeDetailBinding = _BINDING,
                      ) -> SecretRequestApprovalRevokeRelationWitness:
    return qualify_secret_request_approval_revoke_secret_profile_relation(
        _encode(secret), _encode(profile), binding=binding, authenticated_reviewer=reviewer,
    )


def test_secret_profile_join_private_binding_and_metadata_drift() -> None:
    secret, profile = _relation_payloads()
    before = deepcopy((secret, profile))
    witness = _qualify_relation(secret, profile)
    assert (secret, profile) == before
    assert witness.private_binding_digest == _qualify(_payload()).private_binding_digest
    assert {field.name for field in fields(witness)} == {
        "private_binding_digest", "private_secret_metadata_digest", "private_profile_metadata_digest",
    }
    assert all(len(getattr(witness, field.name)) == 64 for field in fields(witness))
    assert "synthetic" not in repr(witness)
    assert witness.private_secret_metadata_digest not in repr(witness)
    with pytest.raises(FrozenInstanceError):
        setattr(witness, "private_profile_metadata_digest", "changed")
    secret["results"][0]["opaque-metadata"]["description"] += " drift"
    secret_drift = _qualify_relation(secret, profile)
    assert secret_drift.private_secret_metadata_digest != witness.private_secret_metadata_digest
    assert secret_drift.private_profile_metadata_digest == witness.private_profile_metadata_digest
    profile["results"][0]["opaque-metadata"] += " drift"
    profile_drift = _qualify_relation(secret, profile)
    assert profile_drift.private_profile_metadata_digest != witness.private_profile_metadata_digest
    assert profile_drift.private_binding_digest == witness.private_binding_digest
    assert _qualify_relation(dict(reversed(list(secret.items()))), profile) == profile_drift
    assert not hasattr(witness, "authorized") and not hasattr(witness, "body")


@pytest.mark.parametrize("failure", [
    "secret_serial", "profile_serial", "secret_id", "secret_bool_id", "secret_origin_type",
    "secret_origin", "secret_profile", "need_approval", "bypass", "profile_mkey",
    "profile_name", "profile_origin", "first_reviewer", "first_origin", "first_extra",
    "first_multiple", "first_compact", "first_bool_num", "first_num", "other_user", "other_group",
    "self_approval", "auto_schedule", "max_duration", "bool_duration", "remote_email", "email_template",
    "approver_permission", "field", "profile_type", "actor", "secret_status", "profile_status",
    "secret_extra_envelope", "profile_missing_revision", "secret_results", "profile_results",
    "secret_bool_build", "profile_method", "secret_row", "missing_principal",
])
def test_secret_profile_join_refuses_identity_source_and_profile_drift(failure: str) -> None:
    secret, profile = _relation_payloads()
    secret_row, profile_row = secret["results"][0], profile["results"][0]
    changes: dict[str, tuple[dict[str, Any], str, object]] = {
        "secret_serial": (secret, "serial", "OTHER"), "profile_serial": (profile, "serial", "OTHER"),
        "secret_id": (secret_row, "id", 8), "secret_bool_id": (secret_row, "id", True),
        "secret_origin_type": (secret_row, "q_origin_key", "7"), "secret_origin": (secret_row, "q_origin_key", 8),
        "secret_profile": (secret_row, "approval-profile", "other-profile"),
        "need_approval": (secret_row, "need-approval", "disable"), "bypass": (secret_row, "bypass-approval", "enable"),
        "profile_mkey": (profile, "mkey", "other-profile"), "profile_name": (profile_row, "name", "other-profile"),
        "profile_origin": (profile_row, "q_origin_key", "other-profile"),
        "first_reviewer": (profile_row["first-user"][0], "name", "other-reviewer"),
        "first_origin": (profile_row["first-user"][0], "q_origin_key", "other-reviewer"),
        "first_extra": (profile_row["first-user"][0], "unknown", "extra"),
        "first_multiple": (profile_row, "first-user", profile_row["first-user"] * 2),
        "first_compact": (profile_row, "first-user", ["synthetic-reviewer"]),
        "first_bool_num": (profile_row, "first-num", True), "first_num": (profile_row, "first-num", 2),
        "other_user": (profile_row, "second-user", ["other"]), "other_group": (profile_row, "first-group", ["other"]),
        "self_approval": (profile_row, "self-approval", "enable"),
        "auto_schedule": (profile_row, "auto-approval-schedule", "other"),
        "max_duration": (profile_row, "max-allowed-duration", 1), "bool_duration": (profile_row, "max-allowed-duration", False),
        "remote_email": (profile_row, "remote-group-email", "enable"), "email_template": (profile_row, "email-template", "other"),
        "approver_permission": (profile_row, "approver-perm-req", "other"), "field": (profile_row, "field", [{}]),
        "profile_type": (profile_row, "type", "multiple"), "secret_status": (secret, "status", "success"),
        "profile_status": (profile, "status", "OK"), "secret_extra_envelope": (secret, "mkey", "7"),
        "secret_results": (secret, "results", secret_row), "profile_results": (profile, "results", profile["results"] * 2),
        "secret_bool_build": (secret, "build", True), "profile_method": (profile, "http_method", "POST"),
        "secret_row": (secret, "results", [False]),
    }
    if failure in changes:
        target, key, value = changes[failure]
        target[key] = value
    elif failure == "profile_missing_revision":
        del profile["revision"]
    elif failure == "missing_principal":
        del profile_row["third-group"]
    with pytest.raises(SecretRequestApprovalRevokeDetailContractError, match="unavailable"):
        _qualify_relation(secret, profile, reviewer="other-reviewer" if failure == "actor" else "synthetic-reviewer")


@pytest.mark.parametrize("empty", [None, "", []])
def test_secret_profile_join_uses_existing_disabled_principal_grammar(empty: object) -> None:
    secret, profile = _relation_payloads()
    profile["results"][0]["second-user"] = empty
    assert _qualify_relation(secret, profile).private_binding_digest


@pytest.mark.parametrize("which", ["secret", "profile"])
@pytest.mark.parametrize("malformed", ["duplicate", "oversize", "nan", "surrogate", "not_bytes"])
def test_secret_profile_join_rejects_raw_ambiguity_before_witness(which: str, malformed: str) -> None:
    secret, profile = _relation_payloads()
    raw: Any = _encode(secret if which == "secret" else profile)
    if malformed == "duplicate":
        # Even identical/nonselected duplicates belong only to a qualified reader's
        # narrow normalization boundary; this pure contract rejects all of them.
        raw = raw.replace(b'"vdom":"root"', b'"vdom":"root","vdom":"root"', 1)
    elif malformed == "oversize":
        raw += b" " * MAX_RESPONSE_BYTES
    elif malformed == "nan":
        raw = raw.replace(b'"build":29', b'"build":NaN', 1)
    elif malformed == "surrogate":
        raw = raw.replace(b'"vdom":"root"', b'"vdom":"root","results_bad":"\\ud800"', 1)
    else:
        raw = False
    secret_raw, profile_raw = (raw, _encode(profile)) if which == "secret" else (_encode(secret), raw)
    with pytest.raises(SecretRequestApprovalRevokeDetailContractError, match="unavailable"):
        qualify_secret_request_approval_revoke_secret_profile_relation(
            secret_raw, profile_raw, binding=_BINDING, authenticated_reviewer="synthetic-reviewer",
        )


def test_secret_profile_join_redacts_material_before_decode_and_zeroizes_copies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import fortipam_mcp.secret_request_approval_revoke_detail_contract as contract

    secret, profile = _relation_payloads()
    secret["results"][0]["field"] = [{"value": "SYNTHETIC_MATERIAL_NEVER_DECODE"}]
    secret["results"][0]["keyinfo"] = {"value": "SYNTHETIC_MATERIAL_NEVER_DECODE"}
    profile["results"][0]["shared-key"] = "SYNTHETIC_MATERIAL_NEVER_DECODE"
    original_loads = json.loads
    original_zeroize = contract._zeroize_mutable
    cleared: list[bytearray] = []

    def loads_without_material(value: Any, *args: Any, **kwargs: Any) -> Any:
        assert "SYNTHETIC_MATERIAL_NEVER_DECODE" not in str(value)
        return original_loads(value, *args, **kwargs)

    def capture_zeroize(value: bytearray) -> None:
        original_zeroize(value)
        cleared.append(value)

    monkeypatch.setattr(json, "loads", loads_without_material)
    monkeypatch.setattr(contract, "_zeroize_mutable", capture_zeroize)
    secret_raw, profile_raw = bytearray(_encode(secret)), bytearray(_encode(profile))
    snapshot = bytes(secret_raw), bytes(profile_raw)
    witness = contract.qualify_secret_request_approval_revoke_secret_profile_relation(
        secret_raw, profile_raw, binding=_BINDING, authenticated_reviewer="synthetic-reviewer",
    )
    assert (bytes(secret_raw), bytes(profile_raw)) == snapshot
    assert len(cleared) == 2 and all(not any(raw) for raw in cleared)
    secret["results"][0]["field"] = [{"value": "different synthetic material"}]
    assert _qualify_relation(secret, profile) == witness


@pytest.mark.parametrize("field_value", [None, [{"value": "SYNTHETIC_UNSAFE_PROFILE_MATERIAL"}], ""])
def test_secret_profile_join_requires_original_raw_profile_empty_field(field_value: object) -> None:
    secret, profile = _relation_payloads()
    profile["results"][0]["field"] = field_value
    with pytest.raises(SecretRequestApprovalRevokeDetailContractError, match="unavailable"):
        _qualify_relation(secret, profile)


def test_secret_profile_join_rejects_duplicate_inside_material_before_redaction() -> None:
    secret, profile = _relation_payloads()
    raw = _encode(secret).replace(b'"id":7', b'"id":7,"field":[{"value":"same","value":"same"}]', 1)
    with pytest.raises(SecretRequestApprovalRevokeDetailContractError, match="unavailable"):
        qualify_secret_request_approval_revoke_secret_profile_relation(
            raw, _encode(profile), binding=_BINDING, authenticated_reviewer="synthetic-reviewer",
        )


def test_get_detail_predecode_material_redaction_and_zeroization(monkeypatch: pytest.MonkeyPatch) -> None:
    import fortipam_mcp.secret_request_approval_revoke_detail_contract as contract

    payload = _payload()
    metadata = payload["results"][0]["opaque-metadata"]
    metadata["field"] = [{"value": "SYNTHETIC_DETAIL_MATERIAL_NEVER_DECODE"}]
    metadata["keyinfo"] = {"value": "SYNTHETIC_DETAIL_MATERIAL_NEVER_DECODE"}
    metadata["shared-key"] = "SYNTHETIC_DETAIL_MATERIAL_NEVER_DECODE"
    original_loads = json.loads
    original_zeroize = contract._zeroize_mutable
    cleared: list[bytearray] = []

    def loads_without_material(value: Any, *args: Any, **kwargs: Any) -> Any:
        assert "SYNTHETIC_DETAIL_MATERIAL_NEVER_DECODE" not in str(value)
        return original_loads(value, *args, **kwargs)

    def capture_zeroize(value: bytearray) -> None:
        original_zeroize(value)
        cleared.append(value)

    monkeypatch.setattr(json, "loads", loads_without_material)
    monkeypatch.setattr(contract, "_zeroize_mutable", capture_zeroize)
    native = bytearray(_encode(payload))
    snapshot = bytes(native)
    witness = contract.qualify_secret_request_approval_revoke_get_detail(
        native, binding=_BINDING, authenticated_reviewer="synthetic-reviewer", server_time=_NOW,
    )
    assert bytes(native) == snapshot
    assert len(cleared) == 1 and not any(cleared[0])
    metadata["field"] = [{"value": "different synthetic material"}]
    assert _qualify(payload) == witness
    metadata["description"] += " metadata drift"
    assert _qualify(payload).private_native_metadata_digest != witness.private_native_metadata_digest


def test_get_detail_predecode_rejects_nested_material_duplicate_and_zeroizes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import fortipam_mcp.secret_request_approval_revoke_detail_contract as contract

    raw = bytearray(_encode(_payload()).replace(
        b'"id":19', b'"id":19,"field":[{"value":"same","value":"same"}]', 1,
    ))
    snapshot = bytes(raw)
    original_zeroize = contract._zeroize_mutable
    cleared: list[bytearray] = []

    def capture_zeroize(value: bytearray) -> None:
        original_zeroize(value)
        cleared.append(value)

    monkeypatch.setattr(contract, "_zeroize_mutable", capture_zeroize)
    with pytest.raises(SecretRequestApprovalRevokeDetailContractError, match="unavailable"):
        contract.qualify_secret_request_approval_revoke_get_detail(
            raw, binding=_BINDING, authenticated_reviewer="synthetic-reviewer", server_time=_NOW,
        )
    assert bytes(raw) == snapshot
    assert len(cleared) == 1 and not any(cleared[0])


def test_get_detail_witness_preserves_private_metadata_and_tiers_without_authority() -> None:
    payload = _payload()
    snapshot = deepcopy(payload)
    witness = _qualify(payload)
    assert payload == snapshot
    assert {field.name for field in fields(witness)} == {
        "private_binding_digest", "private_native_metadata_digest", "private_tier_digest",
    }
    assert all(len(getattr(witness, field.name)) == 64 for field in fields(witness))
    assert "synthetic" not in repr(_BINDING)
    assert witness.private_native_metadata_digest not in repr(witness)
    with pytest.raises(FrozenInstanceError):
        setattr(witness, "private_tier_digest", "changed")
    changed = deepcopy(payload)
    changed["results"][0]["opaque-metadata"]["description"] += " drift"
    drift = _qualify(changed)
    assert drift.private_binding_digest == witness.private_binding_digest
    assert drift.private_native_metadata_digest != witness.private_native_metadata_digest
    assert drift.private_tier_digest == witness.private_tier_digest
    changed["results"][0]["tier1"][0]["comments"] += " tier drift"
    assert _qualify(changed).private_tier_digest != witness.private_tier_digest
    reordered = {key: payload[key] for key in reversed(payload)}
    assert _qualify(reordered) == witness
    # Successful pure GET qualification still has no Secret/Profile join or dispatch API.
    assert not hasattr(witness, "authorized") and not hasattr(witness, "body")


@pytest.mark.parametrize("failure", ["build", "boolean_build", "version", "method", "status", "http_status",
                                    "vdom", "path", "name", "serial", "mkey_type", "mkey_value", "extra_envelope",
                                    "revision_empty", "revision_long", "results_object", "results_duplicate",
                                    "id", "boolean_id", "origin_type", "origin_value", "secret", "requester",
                                    "profile", "profile_missing", "profile_null", "job_type", "job_name",
                                    "pending", "tier_pending", "tier_foreign", "tier_origin", "tier_extra",
                                    "tier_multiple", "tier2", "expired", "future", "window_equal", "timezone",
                                    "numeric_start", "numeric_end", "numeric_update_time"])
def test_get_detail_refuses_other_profiles_or_binding_state_drift(failure: str) -> None:
    payload = _payload()
    row = payload["results"][0]
    envelope_changes = {"build": ("build", 30), "boolean_build": ("build", True),
                        "version": ("version", "v1.9.1"), "method": ("http_method", "POST"),
                        "status": ("status", "OK"), "http_status": ("http_status", 403),
                        "vdom": ("vdom", "other"), "path": ("path", "other"), "name": ("name", "other"),
                        "serial": ("serial", "OTHER"), "mkey_type": ("mkey", 19), "mkey_value": ("mkey", "20"),
                        "revision_empty": ("revision", ""), "revision_long": ("revision", "界" * 43)}
    if failure in envelope_changes:
        key, value = envelope_changes[failure]
        payload[key] = value
    row_changes = {"id": ("id", 20), "boolean_id": ("id", True),
                   "origin_type": ("q_origin_key", "19"), "origin_value": ("q_origin_key", 20),
                   "secret": ("secret-id", 8), "requester": ("user", "other-requester"),
                   "profile": ("approval-profile", "other-profile"), "profile_null": ("approval-profile", None),
                   "job_type": ("request-type", "job"), "job_name": ("job-name", "other-job"),
                   "pending": ("final-status", "pending"), "tier_pending": ("tier1-status", "pending"),
                   "expired": ("expiration-time", "2026-10-08 19:59:59"),
                   "future": ("start-time", "2026-10-08 20:00:01"),
                   "numeric_start": ("start-time", int(_NOW.timestamp()) - 600),
                   "numeric_end": ("expiration-time", int(_NOW.timestamp()) + 600),
                   "window_equal": ("expiration-time", row["start-time"]), "timezone": ("timezone", "UTC")}
    if failure in row_changes:
        key, value = row_changes[failure]
        row[key] = value
    if failure == "extra_envelope": payload["action"] = "default"
    if failure == "results_object": payload["results"] = row
    if failure == "results_duplicate": payload["results"].append(deepcopy(row))
    if failure == "profile_missing": del row["approval-profile"]
    if failure == "tier_foreign": row["tier1"][0]["name"] = "other-reviewer"
    if failure == "tier_origin": row["tier1"][0]["q_origin_key"] = "other-reviewer"
    if failure == "tier_extra": row["tier1"][0]["extra"] = "unknown"
    if failure == "tier_multiple": row["tier1"].append(deepcopy(row["tier1"][0]))
    if failure == "tier2": row["tier2"] = deepcopy(row["tier1"])
    if failure == "numeric_update_time": row["tier1"][0]["update-time"] = 1
    with pytest.raises(SecretRequestApprovalRevokeDetailContractError,
                       match="^The fixed Launcher Request withdrawal detail is unavailable.$"):
        _qualify(payload)


@pytest.mark.parametrize("failure", ["foreign_actor", "absent_date", "naive_date", "stale_date"])
def test_get_detail_requires_original_logged_reviewer_and_fresh_device_date(failure: str) -> None:
    actor, date = "synthetic-reviewer", _NOW
    if failure == "foreign_actor": actor = "other-reviewer"
    if failure == "naive_date": date = _NOW.replace(tzinfo=None)
    if failure == "stale_date": date = _NOW - timedelta(seconds=301)
    with pytest.raises(SecretRequestApprovalRevokeDetailContractError):
        _qualify(_payload(), reviewer=actor, date=None if failure == "absent_date" else date)


@pytest.mark.parametrize("raw", [b'{"build":29,"build":29}', b'{"nested":{"name":"a","name":"b"}}',
                               b'{"unknown":NaN}', b'{}' + b' ' * MAX_RESPONSE_BYTES,
                               b'\xff', b'[]'])
def test_get_detail_rejects_duplicate_keys_invalid_json_or_response_budget(raw: bytes) -> None:
    with pytest.raises(SecretRequestApprovalRevokeDetailContractError):
        qualify_secret_request_approval_revoke_get_detail(
            raw, binding=_BINDING, authenticated_reviewer="synthetic-reviewer", server_time=_NOW,
        )


@pytest.mark.parametrize("location", ["request_id", "tier_name", "opaque_metadata"])
def test_get_detail_rejects_duplicates_inside_otherwise_valid_native_json(location: str) -> None:
    raw = _encode(_payload())
    replacements = {
        "request_id": (b'"id":19', b'"id":20,"id":19'),
        "tier_name": (b'"name":"synthetic-reviewer"',
                      b'"name":"other-reviewer","name":"synthetic-reviewer"'),
        "opaque_metadata": (b'"description":"synthetic preserved native metadata"',
                            b'"description":"first","description":"synthetic preserved native metadata"'),
    }
    old, new = replacements[location]
    assert old in raw
    raw = raw.replace(old, new, 1)
    # Ordinary json.loads would discard the earlier conflicting member.
    _qualify(json.loads(raw))
    with pytest.raises(SecretRequestApprovalRevokeDetailContractError):
        qualify_secret_request_approval_revoke_get_detail(
            raw, binding=_BINDING, authenticated_reviewer="synthetic-reviewer", server_time=_NOW,
        )


@pytest.mark.parametrize("change", [{"request_id": True}, {"secret_id": 0}, {"source_serial": "界" * 22},
                                  {"requester": "synthetic-reviewer"}, {"approval_profile_name": ""},
                                  {"original_reviewer": "invalid\ud800"}])
def test_detail_binding_refuses_unqualified_identity(change: dict[str, Any]) -> None:
    with pytest.raises(SecretRequestApprovalRevokeDetailContractError):
        replace(_BINDING, **change)
