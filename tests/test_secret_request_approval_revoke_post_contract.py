from copy import deepcopy
from dataclasses import FrozenInstanceError, fields
from datetime import datetime, timedelta, timezone
import json
from typing import Any

import pytest

from fortipam_mcp.secret_metadata_http_transport import MAX_RESPONSE_BYTES
from fortipam_mcp.secret_request_approval_revoke_detail_contract import (
    SecretRequestApprovalRevokeDetailBinding,
    qualify_secret_request_approval_revoke_get_detail,
)
from fortipam_mcp.secret_request_approval_revoke_post_contract import (
    SecretRequestApprovalRevokePostContractError,
    SecretRequestApprovalRevokePostWitness,
    qualify_secret_request_approval_revoke_post_state,
)

_BINDING = SecretRequestApprovalRevokeDetailBinding(
    request_id=19, secret_id=7, requester="synthetic-requester",
    approval_profile_name="synthetic-profile", original_reviewer="synthetic-reviewer",
    source_serial="SYNTHETIC29",
)


def _payloads(now: datetime) -> tuple[dict[str, Any], dict[str, Any]]:
    local = now.astimezone(timezone(timedelta(hours=8)))
    before = {
        "version": "v7.0.0", "build": 29, "http_method": "GET", "http_status": 200,
        "status": "success", "path": "secret", "name": "request", "vdom": "root",
        "mkey": "19", "serial": "SYNTHETIC29", "revision": "synthetic-revision",
        "results": [{"id": 19, "q_origin_key": 19, "secret-id": 7,
                     "user": "synthetic-requester", "request-type": "launcher", "job-name": "",
                     "approval-profile": "synthetic-profile", "final-status": "approved",
                     "tier1-status": "approved", "tier2-status": "pending", "tier3-status": "pending",
                     "start-time": (local - timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S"),
                     "expiration-time": (local + timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S"),
                     "timezone": "Asia/Shanghai", "tier-last-sent": 1,
                     "tier1": [{"name": "synthetic-reviewer", "q_origin_key": "synthetic-reviewer",
                                "status": "approved", "comments": "synthetic comment", "update-time": "opaque"}],
                     "tier2": [], "tier3": [], "comments": "preserved comment",
                     "opaque-metadata": {"items": [True, 1, "native"]}}],
    }
    after = deepcopy(before)
    after["results"][0].update({
        "start-time": "0000-00-00 00:00:00", "expiration-time": "0000-00-00 00:00:00",
        "final-status": "pending", "tier1-status": "pending", "tier1": [], "tier-last-sent": 0,
    })
    return before, after


def _encode(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()


def _qualify(before: object, after: object, now: datetime, **kwargs: Any) -> SecretRequestApprovalRevokePostWitness:
    args: dict[str, Any] = {
        "binding": _BINDING, "authenticated_reviewer": "synthetic-reviewer",
        "pre_server_time": now, "post_server_time": now,
    }
    args.update(kwargs)
    return qualify_secret_request_approval_revoke_post_state(
        _encode(before), _encode(after), **args,
    )


def test_fixed_transition_private_immutable_and_reordered_metadata() -> None:
    now = datetime.now(timezone.utc)
    before, after = _payloads(now)
    original = deepcopy((before, after))
    witness = _qualify(before, after, now)
    assert (before, after) == original
    assert witness.private_binding_digest == qualify_secret_request_approval_revoke_get_detail(
        _encode(before), binding=_BINDING, authenticated_reviewer="synthetic-reviewer", server_time=now,
    ).private_binding_digest
    assert {field.name for field in fields(witness)} == {
        "private_binding_digest", "private_pre_metadata_digest", "private_post_metadata_digest", "private_transition_digest",
    }
    assert all(len(getattr(witness, field.name)) == 64 for field in fields(witness))
    assert "synthetic" not in repr(witness)
    assert witness.private_post_metadata_digest not in repr(witness)
    assert not hasattr(witness, "authorized") and not hasattr(witness, "body")
    with pytest.raises(FrozenInstanceError):
        setattr(witness, "private_transition_digest", "changed")
    after = dict(reversed(list(after.items())))
    after["results"][0] = dict(reversed(list(after["results"][0].items())))
    assert _qualify(before, after, now) == witness
    assert _qualify(before, after, now, post_server_time=now + timedelta(seconds=1)) != witness


def test_pending_retained_native_marker_is_bound_without_granting_access() -> None:
    now = datetime.now(timezone.utc)
    before, after = _payloads(now)
    cleared = _qualify(before, after, now)
    after["results"][0]["tier-last-sent"] = 1
    retained = _qualify(before, after, now)
    assert retained.private_binding_digest == cleared.private_binding_digest
    assert retained.private_pre_metadata_digest == cleared.private_pre_metadata_digest
    assert retained.private_post_metadata_digest != cleared.private_post_metadata_digest
    assert retained.private_transition_digest != cleared.private_transition_digest
    assert not hasattr(retained, "authorized") and not hasattr(retained, "body")
    for field, value in (("final-status", "approved"), ("tier1-status", "approved"),
                         ("tier1", before["results"][0]["tier1"]),
                         ("expiration-time", before["results"][0]["expiration-time"])):
        drifted = deepcopy(after)
        drifted["results"][0][field] = value
        with pytest.raises(SecretRequestApprovalRevokePostContractError):
            _qualify(before, drifted, now)


def test_changed_native_revision_is_bound_without_normalizing_or_granting_access() -> None:
    now = datetime.now(timezone.utc)
    before, after = _payloads(now)
    unchanged = _qualify(before, after, now)
    after["revision"] = "synthetic-post-revision"
    original = deepcopy((before, after))
    changed = _qualify(before, after, now)
    assert (before, after) == original
    assert changed.private_binding_digest == unchanged.private_binding_digest
    assert changed.private_pre_metadata_digest == unchanged.private_pre_metadata_digest
    assert changed.private_post_metadata_digest != unchanged.private_post_metadata_digest
    assert changed.private_transition_digest != unchanged.private_transition_digest
    assert not hasattr(changed, "authorized")
    after["results"][0]["comments"] = "unrelated drift"
    with pytest.raises(SecretRequestApprovalRevokePostContractError):
        _qualify(before, after, now)


@pytest.mark.parametrize("revision", [None, "", False, 0, [], {}, "x" * 129, "\u00e9" * 65])
def test_changed_revision_still_requires_the_original_bounded_string_grammar(revision: object) -> None:
    now = datetime.now(timezone.utc)
    before, after = _payloads(now)
    after["revision"] = revision
    with pytest.raises(SecretRequestApprovalRevokePostContractError):
        _qualify(before, after, now)


@pytest.mark.parametrize("field,value", [
    ("start-time", ""), ("expiration-time", 0), ("final-status", "approved"),
    ("tier1-status", "approved"), ("tier1", [{}]), ("tier-last-sent", False),
    ("tier-last-sent", True), ("tier-last-sent", 2), ("tier-last-sent", 3),
    ("tier-last-sent", -1), ("tier-last-sent", "1"),
    ("tier-last-sent", 0.0), ("tier2-status", "approved"),
    ("tier3-status", "approved"), ("user", "other"), ("secret-id", 8),
    ("approval-profile", "other"), ("comments", "drift"), ("tier2", [{}]),
    ("opaque-metadata", {"items": [1, 1, "native"]}),
])
def test_post_field_drift_fails(field: str, value: object) -> None:
    now = datetime.now(timezone.utc)
    before, after = _payloads(now)
    after["results"][0][field] = value
    with pytest.raises(SecretRequestApprovalRevokePostContractError, match="^The fixed Launcher Request withdrawal post-state is unavailable.$"):
        _qualify(before, after, now)


@pytest.mark.parametrize("failure", [
    "missing-revision", "serial", "mkey", "extra-envelope", "missing-row", "extra-row", "pre-last",
    "pre-tier2", "pre-tier3", "pre-pending", "missing-last", "reviewer", "binding",
    "no-date", "naive", "order", "stale", "expired-window", "future-date",
])
def test_bindings_shape_and_dates_fail_closed(failure: str) -> None:
    now = datetime.now(timezone.utc)
    before, after = _payloads(now)
    kwargs: dict[str, Any] = {}
    if failure in {"serial", "mkey"}:
        after[failure] = "drift"
    elif failure == "missing-revision":
        del after["revision"]
    elif failure == "extra-envelope":
        after["extra"] = True
    elif failure == "missing-row":
        del after["results"][0]["comments"]
    elif failure == "extra-row":
        after["results"][0]["extra"] = "drift"
    elif failure == "pre-last":
        before["results"][0]["tier-last-sent"] = True
    elif failure in {"pre-tier2", "pre-tier3"}:
        key = "tier2-status" if failure == "pre-tier2" else "tier3-status"
        before["results"][0][key] = after["results"][0][key] = "approved"
    elif failure == "pre-pending":
        before["results"][0]["final-status"] = "pending"
    elif failure == "missing-last":
        del before["results"][0]["tier-last-sent"]
    elif failure == "reviewer":
        kwargs["authenticated_reviewer"] = "other"
    elif failure == "binding":
        kwargs["binding"] = None
    elif failure == "no-date":
        kwargs["post_server_time"] = None
    elif failure == "naive":
        kwargs["post_server_time"] = now.replace(tzinfo=None)
    elif failure == "order":
        kwargs["post_server_time"] = now - timedelta(seconds=1)
    elif failure == "stale":
        before, after = _payloads(now - timedelta(days=1))
        kwargs.update(pre_server_time=now - timedelta(days=1), post_server_time=now - timedelta(days=1))
    elif failure == "expired-window":
        before["results"][0]["expiration-time"] = (now + timedelta(seconds=1)).astimezone(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S")
        kwargs["post_server_time"] = now + timedelta(seconds=2)
    elif failure == "future-date":
        kwargs["post_server_time"] = now + timedelta(minutes=6)
    with pytest.raises(SecretRequestApprovalRevokePostContractError):
        _qualify(before, after, now, **kwargs)


@pytest.mark.parametrize("bad", [b"", b"{}", b"[]", b"null", b"{", b"x" * (MAX_RESPONSE_BYTES + 1)])
def test_invalid_post_bytes_refused(bad: bytes) -> None:
    now = datetime.now(timezone.utc)
    before, _ = _payloads(now)
    with pytest.raises(SecretRequestApprovalRevokePostContractError):
        qualify_secret_request_approval_revoke_post_state(
            _encode(before), bad, binding=_BINDING, authenticated_reviewer="synthetic-reviewer",
            pre_server_time=now, post_server_time=now,
        )


def test_duplicate_material_and_nonmaterial_keys_refused_and_buffers_unchanged() -> None:
    now = datetime.now(timezone.utc)
    before, after = _payloads(now)
    original = bytearray(_encode(before))
    for suffix in (b',"comments":"duplicate"', b',"password":{"same":1,"same":1}'):
        raw = bytearray(_encode(after).replace(b'"comments":"preserved comment"', b'"comments":"preserved comment"' + suffix))
        saved = bytes(raw)
        with pytest.raises(SecretRequestApprovalRevokePostContractError):
            qualify_secret_request_approval_revoke_post_state(
                original, raw, binding=_BINDING, authenticated_reviewer="synthetic-reviewer",
                pre_server_time=now, post_server_time=now,
            )
        assert bytes(raw) == saved
    assert original == _encode(before)


def test_redacted_member_drift_is_still_refused() -> None:
    now = datetime.now(timezone.utc)
    before, after = _payloads(now)
    # These are synthetic sentinel strings, never actual material.
    before["results"][0]["password"] = "synthetic-before"
    after["results"][0]["password"] = "synthetic-before"
    _qualify(before, after, now)
    after["results"][0]["password"] = "synthetic-after"
    with pytest.raises(SecretRequestApprovalRevokePostContractError):
        _qualify(before, after, now)
