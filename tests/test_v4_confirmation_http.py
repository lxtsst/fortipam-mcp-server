from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path
import re

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from test_v4_m3 import NOW, _requester, _summary
from v4_planning import FinalIntentSummary, ObjectClass, SummaryState

from fortipam_mcp.local_oauth import (
    LocalOAuthProvider,
    LocalOAuthSettings,
    hash_local_password,
)
from fortipam_mcp.v4_confirmation_http import (
    LocalIntentConfirmationService,
    V4ConfirmationHttpError,
    V4ConfirmationSettings,
    confirmation_settings_from_environment,
    _change_html,
)


PASSWORD = "correct-horse-battery-staple"
NAMESPACE = "9" * 64


def test_approval_confirmation_renders_exact_categories_without_private_state() -> None:
    hidden = {
        "username": "private-account-material",
        "native_digest": "private-native-witness",
        "original_state_digest": "private-original-state",
        "binding_digest": "private-transport-binding",
        "ownership_evidence_ref": "private-owned-reference",
    }
    for current, expected in ((False, True), (True, False)):
        page = _change_html({
            "object_class": ObjectClass.SECRET_APPROVAL_BINDING.value,
            "change_kind": "update",
            "current_fields": {"interactive_approval_required": current, **hidden},
            "projected_changes": {"interactive_approval_required": expected, **hidden},
            "expected_fields": {"interactive_approval_required": expected,
                                "owned_original_baseline_verified": True, **hidden},
        })
        assert page.count("interactive_approval_required") == 3
        assert "owned_original_baseline_verified" in page
        assert f"<td>{str(current).lower()}</td>" in page.split("<h4>Proposed</h4>")[0]
        assert f"<td>{str(expected).lower()}</td>" in page.split("<h4>Proposed</h4>")[1]
        assert not any(key in page or value in page for key, value in hidden.items())
    profile = _change_html({
        "object_class": ObjectClass.APPROVAL_PROFILE_BINDING.value,
        "current_fields": {"profile_mode": "single_tier", **hidden},
        "expected_fields": {"profile_mode": "single_tier", **hidden},
    })
    assert profile.count("single_tier") == 2
    assert not any(key in profile or value in profile for key, value in hidden.items())


class MutableClock:
    def __init__(self, value: int) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


class SummaryReader:
    def __init__(self, summary: FinalIntentSummary) -> None:
        self.summary = summary

    def get_summary(self, summary_ref: str, revision: int) -> FinalIntentSummary:
        assert summary_ref == self.summary.summary_ref
        assert revision == self.summary.revision
        return self.summary


def _service(
    tmp_path: Path,
) -> tuple[LocalIntentConfirmationService, MutableClock, FinalIntentSummary]:
    state = tmp_path / "v4-confirmation"
    state.mkdir(mode=0o700)
    os.chmod(state, 0o700)
    oauth_state = tmp_path / "oauth"
    oauth_state.mkdir(mode=0o700)
    os.chmod(oauth_state, 0o700)
    store_key = state / "store.hmac"
    receipt_key = state / "receipt.hmac"
    store_key.write_bytes(b"store-key-000000000000000000000000000000000000")
    receipt_key.write_bytes(b"receipt-key-00000000000000000000000000000000000")
    os.chmod(store_key, 0o600)
    os.chmod(receipt_key, 0o600)
    provider = LocalOAuthProvider(
        LocalOAuthSettings(
            issuer="https://mcp.example.com/fpamcp-v4/oauth",
            resource="https://mcp.example.com/fpamcp-v4",
            database_path=oauth_state / "oauth.sqlite3",
            username="operator",
            password_hash=hash_local_password(
                PASSWORD,
                salt=b"0123456789abcdef",
            ),
        )
    )
    requester = _requester()
    summary = replace(_summary(requester), state=SummaryState.AWAITING_CONFIRMATION)
    clock = MutableClock(NOW + 1)
    service = LocalIntentConfirmationService(
        provider,
        V4ConfirmationSettings(
            state / "confirmation.sqlite3",
            store_key,
            receipt_key,
        ),
        SummaryReader(summary),
        clock=clock,
    )
    return service, clock, summary


def _csrf(text: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', text)
    assert match is not None
    return match.group(1)


def test_local_confirmation_requires_reauthentication_then_records_affirm(
    tmp_path: Path,
) -> None:
    service, clock, summary = _service(tmp_path)
    requester = _requester()
    url = service.issue(
        summary,
        requester,
        principal_namespace_digest=NAMESPACE,
        now_epoch=clock.value,
    )
    path = url.removeprefix("https://mcp.example.com")

    with TestClient(Starlette(routes=service.routes()), base_url="https://mcp.example.com") as client:
        initial = client.get(path)
        assert initial.status_code == 200
        assert summary.summary_ref not in initial.text
        assert "Current / Proposed / Expected" not in initial.text
        for header in (
            "cache-control",
            "content-security-policy",
            "cross-origin-opener-policy",
            "permissions-policy",
            "referrer-policy",
            "x-content-type-options",
        ):
            assert header in initial.headers
        cookie = initial.headers["set-cookie"].lower()
        assert "secure" in cookie and "httponly" in cookie and "samesite=strict" in cookie

        missing_origin = client.post(
            path,
            data={
                "csrf_token": _csrf(initial.text),
                "username": "operator",
                "password": PASSWORD,
                "action": "review",
            },
        )
        assert missing_origin.status_code == 400

        wrong_content_type = client.post(
            path,
            content="csrf_token=ignored&action=review",
            headers={
                "content-type": "text/plain",
                "origin": "https://mcp.example.com",
            },
        )
        assert wrong_content_type.status_code == 400

        initial = client.get(path)
        review = client.post(
            path,
            data={
                "csrf_token": _csrf(initial.text),
                "username": "operator",
                "password": PASSWORD,
                "action": "review",
            },
            headers={"origin": "https://mcp.example.com"},
        )
        assert review.status_code == 200
        assert summary.summary_ref in review.text
        assert "Current / Proposed / Expected" in review.text
        assert "Confirm this exact intent" in review.text
        assert "receipt" not in review.text.lower()
        assert summary.environment_ref not in review.text
        assert summary.scope_ref not in review.text
        assert "owner_ref" not in review.text

        clock.value = NOW + 2
        recorded = client.post(
            path,
            data={"csrf_token": _csrf(review.text), "action": "affirm"},
            headers={"origin": "https://mcp.example.com"},
        )
        assert recorded.status_code == 200
        assert "Decision recorded" in recorded.text

    interaction = service.verify(
        requester,
        principal_namespace_digest=NAMESPACE,
        summary_ref=summary.summary_ref,
        summary_revision=summary.revision,
        now_epoch=clock.value,
    )
    assert interaction.decision == "affirm"
    assert interaction.requester_digest == requester.digest
    service.claim(
        requester,
        principal_namespace_digest=NAMESPACE,
        summary_ref=summary.summary_ref,
        summary_revision=summary.revision,
        now_epoch=clock.value,
    )
    assert service.verify(
        requester,
        principal_namespace_digest=NAMESPACE,
        summary_ref=summary.summary_ref,
        summary_revision=summary.revision,
        now_epoch=clock.value,
    ) == interaction
    service.claim(
        requester,
        principal_namespace_digest=NAMESPACE,
        summary_ref=summary.summary_ref,
        summary_revision=summary.revision,
        now_epoch=clock.value,
    )


def test_confirmation_configuration_is_all_or_nothing(tmp_path: Path) -> None:
    assert confirmation_settings_from_environment({}) is None
    with pytest.raises(V4ConfirmationHttpError, match="requires database"):
        confirmation_settings_from_environment(
            {"FORTIPAM_MCP_V4_PLAN_CONFIRMATION_DB": str(tmp_path / "state.sqlite3")}
        )
