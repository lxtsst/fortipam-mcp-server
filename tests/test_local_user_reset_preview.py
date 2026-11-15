"""Synthetic-only BP002 preflight preview checks; no authentication or POST."""

from dataclasses import replace
import json

import pytest

from fortipam_mcp.local_user_reset_http_transport import (
    LocalUserResetBaseline, LocalUserResetBinding,
)
from fortipam_mcp.local_user_reset_policy_reader import LocalUserResetPolicySnapshot
from fortipam_mcp.local_user_reset_preview import (
    FortiPamLocalUserResetPreviewReader, LocalUserResetPreflightPreview,
    LocalUserResetPreviewError,
)


def _binding() -> LocalUserResetBinding:
    return LocalUserResetBinding(LocalUserResetBaseline(
        username="mcp-v4-user-reset-synthetic", status="disable", is_local=True,
        access_profile="Guest", sponsor_group="", schedule="", guest_auth="disable",
        nonmaterial_state_digest="a" * 64, fixture_creation_digest="b" * 64,
        reported_reference_count=0, usage_entry_count=0,
        product_version="7.0.0", product_build=29,
    ))


def _policy() -> LocalUserResetPolicySnapshot:
    return LocalUserResetPolicySnapshot(
        minimum_length=8, min_change_characters=0,
        min_upper_case_letter=0, min_lower_case_letter=0, min_number=0,
        min_non_alphanumeric=0, status="disable", reuse_password="enable",
        expire_status="disable",
    )


class Inspector:
    def __init__(self, binding: LocalUserResetBinding, policy: LocalUserResetPolicySnapshot) -> None:
        self.binding, self.policy = binding, policy

    def read_nonmaterial_baseline(self) -> LocalUserResetBaseline:
        return self.binding.expected

    def read_policy_snapshot(self) -> LocalUserResetPolicySnapshot:
        return self.policy


def test_preview_is_value_minimized_and_non_executable() -> None:
    binding, policy = _binding(), _policy()
    inspector = Inspector(binding, policy)
    preview = FortiPamLocalUserResetPreviewReader(
        binding, inspector, policy, inspector, clock=lambda: 1000,
    ).read_preview()
    projected = preview.as_dict()
    encoded = json.dumps(projected, sort_keys=True)
    assert projected["state"] == "plan_only"
    assert projected["execution_authorized"] is False
    assert projected["device_write_executed"] is False
    assert projected["Expected State"]["authentication_verified"] is False
    assert preview.expires_at == 1300
    assert preview.summary_digest == FortiPamLocalUserResetPreviewReader(
        binding, inspector, policy, inspector, clock=lambda: 1000,
    ).read_preview().summary_digest
    for forbidden in (binding.expected.username, "Guest", binding.expected.fixture_creation_digest,
                      "initial-password", "next-password", "plan_ref", "authorization_ref"):
        assert forbidden not in encoded


@pytest.mark.parametrize("drift", ["status", "policy", "reference", "age"])
def test_preview_rejects_drift_and_stale_reads(drift: str) -> None:
    binding, policy = _binding(), _policy()
    inspector = Inspector(binding, policy)
    if drift == "status":
        inspector.read_nonmaterial_baseline = lambda: replace(binding.expected, status="enable")  # type: ignore[method-assign]
    elif drift == "policy":
        inspector.policy = replace(policy, minimum_length=12)
    elif drift == "reference":
        inspector.read_nonmaterial_baseline = lambda: replace(  # type: ignore[method-assign]
            binding.expected, reported_reference_count=1,
        )
    times = iter((1000, 1031)) if drift == "age" else iter((1000, 1000))
    reader = FortiPamLocalUserResetPreviewReader(
        binding, inspector, policy, inspector, clock=lambda: next(times),
    )
    with pytest.raises(LocalUserResetPreviewError):
        reader.read_preview()


def test_preview_rejects_unavailable_projection_without_detail() -> None:
    binding, policy = _binding(), _policy()
    inspector = Inspector(binding, policy)
    inspector.read_policy_snapshot = lambda: (_ for _ in ()).throw(  # type: ignore[method-assign]
        RuntimeError("private response must not escape"),
    )
    reader = FortiPamLocalUserResetPreviewReader(
        binding, inspector, policy, inspector, clock=lambda: 1000,
    )
    with pytest.raises(LocalUserResetPreviewError, match="unavailable") as error:
        reader.read_preview()
    assert error.value.__cause__ is None


def test_admin_policy_preview_rejects_guest_admin_fixture() -> None:
    binding = LocalUserResetBinding(replace(_binding().expected, guest_auth="enable"))
    policy = _policy()
    inspector = Inspector(binding, policy)
    with pytest.raises(LocalUserResetPreviewError):
        FortiPamLocalUserResetPreviewReader(binding, inspector, policy, inspector)


def test_preview_digest_cannot_be_relabelled_as_a_different_summary() -> None:
    binding, policy = _binding(), _policy()
    inspector = Inspector(binding, policy)
    preview = FortiPamLocalUserResetPreviewReader(
        binding, inspector, policy, inspector, clock=lambda: 1000,
    ).read_preview()
    with pytest.raises(LocalUserResetPreviewError):
        replace(preview, summary_digest="0" * 64)
    with pytest.raises(LocalUserResetPreviewError):
        LocalUserResetPreflightPreview(
            preview.current_state_digest, preview.policy_digest,
            preview.observed_at, preview.expires_at + 1,
            preview.summary_digest, preview.guest_auth,
        )
