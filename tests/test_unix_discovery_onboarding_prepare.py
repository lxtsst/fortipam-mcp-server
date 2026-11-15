"""Discovery selection may prepare BP005, but cannot itself dispatch onboarding."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat

import pytest

from fortipam_mcp.discovery_review_http_transport import SELECTION_CONTRACT, project_unix_discovery_selection
from fortipam_mcp.discovery_review_mcp_action import SELECTION_BINDING_CONTRACT
from fortipam_mcp.linux_onboarding_prepare import (
    ACCESS_BINDING_NAME,
    DRAFT_INPUT_NAME,
    LinuxOnboardingPrepareSettings,
    PROFILE_CONTRACT,
    PROFILE_VERSION,
    REFERENCE_INPUT_NAME,
    SECRET_BINDING_NAME,
)
from fortipam_mcp.unix_discovery_onboarding_prepare import (
    UnixDiscoveryOnboardingPrepareError,
    prepare_selected_unix_onboarding_bundle,
)
from v4_planning.material_provider import MaterialProviderClass
from test_discovery_review_http_transport import _response


class _SelectionReader:
    def __init__(self, decision: str) -> None:
        self.decision = decision
        self.calls = 0

    def select(self, request: object, selected_account: str) -> dict[str, object]:
        assert getattr(request, "source_name") == "bp014-discovery-unix-disabled-r13"
        assert selected_account == "fpam-bp014-discovery-r3"
        self.calls += 1
        unmanaged = self.decision == "prepare_existing_onboarding"
        return {
            "contract": SELECTION_CONTRACT,
            "source_exact": True,
            "scan_state": "completed",
            "selected_account_exact": True,
            "selected_account_unmanaged": unmanaged,
            "onboarding_decision": self.decision,
            "import_executed": False,
            "device_write_executed": False,
            "selected_account_name_returned": False,
            "credential_values_returned": False,
            "raw_api_response_returned": False,
        }


def _fixture(tmp_path: Path) -> tuple[Path, LinuxOnboardingPrepareSettings]:
    private = tmp_path / "private"
    output = tmp_path / "bundle"
    private.mkdir(mode=0o700)
    output.mkdir(mode=0o700)
    binding = private / "selection.json"
    binding.write_text(json.dumps({
        "contract": SELECTION_BINDING_CONTRACT,
        "source_name": "bp014-discovery-unix-disabled-r13",
        "discovery_secret_id": 17,
        "selected_account": "fpam-bp014-discovery-r3",
    }))
    binding.chmod(0o600)
    profile = private / "profile.json"
    profile.write_text(json.dumps({
        "contract": PROFILE_CONTRACT,
        "version": PROFILE_VERSION,
        "requester_digest": "a" * 64,
        "environment_ref": "bp005-test-environment",
        "scope_ref": "bp005-test-scope",
        "expires_at": 1_950_000_600,
        "folder_name": "test-folder",
        "folder_path": "private/folder/test-folder",
        "parent_folder_id": 9,
        "owner_principal_name": "test-owner",
        "owner_subject_class": "user",
        "acl_relations": [{
            "principal_name": "test-group",
            "subject_class": "group",
            "permission": "use",
            "folder_permission": "view",
            "secret_permission": "view",
        }],
        "target_name": "test-target",
        "target_protocol": "ssh",
        "target_ipv4_address": "192.0.2.20",
        "template_name": "Unix Account (SSH Password)",
        "secret_name": "test-secret-r3",
        "launcher_name": None,
    }))
    profile.chmod(0o600)
    settings = LinuxOnboardingPrepareSettings(
        profile, output, MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE,
    )
    return binding, settings


def test_unmanaged_selection_prepares_existing_bp005_bundle(tmp_path: Path) -> None:
    binding, settings = _fixture(tmp_path)
    reader = _SelectionReader("prepare_existing_onboarding")

    result = prepare_selected_unix_onboarding_bundle(
        selection_binding_path=binding,
        settings=settings,
        selection_reader=reader,
    )

    assert reader.calls == 1
    assert result == {
        "status": "prepared",
        "selection_decision": "prepare_existing_onboarding",
        "decision_scope": "completed_scan_snapshot",
        "import_executed": False,
        "device_write_executed": False,
        "selected_account_name_returned": False,
        "credential_values_returned": False,
    }
    expected = {
        ACCESS_BINDING_NAME, SECRET_BINDING_NAME,
        DRAFT_INPUT_NAME, REFERENCE_INPUT_NAME,
    }
    assert {path.name for path in settings.output_directory.iterdir()} == expected
    assert all(
        path.stat().st_uid == os.getuid()
        and stat.S_IMODE(path.stat().st_mode) == 0o600
        for path in settings.output_directory.iterdir()
    )
    secret = json.loads((settings.output_directory / SECRET_BINDING_NAME).read_text())
    assert secret["secret_name"] == "test-secret-r3"
    assert secret["target_protocol"] == "ssh"
    assert "fpam-bp014-discovery-r3" not in str(result)


def test_managed_selection_never_prepares_or_imports(tmp_path: Path) -> None:
    binding, settings = _fixture(tmp_path)
    reader = _SelectionReader("already_managed")

    with pytest.raises(UnixDiscoveryOnboardingPrepareError) as error:
        prepare_selected_unix_onboarding_bundle(
            selection_binding_path=binding,
            settings=settings,
            selection_reader=reader,
        )

    assert reader.calls == 1
    assert list(settings.output_directory.iterdir()) == []
    assert "fpam-bp014" not in str(error.value)


def test_untrusted_selection_flags_fail_without_bundle(tmp_path: Path) -> None:
    binding, settings = _fixture(tmp_path)
    reader = _SelectionReader("prepare_existing_onboarding")
    original = reader.select

    def untrusted(request: object, selected_account: str) -> dict[str, object]:
        result = original(request, selected_account)
        result["device_write_executed"] = True
        return result

    reader.select = untrusted  # type: ignore[method-assign]
    with pytest.raises(UnixDiscoveryOnboardingPrepareError):
        prepare_selected_unix_onboarding_bundle(
            selection_binding_path=binding,
            settings=settings,
            selection_reader=reader,
        )
    assert list(settings.output_directory.iterdir()) == []


@pytest.mark.parametrize("fault", ["partial", "duplicate", "empty", "unknown-account-field"])
def test_incomplete_snapshot_cannot_prepare_any_onboarding_artifact(tmp_path: Path, fault: str) -> None:
    binding, settings = _fixture(tmp_path)
    class Reader:
        def select(self, request, selected_account):
            value = _response(); row = value["results"][0]
            row["name"] = request.source_name
            row["discovery-results"][0]["name"] = selected_account
            if fault == "partial": value["limit_reached"] = True
            elif fault == "duplicate": row["discovery-results"].append(dict(row["discovery-results"][1]))
            elif fault == "empty": row["discovery-results"] = []
            elif fault == "unknown-account-field": row["discovery-results"][1]["unknown"] = True
            return project_unix_discovery_selection(value, request, selected_account)
    with pytest.raises(UnixDiscoveryOnboardingPrepareError):
        prepare_selected_unix_onboarding_bundle(selection_binding_path=binding, settings=settings, selection_reader=Reader())
    assert list(settings.output_directory.iterdir()) == []
