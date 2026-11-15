"""Disabled AD Source acceptance through the canonical OAuth client only."""
from __future__ import annotations

import asyncio
from copy import deepcopy
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from typing import Any

import pytest

from scripts import v4_linux_onboarding_mcp_oauth_acceptance as acceptance


def _preview() -> dict[str, Any]:
    fields = {
        "FolderBinding": {"exists": True, "folder_ref": "folder-ref-opaque"},
        "DomainTargetBinding": {"exists": True, "profile_ref": "target-profile-opaque",
                                "target_relation_matches": True},
        "TemplateBinding": {"exists": True, "template_ref": "template-ref-opaque",
                            "compatibility": "compatible"},
        "DomainSecretMetadata": {"exists": True, "inherit_permission": True,
                                 "non_privileged_account": True, "services_disabled": True,
                                 "target_association_matches": True},
        "DiscoverySourceMetadata": {"exists": True, "source_type": "active_directory",
            "account_discovery": True, "domain_secret_ref": "domain-secret-object-opaque",
            "periodic_scanning_disabled": True, "auto_onboarding_disabled": True,
            "existing_secret_method": True, "no_scan_timestamp": True},
    }
    return {
        "state": "awaiting_confirmation", "confirmation_state": "awaiting_human_reauthentication",
        "summary_ref": "summary-ref-opaque", "revision": 1,
        "confirmation_url": "https://fpamcp.example.test/confirm/opaque",
        "scheme_id": "BulkOnboardingScheme", "blueprint_ref": "FPA-BP-014",
        "outcome_code": "create_disabled_ad_discovery_source",
        "object_changes": [{
            "object_class": cls,
            "object_ref": "domain-secret-object-opaque" if cls == "DomainSecretMetadata" else f"{cls}-object-opaque",
            "change_kind": "create" if cls == "DiscoverySourceMetadata" else "no_op",
            "current_fields": {"exists": False} if cls == "DiscoverySourceMetadata" else deepcopy(values),
            "projected_changes": deepcopy(values) if cls == "DiscoverySourceMetadata" else {},
            "expected_fields": deepcopy(values),
        } for cls, values in fields.items()],
    }


def _validate(preview: dict[str, Any]) -> None:
    acceptance._validate_secret_onboarding_preview(
        preview, "FPA-BP-014", require_ad_discovery_source=True,
    )


def test_accepts_exact_disabled_source_profile() -> None:
    _validate(_preview())


@pytest.mark.parametrize("defect", [
    "scheme", "outcome", "widened", "duplicate", "domain_create", "source_noop",
    "object_ref", "shared_ref", "private_selector", "missing_anchor", "mutable_anchor",
    "projected_ref", "current_exists", "source_as_secret", "unsafe_extra", "type_enum", "private_secret_ref",
])
def test_rejects_widened_or_misbound_source_profile(defect: str) -> None:
    preview = _preview()
    changes = preview["object_changes"]
    source = changes[-1]
    if defect in {"scheme", "outcome"}:
        preview["scheme_id" if defect == "scheme" else "outcome_code"] = "SecretOnboardingScheme"
    elif defect == "widened":
        changes.append(deepcopy(source))
    elif defect == "duplicate":
        changes[0] = deepcopy(changes[1])
    elif defect == "domain_create":
        changes[-2]["change_kind"] = "create"
    elif defect == "source_noop":
        source["change_kind"] = "no_op"
    elif defect == "object_ref":
        changes[-2]["object_ref"] = "different-secret-opaque"
    elif defect == "shared_ref":
        source["object_ref"] = changes[-2]["object_ref"]
    elif defect == "private_selector":
        changes[0]["expected_fields"]["folder_ref"] = "private folder/path"
    elif defect == "missing_anchor":
        changes[1]["expected_fields"].pop("target_relation_matches")
    elif defect == "mutable_anchor":
        changes[1]["current_fields"]["target_relation_matches"] = False
    elif defect == "projected_ref":
        source["projected_changes"]["domain_secret_ref"] = "different-secret-opaque"
    elif defect == "current_exists":
        source["current_fields"]["exists"] = 0
    elif defect == "source_as_secret":
        source["object_class"] = "DomainSecretMetadata"
    elif defect == "unsafe_extra":
        source["expected_fields"]["scan_requested"] = True
    elif defect == "type_enum":
        source["expected_fields"]["source_type"] = "unix"
    elif defect == "private_secret_ref":
        source["expected_fields"]["domain_secret_ref"] = "private secret/path"
    with pytest.raises(acceptance.LinuxOnboardingMcpOAuthAcceptanceError, match="AD Source"):
        _validate(preview)


@pytest.mark.parametrize("key", [
    "exists", "account_discovery", "periodic_scanning_disabled", "auto_onboarding_disabled",
    "existing_secret_method", "no_scan_timestamp",
])
@pytest.mark.parametrize("value", [False, 1, "true"])
def test_source_requires_strict_safe_booleans(key: str, value: object) -> None:
    preview = _preview()
    for field in ("expected_fields", "projected_changes"):
        preview["object_changes"][-1][field][key] = value
    with pytest.raises(acceptance.LinuxOnboardingMcpOAuthAcceptanceError):
        _validate(preview)


def test_source_cannot_be_accepted_as_domain_secret_profile() -> None:
    with pytest.raises(acceptance.LinuxOnboardingMcpOAuthAcceptanceError):
        acceptance._validate_secret_onboarding_preview(_preview(), "FPA-BP-014", require_domain_secret=True)
    domain = _preview()
    domain["scheme_id"] = "SecretOnboardingScheme"
    domain["object_changes"].pop()
    domain["object_changes"][-1]["change_kind"] = "create"
    acceptance._validate_secret_onboarding_preview(domain, "FPA-BP-014", require_domain_secret=True)
    with pytest.raises(acceptance.LinuxOnboardingMcpOAuthAcceptanceError):
        _validate(domain)


def _execution() -> dict[str, object]:
    return {
        "outcome": "succeeded", "pre_write_status": "match",
        "post_write_status": "expected_state_matches", "reconciliation_required": False,
        "stopped_line_ref": None, "authorization_scope": "source_bound_ad_discovery",
        "lab_exception_applied": True, "policy_mode": "lab_auto",
        "completed_line_refs": ["source-line-opaque"],
    }


def _install_session(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, preview_only: bool = False,
    result: dict[str, object] | None = None,
) -> tuple[Path, Path, list[tuple[str, dict[str, object]]]]:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    draft = state / "draft.json"
    draft.write_text(json.dumps({"scheme_draft_ref": "scheme-draft-opaque"}))
    draft.chmod(0o600)
    calls: list[tuple[str, dict[str, object]]] = []
    payloads = {
        "get_v4_plan_status": {"runtime_profile": "v4-plan-only",
            "host_services_bound": True, "confirmation_transport_bound": True,
            "projection_mode": "source_backed", "scheme_draft_issuance_protocol_bound": True,
            "reference_authorization_protocol_bound": True,
            "secret_create_execution_preflight_available": False,
            "ad_discovery_execution_preflight_available": not preview_only},
        "preview_v4_administrative_intent": _preview(),
        "confirm_v4_administrative_intent": {"confirmation_ref": "confirmation-ref-opaque"},
        "prepare_v4_non_executable_plan": {"plan_ref": "plan-ref-opaque", "dispatchable": False,
            "adapter_registry_bound": False, "executor_runtime_packaged": False,
            "executor_mcp_exposed": False, "planner_mcp_exposed": True},
        "execute_v4_ad_discovery_workflow": _execution() if result is None else result,
    }

    class Session:
        async def call_tool(self, name: str, arguments: dict[str, object]) -> SimpleNamespace:
            calls.append((name, arguments))
            return SimpleNamespace(is_error=False, structured_content=payloads[name])

    async def common(*args: Any, **kwargs: Any) -> dict[str, object]:
        assert kwargs["required_tools"] == (acceptance.PREVIEW_TOOLS if preview_only else acceptance.AD_SOURCE_TOOLS)
        if preview_only:
            assert kwargs["requested_scope"] == acceptance.oauth.PLAN_ONLY_SCOPE
        await kwargs["tool_session_callback"](Session())
        return {"oauth_metadata_verified": True, "mcp_initialized": True,
                "token_revoked": True, "credential_values_returned": False}

    class Browser:
        def __init__(self, **kwargs: object) -> None:
            assert kwargs["verify"] == str(tmp_path / "ca.pem")
            assert kwargs["trust_env"] is False
        async def __aenter__(self) -> Browser:
            return self
        async def __aexit__(self, *args: object) -> None:
            return None

    async def affirm(*args: object, **kwargs: object) -> None:
        assert not preview_only

    monkeypatch.setattr(acceptance.oauth, "run_address_mcp_oauth_surface_acceptance", common)
    monkeypatch.setattr(acceptance.oauth, "_connection_transport", lambda *args, **kwargs: None)
    monkeypatch.setattr(acceptance.httpx2, "AsyncClient", Browser)
    monkeypatch.setattr(acceptance, "_affirm_browser_confirmation", affirm)
    monkeypatch.setenv(acceptance.LOGIN_USERNAME, "fixture-user")
    monkeypatch.setenv(acceptance.LOGIN_PASSWORD, "fixture-not-a-real-secret")
    return draft, state / "dispatch.json", calls


def _run(tmp_path: Path, draft: Path, dispatch: Path) -> dict[str, object]:
    return asyncio.run(acceptance.run_secret_onboarding_mcp_oauth_acceptance(
        "https://fpamcp.example.test/fpamcp-v4", tmp_path / "login.env", tmp_path / "client.json",
        draft, dispatch, blueprint_ref="FPA-BP-014", ad_discovery_source=True,
        ca_file=tmp_path / "ca.pem",
    ))


def test_one_exact_supported_source_dispatch(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    draft, dispatch, calls = _install_session(monkeypatch, tmp_path)
    result = _run(tmp_path, draft, dispatch)
    assert [name for name, _ in calls] == [
        "get_v4_plan_status", "preview_v4_administrative_intent", "confirm_v4_administrative_intent",
        "prepare_v4_non_executable_plan", "execute_v4_ad_discovery_workflow",
    ]
    assert calls[-1][1] == {"plan_ref": "plan-ref-opaque", "scheme_draft_ref": "scheme-draft-opaque"}
    assert result["completed_action_count"] == 1
    assert result["post_write_expected_state_verified"] is True
    assert result["token_revoked"] is True
    assert "opaque" not in json.dumps(result)
    assert json.loads(dispatch.read_text())["retry_allowed"] is False
    with pytest.raises(acceptance.LinuxOnboardingMcpOAuthAcceptanceError, match="Dispatch state"):
        _run(tmp_path, draft, dispatch)
    assert len(calls) == 5


@pytest.mark.parametrize("defect", ["postwrite", "count", "scope"])
def test_source_requires_independent_readback_and_one_action(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, defect: str,
) -> None:
    result = _execution()
    if defect == "postwrite":
        result["post_write_status"] = "expected_state_mismatch"
    elif defect == "count":
        result["completed_line_refs"] = ["line-one-opaque", "line-two-opaque"]
    else:
        result["authorization_scope"] = "source_bound_onboarding"
    draft, dispatch, _ = _install_session(monkeypatch, tmp_path, result=result)
    with pytest.raises(acceptance.LinuxOnboardingMcpOAuthAcceptanceError):
        _run(tmp_path, draft, dispatch)
    assert dispatch.exists()


def test_source_preview_only_never_confirms_prepares_or_dispatches(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    draft, dispatch, calls = _install_session(monkeypatch, tmp_path, preview_only=True)
    result = asyncio.run(acceptance.run_secret_onboarding_mcp_oauth_preview_acceptance(
        "https://fpamcp.example.test/fpamcp-v4", tmp_path / "login.env", tmp_path / "client.json",
        draft, blueprint_ref="FPA-BP-014", ad_discovery_source=True,
    ))
    assert [name for name, _ in calls] == ["get_v4_plan_status", "preview_v4_administrative_intent"]
    assert not dispatch.exists()
    assert result["confirmation_consumed"] is result["plan_prepared"] is result["dispatch_attempted"] is False


@pytest.mark.parametrize("options", [
    {"domain_secret": True, "ad_discovery_source": True}, {"ad_discovery_source": 1},
    {"ad_discovery_source": True, "existing_web_service": True},
    {},
])
@pytest.mark.parametrize("preview_only", [False, True])
def test_rejects_conflicting_bp014_profiles_before_oauth(
    tmp_path: Path, options: dict[str, Any], preview_only: bool,
) -> None:
    with pytest.raises(acceptance.LinuxOnboardingMcpOAuthAcceptanceError, match="Blueprint"):
        if preview_only:
            asyncio.run(acceptance.run_secret_onboarding_mcp_oauth_preview_acceptance(
                "https://fpamcp.example.test/fpamcp-v4", tmp_path / "login.env", tmp_path / "client.json",
                tmp_path / "draft.json", blueprint_ref="FPA-BP-014", **options,
            ))
            return
        asyncio.run(acceptance.run_secret_onboarding_mcp_oauth_acceptance(
            "https://fpamcp.example.test/fpamcp-v4", tmp_path / "login.env", tmp_path / "client.json",
            tmp_path / "draft.json", tmp_path / "dispatch.json", blueprint_ref="FPA-BP-014", **options,
        ))


def test_cli_passes_source_profile_to_preview(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    async def preview(*args: object, **kwargs: object) -> dict[str, object]:
        assert kwargs["ad_discovery_source"] is True and kwargs["domain_secret"] is False
        return {"preview_verified": True}
    monkeypatch.setattr(acceptance, "run_secret_onboarding_mcp_oauth_preview_acceptance", preview)
    monkeypatch.setattr(sys, "argv", ["acceptance", "--url", "https://fpamcp.example.test/fpamcp-v4",
        "--login-file", str(tmp_path / "login.env"), "--client-state-file", str(tmp_path / "client.json"),
        "--scheme-draft-ref-file", str(tmp_path / "draft.json"), "--blueprint-ref", "FPA-BP-014",
        "--ad-discovery-source", "--preview-only"])
    acceptance.main()


@pytest.mark.parametrize("available", [False, None, 1, "true"])
def test_source_execution_requires_exact_ad_preflight(available: object) -> None:
    status = {"runtime_profile": "v4-plan-only", "host_services_bound": True,
              "confirmation_transport_bound": True, "projection_mode": "source_backed",
              "scheme_draft_issuance_protocol_bound": True,
              "reference_authorization_protocol_bound": True,
              "ad_discovery_execution_preflight_available": available}
    with pytest.raises(acceptance.LinuxOnboardingMcpOAuthAcceptanceError):
        acceptance._validate_source_backed_status(
            status, require_secret_create_runtime=False, require_ad_discovery_runtime=True,
        )
    acceptance._validate_source_backed_status(status, require_secret_create_runtime=False)


@pytest.mark.parametrize("blueprint_ref", ["FPA-BP-005", "FPA-BP-006", "FPA-BP-007"])
def test_source_cannot_mix_with_other_blueprints(tmp_path: Path, blueprint_ref: str) -> None:
    with pytest.raises(acceptance.LinuxOnboardingMcpOAuthAcceptanceError, match="Blueprint"):
        asyncio.run(acceptance.run_secret_onboarding_mcp_oauth_preview_acceptance(
            "https://fpamcp.example.test/fpamcp-v4", tmp_path / "login.env", tmp_path / "client.json",
            tmp_path / "draft.json", blueprint_ref=blueprint_ref, ad_discovery_source=True,
        ))


def test_source_cannot_mix_with_session_controls(tmp_path: Path) -> None:
    with pytest.raises(acceptance.LinuxOnboardingMcpOAuthAcceptanceError, match="Blueprint"):
        asyncio.run(acceptance.run_secret_onboarding_mcp_oauth_acceptance(
            "https://fpamcp.example.test/fpamcp-v4", tmp_path / "login.env", tmp_path / "client.json",
            tmp_path / "draft.json", tmp_path / "dispatch.json", blueprint_ref="FPA-BP-014",
            ad_discovery_source=True, existing_session_controls=True,
        ))
