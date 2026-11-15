from __future__ import annotations

import asyncio
import ipaddress
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from types import SimpleNamespace
from typing import Any

import pytest

from scripts import v4_linux_onboarding_mcp_oauth_acceptance as acceptance


def test_script_can_be_invoked_directly_from_outside_the_repository(
    tmp_path: Path,
) -> None:
    script = Path(acceptance.__file__).resolve()
    result = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=tmp_path,
        env={"PATH": os.environ["PATH"], "PYTHONNOUSERSITE": "1"},
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "--scheme-draft-ref-file" in result.stdout


def test_keychain_login_file_is_owner_only_and_removed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_run(command: list[str], **kwargs: object) -> SimpleNamespace:
        calls.append(tuple(command))
        if command[-1] == "-w":
            return SimpleNamespace(returncode=0, stdout=b"protected-password")
        return SimpleNamespace(
            returncode=0,
            stdout='"acct"<blob>="current-oauth-user"',
            stderr="",
        )

    monkeypatch.setattr(acceptance.subprocess, "run", fake_run)

    with acceptance._KeychainOAuthLoginFile("fortipam.example.invalid") as login_file:
        assert stat.S_IMODE(login_file.stat().st_mode) == 0o600
        assert login_file.read_text() == (
            f"{acceptance.LOGIN_USERNAME}=current-oauth-user\n"
            f"{acceptance.LOGIN_PASSWORD}=protected-password\n"
        )

    assert not login_file.exists()
    assert calls == [
        ("security", "find-generic-password", "-s", "fortipam.example.invalid"),
        (
            "security", "find-generic-password", "-s", "fortipam.example.invalid",
            "-a", "current-oauth-user", "-w",
        ),
    ]


def _private_lab_host() -> str:
    return str(ipaddress.IPv4Address(0x0A000001))


def test_nested_onboarding_error_is_reduced_to_its_stable_message() -> None:
    nested = ExceptionGroup(
        "transport task group",
        [
            ExceptionGroup(
                "session task group",
                [
                    acceptance.LinuxOnboardingMcpOAuthAcceptanceError(
                        "Secret onboarding preview Tool call failed."
                    )
                ],
            )
        ],
    )

    assert acceptance._contained_onboarding_error_message(nested) == (
        "Secret onboarding preview Tool call failed."
    )


def test_structured_error_exposes_only_safe_reference_category() -> None:
    result = SimpleNamespace(
        is_error=True,
        structured_content=None,
        content=[
            SimpleNamespace(
                text="Reference is not authorized for the exact scope boundary."
            )
        ],
    )

    with pytest.raises(
        acceptance.LinuxOnboardingMcpOAuthAcceptanceError,
        match="preview Tool call rejected \\(reference_authorization\\)",
    ):
        acceptance._structured(result, "preview")


def test_structured_error_exposes_only_safe_projection_category() -> None:
    result = SimpleNamespace(
        is_error=True,
        structured_content=None,
        content=[
            SimpleNamespace(
                text="FortiPAM Secret onboarding projection source is unavailable."
            )
        ],
    )

    with pytest.raises(
        acceptance.LinuxOnboardingMcpOAuthAcceptanceError,
        match="preview Tool call rejected \\(projection_source\\)",
    ):
        acceptance._structured(result, "preview")


def _preview(
    *classes: str,
    blueprint_ref: str = "FPA-BP-005",
) -> dict[str, object]:
    return {
        "state": "awaiting_confirmation",
        "confirmation_state": "awaiting_human_reauthentication",
        "summary_ref": "summary-ref-opaque",
        "revision": 1,
        "confirmation_url": "https://fpamcp.example.test/confirm/opaque",
        "scheme_id": "SecretOnboardingScheme",
        "blueprint_ref": blueprint_ref,
        "object_changes": [
            {"object_class": object_class, "object_ref": f"object-ref-{index}"}
            for index, object_class in enumerate(classes)
        ],
    }


def _bp005_preview() -> dict[str, object]:
    return _preview(
        "PublicFolder",
        "AccessGrant",
        "AccessGrant",
        "FolderBinding",
        "Target",
        "TemplateBinding",
        "SecretMetadata",
        "LauncherBinding",
    )


def _bp006_preview() -> dict[str, object]:
    return _preview(
        "FolderBinding",
        "Target",
        "TemplateBinding",
        "SecretMetadata",
        "LauncherBinding",
        "PolicyBinding",
        "RdpEventFilterBinding",
        blueprint_ref="FPA-BP-006",
    )


def _bp007_preview() -> dict[str, object]:
    return _preview(
        "FolderBinding",
        "TemplateBinding",
        "WebSecretMetadata",
        blueprint_ref="FPA-BP-007",
    )


def _execution() -> dict[str, object]:
    return {
        "outcome": "succeeded",
        "pre_write_status": "match",
        "post_write_status": "expected_state_matches",
        "reconciliation_required": False,
        "stopped_line_ref": None,
        "authorization_scope": "source_bound_onboarding",
        "lab_exception_applied": True,
        "policy_mode": "lab_auto",
        "completed_line_refs": ["line-ref-one", "line-ref-two"],
    }


def _write_owner_only_json(path: Path, value: dict[str, object]) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o600)


def test_bp005_preview_accepts_multiple_access_grants() -> None:
    acceptance._validate_bp005_preview(_bp005_preview())


@pytest.mark.parametrize(
    ("blueprint_ref", "preview"),
    [
        ("FPA-BP-005", _bp005_preview()),
        ("FPA-BP-006", _bp006_preview()),
        ("FPA-BP-007", _bp007_preview()),
    ],
)
def test_secret_onboarding_preview_accepts_only_each_profile_shape(
    blueprint_ref: str,
    preview: dict[str, object],
) -> None:
    acceptance._validate_secret_onboarding_preview(preview, blueprint_ref)


@pytest.mark.parametrize(
    "classes",
    [
        (
            "PublicFolder",
            "AccessGrant",
            "FolderBinding",
            "Target",
            "TemplateBinding",
        ),
        (
            "PublicFolder",
            "PublicFolder",
            "AccessGrant",
            "FolderBinding",
            "Target",
            "TemplateBinding",
            "SecretMetadata",
        ),
        (
            "PublicFolder",
            "AccessGrant",
            "FolderBinding",
            "Target",
            "TemplateBinding",
            "SecretMetadata",
            "UnexpectedObject",
        ),
    ],
)
def test_bp005_preview_rejects_incomplete_duplicate_or_widened_objects(
    classes: tuple[str, ...],
) -> None:
    with pytest.raises(
        acceptance.LinuxOnboardingMcpOAuthAcceptanceError,
        match="intent preview is invalid",
    ):
        acceptance._validate_bp005_preview(_preview(*classes))


def test_owner_only_draft_ref_and_dispatch_record_are_bounded(tmp_path: Path) -> None:
    state_directory = tmp_path / "state"
    state_directory.mkdir(mode=0o700)
    state_directory.chmod(0o700)
    draft_file = state_directory / "draft.json"
    dispatch_file = state_directory / "dispatch.json"
    _write_owner_only_json(
        draft_file,
        {"scheme_draft_ref": "scheme-draft-ref-opaque"},
    )

    assert acceptance._read_scheme_draft_ref(draft_file) == "scheme-draft-ref-opaque"
    acceptance._validate_new_dispatch_state_path(dispatch_file)
    acceptance._create_dispatch_record(dispatch_file)

    assert stat.S_IMODE(dispatch_file.stat().st_mode) == 0o600
    assert json.loads(dispatch_file.read_text(encoding="utf-8")) == {
        "contract": "fortipam_v4_linux_onboarding_dispatch_record_v1",
        "dispatch_attempted": True,
        "retry_allowed": False,
    }
    acceptance._write_dispatch_outcome(
        dispatch_file,
        "execution_reported_reconciliation",
        failure_stage="fixed_action_target_http_dispatch",
    )
    outcome_file = acceptance._dispatch_outcome_path(dispatch_file)
    assert stat.S_IMODE(outcome_file.stat().st_mode) == 0o600
    assert json.loads(outcome_file.read_text(encoding="utf-8")) == {
        "contract": "fortipam_v4_secret_onboarding_dispatch_outcome_v1",
        "dispatch_attempted": True,
        "failure_stage": "fixed_action_target_http_dispatch",
        "outcome_category": "execution_reported_reconciliation",
        "retry_allowed": False,
    }
    assert json.loads(dispatch_file.read_text(encoding="utf-8"))["retry_allowed"] is False
    with pytest.raises(
        acceptance.LinuxOnboardingMcpOAuthAcceptanceError,
        match="Dispatch state file is unavailable",
    ):
        acceptance._validate_new_dispatch_state_path(dispatch_file)

    _write_owner_only_json(draft_file, {"scheme_draft_ref": "short"})
    with pytest.raises(
        acceptance.LinuxOnboardingMcpOAuthAcceptanceError,
        match="Scheme Draft reference file is invalid",
    ):
        acceptance._read_scheme_draft_ref(draft_file)


def test_dispatch_outcome_rejects_unbounded_category_or_stage(tmp_path: Path) -> None:
    state_directory = tmp_path / "state"
    state_directory.mkdir(mode=0o700)
    state_directory.chmod(0o700)
    dispatch_file = state_directory / "dispatch.json"
    acceptance._create_dispatch_record(dispatch_file)

    with pytest.raises(
        acceptance.LinuxOnboardingMcpOAuthAcceptanceError,
        match="Dispatch outcome state is invalid",
    ):
        acceptance._write_dispatch_outcome(dispatch_file, "raw exception text")

    with pytest.raises(
        acceptance.LinuxOnboardingMcpOAuthAcceptanceError,
        match="Dispatch outcome state is invalid",
    ):
        acceptance._write_dispatch_outcome(
            dispatch_file,
            "execution_reported_reconciliation",
            failure_stage="unexpected private result",
        )

    assert not acceptance._dispatch_outcome_path(dispatch_file).exists()


def test_dispatch_preflight_rejects_existing_outcome_sidecar(tmp_path: Path) -> None:
    state_directory = tmp_path / "state"
    state_directory.mkdir(mode=0o700)
    state_directory.chmod(0o700)
    dispatch_file = state_directory / "dispatch.json"
    outcome_file = acceptance._dispatch_outcome_path(dispatch_file)
    _write_owner_only_json(outcome_file, {"unrelated": True})

    with pytest.raises(
        acceptance.LinuxOnboardingMcpOAuthAcceptanceError,
        match="Dispatch outcome state file is unavailable",
    ):
        acceptance._validate_new_dispatch_state_path(dispatch_file)


def test_execution_requires_successful_final_readback() -> None:
    acceptance._validate_execution(_execution())
    failed = {**_execution(), "reconciliation_required": True}
    with pytest.raises(
        acceptance.LinuxOnboardingMcpOAuthAcceptanceError,
        match="final readback was not accepted",
    ):
        acceptance._validate_execution(failed)


def test_execution_reports_only_a_fixed_safe_failure_stage() -> None:
    failed = {**_execution(), "failure_stage": "fixed_action_resolution"}

    with pytest.raises(
        acceptance.LinuxOnboardingMcpOAuthAcceptanceError,
        match="stopped at fixed_action_resolution",
    ):
        acceptance._validate_execution(failed)

    with pytest.raises(
        acceptance.LinuxOnboardingMcpOAuthAcceptanceError,
        match="execution result is invalid",
    ):
        acceptance._validate_execution({**_execution(), "failure_stage": "unknown"})

    with pytest.raises(
        acceptance.LinuxOnboardingMcpOAuthAcceptanceError,
        match="stopped at fixed_action_runner_binding",
    ):
        acceptance._validate_execution(
            {**_execution(), "failure_stage": "fixed_action_runner_binding"}
        )

    for stage in (
        "fixed_action_target_http_dispatch",
        "fixed_action_target_acknowledgement",
    ):
        with pytest.raises(
            acceptance.LinuxOnboardingMcpOAuthAcceptanceError,
            match=f"stopped at {stage}",
        ):
            acceptance._validate_execution({**_execution(), "failure_stage": stage})

    with pytest.raises(
        acceptance.LinuxOnboardingMcpOAuthAcceptanceError,
        match="stopped at fixed_action_runner_material_binding",
    ):
        acceptance._validate_execution(
            {
                **_execution(),
                "failure_stage": "fixed_action_runner_material_binding",
            }
        )


@pytest.mark.parametrize("preflight", [None, False, 1, "true", True])
def test_create_status_requires_actual_execution_preflight(preflight) -> None:
    status = {
        "runtime_profile": "v4-plan-only",
        "host_services_bound": True,
        "confirmation_transport_bound": True,
        "projection_mode": "source_backed",
        "scheme_draft_issuance_protocol_bound": True,
        "reference_authorization_protocol_bound": True,
        "secret_create_private_runtime_available": True,
        "secret_create_execution_preflight_available": preflight,
    }
    if preflight is True:
        acceptance._validate_source_backed_status(status)
    else:
        with pytest.raises(acceptance.LinuxOnboardingMcpOAuthAcceptanceError):
            acceptance._validate_source_backed_status(status)
    acceptance._validate_source_backed_status(status, require_secret_create_runtime=False)


def test_common_acceptance_requires_token_revocation() -> None:
    result: dict[str, object] = {
        "oauth_metadata_verified": True,
        "mcp_initialized": True,
        "token_revoked": True,
        "credential_values_returned": False,
    }
    acceptance._validate_common_acceptance(result)
    with pytest.raises(
        acceptance.LinuxOnboardingMcpOAuthAcceptanceError,
        match="transport acceptance failed",
    ):
        acceptance._validate_common_acceptance({**result, "token_revoked": False})


@pytest.mark.parametrize(
    ("blueprint_ref", "preview"),
    [
        ("FPA-BP-005", _bp005_preview()),
        ("FPA-BP-006", _bp006_preview()),
        ("FPA-BP-007", _bp007_preview()),
    ],
)
def test_preview_acceptance_never_confirms_prepares_or_dispatches(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    blueprint_ref: str,
    preview: dict[str, object],
) -> None:
    state_directory = tmp_path / "state"
    state_directory.mkdir(mode=0o700)
    state_directory.chmod(0o700)
    draft_file = state_directory / "draft.json"
    _write_owner_only_json(
        draft_file,
        {"scheme_draft_ref": "scheme-draft-ref-opaque"},
    )
    calls: list[tuple[str, dict[str, object]]] = []

    class FakeSession:
        async def call_tool(
            self,
            name: str,
            arguments: dict[str, object],
        ) -> SimpleNamespace:
            calls.append((name, arguments))
            payloads: dict[str, dict[str, object]] = {
                "get_v4_plan_status": {
                    "runtime_profile": "v4-plan-only",
                    "host_services_bound": True,
                    "confirmation_transport_bound": True,
                    "projection_mode": "source_backed",
                    "scheme_draft_issuance_protocol_bound": True,
                    "reference_authorization_protocol_bound": True,
                    "secret_create_private_runtime_available": False,
                    "secret_create_execution_preflight_available": False,
                },
                "preview_v4_administrative_intent": preview,
            }
            return SimpleNamespace(
                is_error=False,
                structured_content=payloads[name],
            )

    async def fake_common(*args: Any, **kwargs: Any) -> dict[str, object]:
        assert kwargs["required_tools"] == acceptance.PREVIEW_TOOLS
        assert kwargs["requested_scope"] == acceptance.oauth.PLAN_ONLY_SCOPE
        callback = kwargs["tool_session_callback"]
        await callback(FakeSession())
        return {
            "oauth_metadata_verified": True,
            "mcp_initialized": True,
            "token_revoked": True,
            "credential_values_returned": False,
        }

    monkeypatch.setattr(
        acceptance.oauth,
        "run_address_mcp_oauth_surface_acceptance",
        fake_common,
    )

    result = asyncio.run(
        acceptance.run_secret_onboarding_mcp_oauth_preview_acceptance(
            "https://fpamcp.example.test/fpamcp-v4",
            tmp_path / "login.env",
            tmp_path / "client.json",
            draft_file,
            blueprint_ref=blueprint_ref,
        )
    )

    assert calls == [
        ("get_v4_plan_status", {}),
        (
            "preview_v4_administrative_intent",
            {"scheme_draft_ref": "scheme-draft-ref-opaque"},
        ),
    ]
    assert result["preview_verified"] is True
    assert result["confirmation_consumed"] is False
    assert result["plan_prepared"] is False
    assert result["dispatch_attempted"] is False
    assert result["device_write_executed"] is False


def test_preview_acceptance_normalizes_transport_failures(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    state_directory = tmp_path / "state"
    state_directory.mkdir(mode=0o700)
    state_directory.chmod(0o700)
    draft_file = state_directory / "draft.json"
    _write_owner_only_json(
        draft_file,
        {"scheme_draft_ref": "scheme-draft-ref-opaque"},
    )

    async def unavailable(*args: Any, **kwargs: Any) -> dict[str, object]:
        raise acceptance.httpx2.ConnectError("private transport detail")

    monkeypatch.setattr(
        acceptance.oauth,
        "run_address_mcp_oauth_surface_acceptance",
        unavailable,
    )

    with pytest.raises(
        acceptance.LinuxOnboardingMcpOAuthAcceptanceError,
        match="preview transport is unavailable",
    ) as error:
        asyncio.run(
            acceptance.run_secret_onboarding_mcp_oauth_preview_acceptance(
                "https://fpamcp.example.test/fpamcp-v4",
                tmp_path / "login.env",
                tmp_path / "client.json",
                draft_file,
                blueprint_ref="FPA-BP-007",
            )
        )
    assert "private transport detail" not in str(error.value)


def test_main_preview_only_selects_the_non_dispatch_client(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[tuple[object, ...]] = []

    async def fake_preview(*args: object, **kwargs: object) -> dict[str, object]:
        calls.append((*args, kwargs))
        return {"contract": "preview", "dispatch_attempted": False}

    async def unexpected_dispatch(*args: object, **kwargs: object) -> dict[str, object]:
        raise AssertionError("dispatch client must not be selected")

    monkeypatch.setattr(
        acceptance,
        "run_secret_onboarding_mcp_oauth_preview_acceptance",
        fake_preview,
    )
    monkeypatch.setattr(
        acceptance,
        "run_secret_onboarding_mcp_oauth_acceptance",
        unexpected_dispatch,
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "v4-linux-onboarding-acceptance",
            "--url",
            "https://fpamcp.example.test/fpamcp-v4",
            "--login-file",
            str(tmp_path / "login.env"),
            "--client-state-file",
            str(tmp_path / "client.json"),
            "--scheme-draft-ref-file",
            str(tmp_path / "draft.json"),
            "--preview-only",
        ],
    )

    acceptance.main()

    assert len(calls) == 1
    assert json.loads(capsys.readouterr().out) == {
        "contract": "preview",
        "dispatch_attempted": False,
    }


@pytest.mark.parametrize("preview_only", [True, False])
def test_cli_mcp_read_timeout_reaches_oauth_surface_without_dispatch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    preview_only: bool,
) -> None:
    state_directory = tmp_path / "state"
    state_directory.mkdir(mode=0o700)
    state_directory.chmod(0o700)
    draft_file = state_directory / "draft.json"
    _write_owner_only_json(draft_file, {"scheme_draft_ref": "scheme-draft-ref-opaque"})
    dispatch_file = state_directory / "dispatch.json"
    timeouts: list[object] = []

    async def offline_surface(*args: object, **kwargs: object) -> dict[str, object]:
        timeouts.append(kwargs["mcp_read_timeout_seconds"])
        assert kwargs["required_tools"] == (
            acceptance.PREVIEW_TOOLS if preview_only else acceptance.TOOLS
        )
        # Stop before the session callback can confirm, prepare, or dispatch.
        raise acceptance.oauth.AddressMcpOAuthSurfaceAcceptanceError(
            "Offline timeout passthrough verified."
        )

    monkeypatch.setattr(
        acceptance.oauth, "run_address_mcp_oauth_surface_acceptance", offline_surface,
    )
    argv = [
        "v4-linux-onboarding-acceptance",
        "--url", "https://fpamcp.example.test/fpamcp-v4",
        "--login-file", str(tmp_path / "login.env"),
        "--client-state-file", str(tmp_path / "client.json"),
        "--scheme-draft-ref-file", str(draft_file),
        "--mcp-read-timeout-seconds", "120",
    ]
    argv.extend(["--preview-only"] if preview_only else ["--dispatch-state-file", str(dispatch_file)])
    monkeypatch.setattr(sys, "argv", argv)

    with pytest.raises(SystemExit, match="Offline timeout passthrough verified"):
        acceptance.main()
    assert timeouts == [120]
    assert not dispatch_file.exists()
    assert not acceptance._dispatch_outcome_path(dispatch_file).exists()


def test_nested_oauth_surface_error_is_normalized() -> None:
    nested = ExceptionGroup(
        "streamable-http",
        [acceptance.oauth.AddressMcpOAuthSurfaceAcceptanceError("internal")],
    )

    assert acceptance._contains_acceptance_error(nested) is True


@pytest.mark.parametrize(
    ("blueprint_ref", "preview", "controls", "web_service"),
    [
        ("FPA-BP-014", _preview("FolderBinding", "TemplateBinding", "DomainTargetBinding", "DomainSecretMetadata", blueprint_ref="FPA-BP-014"), False, False),
        ("FPA-BP-005", _bp005_preview(), False, False),
        ("FPA-BP-006", _bp006_preview(), False, False),
        ("FPA-BP-007", _bp007_preview(), False, False),
        ("FPA-BP-007", _bp007_preview(), False, True),
        ("FPA-BP-006", _bp006_preview(), True, False),
    ],
)
def test_acceptance_uses_one_exact_supported_onboarding_dispatch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    blueprint_ref: str,
    preview: dict[str, object],
    controls: bool,
    web_service: bool,
) -> None:
    state_directory = tmp_path / "state"
    state_directory.mkdir(mode=0o700)
    state_directory.chmod(0o700)
    draft_file = state_directory / "draft.json"
    dispatch_file = state_directory / "dispatch.json"
    _write_owner_only_json(
        draft_file,
        {"scheme_draft_ref": "scheme-draft-ref-opaque"},
    )
    domain_secret = blueprint_ref == "FPA-BP-014"
    if domain_secret:
        for item in preview["object_changes"]:
            item["change_kind"] = "create" if item["object_class"] == "DomainSecretMetadata" else "no_op"
    if web_service:
        preview["object_changes"] = _preview(
            "FolderBinding", "TemplateBinding", "WebSecretMetadata", "WebSecretServiceBinding",
            blueprint_ref="FPA-BP-007",
        )["object_changes"]
        for item in preview["object_changes"]:
            item["change_kind"] = "update" if item["object_class"] == "WebSecretServiceBinding" else "no_op"
    if controls:
        preview["object_changes"] = _preview(
            "FolderBinding", "Target", "TemplateBinding", "SecretMetadata",
            "RdpEventFilterBinding", "SecretSessionControlsBinding",
            blueprint_ref="FPA-BP-006",
        )["object_changes"]
        for item in preview["object_changes"]:
            item["change_kind"] = "update" if item["object_class"] == "SecretSessionControlsBinding" else "no_op"
    calls: list[tuple[str, dict[str, object]]] = []
    browser_transport = object()
    browser_options: list[dict[str, object]] = []

    class FakeSession:
        async def call_tool(
            self,
            name: str,
            arguments: dict[str, object],
        ) -> SimpleNamespace:
            calls.append((name, arguments))
            payloads: dict[str, dict[str, object]] = {
                "get_v4_plan_status": {
                    "runtime_profile": "v4-plan-only",
                    "host_services_bound": True,
                    "confirmation_transport_bound": True,
                    "projection_mode": "source_backed",
                    "scheme_draft_issuance_protocol_bound": True,
                    "reference_authorization_protocol_bound": True,
                    "secret_create_private_runtime_available": False,
                    "secret_create_execution_preflight_available": not (controls or web_service),
                },
                "preview_v4_administrative_intent": preview,
                "confirm_v4_administrative_intent": {
                    "confirmation_ref": "confirmation-ref-opaque"
                },
                "prepare_v4_non_executable_plan": {
                    "dispatchable": False,
                    "adapter_registry_bound": False,
                    "executor_runtime_packaged": False,
                    "executor_mcp_exposed": False,
                    "planner_mcp_exposed": True,
                    "plan_ref": "prepared-plan-ref-opaque",
                },
                "execute_v4_secret_onboarding_workflow": _execution(),
            }
            if controls or web_service or domain_secret:
                payloads["execute_v4_secret_onboarding_workflow"]["completed_line_refs"] = ["controls-line-ref01"]
            return SimpleNamespace(
                is_error=False,
                structured_content=payloads[name],
            )

    async def fake_common(*args: Any, **kwargs: Any) -> dict[str, object]:
        assert kwargs["required_tools"] == acceptance.TOOLS
        assert kwargs["lab_connect_host"] == "127.0.0.1"
        assert kwargs["lab_connect_port"] == 28443
        assert kwargs["allow_loopback_tunnel"] is True
        callback = kwargs["tool_session_callback"]
        await callback(FakeSession())
        return {
            "oauth_metadata_verified": True,
            "mcp_initialized": True,
            "token_revoked": True,
            "credential_values_returned": False,
        }

    async def fake_affirm(*args: object, **kwargs: object) -> None:
        return None

    class FakeBrowser:
        def __init__(self, **kwargs: object) -> None:
            browser_options.append(kwargs)

        async def __aenter__(self) -> FakeBrowser:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

    def fake_connection_transport(
        parsed: object,
        lab_connect_host: str | None,
        verify: str | bool,
        *,
        lab_connect_port: int | None = None,
        allow_loopback_tunnel: bool = False,
    ) -> object:
        assert getattr(parsed, "hostname") == "fpamcp.example.test"
        assert lab_connect_host == "127.0.0.1"
        assert lab_connect_port == 28443
        assert verify is True
        assert allow_loopback_tunnel is True
        return browser_transport

    monkeypatch.setenv(acceptance.LOGIN_USERNAME, "operator")
    monkeypatch.setenv(acceptance.LOGIN_PASSWORD, "not-used-by-test")
    monkeypatch.setattr(
        acceptance.oauth,
        "run_address_mcp_oauth_surface_acceptance",
        fake_common,
    )
    monkeypatch.setattr(
        acceptance.oauth,
        "_connection_transport",
        fake_connection_transport,
    )
    monkeypatch.setattr(acceptance.httpx2, "AsyncClient", FakeBrowser)
    monkeypatch.setattr(acceptance, "_affirm_browser_confirmation", fake_affirm)

    result = asyncio.run(
        acceptance.run_secret_onboarding_mcp_oauth_acceptance(
            "https://fpamcp.example.test/fpamcp-v4",
            tmp_path / "login.env",
            tmp_path / "client.json",
            draft_file,
            dispatch_file,
            blueprint_ref=blueprint_ref,
            existing_session_controls=controls,
            existing_web_service=web_service,
            domain_secret=domain_secret,
            lab_connect_host="127.0.0.1",
            lab_connect_port=28443,
            allow_loopback_tunnel=True,
        )
    )

    assert calls == [
        ("get_v4_plan_status", {}),
        (
            "preview_v4_administrative_intent",
            {"scheme_draft_ref": "scheme-draft-ref-opaque"},
        ),
        (
            "confirm_v4_administrative_intent",
            {"summary_ref": "summary-ref-opaque", "summary_revision": 1},
        ),
        (
            "prepare_v4_non_executable_plan",
            {
                "summary_ref": "summary-ref-opaque",
                "confirmation_ref": "confirmation-ref-opaque",
            },
        ),
        (
            "execute_v4_secret_onboarding_workflow",
            {
                "plan_ref": "prepared-plan-ref-opaque",
                "scheme_draft_ref": "scheme-draft-ref-opaque",
            },
        ),
    ]
    assert result["completed_action_count"] == (1 if (controls or web_service or domain_secret) else 2)
    assert result["blueprint_ref"] == blueprint_ref
    assert result["dispatch_attempted_once"] is True
    assert result["post_write_expected_state_verified"] is True
    assert result["credential_values_returned"] is False
    assert dispatch_file.exists()
    if controls:
        assert json.loads(dispatch_file.read_text())["policy_mode"] == "lab_auto"
        assert json.loads(dispatch_file.read_text())["profile"] == "bp006_existing_session_controls"
    assert browser_options == [
        {
            "timeout": 30.0,
            "follow_redirects": False,
            "trust_env": False,
            "verify": True,
            "headers": {
                "User-Agent": "fortipam-mcp-v4-secret-onboarding-acceptance/1"
            },
            "transport": browser_transport,
        }
    ]


def test_existing_controls_shape_is_preview_only_and_preserves_relations() -> None:
    preview = _preview("FolderBinding", "Target", "TemplateBinding", "SecretMetadata",
                       "RdpEventFilterBinding", "SecretSessionControlsBinding", blueprint_ref="FPA-BP-006")
    for item in preview["object_changes"]:
        item["change_kind"] = "update" if item["object_class"] == "SecretSessionControlsBinding" else "no_op"
    acceptance._validate_secret_onboarding_preview(preview, "FPA-BP-006", allow_existing_session_controls=True)
    with pytest.raises(acceptance.LinuxOnboardingMcpOAuthAcceptanceError):
        acceptance._validate_secret_onboarding_preview(preview, "FPA-BP-006")
    preview["object_changes"][3]["change_kind"] = "create"
    with pytest.raises(acceptance.LinuxOnboardingMcpOAuthAcceptanceError):
        acceptance._validate_secret_onboarding_preview(preview, "FPA-BP-006", allow_existing_session_controls=True)


def test_controls_execution_requires_exact_update_and_never_accepts_create_or_noop() -> None:
    preview = _preview(
        "FolderBinding", "Target", "TemplateBinding", "SecretMetadata",
        "RdpEventFilterBinding", "SecretSessionControlsBinding",
        blueprint_ref="FPA-BP-006",
    )
    for item in preview["object_changes"]:
        item["change_kind"] = (
            "update" if item["object_class"] == "SecretSessionControlsBinding" else "no_op"
        )
    options = {"allow_existing_session_controls": True, "require_existing_session_controls": True}
    acceptance._validate_secret_onboarding_preview(preview, "FPA-BP-006", **options)
    preview["object_changes"][-1]["change_kind"] = "no_op"
    with pytest.raises(acceptance.LinuxOnboardingMcpOAuthAcceptanceError):
        acceptance._validate_secret_onboarding_preview(preview, "FPA-BP-006", **options)
    preview["object_changes"].pop()
    with pytest.raises(acceptance.LinuxOnboardingMcpOAuthAcceptanceError):
        acceptance._validate_secret_onboarding_preview(preview, "FPA-BP-006", **options)


@pytest.mark.parametrize("change_kind", ["create", "no_op", "delete"])
def test_existing_web_service_rejects_non_update(change_kind: str) -> None:
    preview = _preview("FolderBinding", "TemplateBinding", "WebSecretMetadata", "WebSecretServiceBinding", blueprint_ref="FPA-BP-007")
    for item in preview["object_changes"]:
        item["change_kind"] = change_kind if item["object_class"] == "WebSecretServiceBinding" else "no_op"
    with pytest.raises(acceptance.LinuxOnboardingMcpOAuthAcceptanceError):
        acceptance._validate_secret_onboarding_preview(preview, "FPA-BP-007", require_existing_web_service=True)


def test_target_bound_web_requires_exact_create_and_unchanged_dependencies() -> None:
    preview = _preview(
        "FolderBinding", "TemplateBinding", "WebTargetBinding",
        "TargetBoundWebSecretMetadata", blueprint_ref="FPA-BP-007",
    )
    changes = preview["object_changes"]
    for item in changes:
        item["change_kind"] = (
            "create" if item["object_class"] == "TargetBoundWebSecretMetadata" else "no_op"
        )
    acceptance._validate_secret_onboarding_preview(
        preview, "FPA-BP-007", require_target_bound_web=True,
    )
    with pytest.raises(acceptance.LinuxOnboardingMcpOAuthAcceptanceError):
        acceptance._validate_secret_onboarding_preview(preview, "FPA-BP-007")
    for item in changes:
        original = item["change_kind"]
        for invalid in ({"create", "update", "delete", "no_op"} - {original}):
            item["change_kind"] = invalid
            with pytest.raises(acceptance.LinuxOnboardingMcpOAuthAcceptanceError):
                acceptance._validate_secret_onboarding_preview(
                    preview, "FPA-BP-007", require_target_bound_web=True,
                )
        item["change_kind"] = original
    changes.append(changes[-1])
    with pytest.raises(acceptance.LinuxOnboardingMcpOAuthAcceptanceError):
        acceptance._validate_secret_onboarding_preview(
            preview, "FPA-BP-007", require_target_bound_web=True,
        )


def test_domain_secret_preview_requires_exact_create_and_unchanged_dependencies() -> None:
    preview = _preview(
        "FolderBinding", "TemplateBinding", "DomainTargetBinding",
        "DomainSecretMetadata", blueprint_ref="FPA-BP-014",
    )
    changes = preview["object_changes"]
    for item in changes:
        item["change_kind"] = "create" if item["object_class"] == "DomainSecretMetadata" else "no_op"
    acceptance._validate_secret_onboarding_preview(
        preview, "FPA-BP-014", require_domain_secret=True,
    )
    with pytest.raises(acceptance.LinuxOnboardingMcpOAuthAcceptanceError):
        acceptance._validate_secret_onboarding_preview(preview, "FPA-BP-014")
    for item in changes:
        original = item["change_kind"]
        for invalid in ({"create", "update", "delete", "no_op"} - {original}):
            item["change_kind"] = invalid
            with pytest.raises(acceptance.LinuxOnboardingMcpOAuthAcceptanceError):
                acceptance._validate_secret_onboarding_preview(
                    preview, "FPA-BP-014", require_domain_secret=True,
                )
        item["change_kind"] = original
    for option in ("require_target_bound_web", "require_existing_web_service", "require_existing_session_controls"):
        with pytest.raises(acceptance.LinuxOnboardingMcpOAuthAcceptanceError):
            acceptance._validate_secret_onboarding_preview(
                preview, "FPA-BP-014", require_domain_secret=True, **{option: True},
            )
    changes.append(changes[-1])
    with pytest.raises(acceptance.LinuxOnboardingMcpOAuthAcceptanceError):
        acceptance._validate_secret_onboarding_preview(
            preview, "FPA-BP-014", require_domain_secret=True,
        )


@pytest.mark.parametrize("fault",[None,"target-create","folder-update","missing","legacy"])
def test_fixed_existing_linux_dependencies_allow_only_one_secret_create(fault):
    changes=[{"object_class":name,"change_kind":"create" if name=="SecretMetadata" else "no_op"}
        for name in ("FolderBinding","Target","TemplateBinding","SecretMetadata")]
    preview={"scheme_id":"SecretOnboardingScheme","blueprint_ref":"FPA-BP-005","object_changes":changes}
    if fault=="target-create":changes[1]["change_kind"]="create"
    elif fault=="folder-update":changes[0]["change_kind"]="update"
    elif fault=="missing":changes.pop()
    if fault:
        with pytest.raises(acceptance.LinuxOnboardingMcpOAuthAcceptanceError):
            acceptance._validate_secret_onboarding_preview(preview,"FPA-BP-005",require_existing_linux_dependencies=fault!="legacy")
    else:acceptance._validate_secret_onboarding_preview(preview,"FPA-BP-005",require_existing_linux_dependencies=True)
