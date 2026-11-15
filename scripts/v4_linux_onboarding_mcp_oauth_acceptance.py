#!/usr/bin/env python3
"""Run one confirmed BP005, BP006, or BP007 onboarding plan through OAuth/MCP."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from typing import Any
from urllib.parse import urlunsplit

import httpx2
from mcp import ClientSession

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) in sys.path:
    sys.path.remove(str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT))

from fortipam_mcp.env import EnvironmentFileError
from scripts import v4_address_mcp_oauth_surface_acceptance as oauth
from scripts.local_oauth_http_acceptance import LOGIN_PASSWORD, LOGIN_USERNAME
from scripts.v4_https_oauth_acceptance import (
    V4HttpsOAuthAcceptanceError,
    _affirm_browser_confirmation,
    _confirmation_url,
    _revision,
    _validate_https_mcp_url,
    _validate_plan,
    _validate_preview,
)
from v4_planning.models import PlanningContractError, require_ref


TOOLS = frozenset(
    {
        "get_v4_plan_status",
        "preview_v4_administrative_intent",
        "confirm_v4_administrative_intent",
        "prepare_v4_non_executable_plan",
        "execute_v4_secret_onboarding_workflow",
    }
)
AD_SOURCE_TOOLS = (TOOLS - {"execute_v4_secret_onboarding_workflow"}) | {
    "execute_v4_ad_discovery_workflow"
}
PREVIEW_TOOLS = frozenset(
    {
        "get_v4_plan_status",
        "preview_v4_administrative_intent",
    }
)
_MAX_REF_FILE_BYTES = 1_024
_DISPATCH_CONTRACT = "fortipam_v4_linux_onboarding_dispatch_record_v1"
_DISPATCH_OUTCOME_CONTRACT = "fortipam_v4_secret_onboarding_dispatch_outcome_v1"
_DISPATCH_OUTCOME_CATEGORIES = frozenset(
    {
        "execution_reported_success",
        "execution_reported_reconciliation",
        "execution_response_unavailable",
        "execution_result_unclassified",
    }
)
_EXECUTION_FAILURE_STAGES = frozenset(
    {
        "pre_write_projection",
        "fixed_action_resolution",
        "fixed_action_context",
        "fixed_action_private_binding",
        "fixed_action_plan_validation",
        "fixed_action_runner_binding",
        "fixed_action_runner_promotion",
        "fixed_action_runner_promotion_freshness",
        "fixed_action_runner_promotion_context",
        "fixed_action_runner_promotion_shape",
        "fixed_action_runner_promotion_material",
        "fixed_action_runner_material_binding",
        "fixed_action_runner_runtime_binding",
        "fixed_action_execution",
        "fixed_action_verification",
        "fixed_action_target_http_dispatch",
        "fixed_action_target_acknowledgement",
        "fixed_action_target_preview",
        "fixed_action_target_confirmation",
        "fixed_action_target_execution",
        "fixed_action_target_address_conflict",
        "post_write_projection",
        "post_write_comparison",
    }
)
_SUPPORTED_BLUEPRINTS = frozenset({"FPA-BP-005", "FPA-BP-006", "FPA-BP-007", "FPA-BP-014"})
_KEYCHAIN_ACCOUNT = re.compile(r'"acct"<blob>="(?P<account>[^"]+)"')


class LinuxOnboardingMcpOAuthAcceptanceError(RuntimeError):
    """Stable legacy name for one Secret onboarding acceptance failure."""


class _KeychainOAuthLoginFile:
    """Create one owner-only OAuth input from a specifically selected Keychain item."""

    def __init__(self, service: str) -> None:
        self._service = service
        self._directory: Path | None = None
        self.path: Path | None = None

    def __enter__(self) -> Path:
        metadata = subprocess.run(
            ["security", "find-generic-password", "-s", self._service],
            check=False,
            capture_output=True,
            text=True,
        )
        account_match = _KEYCHAIN_ACCOUNT.search(metadata.stdout + metadata.stderr)
        if metadata.returncode != 0 or account_match is None:
            raise LinuxOnboardingMcpOAuthAcceptanceError(
                "The selected Keychain OAuth login is unavailable."
            )
        account = account_match.group("account")
        password = subprocess.run(
            [
                "security",
                "find-generic-password",
                "-s",
                self._service,
                "-a",
                account,
                "-w",
            ],
            check=False,
            capture_output=True,
        )
        if password.returncode != 0 or not password.stdout:
            raise LinuxOnboardingMcpOAuthAcceptanceError(
                "The selected Keychain OAuth login is unavailable."
            )

        self._directory = Path(tempfile.mkdtemp(prefix="fortipam-mcp-oauth-"))
        os.chmod(self._directory, 0o700)
        self.path = self._directory / "login.env"
        descriptor = os.open(
            self.path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(f"{LOGIN_USERNAME}={account}\n{LOGIN_PASSWORD}=".encode())
            handle.write(password.stdout)
            handle.write(b"\n")
        return self.path

    def __exit__(self, *_: object) -> None:
        if self.path is not None:
            self.path.unlink(missing_ok=True)
        if self._directory is not None:
            self._directory.rmdir()


async def run_linux_onboarding_mcp_oauth_acceptance(
    url: str,
    login_file: Path,
    client_state_file: Path,
    scheme_draft_ref_file: Path,
    dispatch_state_file: Path,
    *,
    ca_file: Path | None = None,
    lab_connect_host: str | None = None,
    lab_connect_port: int | None = None,
    allow_loopback_tunnel: bool = False,
    mcp_read_timeout_seconds: int = 30,
) -> dict[str, object]:
    """Run the original BP005 entrypoint through the shared onboarding client."""

    return await run_secret_onboarding_mcp_oauth_acceptance(
        url,
        login_file,
        client_state_file,
        scheme_draft_ref_file,
        dispatch_state_file,
        blueprint_ref="FPA-BP-005",
        ca_file=ca_file,
        lab_connect_host=lab_connect_host,
        lab_connect_port=lab_connect_port,
        allow_loopback_tunnel=allow_loopback_tunnel,
        mcp_read_timeout_seconds=mcp_read_timeout_seconds,
    )


async def run_secret_onboarding_mcp_oauth_acceptance(
    url: str,
    login_file: Path,
    client_state_file: Path,
    scheme_draft_ref_file: Path,
    dispatch_state_file: Path,
    *,
    blueprint_ref: str,
    existing_session_controls: bool = False,
    existing_linux_dependencies: bool = False,
    existing_web_service: bool = False,
    target_bound_web: bool = False,
    domain_secret: bool = False,
    ad_discovery_source: bool = False,
    ca_file: Path | None = None,
    lab_connect_host: str | None = None,
    lab_connect_port: int | None = None,
    allow_loopback_tunnel: bool = False,
    mcp_read_timeout_seconds: int = 30,
) -> dict[str, object]:
    """Preview, confirm, prepare, and dispatch one supported onboarding Draft."""

    if (
        blueprint_ref not in _SUPPORTED_BLUEPRINTS
        or type(existing_linux_dependencies) is not bool
        or (existing_linux_dependencies and (blueprint_ref!="FPA-BP-005" or existing_session_controls or existing_web_service or target_bound_web or domain_secret or ad_discovery_source))
        or type(existing_session_controls) is not bool
        or type(existing_web_service) is not bool
        or type(domain_secret) is not bool
        or type(ad_discovery_source) is not bool
        or ((domain_secret or ad_discovery_source) != (blueprint_ref == "FPA-BP-014"))
        or (domain_secret and ad_discovery_source)
        or ((domain_secret or ad_discovery_source) and (target_bound_web or existing_web_service))
        or type(target_bound_web) is not bool
        or (target_bound_web and (blueprint_ref != "FPA-BP-007" or existing_web_service))
        or (existing_web_service and blueprint_ref != "FPA-BP-007")
        or (existing_session_controls and blueprint_ref != "FPA-BP-006")
    ):
        raise LinuxOnboardingMcpOAuthAcceptanceError(
            "Secret onboarding Blueprint is unavailable."
        )

    parsed = _validate_https_mcp_url(url)
    origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    verify: str | bool = str(ca_file) if ca_file is not None else True
    scheme_draft_ref = _read_scheme_draft_ref(scheme_draft_ref_file)
    _validate_new_dispatch_state_path(dispatch_state_file)
    execution_result: dict[str, object] | None = None
    preview_verified = False
    confirmation_consumed = False
    plan_prepared = False
    dispatch_attempted = False

    async def callback(session: ClientSession) -> None:
        nonlocal execution_result
        nonlocal preview_verified, confirmation_consumed, plan_prepared
        nonlocal dispatch_attempted

        status = _structured(
            await session.call_tool("get_v4_plan_status", {}),
            "status",
        )
        _validate_source_backed_status(
            status,
            require_secret_create_runtime=not (existing_session_controls or existing_web_service or ad_discovery_source),
            require_ad_discovery_runtime=ad_discovery_source,
        )
        preview = _structured(
            await session.call_tool(
                "preview_v4_administrative_intent",
                {"scheme_draft_ref": scheme_draft_ref},
            ),
            "preview",
        )
        _validate_preview(preview)
        _validate_secret_onboarding_preview(
            preview, blueprint_ref,
            allow_existing_session_controls=existing_session_controls,
            require_existing_session_controls=existing_session_controls,
            require_existing_web_service=existing_web_service,
            require_target_bound_web=target_bound_web,
            require_domain_secret=domain_secret,
            require_ad_discovery_source=ad_discovery_source,
            require_existing_linux_dependencies=existing_linux_dependencies,
        )
        preview_verified = True

        username = os.environ.get(LOGIN_USERNAME)
        password = os.environ.get(LOGIN_PASSWORD)
        if not username or not password:
            raise LinuxOnboardingMcpOAuthAcceptanceError(
                "OAuth confirmation identity is unavailable."
            )
        browser_transport = oauth._connection_transport(
            parsed,
            lab_connect_host,
            verify,
            lab_connect_port=lab_connect_port,
            allow_loopback_tunnel=allow_loopback_tunnel,
        )
        async with httpx2.AsyncClient(
            timeout=30.0,
            follow_redirects=False,
            trust_env=False,
            verify=verify,
            headers={"User-Agent": "fortipam-mcp-v4-secret-onboarding-acceptance/1"},
            transport=browser_transport,
        ) as browser:
            await _affirm_browser_confirmation(
                browser,
                _confirmation_url(preview, origin),
                origin=origin,
                username=username,
                password=password,
            )

        summary_ref = str(preview["summary_ref"])
        confirmation = _structured(
            await session.call_tool(
                "confirm_v4_administrative_intent",
                {
                    "summary_ref": summary_ref,
                    "summary_revision": _revision(preview),
                },
            ),
            "confirmation",
        )
        confirmation_ref = confirmation.get("confirmation_ref")
        if not isinstance(confirmation_ref, str):
            raise LinuxOnboardingMcpOAuthAcceptanceError(
                "Secret onboarding confirmation consumption failed."
            )
        confirmation_consumed = True
        plan = _structured(
            await session.call_tool(
                "prepare_v4_non_executable_plan",
                {
                    "summary_ref": summary_ref,
                    "confirmation_ref": confirmation_ref,
                },
            ),
            "plan",
        )
        _validate_plan(plan)
        plan_ref = plan.get("plan_ref")
        if not isinstance(plan_ref, str):
            raise LinuxOnboardingMcpOAuthAcceptanceError(
                "Secret onboarding prepared Plan is unavailable."
            )
        plan_prepared = True
        _create_dispatch_record(
            dispatch_state_file, existing_session_controls=existing_session_controls,
            existing_web_service=existing_web_service,
        )
        dispatch_attempted = True
        try:
            raw_execution_result = await session.call_tool(
                "execute_v4_ad_discovery_workflow" if ad_discovery_source
                else "execute_v4_secret_onboarding_workflow",
                {"plan_ref": plan_ref, "scheme_draft_ref": scheme_draft_ref},
            )
        except BaseException:
            _write_dispatch_outcome(
                dispatch_state_file,
                "execution_response_unavailable",
            )
            raise
        try:
            execution_result = _structured(raw_execution_result, "execution")
        except BaseException:
            _write_dispatch_outcome(
                dispatch_state_file,
                "execution_response_unavailable",
            )
            raise
        failure_stage = execution_result.get("failure_stage")
        if isinstance(failure_stage, str) and failure_stage in _EXECUTION_FAILURE_STAGES:
            _write_dispatch_outcome(
                dispatch_state_file,
                "execution_reported_reconciliation",
                failure_stage=failure_stage,
            )
        elif execution_result.get("outcome") == "succeeded":
            _write_dispatch_outcome(
                dispatch_state_file,
                "execution_reported_success",
            )
        else:
            _write_dispatch_outcome(
                dispatch_state_file,
                "execution_result_unclassified",
            )
        _validate_execution(
            execution_result,
            authorization_scope="source_bound_ad_discovery" if ad_discovery_source
            else "source_bound_onboarding",
        )
        completed_lines = execution_result.get("completed_line_refs")
        if (existing_session_controls or existing_web_service or target_bound_web or domain_secret or ad_discovery_source) and (
            not isinstance(completed_lines, list) or len(completed_lines) != 1
        ):
            raise LinuxOnboardingMcpOAuthAcceptanceError(
                "Existing Secret controls execution count is invalid."
            )

    try:
        common = await oauth.run_address_mcp_oauth_surface_acceptance(
            url,
            login_file,
            client_state_file,
            ca_file=ca_file,
            tool_session_callback=callback,
            required_tools=AD_SOURCE_TOOLS if ad_discovery_source else TOOLS,
            lab_connect_host=lab_connect_host,
            lab_connect_port=lab_connect_port,
            allow_loopback_tunnel=allow_loopback_tunnel,
            mcp_read_timeout_seconds=mcp_read_timeout_seconds,
        )
    except oauth.AddressMcpOAuthSurfaceAcceptanceError as exc:
        raise LinuxOnboardingMcpOAuthAcceptanceError(str(exc)) from None
    except V4HttpsOAuthAcceptanceError as exc:
        raise LinuxOnboardingMcpOAuthAcceptanceError(str(exc)) from None
    except httpx2.HTTPError:
        raise LinuxOnboardingMcpOAuthAcceptanceError(
            "Secret onboarding OAuth/MCP transport is unavailable."
        ) from None
    except BaseExceptionGroup as exc:
        message = _contained_onboarding_error_message(exc)
        if message is not None:
            raise LinuxOnboardingMcpOAuthAcceptanceError(
                message
            ) from None
        raise
    _validate_common_acceptance(common)
    if execution_result is None:
        raise LinuxOnboardingMcpOAuthAcceptanceError(
            "Secret onboarding OAuth/MCP acceptance did not dispatch."
        )
    completed = execution_result["completed_line_refs"]
    assert isinstance(completed, list)
    return {
        "contract": "fortipam_v4_secret_onboarding_mcp_oauth_acceptance_v1",
        "blueprint_ref": blueprint_ref,
        "oauth_metadata_verified": common["oauth_metadata_verified"],
        "mcp_initialized": common["mcp_initialized"],
        "required_tool_surface_complete": True,
        "source_backed_status_verified": True,
        "preview_verified": preview_verified,
        "browser_confirmation_completed": True,
        "confirmation_consumed": confirmation_consumed,
        "plan_prepared": plan_prepared,
        "dispatch_attempted_once": dispatch_attempted,
        "completed_action_count": len(completed),
        "post_write_expected_state_verified": True,
        "device_write_executed": True,
        "reconciliation_required": False,
        "token_revoked": common["token_revoked"],
        "credential_values_returned": False,
        "scheme_draft_ref_returned": False,
        "plan_or_line_refs_returned": False,
        "client_id_returned": False,
        "token_returned": False,
    }


async def run_secret_onboarding_mcp_oauth_preview_acceptance(
    url: str,
    login_file: Path,
    client_state_file: Path,
    scheme_draft_ref_file: Path,
    *,
    blueprint_ref: str,
    existing_web_service: bool = False,
    target_bound_web: bool = False,
    domain_secret: bool = False,
    ad_discovery_source: bool = False,
    ca_file: Path | None = None,
    lab_connect_host: str | None = None,
    lab_connect_port: int | None = None,
    allow_loopback_tunnel: bool = False,
    mcp_read_timeout_seconds: int = 30,
) -> dict[str, object]:
    """Verify one source-backed onboarding preview without confirmation or dispatch."""

    if (blueprint_ref not in _SUPPORTED_BLUEPRINTS
        or type(existing_web_service) is not bool
        or type(domain_secret) is not bool
        or type(ad_discovery_source) is not bool
        or ((domain_secret or ad_discovery_source) != (blueprint_ref == "FPA-BP-014"))
        or (domain_secret and ad_discovery_source)
        or ((domain_secret or ad_discovery_source) and (target_bound_web or existing_web_service))
        or type(target_bound_web) is not bool
        or (target_bound_web and (blueprint_ref != "FPA-BP-007" or existing_web_service))
        or (existing_web_service and blueprint_ref != "FPA-BP-007")):
        raise LinuxOnboardingMcpOAuthAcceptanceError(
            "Secret onboarding Blueprint is unavailable."
        )

    _validate_https_mcp_url(url)
    scheme_draft_ref = _read_scheme_draft_ref(scheme_draft_ref_file)
    preview_verified = False

    async def callback(session: ClientSession) -> None:
        nonlocal preview_verified
        status = _structured(
            await session.call_tool("get_v4_plan_status", {}),
            "status",
        )
        _validate_source_backed_status(status, require_secret_create_runtime=False)
        preview = _structured(
            await session.call_tool(
                "preview_v4_administrative_intent",
                {"scheme_draft_ref": scheme_draft_ref},
            ),
            "preview",
        )
        _validate_preview(preview)
        _validate_secret_onboarding_preview(
            preview, blueprint_ref, allow_existing_session_controls=True,
            require_existing_web_service=existing_web_service,
            require_target_bound_web=target_bound_web,
            require_domain_secret=domain_secret,
            require_ad_discovery_source=ad_discovery_source,
        )
        preview_verified = True

    try:
        common = await oauth.run_address_mcp_oauth_surface_acceptance(
            url,
            login_file,
            client_state_file,
            ca_file=ca_file,
            tool_session_callback=callback,
            required_tools=PREVIEW_TOOLS,
            requested_scope=oauth.PLAN_ONLY_SCOPE,
            lab_connect_host=lab_connect_host,
            lab_connect_port=lab_connect_port,
            allow_loopback_tunnel=allow_loopback_tunnel,
            mcp_read_timeout_seconds=mcp_read_timeout_seconds,
        )
    except oauth.AddressMcpOAuthSurfaceAcceptanceError as exc:
        raise LinuxOnboardingMcpOAuthAcceptanceError(str(exc)) from None
    except V4HttpsOAuthAcceptanceError as exc:
        raise LinuxOnboardingMcpOAuthAcceptanceError(str(exc)) from None
    except httpx2.HTTPError:
        raise LinuxOnboardingMcpOAuthAcceptanceError(
            "Secret onboarding OAuth/MCP preview transport is unavailable."
        ) from None
    except BaseExceptionGroup as exc:
        message = _contained_onboarding_error_message(exc)
        if message is not None:
            raise LinuxOnboardingMcpOAuthAcceptanceError(
                message
            ) from None
        raise
    _validate_common_acceptance(common)
    if not preview_verified:
        raise LinuxOnboardingMcpOAuthAcceptanceError(
            "Secret onboarding intent preview was not verified."
        )
    return {
        "contract": "fortipam_v4_secret_onboarding_mcp_oauth_preview_v1",
        "blueprint_ref": blueprint_ref,
        "oauth_metadata_verified": common["oauth_metadata_verified"],
        "mcp_initialized": common["mcp_initialized"],
        "required_tool_surface_complete": True,
        "source_backed_status_verified": True,
        "preview_verified": True,
        "confirmation_consumed": False,
        "plan_prepared": False,
        "dispatch_attempted": False,
        "device_write_executed": False,
        "token_revoked": common["token_revoked"],
        "credential_values_returned": False,
        "scheme_draft_ref_returned": False,
        "client_id_returned": False,
        "token_returned": False,
    }


def _validate_common_acceptance(result: dict[str, object]) -> None:
    if (
        result.get("oauth_metadata_verified") is not True
        or result.get("mcp_initialized") is not True
        or result.get("token_revoked") is not True
        or result.get("credential_values_returned") is not False
    ):
        raise LinuxOnboardingMcpOAuthAcceptanceError(
            "Secret onboarding OAuth/MCP transport acceptance failed."
        )


def _validate_source_backed_status(
    status: dict[str, object], *, require_secret_create_runtime: bool = True,
    require_ad_discovery_runtime: bool = False,
) -> None:
    if (
        status.get("runtime_profile") != "v4-plan-only"
        or status.get("host_services_bound") is not True
        or status.get("confirmation_transport_bound") is not True
        or status.get("projection_mode") != "source_backed"
        or status.get("scheme_draft_issuance_protocol_bound") is not True
        or status.get("reference_authorization_protocol_bound") is not True
        or (require_secret_create_runtime and
            status.get("secret_create_execution_preflight_available") is not True)
        or (require_ad_discovery_runtime and
            status.get("ad_discovery_execution_preflight_available") is not True)
        or "synthetic_scheme_draft_refs" in status
    ):
        raise LinuxOnboardingMcpOAuthAcceptanceError(
            "Secret onboarding source-backed Host status is unavailable."
        )


def _validate_bp005_preview(preview: dict[str, object]) -> None:
    _validate_secret_onboarding_preview(preview, "FPA-BP-005")


def _validate_secret_onboarding_preview(
    preview: dict[str, object],
    blueprint_ref: str,
    *,
    require_existing_linux_dependencies: bool = False,
    allow_existing_session_controls: bool = False,
    require_existing_session_controls: bool = False,
    require_existing_web_service: bool = False,
    require_target_bound_web: bool = False,
    require_domain_secret: bool = False,
    require_ad_discovery_source: bool = False,
) -> None:
    if require_ad_discovery_source:
        if (require_domain_secret or require_target_bound_web
            or require_existing_web_service or require_existing_session_controls
            or blueprint_ref != "FPA-BP-014"):
            raise LinuxOnboardingMcpOAuthAcceptanceError(
                "AD Source preview profile is invalid."
            )
        _validate_ad_discovery_source_preview(preview)
        return
    changes = preview.get("object_changes")
    if (
        preview.get("scheme_id") != "SecretOnboardingScheme"
        or blueprint_ref not in _SUPPORTED_BLUEPRINTS
        or preview.get("blueprint_ref") != blueprint_ref
        or not isinstance(changes, list)
        or not changes
    ):
        raise LinuxOnboardingMcpOAuthAcceptanceError(
            "Secret onboarding intent preview is invalid."
        )
    if any(not isinstance(item, dict) for item in changes):
        raise LinuxOnboardingMcpOAuthAcceptanceError(
            "Secret onboarding intent preview is invalid."
        )
    classes = [item.get("object_class") for item in changes]
    if require_existing_linux_dependencies:
        required={"FolderBinding","Target","TemplateBinding","SecretMetadata"}
        if (blueprint_ref!="FPA-BP-005" or len(classes)!=4 or set(classes)!=required
                or any(item.get("change_kind")!=("create" if item["object_class"]=="SecretMetadata" else "no_op") for item in changes)
                or any((allow_existing_session_controls,require_existing_session_controls,require_existing_web_service,
                    require_target_bound_web,require_domain_secret,require_ad_discovery_source))):
            raise LinuxOnboardingMcpOAuthAcceptanceError("Existing Linux dependencies preview is invalid.")
        return

    if any(not isinstance(item, str) for item in classes):
        raise LinuxOnboardingMcpOAuthAcceptanceError(
            "Secret onboarding intent preview is invalid."
        )
    if require_domain_secret or blueprint_ref == "FPA-BP-014" or any(
        item in classes for item in ("DomainTargetBinding", "DomainSecretMetadata")
    ):
        expected = {
            "FolderBinding": "no_op", "TemplateBinding": "no_op",
            "DomainTargetBinding": "no_op", "DomainSecretMetadata": "create",
        }
        if (
            not require_domain_secret
            or require_target_bound_web or require_existing_web_service
            or require_existing_session_controls
            or blueprint_ref != "FPA-BP-014"
            or len(changes) != len(expected)
            or {item["object_class"]: item.get("change_kind") for item in changes} != expected
        ):
            raise LinuxOnboardingMcpOAuthAcceptanceError(
                "Domain Secret create preview is invalid."
            )
        return
    if require_target_bound_web or any(
        item in classes for item in ("WebTargetBinding", "TargetBoundWebSecretMetadata")
    ):
        expected = {
            "FolderBinding": "no_op", "TemplateBinding": "no_op",
            "WebTargetBinding": "no_op", "TargetBoundWebSecretMetadata": "create",
        }
        if (
            not require_target_bound_web
            or require_existing_web_service
            or blueprint_ref != "FPA-BP-007"
            or len(changes) != len(expected)
            or {item["object_class"]: item.get("change_kind") for item in changes} != expected
        ):
            raise LinuxOnboardingMcpOAuthAcceptanceError(
                "Target-bound Web Secret create preview is invalid."
            )
        return
    if require_existing_web_service or "WebSecretServiceBinding" in classes:
        web_required = ["FolderBinding", "TemplateBinding", "WebSecretMetadata", "WebSecretServiceBinding"]
        if (
            not require_existing_web_service
            or blueprint_ref != "FPA-BP-007"
            or classes != web_required
            or any(
                item.get("change_kind") != ("update" if item["object_class"] == "WebSecretServiceBinding" else "no_op")
                for item in changes
            )
        ):
            raise LinuxOnboardingMcpOAuthAcceptanceError(
                "Existing Web Secret service preview is invalid."
            )
        return
    if require_existing_session_controls and "SecretSessionControlsBinding" not in classes:
        raise LinuxOnboardingMcpOAuthAcceptanceError(
            "Existing Secret controls profile is required."
        )
    if "SecretSessionControlsBinding" in classes:
        required = {"FolderBinding", "Target", "TemplateBinding", "SecretMetadata",
                    "RdpEventFilterBinding", "SecretSessionControlsBinding"}
        if (
            not allow_existing_session_controls
            or (require_existing_session_controls and any(
                item.get("change_kind") != "update"
                for item in changes
                if item["object_class"] == "SecretSessionControlsBinding"
            ))
            or blueprint_ref != "FPA-BP-006"
            or set(classes) != required or len(classes) != len(required)
            or any(
                item.get("change_kind") not in {"update", "no_op"}
                if item["object_class"] == "SecretSessionControlsBinding"
                else item.get("change_kind") != "no_op"
                for item in changes
            )
        ):
            raise LinuxOnboardingMcpOAuthAcceptanceError(
                "Existing Secret controls preview is invalid or execution is unbound."
            )
        return
    if blueprint_ref == "FPA-BP-005":
        required = {
            "PublicFolder",
            "AccessGrant",
            "FolderBinding",
            "Target",
            "TemplateBinding",
            "SecretMetadata",
        }
        allowed = required | {"LauncherBinding"}
        counts = {
            object_class: classes.count(object_class) for object_class in allowed
        }
        valid = (
            required <= set(classes) <= allowed
            and all(
                counts[object_class] == 1
                for object_class in required - {"AccessGrant"}
            )
            and 1 <= counts["AccessGrant"] <= 12
            and counts["LauncherBinding"] <= 1
        )
    elif blueprint_ref == "FPA-BP-006":
        required = {
            "FolderBinding",
            "Target",
            "TemplateBinding",
            "SecretMetadata",
            "LauncherBinding",
            "PolicyBinding",
        }
        allowed = required | {"RdpEventFilterBinding"}
        valid = set(classes) == required or (
            set(classes) == allowed and classes.count("RdpEventFilterBinding") == 1
        )
        valid = valid and all(classes.count(item) == 1 for item in required)
    else:
        valid = classes == [
            "FolderBinding",
            "TemplateBinding",
            "WebSecretMetadata",
        ]
    if not valid:
        raise LinuxOnboardingMcpOAuthAcceptanceError(
            "Secret onboarding intent preview is invalid."
        )



def _validate_ad_discovery_source_preview(preview: dict[str, object]) -> None:
    """Accept only the disabled Source create and four unchanged opaque anchors."""

    message = "AD Source disabled create preview is invalid."
    changes = preview.get("object_changes")
    expected_kinds = {
        "FolderBinding": "no_op", "DomainTargetBinding": "no_op",
        "TemplateBinding": "no_op", "DomainSecretMetadata": "no_op",
        "DiscoverySourceMetadata": "create",
    }
    if (preview.get("scheme_id") != "BulkOnboardingScheme"
        or preview.get("blueprint_ref") != "FPA-BP-014"
        or preview.get("outcome_code") != "create_disabled_ad_discovery_source"
        or not isinstance(changes, list) or len(changes) != 5
        or any(not isinstance(item, dict) for item in changes)):
        raise LinuxOnboardingMcpOAuthAcceptanceError(message)
    by_class: dict[str, dict[str, object]] = {}
    refs: set[str] = set()
    for item in changes:
        object_class = item.get("object_class")
        ref = item.get("object_ref")
        if (not isinstance(object_class, str) or object_class not in expected_kinds
            or object_class in by_class or item.get("change_kind") != expected_kinds[object_class]
            or not isinstance(ref, str) or ref in refs):
            raise LinuxOnboardingMcpOAuthAcceptanceError(message)
        try:
            require_ref(ref, "object_ref")
        except PlanningContractError:
            raise LinuxOnboardingMcpOAuthAcceptanceError(message) from None
        refs.add(ref)
        by_class[object_class] = item

    expected: dict[str, dict[str, object]] = {
        "FolderBinding": {"exists": True, "folder_ref": None},
        "DomainTargetBinding": {"exists": True, "profile_ref": None,
                                "target_relation_matches": True},
        "TemplateBinding": {"exists": True, "template_ref": None,
                            "compatibility": "compatible"},
        "DomainSecretMetadata": {"exists": True, "inherit_permission": True,
                                 "non_privileged_account": True, "services_disabled": True,
                                 "target_association_matches": True},
        "DiscoverySourceMetadata": {
            "exists": True, "source_type": "active_directory", "account_discovery": True,
            "domain_secret_ref": by_class["DomainSecretMetadata"]["object_ref"],
            "periodic_scanning_disabled": True, "auto_onboarding_disabled": True,
            "existing_secret_method": True, "no_scan_timestamp": True,
        },
    }
    for object_class, fields in expected.items():
        item = by_class[object_class]
        current = item.get("current_fields")
        projected = item.get("projected_changes")
        final = item.get("expected_fields")
        if not isinstance(final, dict) or set(final) != set(fields):
            raise LinuxOnboardingMcpOAuthAcceptanceError(message)
        for key, value in fields.items():
            actual = final[key]
            if value is None:
                if not isinstance(actual, str):
                    raise LinuxOnboardingMcpOAuthAcceptanceError(message)
                try:
                    require_ref(actual, key)
                except PlanningContractError:
                    raise LinuxOnboardingMcpOAuthAcceptanceError(message) from None
            elif type(actual) is not type(value) or actual != value:
                raise LinuxOnboardingMcpOAuthAcceptanceError(message)
        if object_class == "DiscoverySourceMetadata":
            if (type(current) is not dict or set(current) != {"exists"}
                or current["exists"] is not False or projected != final
                or not isinstance(projected, dict)
                or any(type(projected[key]) is not type(final[key]) for key in final)):
                raise LinuxOnboardingMcpOAuthAcceptanceError(message)
        elif (not isinstance(current, dict) or current != final
              or any(type(current[key]) is not type(final[key]) for key in final)
              or type(projected) is not dict or projected):
            raise LinuxOnboardingMcpOAuthAcceptanceError(message)


def _validate_execution(
    result: dict[str, object], *, authorization_scope: str = "source_bound_onboarding",
) -> None:
    completed = result.get("completed_line_refs")
    failure_stage = result.get("failure_stage")
    if failure_stage is not None:
        if failure_stage not in _EXECUTION_FAILURE_STAGES:
            raise LinuxOnboardingMcpOAuthAcceptanceError(
                "Secret onboarding execution result is invalid."
            )
        raise LinuxOnboardingMcpOAuthAcceptanceError(
            f"Secret onboarding execution stopped at {failure_stage}."
        )
    if (
        result.get("outcome") != "succeeded"
        or result.get("pre_write_status") != "match"
        or result.get("post_write_status") != "expected_state_matches"
        or result.get("reconciliation_required") is not False
        or result.get("stopped_line_ref") is not None
        or result.get("authorization_scope") != authorization_scope
        or result.get("lab_exception_applied") is not True
        or result.get("policy_mode") != "lab_auto"
        or not isinstance(completed, list)
        or not completed
        or any(not isinstance(item, str) for item in completed)
    ):
        raise LinuxOnboardingMcpOAuthAcceptanceError(
            "Secret onboarding execution or final readback was not accepted."
        )


def _structured(result: Any, stage: str) -> dict[str, object]:
    value = getattr(result, "structured_content", None)
    if getattr(result, "is_error", True) or not isinstance(value, dict):
        category = _safe_tool_failure_category(result)
        if category is not None:
            raise LinuxOnboardingMcpOAuthAcceptanceError(
                f"Secret onboarding {stage} Tool call rejected ({category})."
            )
        raise LinuxOnboardingMcpOAuthAcceptanceError(
            f"Secret onboarding {stage} Tool call failed."
        )
    return dict(value)


def _safe_tool_failure_category(result: Any) -> str | None:
    """Classify only known server rejections without returning server text."""

    texts: list[str] = []
    for item in getattr(result, "content", ()):
        text = getattr(item, "text", None)
        if isinstance(text, str):
            texts.append(text)
    message = " ".join(texts)
    if "Reference is not authorized for the exact" in message:
        return "reference_authorization"
    if "Scheme Draft" in message:
        return "scheme_draft"
    if "planning authorization denied" in message.lower():
        return "planning_authorization"
    if "Secret onboarding projection source is unavailable" in message:
        return "projection_source"
    if "V4 planning host services are unavailable" in message:
        return "planning_host"
    if "Projection is unavailable, unsafe, or stale" in message:
        return "projection_state"
    return None


def _read_scheme_draft_ref(path: Path) -> str:
    value = _read_owner_only_json(path, _MAX_REF_FILE_BYTES)
    ref = value.get("scheme_draft_ref")
    if set(value) != {"scheme_draft_ref"} or not isinstance(ref, str):
        raise LinuxOnboardingMcpOAuthAcceptanceError(
            "Scheme Draft reference file is invalid."
        )
    try:
        require_ref(ref, "scheme_draft_ref")
        return ref
    except PlanningContractError:
        raise LinuxOnboardingMcpOAuthAcceptanceError(
            "Scheme Draft reference file is invalid."
        ) from None


def _read_owner_only_json(path: Path, maximum_bytes: int) -> dict[str, object]:
    if not path.is_absolute():
        raise LinuxOnboardingMcpOAuthAcceptanceError(
            "Acceptance state path is invalid."
        )
    try:
        metadata = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or not 0 < metadata.st_size <= maximum_bytes
        ):
            raise OSError
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            content = os.read(descriptor, maximum_bytes + 1)
        finally:
            os.close(descriptor)
        value = json.loads(content)
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise LinuxOnboardingMcpOAuthAcceptanceError(
            "Acceptance state file is unavailable."
        ) from None
    if type(value) is not dict or not all(type(key) is str for key in value):
        raise LinuxOnboardingMcpOAuthAcceptanceError(
            "Acceptance state file is invalid."
        )
    return value


def _validate_new_dispatch_state_path(path: Path) -> None:
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise LinuxOnboardingMcpOAuthAcceptanceError(
            "Dispatch state file is unavailable."
        )
    try:
        parent = path.parent.lstat()
    except OSError:
        raise LinuxOnboardingMcpOAuthAcceptanceError(
            "Dispatch state directory is unavailable."
        ) from None
    if (
        path.parent.is_symlink()
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.getuid()
        or stat.S_IMODE(parent.st_mode) & 0o077
    ):
        raise LinuxOnboardingMcpOAuthAcceptanceError(
            "Dispatch state directory must be owner-only."
        )
    outcome_path = _dispatch_outcome_path(path)
    if outcome_path.exists() or outcome_path.is_symlink():
        raise LinuxOnboardingMcpOAuthAcceptanceError(
            "Dispatch outcome state file is unavailable."
        )


def _dispatch_outcome_path(dispatch_path: Path) -> Path:
    return dispatch_path.with_name(dispatch_path.name + ".outcome.json")


def _write_dispatch_outcome(
    dispatch_path: Path,
    category: str,
    *,
    failure_stage: str | None = None,
) -> None:
    """Persist only the fixed outcome class beside a consumed dispatch claim."""

    if (
        category not in _DISPATCH_OUTCOME_CATEGORIES
        or (failure_stage is not None and failure_stage not in _EXECUTION_FAILURE_STAGES)
        or not dispatch_path.is_absolute()
    ):
        raise LinuxOnboardingMcpOAuthAcceptanceError(
            "Dispatch outcome state is invalid."
        )
    outcome_path = _dispatch_outcome_path(dispatch_path)
    content = json.dumps(
        {
            "contract": _DISPATCH_OUTCOME_CONTRACT,
            "dispatch_attempted": True,
            "failure_stage": failure_stage,
            "outcome_category": category,
            "retry_allowed": False,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii") + b"\n"
    try:
        parent = dispatch_path.parent.lstat()
        if (
            dispatch_path.parent.is_symlink()
            or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.getuid()
            or stat.S_IMODE(parent.st_mode) & 0o077
        ):
            raise OSError
        descriptor = os.open(
            outcome_path,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            written = 0
            while written < len(content):
                count = os.write(descriptor, content[written:])
                if count <= 0:
                    raise OSError
                written += count
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        raise LinuxOnboardingMcpOAuthAcceptanceError(
            "Dispatch outcome state is unavailable."
        ) from None


def _create_dispatch_record(
    path: Path, *, existing_session_controls: bool = False,
    existing_web_service: bool = False,
) -> None:
    content = json.dumps(
        {
            "contract": _DISPATCH_CONTRACT,
            "dispatch_attempted": True,
            "retry_allowed": False,
            **({
                "policy_mode": "lab_auto",
                "lab_exception_applied": True,
                "profile": "bp007_existing_web_service" if existing_web_service else "bp006_existing_session_controls",
            } if (existing_session_controls or existing_web_service) else {}),
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii") + b"\n"
    try:
        descriptor = os.open(
            path,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            written = 0
            while written < len(content):
                count = os.write(descriptor, content[written:])
                if count <= 0:
                    raise OSError
                written += count
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.chmod(path, 0o600)
    except OSError:
        raise LinuxOnboardingMcpOAuthAcceptanceError(
            "Dispatch state file is unavailable."
        ) from None


def _contained_onboarding_error_message(error: BaseExceptionGroup) -> str | None:
    """Return one stable nested acceptance failure without task-group detail."""

    for item in error.exceptions:
        if isinstance(
            item,
            (
                LinuxOnboardingMcpOAuthAcceptanceError,
                V4HttpsOAuthAcceptanceError,
                oauth.AddressMcpOAuthSurfaceAcceptanceError,
            ),
        ):
            return str(item)
        if isinstance(item, BaseExceptionGroup):
            message = _contained_onboarding_error_message(item)
            if message is not None:
                return message
    return None


def _contains_acceptance_error(error: BaseExceptionGroup) -> bool:
    """Retain the existing boolean classifier for callers that need it."""

    return _contained_onboarding_error_message(error) is not None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    login_source = parser.add_mutually_exclusive_group(required=True)
    login_source.add_argument("--login-file", type=Path)
    login_source.add_argument(
        "--keychain-service",
        help="Read one generic-password OAuth login into a one-shot owner-only file.",
    )
    parser.add_argument("--client-state-file", type=Path, required=True)
    parser.add_argument("--scheme-draft-ref-file", type=Path, required=True)
    parser.add_argument("--dispatch-state-file", type=Path)
    parser.add_argument(
        "--preview-only",
        action="store_true",
        help="Verify only OAuth/MCP status and the source-backed preview; never confirm or dispatch.",
    )
    parser.add_argument(
        "--blueprint-ref",
        choices=sorted(_SUPPORTED_BLUEPRINTS),
        default="FPA-BP-005",
    )
    parser.add_argument(
        "--existing-session-controls", action="store_true",
        help="Require the exact BP006 existing-Secret controls update profile.",
    )
    parser.add_argument("--existing-web-service", action="store_true",
                        help="Require the exact BP007 existing Web Secret service update profile.")
    parser.add_argument("--domain-secret", action="store_true",
                        help="Require the exact BP014 existing-Target Domain Secret create profile.")
    parser.add_argument("--ad-discovery-source", action="store_true",
                        help="Require the exact BP014 disabled AD Source create profile.")
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument(
        "--lab-connect-host",
        help="Dial this private IPv4 address while retaining HTTPS hostname verification.",
    )
    parser.add_argument(
        "--lab-connect-port",
        type=int,
        help="Use this TCP port only with an explicit loopback SSH tunnel.",
    )
    parser.add_argument(
        "--allow-loopback-tunnel",
        action="store_true",
        help="Allow only an explicit strict-TLS SSH tunnel at 127.0.0.1.",
    )
    parser.add_argument("--mcp-read-timeout-seconds", type=int, default=30)
    args = parser.parse_args()
    if ((args.domain_secret or args.ad_discovery_source) != (args.blueprint_ref == "FPA-BP-014")
        or (args.domain_secret and args.ad_discovery_source)):
        parser.error("BP014 requires exactly one of --domain-secret or --ad-discovery-source")
    if args.existing_web_service and args.blueprint_ref != "FPA-BP-007":
        parser.error("--existing-web-service requires BP007")
    if args.existing_session_controls and (args.blueprint_ref != "FPA-BP-006" or args.preview_only):
        parser.error("--existing-session-controls requires BP006 execution mode")
    if not args.preview_only and args.dispatch_state_file is None:
        parser.error("--dispatch-state-file is required unless --preview-only is used")
    if args.preview_only and args.dispatch_state_file is not None:
        parser.error("--dispatch-state-file cannot be used with --preview-only")
    try:
        source = (
            _KeychainOAuthLoginFile(args.keychain_service)
            if args.keychain_service is not None
            else None
        )
        if source is None:
            if args.login_file is None:
                raise LinuxOnboardingMcpOAuthAcceptanceError(
                    "OAuth login source is unavailable."
                )
            login_file = args.login_file
            result = asyncio.run(
                run_secret_onboarding_mcp_oauth_preview_acceptance(
                    args.url, login_file, args.client_state_file,
                    args.scheme_draft_ref_file, blueprint_ref=args.blueprint_ref,
                    existing_web_service=args.existing_web_service,
                    domain_secret=args.domain_secret,
                    ad_discovery_source=args.ad_discovery_source,
                    ca_file=args.ca_file, lab_connect_host=args.lab_connect_host,
                    lab_connect_port=args.lab_connect_port,
                    allow_loopback_tunnel=args.allow_loopback_tunnel,
                    mcp_read_timeout_seconds=args.mcp_read_timeout_seconds,
                ) if args.preview_only else run_secret_onboarding_mcp_oauth_acceptance(
                    args.url, login_file, args.client_state_file,
                    args.scheme_draft_ref_file, args.dispatch_state_file,
                    blueprint_ref=args.blueprint_ref, ca_file=args.ca_file,
                    existing_session_controls=args.existing_session_controls,
                    existing_web_service=args.existing_web_service,
                    domain_secret=args.domain_secret,
                    ad_discovery_source=args.ad_discovery_source,
                    lab_connect_host=args.lab_connect_host,
                    lab_connect_port=args.lab_connect_port,
                    allow_loopback_tunnel=args.allow_loopback_tunnel,
                    mcp_read_timeout_seconds=args.mcp_read_timeout_seconds,
                )
            )
        else:
            with source as login_file:
                result = asyncio.run(
                    run_secret_onboarding_mcp_oauth_preview_acceptance(
                        args.url, login_file, args.client_state_file,
                        args.scheme_draft_ref_file, blueprint_ref=args.blueprint_ref,
                        existing_web_service=args.existing_web_service,
                        domain_secret=args.domain_secret,
                        ad_discovery_source=args.ad_discovery_source,
                        ca_file=args.ca_file, lab_connect_host=args.lab_connect_host,
                        lab_connect_port=args.lab_connect_port,
                        allow_loopback_tunnel=args.allow_loopback_tunnel,
                        mcp_read_timeout_seconds=args.mcp_read_timeout_seconds,
                    ) if args.preview_only else run_secret_onboarding_mcp_oauth_acceptance(
                        args.url, login_file, args.client_state_file,
                        args.scheme_draft_ref_file, args.dispatch_state_file,
                        blueprint_ref=args.blueprint_ref, ca_file=args.ca_file,
                        existing_session_controls=args.existing_session_controls,
                        existing_web_service=args.existing_web_service,
                        domain_secret=args.domain_secret,
                        ad_discovery_source=args.ad_discovery_source,
                        lab_connect_host=args.lab_connect_host,
                        lab_connect_port=args.lab_connect_port,
                        allow_loopback_tunnel=args.allow_loopback_tunnel,
                        mcp_read_timeout_seconds=args.mcp_read_timeout_seconds,
                    )
                )
    except (
        EnvironmentFileError,
        LinuxOnboardingMcpOAuthAcceptanceError,
        ValueError,
    ) as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
