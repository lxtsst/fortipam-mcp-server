#!/usr/bin/env python3
"""Accept one bounded V4 Target Classification Tag OAuth/MCP C/P/E flow."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any

from mcp import ClientSession

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts import v4_address_mcp_oauth_surface_acceptance as oauth


TOOLS = frozenset(
    {
        "preview_v4_classification_tag_assign",
        "confirm_v4_classification_tag_assign",
        "execute_confirmed_v4_classification_tag_assign",
        "preview_v4_classification_tag_assign_rollback",
        "confirm_v4_classification_tag_assign_rollback",
        "execute_confirmed_v4_classification_tag_assign_rollback",
        "preview_v4_classification_tag_delete",
        "confirm_v4_classification_tag_delete",
        "execute_confirmed_v4_classification_tag_delete",
    }
)
EXPECTED_TOOL_COUNT = 298
FORWARD_TOOLS = (
    "preview_v4_classification_tag_assign",
    "confirm_v4_classification_tag_assign",
    "execute_confirmed_v4_classification_tag_assign",
)
ROLLBACK_TOOLS = (
    "preview_v4_classification_tag_assign_rollback",
    "confirm_v4_classification_tag_assign_rollback",
    "execute_confirmed_v4_classification_tag_assign_rollback",
)
FORWARD_WORKFLOW = "fortipam_v4_classification_tag_assign_api_workflow_v1"
FORWARD_EXECUTION = "fortipam_v4_classification_tag_assign_api_execution_v1"
FORWARD_PREVIEW_PREFIX = "classification-tag-assign-preview-"
FORWARD_AUTHORIZATION_PREFIX = "classification-tag-assign-authorized-"
ROLLBACK_WORKFLOW = "fortipam_v4_classification_tag_assign_rollback_api_workflow_v1"
ROLLBACK_EXECUTION = "fortipam_v4_classification_tag_assign_rollback_api_execution_v1"
ROLLBACK_PREVIEW_PREFIX = "classification-tag-assign-rollback-preview-"
ROLLBACK_AUTHORIZATION_PREFIX = "classification-tag-assign-rollback-authorized-"
DELETE_TOOLS = (
    "preview_v4_classification_tag_delete",
    "confirm_v4_classification_tag_delete",
    "execute_confirmed_v4_classification_tag_delete",
)
DELETE_WORKFLOW = "fortipam_v4_classification_tag_delete_api_workflow_v1"
DELETE_EXECUTION = "fortipam_v4_classification_tag_delete_api_execution_v1"
DELETE_PREVIEW_PREFIX = "classification-tag-delete-preview-"
DELETE_AUTHORIZATION_PREFIX = "classification-tag-delete-authorized-"


class ClassificationTagAssignMcpOAuthAcceptanceError(RuntimeError):
    """Raised when bounded assignment acceptance fails."""


async def run_classification_tag_assign_mcp_oauth_acceptance(
    url: str,
    login_file: Path,
    client_state_file: Path,
    *,
    target_name: str | None = None,
    classification_tag_name: str | None = None,
    preview_state_file: Path | None = None,
    execute_preview_state_file: Path | None = None,
    ca_file: Path | None = None,
    rollback: bool = False,
    delete: bool = False,
) -> dict[str, object]:
    """Verify or execute one exact assignment once."""

    if rollback and delete:
        raise ClassificationTagAssignMcpOAuthAcceptanceError(
            "Rollback and delete modes cannot be combined."
        )
    if (rollback or delete) and any(
        value is not None for value in (target_name, classification_tag_name)
    ):
        raise ClassificationTagAssignMcpOAuthAcceptanceError(
            "Fixed recovery does not accept Target or Classification Tag selectors."
        )
    fixed_mode = rollback or delete
    preview_requested = (
        preview_state_file is not None
        if fixed_mode
        else any(
            value is not None
            for value in (target_name, classification_tag_name, preview_state_file)
        )
    )
    if preview_requested and execute_preview_state_file is not None:
        raise ClassificationTagAssignMcpOAuthAcceptanceError(
            "Assignment preview and execution inputs cannot be combined."
        )
    if not fixed_mode and preview_requested and None in {
        target_name,
        classification_tag_name,
        preview_state_file,
    }:
        raise ClassificationTagAssignMcpOAuthAcceptanceError(
            "Assignment preview inputs are incomplete."
        )
    preview_verified = False
    execution_verified = False
    phase = "Tool-surface discovery"
    selected_tools = DELETE_TOOLS if delete else (ROLLBACK_TOOLS if rollback else FORWARD_TOOLS)
    workflow = DELETE_WORKFLOW if delete else (ROLLBACK_WORKFLOW if rollback else FORWARD_WORKFLOW)
    execution = DELETE_EXECUTION if delete else (ROLLBACK_EXECUTION if rollback else FORWARD_EXECUTION)
    preview_prefix = DELETE_PREVIEW_PREFIX if delete else (ROLLBACK_PREVIEW_PREFIX if rollback else FORWARD_PREVIEW_PREFIX)
    authorization_prefix = DELETE_AUTHORIZATION_PREFIX if delete else (
        ROLLBACK_AUTHORIZATION_PREFIX if rollback else FORWARD_AUTHORIZATION_PREFIX
    )

    async def callback(session: ClientSession) -> None:
        nonlocal preview_verified, execution_verified, phase
        tool_names = {tool.name for tool in (await session.list_tools()).tools}
        if not TOOLS <= tool_names or len(tool_names) != EXPECTED_TOOL_COUNT:
            raise ClassificationTagAssignMcpOAuthAcceptanceError(
                "Assignment MCP Tool surface is incomplete."
            )
        if preview_requested:
            assert preview_state_file is not None
            phase = "preview"
            reply = await session.call_tool(
                selected_tools[0],
                (
                    {}
                    if fixed_mode
                    else {
                        "target_name": target_name,
                        "classification_tag_name": classification_tag_name,
                    }
                ),
            )
            _validate_preview(
                reply.structured_content,
                target_name,
                classification_tag_name,
                reply.is_error,
                rollback=rollback,
                delete=delete,
            )
            assert isinstance(reply.structured_content, dict)
            _write_preview_state(
                preview_state_file,
                str(reply.structured_content["preview_ref"]),
                prefix=preview_prefix,
            )
            preview_verified = True
        if execute_preview_state_file is not None:
            phase = "confirmation"
            confirmation = await session.call_tool(
                selected_tools[1],
                {
                    "preview_ref": _read_preview_ref(
                        execute_preview_state_file,
                        prefix=preview_prefix,
                    )
                },
            )
            body = confirmation.structured_content
            authorization_ref = (
                body.get("authorization_ref") if isinstance(body, dict) else None
            )
            if (
                confirmation.is_error
                or not isinstance(body, dict)
                or not isinstance(authorization_ref, str)
                or not authorization_ref.startswith(authorization_prefix)
                or body.get("contract") != workflow
                or body.get("confirmation") != "recorded"
                or body.get("execution") != "authorized_once"
                or body.get("device_write_executed") is not False
            ):
                raise ClassificationTagAssignMcpOAuthAcceptanceError(
                    "Assignment MCP confirmation failed."
                )
            phase = "execution readback"
            reply = await session.call_tool(
                selected_tools[2],
                {"authorization_ref": authorization_ref},
            )
            _validate_execution(
                reply.structured_content,
                reply.is_error,
                rollback=rollback,
                delete=delete,
            )
            execute_preview_state_file.unlink()
            execution_verified = True

    try:
        common = await oauth.run_address_mcp_oauth_surface_acceptance(
            url,
            login_file,
            client_state_file,
            ca_file=ca_file,
            tool_session_callback=callback,
            required_tools=TOOLS,
        )
    except oauth.AddressMcpOAuthSurfaceAcceptanceError as exc:
        raise ClassificationTagAssignMcpOAuthAcceptanceError(str(exc)) from None
    except BaseExceptionGroup as exc:
        if _contains_acceptance_error(exc):
            raise ClassificationTagAssignMcpOAuthAcceptanceError(
                f"Assignment MCP {phase} failed."
            ) from None
        raise
    return {
        "contract": "fortipam_v4_classification_tag_assign_mcp_oauth_acceptance_v1",
        "oauth_metadata_verified": common["oauth_metadata_verified"],
        "mcp_initialized": common["mcp_initialized"],
        "classification_tag_assign_tool_surface_complete": True,
        "exact_tool_count_verified": True,
        "classification_tag_assign_direction": (
            "delete" if delete else ("rollback" if rollback else "forward")
        ),
        "classification_tag_assign_preview_verified": preview_verified,
        "classification_tag_assign_execution_verified": execution_verified,
        "device_tool_invoked": preview_verified or execution_verified,
        "device_write_executed": execution_verified,
        "token_revoked": common["token_revoked"],
        "credential_values_returned": common["credential_values_returned"],
        "token_returned": False,
        "client_id_returned": False,
    }


def _validate_preview(
    projection: Any,
    target_name: str | None,
    classification_tag_name: str | None,
    is_error: bool,
    *,
    rollback: bool = False,
    delete: bool = False,
) -> None:
    current = projection.get("Current State") if isinstance(projection, dict) else None
    proposed = projection.get("Proposed Changes") if isinstance(projection, dict) else None
    expected = projection.get("Expected State") if isinstance(projection, dict) else None
    preview_ref = projection.get("preview_ref") if isinstance(projection, dict) else None
    workflow = DELETE_WORKFLOW if delete else (ROLLBACK_WORKFLOW if rollback else FORWARD_WORKFLOW)
    preview_prefix = DELETE_PREVIEW_PREFIX if delete else (ROLLBACK_PREVIEW_PREFIX if rollback else FORWARD_PREVIEW_PREFIX)
    expected_current = (
        {
            "accepted_classification_tag_exists": True,
            "complete_api_record_digest_matches": True,
            "protected_target_class_is_other": True,
            "classification_tag_reference_count": 0,
            "selectors_returned": False,
            "read_transports": ["rest_api", "ssh_cli"],
        }
        if delete
        else
        {
            "target_exists": True,
            "classification_tag_exists": True,
            "target_class_matches_protected_tag": True,
            "target_or_tag_reference_returned": False,
            "write_transport": "rest_api",
        }
        if rollback
        else {
            "requested_target_name": target_name,
            "target_exists": True,
            "current_classification_tag_is_default": True,
            "requested_classification_tag_name": classification_tag_name,
            "classification_tag_exists": True,
            "write_transport": "rest_api",
        }
    )
    expected_proposed = (
        {
            "operation": "delete_exact_unreferenced_classification_tag_via_api",
            "classification_tag_count_affected": 1,
            "irreversible_after_execution": True,
            "target_write": False,
            "secret_folder_or_session_change": False,
        }
        if delete
        else
        {
            "operation": "restore_target_default_classification_via_api",
            "request_body": "fixed_class_only",
            "target_classification": "Other",
            "target_non_class_fields_changed": False,
            "classification_tag_changed": False,
            "secret_folder_ztna_or_session_changed": False,
        }
        if rollback
        else {
            "operation": "assign_classification_tag_to_target_via_api",
            "target_name": target_name,
            "classification_tag_name": classification_tag_name,
            "request_body": "fixed_class_only",
        }
    )
    expected_expected = (
        {
            "classification_tag_absent": True,
            "protected_target_exists": True,
            "protected_target_class_is_other": True,
            "protected_target_non_class_state_preserved": True,
            "classification_tag_reference_count": 0,
            "read_transports": ["rest_api", "ssh_cli"],
        }
        if delete
        else
        {
            "pre_action_state_restored": True,
            "target_classification_is_default": True,
            "target_non_class_state_preserved": True,
            "classification_tag_state_preserved": True,
            "target_or_tag_reference_returned": False,
            "readback_transport": "rest_api",
        }
        if rollback
        else {
            "target_exists": True,
            "classification_tag_exists": True,
            "target_class_matches": True,
            "target_non_class_state_preserved": True,
            "classification_tag_state_preserved": True,
            "readback_transport": "rest_api",
        }
    )
    if (
        is_error
        or not isinstance(current, dict)
        or not isinstance(proposed, dict)
        or not isinstance(expected, dict)
        or not isinstance(preview_ref, str)
        or not preview_ref.startswith(preview_prefix)
        or projection.get("contract") != workflow
        or projection.get("device_write_executed") is not False
        or current != expected_current
        or proposed != expected_proposed
        or expected != expected_expected
    ):
        raise ClassificationTagAssignMcpOAuthAcceptanceError(
            "Assignment C/P/E projection was invalid."
        )


def _validate_execution(
    result: Any,
    is_error: bool,
    *,
    rollback: bool = False,
    delete: bool = False,
) -> None:
    execution = DELETE_EXECUTION if delete else (ROLLBACK_EXECUTION if rollback else FORWARD_EXECUTION)
    if delete:
        if (
            is_error
            or not isinstance(result, dict)
            or result.get("contract") != execution
            or result.get("outcome") != "succeeded"
            or result.get("verification") != "verified"
            or result.get("idempotent_replay") is not False
            or result.get("compensation")
            != "separate_classification_tag_create_action_required"
            or any(
                result.get(key) is not False
                for key in (
                    "classification_tag_name_returned",
                    "target_name_returned",
                    "raw_api_response_returned",
                )
            )
        ):
            raise ClassificationTagAssignMcpOAuthAcceptanceError(
                "Classification Tag delete execution readback failed."
            )
        return
    if (
        is_error
        or not isinstance(result, dict)
        or result.get("contract") != execution
        or result.get("outcome") != "succeeded"
        or result.get("verification") != "verified"
        or result.get("idempotent_replay") is not False
        or (
            not rollback
            and result.get("compensation")
            != "separate_confirmed_target_classification_change_required"
        )
        or (rollback and result.get("pre_action_state_restored") is not True)
        or (rollback and result.get("target_classification_is_default") is not True)
        or (rollback and result.get("target_non_class_state_preserved") is not True)
        or (rollback and result.get("classification_tag_state_preserved") is not True)
        or any(
            result.get(key) is not False
            for key in (
                "target_name_returned",
                "classification_tag_name_returned",
                "target_payload_returned",
                "classification_tag_payload_returned",
                "raw_api_response_returned",
            )
        )
    ):
        raise ClassificationTagAssignMcpOAuthAcceptanceError(
            "Assignment MCP execution readback failed."
        )


def _contains_acceptance_error(error: BaseExceptionGroup) -> bool:
    return any(
        isinstance(item, ClassificationTagAssignMcpOAuthAcceptanceError)
        or (isinstance(item, BaseExceptionGroup) and _contains_acceptance_error(item))
        for item in error.exceptions
    )


def _write_preview_state(
    path: Path,
    preview_ref: str,
    *,
    prefix: str = FORWARD_PREVIEW_PREFIX,
) -> None:
    if (
        path.parent.is_symlink()
        or not path.parent.is_dir()
        or stat.S_IMODE(path.parent.stat().st_mode) & 0o077
        or path.exists()
        or path.is_symlink()
        or not preview_ref.startswith(prefix)
    ):
        raise ClassificationTagAssignMcpOAuthAcceptanceError(
            "Preview state reference is invalid."
        )
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, json.dumps({"preview_ref": preview_ref}).encode("utf-8"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    path.chmod(0o600)


def _read_preview_ref(
    path: Path,
    *,
    prefix: str = FORWARD_PREVIEW_PREFIX,
) -> str:
    if (
        path.is_symlink()
        or not path.is_file()
        or stat.S_IMODE(path.stat().st_mode) & 0o077
    ):
        raise ClassificationTagAssignMcpOAuthAcceptanceError(
            "Preview state file is invalid."
        )
    try:
        preview_ref = json.loads(path.read_text(encoding="utf-8")).get(
            "preview_ref"
        )
    except (OSError, json.JSONDecodeError, AttributeError) as exc:
        raise ClassificationTagAssignMcpOAuthAcceptanceError(
            "Preview state file is invalid."
        ) from exc
    if not isinstance(preview_ref, str) or not preview_ref.startswith(prefix):
        raise ClassificationTagAssignMcpOAuthAcceptanceError(
            "Preview state reference is invalid."
        )
    return preview_ref


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--login-file", type=Path, required=True)
    parser.add_argument("--client-state-file", type=Path, required=True)
    parser.add_argument("--target-name")
    parser.add_argument("--classification-tag-name")
    parser.add_argument("--preview-state-file", type=Path)
    parser.add_argument("--execute-preview-state-file", type=Path)
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--rollback", action="store_true")
    parser.add_argument("--delete", action="store_true")
    args = parser.parse_args()
    try:
        result = asyncio.run(
            run_classification_tag_assign_mcp_oauth_acceptance(
                args.url,
                args.login_file,
                args.client_state_file,
                target_name=args.target_name,
                classification_tag_name=args.classification_tag_name,
                preview_state_file=args.preview_state_file,
                execute_preview_state_file=args.execute_preview_state_file,
                ca_file=args.ca_file,
                rollback=args.rollback,
                delete=args.delete,
            )
        )
    except ClassificationTagAssignMcpOAuthAcceptanceError as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
