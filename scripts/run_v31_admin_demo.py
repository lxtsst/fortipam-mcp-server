#!/usr/bin/env python3
"""Run the repository-only V3.1 administrative LAB ADAPTER demonstration.

This command never contacts FortiPAM.  It exercises a deterministic in-memory
adapter so a reviewer can see the mandatory preview, exact confirmation-token
binding, pre-write re-read, and post-write comparison for five administrative
actions.  It is a demonstration surface, not an MCP Tool or product adapter.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
from typing import Mapping, Protocol, Sequence


JsonValue = None | bool | int | str | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject = dict[str, JsonValue]

LAB_ADAPTER = "LAB ADAPTER (deterministic in-memory simulation)"
CONFIRMATION_PREFIX = "CONFIRM-"


@dataclass(frozen=True, slots=True)
class ActionSpec:
    action_id: str
    title: str
    current: JsonObject
    proposed: JsonObject
    expected: JsonObject


@dataclass(frozen=True, slots=True)
class ActionPreview:
    action_id: str
    title: str
    current: JsonObject
    proposed: JsonObject
    expected: JsonObject

    def binding_content(self) -> JsonObject:
        return {
            "action_id": self.action_id,
            "adapter": LAB_ADAPTER,
            "current": deepcopy(self.current),
            "expected": deepcopy(self.expected),
            "proposed": deepcopy(self.proposed),
            "title": self.title,
        }

    @property
    def confirmation_token(self) -> str:
        encoded = json.dumps(
            self.binding_content(),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return f"{CONFIRMATION_PREFIX}{hashlib.sha256(encoded).hexdigest()[:16].upper()}"


class AdministrativeLabService(Protocol):
    """Minimal replaceable protocol for the repository-only demonstration."""

    def preview(self, action_id: str) -> ActionPreview: ...

    def reread_current(self, action_id: str) -> JsonObject: ...

    def execute(self, action_id: str) -> None: ...


ACTION_SPECS: Mapping[str, ActionSpec] = {
    "public-folder": ActionSpec(
        action_id="public-folder",
        title="Create Public Folder",
        current={"exists": False, "object_ref": "lab-folder-ref-01"},
        proposed={
            "change_kind": "create",
            "enabled": True,
            "folder_class": "public",
            "object_ref": "lab-folder-ref-01",
            "owner_ref": "lab-owner-ref-01",
        },
        expected={
            "enabled": True,
            "exists": True,
            "folder_class": "public",
            "object_ref": "lab-folder-ref-01",
            "owner_ref": "lab-owner-ref-01",
        },
    ),
    "target": ActionSpec(
        action_id="target",
        title="Create Target",
        current={"exists": False, "object_ref": "lab-target-ref-01"},
        proposed={
            "change_kind": "create",
            "connectivity_profile_ref": "lab-connectivity-profile-ref-01",
            "object_ref": "lab-target-ref-01",
            "protocol": "ssh",
        },
        expected={
            "connectivity_profile_ref": "lab-connectivity-profile-ref-01",
            "exists": True,
            "object_ref": "lab-target-ref-01",
            "protocol": "ssh",
        },
    ),
    "secret": ActionSpec(
        action_id="secret",
        title="Create Secret Metadata",
        current={"exists": False, "object_ref": "lab-secret-ref-01"},
        proposed={
            "account_class": "local",
            "change_kind": "create",
            "lifecycle_class": "managed",
            "material_lifecycle": "available",
            "material_provider_class": "external_vault_lease",
            "material_purpose": "initial_onboarding",
            "object_ref": "lab-secret-ref-01",
            "target_ref": "lab-target-ref-01",
        },
        expected={
            "account_class": "local",
            "exists": True,
            "lifecycle_class": "managed",
            "material_lifecycle": "available",
            "material_provider_class": "external_vault_lease",
            "material_purpose": "initial_onboarding",
            "object_ref": "lab-secret-ref-01",
            "target_ref": "lab-target-ref-01",
        },
    ),
    "local-user": ActionSpec(
        action_id="local-user",
        title="Create Local User",
        current={"exists": False, "object_ref": "lab-user-ref-01"},
        proposed={
            "change_kind": "create",
            "enabled": True,
            "object_ref": "lab-user-ref-01",
            "role_class": "standard_user",
        },
        expected={
            "enabled": True,
            "exists": True,
            "object_ref": "lab-user-ref-01",
            "role_class": "standard_user",
        },
    ),
    "folder-access-assignment": ActionSpec(
        action_id="folder-access-assignment",
        title="Assign Folder Access",
        current={"exists": False, "object_ref": "lab-folder-grant-ref-01"},
        proposed={
            "change_kind": "create",
            "folder_ref": "lab-folder-ref-01",
            "object_ref": "lab-folder-grant-ref-01",
            "permission": "use",
            "principal_ref": "lab-user-ref-01",
        },
        expected={
            "exists": True,
            "folder_ref": "lab-folder-ref-01",
            "object_ref": "lab-folder-grant-ref-01",
            "permission": "use",
            "principal_ref": "lab-user-ref-01",
        },
    ),
}


class InMemoryAdministrativeLabService:
    """Single-process LAB ADAPTER with no external I/O or credential access."""

    def __init__(self, specs: Mapping[str, ActionSpec]) -> None:
        self._specs = specs
        self._state = {key: deepcopy(spec.current) for key, spec in specs.items()}

    def preview(self, action_id: str) -> ActionPreview:
        spec = self._specs[action_id]
        return ActionPreview(
            action_id=spec.action_id,
            title=spec.title,
            current=deepcopy(self._state[action_id]),
            proposed=deepcopy(spec.proposed),
            expected=deepcopy(spec.expected),
        )

    def reread_current(self, action_id: str) -> JsonObject:
        return deepcopy(self._state[action_id])

    def execute(self, action_id: str) -> None:
        self._state[action_id] = deepcopy(self._specs[action_id].expected)

    def inject_safe_demo_drift(self, action_id: str) -> None:
        current = deepcopy(self._state[action_id])
        current["demo_drift_marker"] = "changed_after_preview"
        self._state[action_id] = current


def _json_dump(value: JsonObject) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)


def _preview_record(preview: ActionPreview) -> JsonObject:
    return {
        "action_id": preview.action_id,
        "adapter": LAB_ADAPTER,
        "confirmation_token": preview.confirmation_token,
        "confirmation_token_kind": "preview_binding_only_not_signature_or_approval",
        "current": deepcopy(preview.current),
        "expected": deepcopy(preview.expected),
        "fortipam_contacted": False,
        "proposed": deepcopy(preview.proposed),
        "title": preview.title,
    }


def _render_human_preview(preview: ActionPreview) -> None:
    print("=== FortiPAM V3.1 Administrative Lab Demo ===")
    print(f"Adapter: {LAB_ADAPTER}")
    print("Real FortiPAM contacted: NO")
    print("Credential material displayed: NO")
    print(f"Action: {preview.title} [{preview.action_id}]")
    print("\nCurrent State")
    print(_json_dump(preview.current))
    print("\nProposed Changes")
    print(_json_dump(preview.proposed))
    print("\nExpected State")
    print(_json_dump(preview.expected))
    print(f"\nConfirmation token: {preview.confirmation_token}")
    print("This token binds this preview only; it is not a signature, approval, or FortiPAM authorization.")


def _emit(record: JsonObject, output_format: str) -> None:
    if output_format == "json":
        print(json.dumps(record, ensure_ascii=False, sort_keys=True))
    else:
        status = record.get("status")
        if status == "preview_ready":
            return
        print(f"\nLab result: {status}")
        reason = record.get("reason")
        if reason is not None:
            print(f"Reason: {reason}")
        print("Real FortiPAM contacted: NO")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action", required=True, choices=tuple(ACTION_SPECS))
    parser.add_argument("--preview-only", action="store_true")
    parser.add_argument(
        "--yes",
        action="store_true",
        help="non-interactive acknowledgement; never bypasses the exact preview token",
    )
    parser.add_argument(
        "--confirm-token",
        help="exact token printed with the preview; required with --yes",
    )
    parser.add_argument("--format", choices=("human", "json"), default="human")
    parser.add_argument(
        "--simulate-drift",
        action="store_true",
        help="LAB-only denial demonstration: change in-memory Current State after preview",
    )
    return parser


def run(argv: Sequence[str] | None = None, *, service: AdministrativeLabService | None = None) -> int:
    args = _parser().parse_args(argv)
    lab_service = service or InMemoryAdministrativeLabService(ACTION_SPECS)
    preview = lab_service.preview(args.action)
    preview_record = _preview_record(preview)

    if args.format == "human":
        _render_human_preview(preview)

    if args.preview_only:
        preview_record["status"] = "preview_ready"
        _emit(preview_record, args.format)
        return 0

    supplied_token = args.confirm_token
    if args.yes and supplied_token is None:
        result = {
            **preview_record,
            "reason": "--yes cannot bypass the exact preview confirmation token",
            "status": "confirmation_denied",
        }
        _emit(result, args.format)
        return 2
    if supplied_token is None:
        try:
            supplied_token = input("Type the exact confirmation token to run the LAB ADAPTER: ").strip()
        except EOFError:
            supplied_token = ""
    if supplied_token != preview.confirmation_token:
        result = {
            **preview_record,
            "reason": "confirmation token does not match this exact preview",
            "status": "confirmation_denied",
        }
        _emit(result, args.format)
        return 2

    if args.simulate_drift:
        drift_injector = getattr(lab_service, "inject_safe_demo_drift", None)
        if not callable(drift_injector):
            result = {
                **preview_record,
                "reason": "selected LAB ADAPTER does not expose the safe drift fixture",
                "status": "demo_fixture_unavailable",
            }
            _emit(result, args.format)
            return 3
        drift_injector(args.action)

    reread = lab_service.reread_current(args.action)
    if reread != preview.current:
        result = {
            **preview_record,
            "actual_current": reread,
            "reason": "Current State changed after confirmation; preview token is invalidated",
            "status": "prewrite_drift_denied",
        }
        _emit(result, args.format)
        return 4

    lab_service.execute(args.action)
    actual = lab_service.reread_current(args.action)
    verified = actual == preview.expected
    result = {
        **preview_record,
        "actual": actual,
        "adapter_effect": "in_memory_lab_state_changed" if verified else "comparison_mismatch",
        "fortipam_contacted": False,
        "status": "lab_expected_state_verified" if verified else "lab_expected_state_mismatch",
    }
    _emit(result, args.format)
    return 0 if verified else 5


def main() -> int:
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
