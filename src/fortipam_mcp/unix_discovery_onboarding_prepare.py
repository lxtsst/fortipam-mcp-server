"""Private Unix Discovery selection handoff to the existing BP005 preparer."""

from __future__ import annotations

from collections.abc import Mapping
import json
import os
from pathlib import Path
import sys
from typing import Protocol

from v4_planning.material_provider import MaterialProviderClass

from .discovery_entry_create_contract import DisabledUnixDiscoveryCreateInput
from .discovery_review_http_transport import (
    SELECTION_CONTRACT,
    FortiPamDiscoveryReviewHttpTransport,
)
from .discovery_review_mcp_action import _load_review_binding
from .linux_onboarding_prepare import (
    LinuxOnboardingPrepareSettings,
    PROFILE_CONTRACT,
    PROFILE_VERSION,
    _load_profile,
    prepare_linux_onboarding_bundle,
    settings_from_environment,
)
from .secret_metadata_http_transport import load_secret_metadata_http_transport_config
from .unix_discovery_onboarding_guard import UnixDiscoveryOnboardingGuard


SELECTION_BINDING_FILE_ENV = (
    "FORTIPAM_MCP_V4_UNIX_DISCOVERY_ONBOARDING_SELECTION_BINDING_FILE"
)
_UNAVAILABLE = "Unix Discovery onboarding preparation is unavailable."


class UnixDiscoveryOnboardingPrepareError(RuntimeError):
    """Stable error without account, Secret, credential, or response values."""


class UnixSelectionReader(Protocol):
    def select(
        self, request: DisabledUnixDiscoveryCreateInput, selected_account: str,
    ) -> Mapping[str, object]: ...


def prepare_selected_unix_onboarding_bundle(
    *,
    selection_binding_path: Path,
    settings: LinuxOnboardingPrepareSettings,
    selection_reader: UnixSelectionReader,
    relation_guard: UnixDiscoveryOnboardingGuard | None = None,
) -> dict[str, object]:
    """Permit BP005 Draft preparation only for one exact unmanaged snapshot row.

    The CLI always supplies the relation guard; trusted historical fixture
    callers may omit it but then establish no Source/Target/material relation.
    The guarded runner must also enable its paired private settings to check
    account bytes at lease use. This function has no create or Import path.
    """

    try:
        if (
            not isinstance(selection_binding_path, Path)
            or not selection_binding_path.is_absolute()
            or not isinstance(settings, LinuxOnboardingPrepareSettings)
            or not callable(getattr(selection_reader, "select", None))
            or settings.material_provider_class
            is not MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE
        ):
            raise ValueError
        request, selected_account = _load_review_binding(selection_binding_path)
        if selected_account is None:
            raise ValueError
        decision = selection_reader.select(request, selected_account)
        if (
            not isinstance(decision, Mapping)
            or decision.get("contract") != SELECTION_CONTRACT
            or decision.get("source_exact") is not True
            or decision.get("scan_state") != "completed"
            or decision.get("selected_account_exact") is not True
            or decision.get("selected_account_unmanaged") is not True
            or decision.get("onboarding_decision") != "prepare_existing_onboarding"
            or decision.get("import_executed") is not False
            or decision.get("device_write_executed") is not False
            or decision.get("selected_account_name_returned") is not False
            or decision.get("credential_values_returned") is not False
            or decision.get("raw_api_response_returned") is not False
        ):
            raise ValueError
        profile = _load_profile(settings.profile_path)
        if (
            profile.get("contract") != PROFILE_CONTRACT
            or profile.get("version") != PROFILE_VERSION
            or profile.get("target_protocol") != "ssh"
            or profile.get("template_name") != "Unix Account (SSH Password)"
        ):
            raise ValueError
        if relation_guard is not None:
            if type(relation_guard) is not UnixDiscoveryOnboardingGuard:
                raise ValueError
            relation_guard.check_inputs(selection_binding_path=selection_binding_path, profile_path=settings.profile_path)
            relation_guard.observe()
        prepare_linux_onboarding_bundle(settings, expected_profile_digest=(
            relation_guard.profile_digest if relation_guard is not None else None))
        return {
            "status": "prepared",
            "selection_decision": "prepare_existing_onboarding",
            "decision_scope": "completed_scan_snapshot",
            "import_executed": False,
            "device_write_executed": False,
            "selected_account_name_returned": False,
            "credential_values_returned": False,
        }
    except Exception:
        raise UnixDiscoveryOnboardingPrepareError(_UNAVAILABLE) from None


def main() -> None:
    guard = None
    try:
        path = Path(os.environ[SELECTION_BINDING_FILE_ENV])
        if not path.is_absolute():
            raise ValueError
        settings = settings_from_environment(os.environ)
        config = load_secret_metadata_http_transport_config(os.environ)
        reader = FortiPamDiscoveryReviewHttpTransport(config)
        guard = UnixDiscoveryOnboardingGuard(config, selection_binding_path=path, profile_path=settings.profile_path)
        result = prepare_selected_unix_onboarding_bundle(
            selection_binding_path=path,
            settings=settings,
            selection_reader=reader,
            relation_guard=guard,
        )
    except Exception:
        sys.stderr.write('{"status":"failed"}\n')
        raise SystemExit(1) from None
    finally:
        if guard is not None: guard.close()
    sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()


__all__ = [
    "SELECTION_BINDING_FILE_ENV",
    "UnixDiscoveryOnboardingPrepareError",
    "UnixSelectionReader",
    "prepare_selected_unix_onboarding_bundle",
]
