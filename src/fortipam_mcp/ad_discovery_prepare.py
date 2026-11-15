"""Offline private bootstrap inputs for one fixed disabled AD Source intent."""

from collections.abc import Mapping
import json
import os
from pathlib import Path
import stat
import sys
import time

from v4_planning import SchemeDraft, SchemeId, scheme_draft_as_mapping
from v4_planning.models import require_ref

from .ad_discovery_projection_source import OUTCOME, ad_discovery_projection_contract
from .ad_discovery_runtime_config import load_ad_discovery_runtime_binding
from .linux_onboarding_prepare import (
    DRAFT_INPUT_NAME, REFERENCE_INPUT_NAME, _assert_owner_only, _desired,
    _new_ref, _reference_bindings, _write_private_json,
)


AD_DISCOVERY_PREPARE_PREFIX = "FORTIPAM_MCP_V4_AD_DISCOVERY_PREPARE_"
_UNAVAILABLE = "AD Discovery preparation is unavailable."


class AdDiscoveryPrepareError(RuntimeError):
    """Stable local denial without paths, private selectors or material."""


def _absolute_unaliased(path: Path) -> None:
    if (not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts
        or any(part.is_symlink() for part in (path, *path.parents))):
        raise ValueError


def prepare_ad_discovery_bundle(
    binding_path: Path, output_directory: Path, *, audience_ref: str,
    now_epoch: int, expires_at: int,
) -> dict[str, object]:
    """Write two bootstrap inputs, never authority state or an execution grant."""
    created: list[tuple[Path, int, int]] = []
    try:
        _absolute_unaliased(binding_path)
        _absolute_unaliased(output_directory)
        _assert_owner_only(output_directory, directory=True)
        if stat.S_IMODE(output_directory.lstat().st_mode) != 0o700:
            raise ValueError
        if (type(now_epoch) is not int or type(expires_at) is not int
            or not 0 <= now_epoch < expires_at < 2**31 - 1
            or expires_at - now_epoch > 300):
            raise ValueError
        require_ref(audience_ref, "AD preparation audience")
        binding = load_ad_discovery_runtime_binding(binding_path)
        draft = SchemeDraft(
            scheme_id=SchemeId.BULK_ONBOARDING, scheme_version="1.0.0",
            registry_schema_version="1.1.0", blueprint_ref="FPA-BP-014",
            environment_ref=binding.domain.environment_ref, scope_ref=binding.domain.scope_ref,
            owner_ref=_new_ref("owner", "bp014"), audience_ref=audience_ref,
            outcome_code=OUTCOME,
            desired_objects=tuple(_desired(ref, cls, fields)
                for ref, (cls, fields) in binding.expected_objects().items()),
            approval_class="independent_approval", separation_required=True, risk_class="medium",
            external_effects=("discovery_source_configuration_change",),
            assumption_codes=("private_binding_prevalidated",),
            excluded_scope_codes=("credential_material", "domain_secret_creation", "discovery_scan", "discovery_import"),
            verification_codes=("domain_dependency_readback", "disabled_source_readback"),
            stop_codes=("current_state_drift", "domain_dependency_unavailable"),
            evidence_policy="redacted_contract_evidence", maintenance_class="none",
            reversibility_class="manual_reconciliation_only",
            evidence_refs=(_new_ref("evidence", "bp014"),), unresolved_gap_codes=(),
            reconciliation_strategy="reconcile_or_manual", summary_ttl_seconds=300,
            material_reference_metadata=None,
        )
        bundle: dict[str, Mapping[str, object]] = {
            DRAFT_INPUT_NAME: {
                "draft": scheme_draft_as_mapping(draft), "expires_at": expires_at,
                "requester_digest": binding.domain.requester_digest,
            },
            REFERENCE_INPUT_NAME: {
                "references": _reference_bindings(draft, include_access_source=False,
                    projection_contract_resolver=ad_discovery_projection_contract),
                "requester_digest": binding.domain.requester_digest,
                "environment_ref": binding.domain.environment_ref,
                "scope_ref": binding.domain.scope_ref, "expires_at": expires_at,
            },
        }
        paths = {name: output_directory / name for name in bundle}
        if any(path.exists() or path.is_symlink() for path in paths.values()):
            raise ValueError
        for name, path in paths.items():
            _write_private_json(path, bundle[name])
            info = path.lstat()
            created.append((path, info.st_dev, info.st_ino))
        return {
            "status": "prepared", "blueprint_ref": "FPA-BP-014", "object_count": 5,
            "material_provider_used": False, "device_contacted": False,
            "execution_authorized": False,
        }
    except Exception:
        for path, device, inode in reversed(created):
            try:
                info = path.lstat()
                if info.st_dev == device and info.st_ino == inode:
                    path.unlink()
            except OSError:
                pass
        raise AdDiscoveryPrepareError(_UNAVAILABLE) from None


def main() -> None:
    try:
        prefix = AD_DISCOVERY_PREPARE_PREFIX
        result = prepare_ad_discovery_bundle(
            Path(os.environ[prefix + "BINDING_FILE"]),
            Path(os.environ[prefix + "OUTPUT_DIRECTORY"]),
            audience_ref=os.environ[prefix + "AUDIENCE_REF"], now_epoch=int(time.time()),
            expires_at=int(os.environ[prefix + "EXPIRES_AT"]),
        )
    except Exception:
        sys.stderr.write('{"status":"failed"}\n')
        raise SystemExit(1) from None
    sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()


__all__ = ["AD_DISCOVERY_PREPARE_PREFIX", "AdDiscoveryPrepareError", "prepare_ad_discovery_bundle"]
