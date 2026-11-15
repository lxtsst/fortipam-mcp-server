"""Conditional pinned-provider effects; no value review, permission or execution.

This private projection extends neither the synthetic receipt nor the MCP Tool.
Source facts describe the reference revision, not the binary used by an input.
Opaque expressions, state values and material are never deserialized or returned.
"""
from __future__ import annotations

from dataclasses import dataclass

from v4_planning.material_provider import _OpaqueC3Object

from . import secret_bulk_import_metadata as metadata
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable
from .terraform_plan_configuration import (
    TerraformConfigurationProjection, _CALL, _RESOURCE as _CONFIG_RESOURCE, _items,
    project_private_terraform_configuration,
)
from .terraform_plan_projection import (
    _ACTIONS, _CATEGORIES, _CHANGE, _DATA, _FOLDER, _PROVIDER, _RESOURCE, _SECRET,
    _TOP, Span, _action, _equals, _object,
)

CONTRACT = "fortipam-terraform-reference-provider-effects-private-v1"
REFERENCE_COMMIT = "f502400a020d12091b32e4ccce9aff0b2025034b"
_KINDS = ("folder", "managed_secret", "secret_data")
_STATE_RESOURCE = frozenset({"address", "mode", "type", "name", "index", "provider_name",
    "schema_version", "values", "sensitive_values", "depends_on", "deposed"})
_ERROR = "The private Terraform provider-effect projection is unavailable."


class TerraformProviderEffectError(ValueError):
    """Fixed denial with no partial projection, source values or locators."""


def _kind(content: bytearray, fields: dict[str, Span]) -> int:
    if _equals(content, fields["mode"], b'"managed"'):
        if _equals(content, fields["type"], _FOLDER):
            return 0
        if _equals(content, fields["type"], _SECRET):
            return 1
    elif _equals(content, fields["mode"], b'"data"') and _equals(content, fields["type"], _DATA):
        return 2
    raise ValueError


def _changes(content: bytearray, span: Span) -> tuple[tuple[tuple[int, ...], ...], int]:
    counts = [[0] * len(_ACTIONS) for _ in _KINDS]
    imports = 0
    for item in metadata._array(content, span, 4096):
        fields = _object(content, item, _RESOURCE)
        kind = _kind(content, fields)
        change = _object(content, fields["change"], _CHANGE)
        counts[kind][_action(content, change["actions"])] += 1
        if "importing" in change and not _equals(content, change["importing"], b"null"):
            imports += 1
    return tuple(tuple(row) for row in counts), imports


class _Inventory:
    def __init__(self) -> None:
        self.configured = [0, 0, 0]
        self.state = [0, 0, 0]
        self.modules = self.resources = 0

    def module(self, content: bytearray, span: Span, *, configured: bool, depth: int = 0) -> None:
        self.modules += 1
        if depth > 8 or self.modules > 384:
            raise ValueError
        # Configuration has already passed the complete structural validator.
        allowed = (frozenset({"resources", "module_calls", "variables", "outputs", "actions"})
            if configured else frozenset({"resources", "child_modules", "address"}))
        fields = _object(content, span, allowed)
        if "resources" in fields:
            for item in metadata._array(content, fields["resources"], 4096):
                self.resources += 1
                if self.resources > 12288:
                    raise ValueError
                if configured:
                    # Keys were checked by the configuration projection.
                    resource = _object(content, item, _CONFIG_RESOURCE)
                else:
                    resource = _object(content, item, _STATE_RESOURCE)
                    if not {"address", "mode", "type", "name", "provider_name", "values", "schema_version"} <= resource.keys():
                        raise ValueError
                    if not _equals(content, resource["provider_name"], _PROVIDER):
                        raise ValueError
                    if not _equals(content, resource["schema_version"], b"0"):
                        raise ValueError
                counts = self.configured if configured else self.state
                counts[_kind(content, resource)] += 1
        if configured and "module_calls" in fields:
            for _, item in _items(content, fields["module_calls"]):
                call = _object(content, item, _CALL)
                self.module(content, call["module"], configured=True, depth=depth + 1)
        elif not configured and "child_modules" in fields:
            for item in metadata._array(content, fields["child_modules"], 128):
                self.module(content, item, configured=False, depth=depth + 1)

    def values(self, content: bytearray, span: Span) -> None:
        fields = _object(content, span, frozenset({"outputs", "root_module"}))
        if "root_module" in fields:
            self.module(content, fields["root_module"], configured=False)


@dataclass(frozen=True, slots=True, repr=False)
class TerraformProviderEffectProjection(_OpaqueC3Object):
    configuration: TerraformConfigurationProjection
    configured_counts: tuple[int, ...]
    state_counts: tuple[int, ...]
    change_counts: tuple[tuple[int, ...], ...]
    drift_counts: tuple[tuple[int, ...], ...]
    importing_entries: int

    def summary(self) -> dict[str, object]:
        result = self.configuration.summary()
        effects = {"provider_configures_bearer_authentication", "provider_default_tls_verification_disabled",
            "provider_http_timeout_and_ancestor_cycle_bound_absent", "base_url_scheme_not_validated",
            "provider_token_schema_not_sensitive", "provider_response_body_read_unbounded"}
        requirements = set()
        folder = self.configured_counts[0] + self.state_counts[0] + sum(self.change_counts[0])
        secret = self.configured_counts[1] + self.state_counts[1] + sum(self.change_counts[1])
        data = self.configured_counts[2] + self.state_counts[2] + sum(self.change_counts[2])
        if folder or secret or data:
            effects.add("refresh_or_import_can_read_before_apply")
            effects.add("query_errors_can_collapse_to_missing_object")
            requirements.add("object_scoped_query_and_ancestor_traversal")
        if folder or secret:
            effects.add("managed_resource_read_discards_helper_error")
            requirements.add("independent_query_denial_evidence_not_plan_success")
        if secret or data:
            effects.add("credential_values_can_enter_state_and_plan")
            requirements.add("credential_read_permission_requires_separate_qualification")
        if any(self.change_counts[0][i] for i in (1, 2, 5, 6, 8, 9)):
            effects.add("folder_write_enables_inheritance_and_sends_empty_acl_arrays")
            requirements.add("folder_write_and_inheritance_acl_effect_scope")
            requirements.add("root_folder_creation_requires_distinct_scope")
        if any(self.change_counts[1][i] for i in (2, 5, 6, 8, 9)):
            effects.add("secret_update_disables_av_dlp_ssh_and_rdp_filters")
            effects.add("secret_update_does_not_preserve_complete_configuration")
        if any(self.change_counts[1][i] for i in (1, 2, 5, 6, 8, 9)):
            effects.add("invalid_secret_field_pair_may_be_logged")
            requirements.add("secret_write_and_post_write_credential_read")
        if any(row[i] for row in self.change_counts for i in (3, 5, 6, 7, 8, 9)):
            effects.add("delete_replace_or_forget_requires_distinct_recovery_assessment")
            requirements.add("delete_or_state_removal_scope_and_ownership")
        if self.importing_entries:
            effects.add("import_reads_existing_object_without_creation_ownership")
        if any(self.configuration.provisioner_counts):
            effects.add("provisioner_commands_or_file_transfers_excluded")
        result.update(effect_contract=CONTRACT, reference_provider_commit=REFERENCE_COMMIT,
            reference_effect_scope="conditional_source_model_only",
            reference_provider_matches_input_binary_verified=False,
            configured_kind_entry_counts=dict(zip(_KINDS, self.configured_counts, strict=True)),
            state_kind_entry_counts=dict(zip(_KINDS, self.state_counts, strict=True)),
            change_kind_action_entry_counts={kind: dict(zip(_CATEGORIES, row, strict=True))
                for kind, row in zip(_KINDS, self.change_counts, strict=True)},
            drift_kind_action_entry_counts={kind: dict(zip(_CATEGORIES, row, strict=True))
                for kind, row in zip(_KINDS, self.drift_counts, strict=True)},
            importing_entries=self.importing_entries, conditional_provider_effects=sorted(effects),
            permission_requirements_to_qualify=sorted(requirements),
            actual_values_and_effects_reviewed=False, actual_permission_evidence_verified=False)
        return result


def project_private_terraform_provider_effects(content: bytearray) -> TerraformProviderEffectProjection:
    """Consume and wipe input; classify source effects without reading a device."""
    duplicate = bytearray()
    try:
        if type(content) is not bytearray or not 0 < len(content) <= 2 * 1024 * 1024:
            raise ValueError
        duplicate = bytearray(content)
        configuration = project_private_terraform_configuration(duplicate)
        left = _skip_json_space(content, 0)
        fields = _object(content, (left, _json_value_end(content, left)), _TOP)
        config = _object(content, fields["configuration"], frozenset({"provider_config", "root_module"}))
        inventory = _Inventory()
        inventory.module(content, config["root_module"], configured=True)
        if "planned_values" in fields:
            inventory.values(content, fields["planned_values"])
        if "prior_state" in fields:
            prior = _object(content, fields["prior_state"], frozenset({"format_version", "terraform_version", "values"}))
            inventory.values(content, prior["values"])
        empty = tuple((0,) * len(_ACTIONS) for _ in _KINDS)
        changes, imports = _changes(content, fields["resource_changes"]) if "resource_changes" in fields else (empty, 0)
        drift, drift_imports = _changes(content, fields["resource_drift"]) if "resource_drift" in fields else (empty, 0)
        return TerraformProviderEffectProjection(configuration, tuple(inventory.configured), tuple(inventory.state),
            changes, drift, imports + drift_imports)
    except Exception:
        raise TerraformProviderEffectError(_ERROR) from None
    finally:
        if type(content) is bytearray:
            _zeroize_mutable(content)
        _zeroize_mutable(duplicate)
