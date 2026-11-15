"""Prepare one private Secret onboarding bundle without issuing authority state."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
import ipaddress
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
from typing import Mapping, cast
from urllib.parse import urlsplit

from v4_planning import (
    DesiredObject,
    FieldKind,
    MaterialReferenceMetadata,
    ObjectClass,
    ProjectionContract,
    SchemeDraft,
    SchemeId,
    scheme_draft_as_mapping,
)
from v4_planning.canonical import canonical_json
from v4_planning.models import require_digest, require_ref
from v4_planning.material_provider import MaterialProviderClass

from .access_domain_projection_source import (
    AccessDomainFolderBinding,
    BoundAclRelation,
    SOURCE_CONTRACT as ACCESS_SOURCE_CONTRACT,
    SOURCE_REF as ACCESS_SOURCE_REF,
    SOURCE_VERSION as ACCESS_SOURCE_VERSION,
    access_domain_projection_contract,
)
from .secret_metadata_http_transport import secret_session_controls_event_filter_profile_digest
from .rdp_event_filter_ssh_transport import RDP_EVENT_FILTER_NAME_PREFIX
from .secret_onboarding_projection_source import (
    SOURCE_CONTRACT as SECRET_SOURCE_CONTRACT,
    SOURCE_REF as SECRET_SOURCE_REF,
    SOURCE_VERSION as SECRET_SOURCE_VERSION,
    SECRET_SESSION_CONTROLS_BINDING_VERSION,
    SecretOnboardingBinding,
    WebSecretOnboardingBinding,
    secret_onboarding_projection_contract,
)


from .secret_create_191_private_adapter import SecretCreate700WinrmBinding
from .winrm_collector_projection_reader import winrm_collector_projection_contract

COLLECTOR_BINDING_NAME = "winrm-collector-binding.json"
COLLECTOR_PROFILE_VERSION = "1.3.0"

PROFILE_PATH_ENV = "FORTIPAM_MCP_V4_LINUX_ONBOARDING_PROFILE"
OUTPUT_DIRECTORY_ENV = "FORTIPAM_MCP_V4_LINUX_ONBOARDING_OUTPUT_DIR"
SECRET_PROFILE_PATH_ENV = "FORTIPAM_MCP_V4_SECRET_ONBOARDING_PROFILE"
SECRET_OUTPUT_DIRECTORY_ENV = "FORTIPAM_MCP_V4_SECRET_ONBOARDING_OUTPUT_DIR"
MATERIAL_PROVIDER_CLASS_ENV = (
    "FORTIPAM_MCP_V4_SECRET_ONBOARDING_MATERIAL_PROVIDER_CLASS"
)
MCP_PUBLIC_URL_ENV = "FORTIPAM_MCP_HTTP_PUBLIC_URL"
PROFILE_CONTRACT = "fortipam-linux-onboarding-private-profile-v1"
PROFILE_VERSION = "1.0.0"
SECRET_PROFILE_CONTRACT = "fortipam-secret-onboarding-private-profile-v1"
SECRET_PROFILE_VERSION = "1.0.0"
SECRET_REUSE_PROFILE_VERSION = "1.2.0"
ACCESS_BINDING_NAME = "access-domain-binding.json"
SECRET_BINDING_NAME = "secret-onboarding-binding.json"
DRAFT_INPUT_NAME = "scheme-draft-bootstrap-input.json"
REFERENCE_INPUT_NAME = "reference-bootstrap-input.json"
_MAX_PROFILE_BYTES = 32_768
_PRODUCT_PERMISSIONS = {"view", "edit", "owner", "add-secret"}
_BP005_PROFILE_FIELDS = {
    "contract",
    "version",
    "requester_digest",
    "environment_ref",
    "scope_ref",
    "expires_at",
    "folder_name",
    "folder_path",
    "parent_folder_id",
    "owner_principal_name",
    "owner_subject_class",
    "acl_relations",
    "target_name",
    "target_protocol",
    "target_ipv4_address",
    "template_name",
    "secret_name",
    "launcher_name",
}
_SECRET_PROFILE_COMMON_FIELDS = {
    "contract",
    "version",
    "blueprint_ref",
    "requester_digest",
    "environment_ref",
    "scope_ref",
    "expires_at",
    "folder_path",
    "secret_name",
}


class LinuxOnboardingPrepareError(RuntimeError):
    """Stable failure for the private BP005 preparation boundary."""


@dataclass(frozen=True, slots=True)
class LinuxOnboardingPrepareSettings:
    profile_path: Path
    output_directory: Path
    material_provider_class: MaterialProviderClass = (
        MaterialProviderClass.EXTERNAL_VAULT_LEASE
    )
    mcp_public_url: str | None = None

    def __post_init__(self) -> None:
        if (
            not self.profile_path.is_absolute()
            or not self.output_directory.is_absolute()
            or self.profile_path == self.output_directory
            or not isinstance(self.material_provider_class, MaterialProviderClass)
            or (
                self.mcp_public_url is not None
                and not isinstance(self.mcp_public_url, str)
            )
        ):
            raise LinuxOnboardingPrepareError(
                "Linux onboarding preparation configuration is invalid."
            )


def settings_from_environment(
    environment: Mapping[str, str],
) -> LinuxOnboardingPrepareSettings:
    """Load exactly one legacy or shared private path pair."""

    legacy = (
        _environment_value(environment, PROFILE_PATH_ENV),
        _environment_value(environment, OUTPUT_DIRECTORY_ENV),
    )
    shared = (
        _environment_value(environment, SECRET_PROFILE_PATH_ENV),
        _environment_value(environment, SECRET_OUTPUT_DIRECTORY_ENV),
    )
    complete = [pair for pair in (legacy, shared) if all(pair)]
    configured_values = sum(
        value is not None for pair in (legacy, shared) for value in pair
    )
    if len(complete) != 1 or configured_values != 2:
        raise LinuxOnboardingPrepareError(
            "Linux onboarding preparation configuration is incomplete."
        )
    profile, output = complete[0]
    assert profile is not None and output is not None
    return LinuxOnboardingPrepareSettings(
        Path(profile).expanduser(),
        Path(output).expanduser(),
        _material_provider_class_from_environment(environment),
        _optional_mcp_public_url(environment),
    )


def prepare_linux_onboarding_bundle(
    settings: LinuxOnboardingPrepareSettings,
    *, expected_profile_digest: str | None = None,
) -> None:
    """Write the owner-only bundle, optionally pinning its qualified profile.

    The digest checks the exact effective metadata consumed by the builder;
    it supplies no source, material, intent or execution authorization.
    """

    if not isinstance(settings, LinuxOnboardingPrepareSettings):
        raise LinuxOnboardingPrepareError(
            "Linux onboarding preparation configuration is invalid."
        )
    _assert_owner_only(settings.profile_path.parent, directory=True)
    _assert_owner_only(settings.profile_path, directory=False)
    _assert_owner_only(settings.output_directory, directory=True)
    profile = _load_profile(settings.profile_path)
    if expected_profile_digest is not None and (
            type(expected_profile_digest) is not str
            or hashlib.sha256(canonical_json(profile).encode()).hexdigest() != expected_profile_digest):
        raise LinuxOnboardingPrepareError("Linux onboarding preparation input changed.")
    bundle = _build_bundle(
        profile,
        settings.material_provider_class,
        mcp_public_url=settings.mcp_public_url,
    )
    allowed_names = {
        ACCESS_BINDING_NAME,
        SECRET_BINDING_NAME,
        DRAFT_INPUT_NAME,
        REFERENCE_INPUT_NAME,
        COLLECTOR_BINDING_NAME,
    }
    if frozenset(bundle) not in {
        frozenset(allowed_names - {COLLECTOR_BINDING_NAME}),
        frozenset(allowed_names - {ACCESS_BINDING_NAME, COLLECTOR_BINDING_NAME}),
        frozenset(allowed_names - {ACCESS_BINDING_NAME}),
    }:
        raise LinuxOnboardingPrepareError(
            "Linux onboarding preparation output is unavailable."
        )
    paths = {name: settings.output_directory / name for name in bundle}
    reserved_paths = (
        settings.output_directory / name for name in allowed_names
    )
    if any(path.exists() or path.is_symlink() for path in reserved_paths):
        raise LinuxOnboardingPrepareError(
            "Linux onboarding preparation output is unavailable."
        )
    created: list[Path] = []
    try:
        for name, path in paths.items():
            _write_private_json(path, bundle[name])
            created.append(path)
    except LinuxOnboardingPrepareError:
        for path in created:
            try:
                path.unlink()
            except OSError:
                pass
        raise


def _build_bundle(
    profile: Mapping[str, object],
    material_provider_class: MaterialProviderClass,
    *,
    mcp_public_url: str | None,
) -> dict[str, dict[str, object]]:
    if profile.get("contract") == SECRET_PROFILE_CONTRACT:
        return _build_secret_profile_bundle(
            profile,
            material_provider_class,
            mcp_public_url=mcp_public_url,
        )
    return _build_bp005_bundle(profile, material_provider_class)


def _build_bp005_bundle(
    profile: Mapping[str, object],
    material_provider_class: MaterialProviderClass,
) -> dict[str, dict[str, object]]:
    if (
        set(profile) != _BP005_PROFILE_FIELDS
        or profile.get("contract") != PROFILE_CONTRACT
        or profile.get("version") != PROFILE_VERSION
    ):
        raise LinuxOnboardingPrepareError(
            "Linux onboarding preparation input is invalid."
        )
    requester_digest = _digest(profile, "requester_digest")
    environment_ref = _ref(profile, "environment_ref")
    scope_ref = _ref(profile, "scope_ref")
    expires_at = _integer(profile, "expires_at")
    if expires_at <= 0:
        raise LinuxOnboardingPrepareError(
            "Linux onboarding preparation input is invalid."
        )

    folder_name = _selector(profile, "folder_name")
    folder_path = _selector(profile, "folder_path")
    parent_folder_id = _integer(profile, "parent_folder_id")
    owner_name = _selector(profile, "owner_principal_name")
    owner_class = _string(profile, "owner_subject_class")
    if (
        owner_class not in {"user", "group"}
        or not 0 <= parent_folder_id <= 2_147_483_647
        or folder_path.rstrip("/").rsplit("/", 1)[-1] != folder_name
    ):
        raise LinuxOnboardingPrepareError(
            "Linux onboarding preparation input is invalid."
        )
    protocol = _string(profile, "target_protocol")
    if protocol not in {"ssh", "sftp"}:
        raise LinuxOnboardingPrepareError(
            "Linux onboarding preparation input is invalid."
        )
    target_name = _selector(profile, "target_name")
    target_address = _string(profile, "target_ipv4_address")
    try:
        if str(ipaddress.IPv4Address(target_address)) != target_address:
            raise ValueError
    except (ipaddress.AddressValueError, ValueError):
        raise LinuxOnboardingPrepareError(
            "Linux onboarding preparation input is invalid."
        ) from None
    template_name = _selector(profile, "template_name")
    secret_name = _selector(profile, "secret_name")
    launcher_name = profile.get("launcher_name")
    if launcher_name is not None:
        if type(launcher_name) is not str:
            raise LinuxOnboardingPrepareError(
                "Linux onboarding preparation input is invalid."
            )
        launcher_name = _selector(profile, "launcher_name")

    owner_ref = _new_ref("owner")
    audience_ref = _new_ref("audience")
    evidence_ref = _new_ref("evidence")
    folder_ref = _new_ref("folder")
    folder_binding_ref = _new_ref("folder-binding")
    target_ref = _new_ref("target")
    connectivity_ref = _new_ref("connectivity")
    template_object_ref = _new_ref("template-binding")
    template_ref = _new_ref("template")
    secret_ref = _new_ref("secret")
    launcher_object_ref = _new_ref("launcher-binding") if launcher_name else None
    launcher_profile_ref = _new_ref("launcher") if launcher_name else None

    raw_relations = profile.get("acl_relations")
    if type(raw_relations) is not list or not 1 <= len(raw_relations) <= 12:
        raise LinuxOnboardingPrepareError(
            "Linux onboarding preparation input is invalid."
        )
    acl_bindings: list[BoundAclRelation] = []
    grant_objects: list[DesiredObject] = []
    seen_principals: set[tuple[str, str]] = set()
    for raw in cast(list[object], raw_relations):
        if type(raw) is not dict or set(raw) != {
            "principal_name",
            "subject_class",
            "permission",
            "folder_permission",
            "secret_permission",
        }:
            raise LinuxOnboardingPrepareError(
                "Linux onboarding preparation input is invalid."
            )
        relation = cast(dict[str, object], raw)
        principal_name = _selector(relation, "principal_name")
        subject_class = _string(relation, "subject_class")
        permission = _string(relation, "permission")
        folder_permission = _string(relation, "folder_permission")
        secret_permission = _string(relation, "secret_permission")
        if (
            subject_class not in {"user", "group", "role"}
            or permission not in {"use", "manage"}
            or folder_permission not in _PRODUCT_PERMISSIONS
            or secret_permission not in _PRODUCT_PERMISSIONS - {"add-secret"}
        ):
            raise LinuxOnboardingPrepareError(
                "Linux onboarding preparation input is invalid."
            )
        principal_key = (subject_class, principal_name)
        if principal_key in seen_principals or principal_key == (
            owner_class,
            owner_name,
        ):
            raise LinuxOnboardingPrepareError(
                "Linux onboarding preparation input is invalid."
            )
        seen_principals.add(principal_key)
        object_ref = _new_ref("grant")
        subject_ref = _new_ref("subject")
        acl_bindings.append(
            BoundAclRelation(
                object_ref,
                subject_ref,
                subject_class,
                principal_name,
                permission,
                folder_permission,
                secret_permission,
            )
        )
        grant_objects.append(
            _desired(
                object_ref,
                ObjectClass.ACCESS_GRANT,
                {
                    "permission": permission,
                    "subject_class": subject_class,
                    "subject_ref": subject_ref,
                },
            )
        )

    access_binding = AccessDomainFolderBinding(
        folder_ref,
        folder_name,
        parent_folder_id,
        owner_ref,
        owner_name,
        owner_class,
        tuple(acl_bindings),
    )
    secret_binding = SecretOnboardingBinding(
        folder_binding_ref,
        folder_path,
        folder_ref,
        target_ref,
        target_name,
        protocol,
        connectivity_ref,
        target_address,
        template_object_ref,
        template_name,
        template_ref,
        secret_ref,
        secret_name,
        launcher_object_ref,
        cast(str | None, launcher_name),
        launcher_profile_ref,
    )
    desired_objects = [
        _desired(
            folder_ref,
            ObjectClass.PUBLIC_FOLDER,
            {"enabled": True, "owner_ref": owner_ref},
        ),
        *grant_objects,
        _desired(
            folder_binding_ref,
            ObjectClass.FOLDER_BINDING,
            {"folder_ref": folder_ref},
        ),
        _desired(
            target_ref,
            ObjectClass.TARGET,
            {"connectivity_profile_ref": connectivity_ref, "protocol": protocol},
        ),
        _desired(
            template_object_ref,
            ObjectClass.TEMPLATE_BINDING,
            {"compatibility": "compatible", "template_ref": template_ref},
        ),
        _desired(
            secret_ref,
            ObjectClass.SECRET_METADATA,
            {"inherit_permission": True},
        ),
    ]
    if launcher_object_ref is not None and launcher_profile_ref is not None:
        desired_objects.append(
            _desired(
                launcher_object_ref,
                ObjectClass.LAUNCHER_BINDING,
                {"launcher_profile_ref": launcher_profile_ref},
            )
        )
    draft = SchemeDraft(
        scheme_id=SchemeId.SECRET_ONBOARDING,
        scheme_version="1.0.0",
        registry_schema_version="1.1.0",
        blueprint_ref="FPA-BP-005",
        environment_ref=environment_ref,
        scope_ref=scope_ref,
        owner_ref=owner_ref,
        audience_ref=audience_ref,
        outcome_code="onboard_privileged_resource",
        desired_objects=tuple(desired_objects),
        approval_class="independent_approval",
        separation_required=True,
        risk_class="high",
        external_effects=("access_scope_change", "privileged_access_metadata_change"),
        assumption_codes=("private_binding_prevalidated",),
        excluded_scope_codes=("credential_material", "session_launch"),
        verification_codes=("acl_relation_readback", "association_readback"),
        stop_codes=("current_state_drift", "material_unavailable"),
        evidence_policy="redacted_contract_evidence",
        maintenance_class="maintenance_window_required",
        reversibility_class="manual_reconciliation_only",
        evidence_refs=(evidence_ref,),
        unresolved_gap_codes=(),
        reconciliation_strategy="reconcile_or_manual",
        summary_ttl_seconds=300,
        material_reference_metadata=MaterialReferenceMetadata(
            provider_class=material_provider_class.value,
            purpose="initial_onboarding",
            lifecycle="available",
        ),
    )
    access_mapping: dict[str, object] = {
        "contract": ACCESS_SOURCE_CONTRACT,
        "version": ACCESS_SOURCE_VERSION,
        "requester_digest": requester_digest,
        "environment_ref": environment_ref,
        "scope_ref": scope_ref,
        **asdict(access_binding),
    }
    secret_mapping: dict[str, object] = {
        "contract": SECRET_SOURCE_CONTRACT,
        "version": SECRET_SOURCE_VERSION,
        "requester_digest": requester_digest,
        "environment_ref": environment_ref,
        "scope_ref": scope_ref,
        **asdict(secret_binding),
    }
    secret_mapping.pop("secret_session_controls_object_ref")
    secret_mapping.pop("existing_secret_id")
    secret_mapping.pop("session_controls_identity_digest")
    draft_mapping = scheme_draft_as_mapping(draft)
    return {
        ACCESS_BINDING_NAME: access_mapping,
        SECRET_BINDING_NAME: secret_mapping,
        DRAFT_INPUT_NAME: {
            "draft": draft_mapping,
            "expires_at": expires_at,
            "requester_digest": requester_digest,
        },
        REFERENCE_INPUT_NAME: {
            "references": _reference_bindings(draft),
            "requester_digest": requester_digest,
            "environment_ref": environment_ref,
            "scope_ref": scope_ref,
            "expires_at": expires_at,
        },
    }


def _build_secret_profile_bundle(
    profile: Mapping[str, object],
    material_provider_class: MaterialProviderClass,
    *,
    mcp_public_url: str | None,
) -> dict[str, dict[str, object]]:
    blueprint_ref = profile.get("blueprint_ref")
    if profile.get("version") == COLLECTOR_PROFILE_VERSION and blueprint_ref == "FPA-BP-006":
        return _build_bp006_collector_bundle(profile, material_provider_class)
    if (
        profile.get("version") == SECRET_REUSE_PROFILE_VERSION
        and blueprint_ref == "FPA-BP-006"
    ):
        return _build_bp006_existing_controls_bundle(profile, material_provider_class)
    if (
        profile.get("version") == SECRET_REUSE_PROFILE_VERSION
        and blueprint_ref == "FPA-BP-007"
        and profile.get("mode") == "existing_web_service"
    ):
        return _build_bp007_bundle(profile, material_provider_class, mcp_public_url=mcp_public_url)
    if (
        profile.get("version") != SECRET_PROFILE_VERSION
        or blueprint_ref not in {"FPA-BP-005", "FPA-BP-006", "FPA-BP-007"}
    ):
        raise LinuxOnboardingPrepareError(
            "Linux onboarding preparation input is invalid."
        )
    if blueprint_ref == "FPA-BP-005":
        if set(profile) != _BP005_PROFILE_FIELDS | {"blueprint_ref"}:
            raise LinuxOnboardingPrepareError(
                "Linux onboarding preparation input is invalid."
            )
        legacy = dict(profile)
        legacy.pop("blueprint_ref")
        legacy["contract"] = PROFILE_CONTRACT
        legacy["version"] = PROFILE_VERSION
        return _build_bp005_bundle(legacy, material_provider_class)
    if blueprint_ref == "FPA-BP-006":
        return _build_bp006_bundle(profile, material_provider_class)
    return _build_bp007_bundle(
        profile,
        material_provider_class,
        mcp_public_url=mcp_public_url,
    )


def _build_bp006_collector_bundle(
    profile: Mapping[str, object], material_provider_class: MaterialProviderClass,
) -> dict[str, dict[str, object]]:
    if (set(profile) != _SECRET_PROFILE_COMMON_FIELDS | {
        "workflow_variant", "target_name", "target_ipv4_address", "template_name",
        "folder_owner_name", "witness_folder_path", "witness_secret_name",
        "rdp_event_filter_profile_name",
    } or profile.get("workflow_variant") != "winrm_collector"):
        raise LinuxOnboardingPrepareError("Collector preparation input is invalid.")
    requester, environment, scope, expires = _secret_profile_context(profile)
    refs = _secret_refs("bp006-winrm")
    private = SecretCreate700WinrmBinding(
        "fortipam-700-build29-winrm-collector-create-candidate-v2", "7.0.0", "0" * 64,
        _selector(profile, "folder_path"), _selector(profile, "secret_name"),
        _selector(profile, "template_name"), _selector(profile, "target_name"),
        _ipv4(profile, "target_ipv4_address"), _selector(profile, "folder_owner_name"),
        _selector(profile, "witness_folder_path"), _selector(profile, "witness_secret_name"),
        _selector(profile, "rdp_event_filter_profile_name"),
    )
    binding = SecretOnboardingBinding(
        refs["folder_object"], private.folder_path, refs["folder"],
        refs["target_object"], private.target_name, "rdp", refs["connectivity"], private.target_ipv4_address,
        refs["template_object"], private.template_name, refs["template"], refs["secret_object"], private.secret_name,
    )
    desired = [
        _desired(refs["folder_object"], ObjectClass.FOLDER_BINDING, {"folder_ref": refs["folder"]}),
        _desired(refs["target_object"], ObjectClass.TARGET, {"protocol": "rdp", "connectivity_profile_ref": refs["connectivity"]}),
        _desired(refs["template_object"], ObjectClass.TEMPLATE_BINDING, {"compatibility": "compatible", "template_ref": refs["template"]}),
        _desired(refs["secret_object"], ObjectClass.WINRM_COLLECTOR_METADATA, {
            "inherit_permission": True, "privileged_account": True, "owner_only_folder": True,
            "rdp_service_enabled": True, "recording_enabled": True,
            "rdp_event_filter_enabled": True, "rdp_event_filter_profile_matches": True,
            "non_rdp_services_disabled": True, "target_association_matches": True}),
    ]
    draft = _secret_only_draft(
        blueprint_ref="FPA-BP-006", outcome_code="onboard_windows_rdp_resource",
        environment_ref=environment, scope_ref=scope, owner_ref=refs["owner"],
        audience_ref=refs["audience"], evidence_ref=refs["evidence"], desired_objects=desired,
        material_provider_class=MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE,
    )
    draft = replace(draft, external_effects=("privileged_credential_registration",),
                    verification_codes=("collector_association_readback", "owner_only_folder_readback",
                                        "rdp_service_enabled", "recording_enabled",
                                        "rdp_event_filter_enabled", "non_rdp_services_disabled"))
    bundle = _secret_only_bundle(binding, draft, requester_digest=requester, expires_at=expires)
    values = asdict(private)
    values.pop("plan_digest")
    bundle[COLLECTOR_BINDING_NAME] = values
    return bundle


def _build_bp006_bundle(
    profile: Mapping[str, object],
    material_provider_class: MaterialProviderClass,
) -> dict[str, dict[str, object]]:
    expected = _SECRET_PROFILE_COMMON_FIELDS | {
        "target_name",
        "target_ipv4_address",
        "template_name",
        "launcher_name",
        "policy_folder_id",
        "policy_folder_name",
        "policy_profile_name",
        "rdp_event_filter_profile_name",
    }
    if set(profile) != expected:
        raise LinuxOnboardingPrepareError(
            "Linux onboarding preparation input is invalid."
        )
    requester_digest, environment_ref, scope_ref, expires_at = (
        _secret_profile_context(profile)
    )
    folder_path = _selector(profile, "folder_path")
    target_name = _selector(profile, "target_name")
    target_address = _ipv4(profile, "target_ipv4_address")
    template_name = _selector(profile, "template_name")
    secret_name = _selector(profile, "secret_name")
    launcher_name = _selector(profile, "launcher_name")
    policy_folder_id = _integer(profile, "policy_folder_id")
    if not 0 < policy_folder_id <= 2_147_483_647:
        raise LinuxOnboardingPrepareError(
            "Linux onboarding preparation input is invalid."
        )
    policy_folder_name = _selector(profile, "policy_folder_name")
    policy_profile_name = _selector(profile, "policy_profile_name")
    event_filter_name = profile.get("rdp_event_filter_profile_name")
    if event_filter_name is not None:
        event_filter_name = _selector(profile, "rdp_event_filter_profile_name")
        if not event_filter_name.startswith(RDP_EVENT_FILTER_NAME_PREFIX):
            raise LinuxOnboardingPrepareError(
                "Linux onboarding preparation input is invalid."
            )

    refs = _secret_refs("bp006")
    launcher_object_ref = _new_ref("launcher-binding", "bp006")
    launcher_profile_ref = _new_ref("launcher", "bp006")
    policy_object_ref = _new_ref("policy-binding", "bp006")
    policy_profile_ref = _new_ref("policy", "bp006")
    event_object_ref = (
        _new_ref("rdp-event-filter-binding", "bp006")
        if event_filter_name is not None
        else None
    )
    event_profile_ref = (
        _new_ref("rdp-event-filter", "bp006")
        if event_filter_name is not None
        else None
    )
    binding = SecretOnboardingBinding(
        refs["folder_object"],
        folder_path,
        refs["folder"],
        refs["target_object"],
        target_name,
        "rdp",
        refs["connectivity"],
        target_address,
        refs["template_object"],
        template_name,
        refs["template"],
        refs["secret_object"],
        secret_name,
        launcher_object_ref,
        launcher_name,
        launcher_profile_ref,
        policy_object_ref,
        policy_folder_id,
        policy_folder_name,
        policy_profile_name,
        policy_profile_ref,
        event_object_ref,
        cast(str | None, event_filter_name),
        event_profile_ref,
    )
    desired_objects = [
        _desired(
            refs["folder_object"],
            ObjectClass.FOLDER_BINDING,
            {"folder_ref": refs["folder"]},
        ),
        _desired(
            refs["target_object"],
            ObjectClass.TARGET,
            {"connectivity_profile_ref": refs["connectivity"], "protocol": "rdp"},
        ),
        _desired(
            refs["template_object"],
            ObjectClass.TEMPLATE_BINDING,
            {"compatibility": "compatible", "template_ref": refs["template"]},
        ),
        _desired(
            refs["secret_object"],
            ObjectClass.SECRET_METADATA,
            {"inherit_permission": True},
        ),
        _desired(
            launcher_object_ref,
            ObjectClass.LAUNCHER_BINDING,
            {"launcher_profile_ref": launcher_profile_ref},
        ),
        _desired(
            policy_object_ref,
            ObjectClass.POLICY_BINDING,
            {"policy_profile_ref": policy_profile_ref},
        ),
    ]
    if event_object_ref is not None and event_profile_ref is not None:
        desired_objects.append(
            _desired(
                event_object_ref,
                ObjectClass.RDP_EVENT_FILTER_BINDING,
                {"profile_ref": event_profile_ref},
            )
        )
    draft = _secret_only_draft(
        blueprint_ref="FPA-BP-006",
        outcome_code="onboard_windows_rdp_resource",
        environment_ref=environment_ref,
        scope_ref=scope_ref,
        owner_ref=refs["owner"],
        audience_ref=refs["audience"],
        evidence_ref=refs["evidence"],
        desired_objects=desired_objects,
        material_provider_class=material_provider_class,
    )
    return _secret_only_bundle(
        binding,
        draft,
        requester_digest=requester_digest,
        expires_at=expires_at,
    )


def _build_bp006_existing_controls_bundle(
    profile: Mapping[str, object],
    material_provider_class: MaterialProviderClass,
) -> dict[str, dict[str, object]]:
    expected = _SECRET_PROFILE_COMMON_FIELDS | {
        "mode", "target_name", "target_ipv4_address", "template_name",
        "existing_secret_id", "inherit_permission", "rdp_event_filter_profile_name",
        "preserved_identity_relations_digest",
    }
    if (
        set(profile) != expected
        or profile.get("mode") != "existing_session_controls"
        or type(profile.get("inherit_permission")) is not bool
    ):
        raise LinuxOnboardingPrepareError("Existing Secret controls input is invalid.")
    requester_digest, environment_ref, scope_ref, expires_at = _secret_profile_context(profile)
    refs = _secret_refs("bp006")
    controls_ref = _new_ref("secret-controls", "bp006")
    event_object_ref = _new_ref("rdp-event-filter-binding", "bp006")
    event_profile_ref = _new_ref("rdp-event-filter", "bp006")
    binding = SecretOnboardingBinding(
        folder_object_ref=refs["folder_object"],
        folder_path=_selector(profile, "folder_path"),
        folder_ref=refs["folder"],
        target_object_ref=refs["target_object"],
        target_name=_selector(profile, "target_name"),
        target_protocol="rdp",
        connectivity_profile_ref=refs["connectivity"],
        target_ipv4_address=_ipv4(profile, "target_ipv4_address"),
        template_object_ref=refs["template_object"],
        template_name=_selector(profile, "template_name"),
        template_ref=refs["template"],
        secret_object_ref=refs["secret_object"],
        secret_name=_selector(profile, "secret_name"),
        rdp_event_filter_object_ref=event_object_ref,
        rdp_event_filter_profile_name=_selector(profile, "rdp_event_filter_profile_name"),
        rdp_event_filter_profile_ref=event_profile_ref,
        secret_session_controls_object_ref=controls_ref,
        existing_secret_id=_integer(profile, "existing_secret_id"),
        session_controls_identity_digest=_digest(profile, "preserved_identity_relations_digest"),
    )
    desired_objects = [
        _desired(refs["folder_object"], ObjectClass.FOLDER_BINDING, {"folder_ref": refs["folder"]}),
        _desired(refs["target_object"], ObjectClass.TARGET,
                 {"connectivity_profile_ref": refs["connectivity"], "protocol": "rdp"}),
        _desired(refs["template_object"], ObjectClass.TEMPLATE_BINDING,
                 {"compatibility": "compatible", "template_ref": refs["template"]}),
        _desired(refs["secret_object"], ObjectClass.SECRET_METADATA,
                 {"inherit_permission": cast(bool, profile["inherit_permission"])}),
        _desired(event_object_ref, ObjectClass.RDP_EVENT_FILTER_BINDING,
                 {"profile_ref": event_profile_ref}),
        _desired(controls_ref, ObjectClass.SECRET_SESSION_CONTROLS_BINDING,
                 {"recording_enabled": True, "clipboard_blocking_enabled": True,
                  "rdp_event_filter_enabled": True, "rdp_event_filter_profile_matches": True,
                  "profile_ref": event_profile_ref,
                  "preserved_identity_digest": cast(str, binding.session_controls_identity_digest),
                  "event_filter_profile_digest": secret_session_controls_event_filter_profile_digest(cast(str, binding.rdp_event_filter_profile_name))}),
    ]
    draft = replace(
        _secret_only_draft(
            blueprint_ref="FPA-BP-006", outcome_code="onboard_windows_rdp_resource",
            environment_ref=environment_ref, scope_ref=scope_ref,
            owner_ref=refs["owner"], audience_ref=refs["audience"], evidence_ref=refs["evidence"],
            desired_objects=desired_objects, material_provider_class=material_provider_class,
        ),
        material_reference_metadata=None,
        excluded_scope_codes=("credential_material", "session_launch", "effective_policy_validation"),
        verification_codes=("association_readback", "secret_session_controls_readback"),
        stop_codes=("current_state_drift", "existing_secret_unavailable"),
    )
    return _secret_only_bundle(binding, draft, requester_digest=requester_digest, expires_at=expires_at)


def _build_bp007_bundle(
    profile: Mapping[str, object],
    material_provider_class: MaterialProviderClass,
    *,
    mcp_public_url: str | None,
) -> dict[str, dict[str, object]]:
    existing_service = profile.get("mode") == "existing_web_service"
    if existing_service and profile.get("version") != SECRET_REUSE_PROFILE_VERSION:
        raise LinuxOnboardingPrepareError("Existing Web service input is invalid.")
    expected = _SECRET_PROFILE_COMMON_FIELDS | {"web_url"}
    if existing_service:
        expected |= {"mode", "existing_secret_id"}
    if set(profile) != expected:
        raise LinuxOnboardingPrepareError(
            "Linux onboarding preparation input is invalid."
        )
    requester_digest, environment_ref, scope_ref, expires_at = (
        _secret_profile_context(profile)
    )
    refs = _secret_refs("bp007")
    web_url = _web_url(profile, "web_url")
    if mcp_public_url is not None and _targets_mcp_route(web_url, mcp_public_url):
        raise LinuxOnboardingPrepareError(
            "Linux onboarding preparation input is invalid."
        )
    binding = WebSecretOnboardingBinding(
        refs["folder_object"],
        _selector(profile, "folder_path"),
        refs["folder"],
        refs["template_object"],
        "Web Account",
        refs["template"],
        refs["secret_object"],
        _selector(profile, "secret_name"),
        web_url,
        True,
        service_object_ref=_new_ref("web-service", "bp007") if existing_service else None,
        existing_secret_id=_integer(profile, "existing_secret_id") if existing_service else None,
    )
    desired_objects = [
        _desired(
            refs["folder_object"],
            ObjectClass.FOLDER_BINDING,
            {"folder_ref": refs["folder"]},
        ),
        _desired(
            refs["template_object"],
            ObjectClass.TEMPLATE_BINDING,
            {"compatibility": "compatible", "template_ref": refs["template"]},
        ),
        _desired(
            refs["secret_object"],
            ObjectClass.WEB_SECRET_METADATA,
            {"inherit_permission": True, "session_recording": True},
        ),
    ]
    if existing_service:
        assert binding.service_object_ref is not None
        desired_objects.append(_desired(
            binding.service_object_ref, ObjectClass.WEB_SECRET_SERVICE_BINDING,
            {"http_service_enabled": True},
        ))
    draft = _secret_only_draft(
        blueprint_ref="FPA-BP-007",
        outcome_code="onboard_web_account",
        environment_ref=environment_ref,
        scope_ref=scope_ref,
        owner_ref=refs["owner"],
        audience_ref=refs["audience"],
        evidence_ref=refs["evidence"],
        desired_objects=desired_objects,
        material_provider_class=material_provider_class,
    )
    if existing_service:
        draft = replace(
            draft, material_reference_metadata=None,
            excluded_scope_codes=("credential_material", "session_launch"),
            verification_codes=("association_readback", "web_service_readback"),
            stop_codes=("current_state_drift", "existing_secret_unavailable"),
        )
    return _secret_only_bundle(
        binding,
        draft,
        requester_digest=requester_digest,
        expires_at=expires_at,
    )


def _secret_profile_context(
    profile: Mapping[str, object],
) -> tuple[str, str, str, int]:
    requester_digest = _digest(profile, "requester_digest")
    environment_ref = _ref(profile, "environment_ref")
    scope_ref = _ref(profile, "scope_ref")
    expires_at = _integer(profile, "expires_at")
    if expires_at <= 0:
        raise LinuxOnboardingPrepareError(
            "Linux onboarding preparation input is invalid."
        )
    return requester_digest, environment_ref, scope_ref, expires_at


def _secret_refs(prefix: str) -> dict[str, str]:
    return {
        "owner": _new_ref("owner", prefix),
        "audience": _new_ref("audience", prefix),
        "evidence": _new_ref("evidence", prefix),
        "folder_object": _new_ref("folder-binding", prefix),
        "folder": _new_ref("folder", prefix),
        "target_object": _new_ref("target", prefix),
        "connectivity": _new_ref("connectivity", prefix),
        "template_object": _new_ref("template-binding", prefix),
        "template": _new_ref("template", prefix),
        "secret_object": _new_ref("secret", prefix),
    }


def _secret_only_draft(
    *,
    blueprint_ref: str,
    outcome_code: str,
    environment_ref: str,
    scope_ref: str,
    owner_ref: str,
    audience_ref: str,
    evidence_ref: str,
    desired_objects: list[DesiredObject],
    material_provider_class: MaterialProviderClass,
) -> SchemeDraft:
    return SchemeDraft(
        scheme_id=SchemeId.SECRET_ONBOARDING,
        scheme_version="1.0.0",
        registry_schema_version="1.1.0",
        blueprint_ref=blueprint_ref,
        environment_ref=environment_ref,
        scope_ref=scope_ref,
        owner_ref=owner_ref,
        audience_ref=audience_ref,
        outcome_code=outcome_code,
        desired_objects=tuple(desired_objects),
        approval_class="independent_approval",
        separation_required=True,
        risk_class="high",
        external_effects=("privileged_access_metadata_change",),
        assumption_codes=("private_binding_prevalidated",),
        excluded_scope_codes=("credential_material", "session_launch"),
        verification_codes=("association_readback", "launch_readiness_metadata"),
        stop_codes=("current_state_drift", "material_unavailable"),
        evidence_policy="redacted_contract_evidence",
        maintenance_class="maintenance_window_required",
        reversibility_class="manual_reconciliation_only",
        evidence_refs=(evidence_ref,),
        unresolved_gap_codes=(),
        reconciliation_strategy="reconcile_or_manual",
        summary_ttl_seconds=300,
        material_reference_metadata=MaterialReferenceMetadata(
            provider_class=material_provider_class.value,
            purpose="initial_onboarding",
            lifecycle="available",
        ),
    )


def _secret_only_bundle(
    binding: SecretOnboardingBinding | WebSecretOnboardingBinding,
    draft: SchemeDraft,
    *,
    requester_digest: str,
    expires_at: int,
) -> dict[str, dict[str, object]]:
    binding_values = asdict(binding)
    if isinstance(binding, WebSecretOnboardingBinding) and binding.service_object_ref is None:
        binding_values.pop("service_object_ref")
        binding_values.pop("existing_secret_id")
    reuse = isinstance(binding, SecretOnboardingBinding) and binding.secret_session_controls_object_ref is not None
    if reuse:
        for field in ("policy_object_ref", "policy_folder_id", "policy_folder_name",
                      "policy_profile_name", "policy_profile_ref"):
            binding_values.pop(field)
    if isinstance(binding, SecretOnboardingBinding) and not reuse:
        binding_values.pop("secret_session_controls_object_ref")
        binding_values.pop("existing_secret_id")
        binding_values.pop("session_controls_identity_digest")
    return {
        SECRET_BINDING_NAME: {
            "contract": SECRET_SOURCE_CONTRACT,
            "version": SECRET_SESSION_CONTROLS_BINDING_VERSION if reuse else SECRET_SOURCE_VERSION,
            "requester_digest": requester_digest,
            "environment_ref": draft.environment_ref,
            "scope_ref": draft.scope_ref,
            **binding_values,
        },
        DRAFT_INPUT_NAME: {
            "draft": scheme_draft_as_mapping(draft),
            "expires_at": expires_at,
            "requester_digest": requester_digest,
        },
        REFERENCE_INPUT_NAME: {
            "references": _reference_bindings(draft, include_access_source=False),
            "requester_digest": requester_digest,
            "environment_ref": draft.environment_ref,
            "scope_ref": draft.scope_ref,
            "expires_at": expires_at,
        },
    }


def _reference_bindings(
    draft: SchemeDraft,
    *,
    include_access_source: bool = True,
    projection_contract_resolver: Callable[[ObjectClass], ProjectionContract] | None = None,
) -> list[dict[str, str]]:
    collector = any(item.object_class is ObjectClass.WINRM_COLLECTOR_METADATA for item in draft.desired_objects)
    values: set[tuple[str, str]] = {
        (draft.environment_ref, "environment"),
        (draft.scope_ref, "scope"),
        (draft.owner_ref, "owner"),
        (draft.audience_ref, "audience"),
        *((item, "evidence") for item in draft.evidence_refs),
    }
    if projection_contract_resolver is None:
        values.add((winrm_collector_projection_contract().source_ref if collector else SECRET_SOURCE_REF,
                    "projection_source"))
    if include_access_source:
        values.add((ACCESS_SOURCE_REF, "projection_source"))
    for item in draft.desired_objects:
        kind = re.sub(r"(?<!^)(?=[A-Z])", "_", item.object_class.value).lower()
        values.add((item.object_ref, f"object_{kind}"))
        contract = (
            projection_contract_resolver(item.object_class) if projection_contract_resolver is not None else
            winrm_collector_projection_contract(item.object_class) if collector else
            access_domain_projection_contract(item.object_class)
            if item.object_class in {ObjectClass.PUBLIC_FOLDER, ObjectClass.ACCESS_GRANT}
            else secret_onboarding_projection_contract(item.object_class)
        )
        values.add((contract.source_ref, "projection_source"))
        values.update(
            (value, f"field_{name}")
            for name, value in item.desired_fields
            if contract.rules[name].kind is FieldKind.REFERENCE
            and type(value) is str
        )
    return [
        {"reference": reference, "reference_kind": kind}
        for reference, kind in sorted(values)
    ]


def _desired(
    object_ref: str,
    object_class: ObjectClass,
    fields: Mapping[str, bool | str],
) -> DesiredObject:
    return DesiredObject(
        object_ref,
        object_class,
        True,
        tuple(sorted(fields.items())),
    )


def _new_ref(kind: str, prefix: str = "bp005") -> str:
    return f"{prefix}-{kind}-{secrets.token_hex(12)}"


def _load_profile(path: Path) -> Mapping[str, object]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) & 0o077
                or not 0 < metadata.st_size <= _MAX_PROFILE_BYTES
            ):
                raise LinuxOnboardingPrepareError(
                    "Linux onboarding preparation input is unavailable."
                )
            content = os.read(descriptor, _MAX_PROFILE_BYTES + 1)
        finally:
            os.close(descriptor)
        value = json.loads(content)
    except LinuxOnboardingPrepareError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise LinuxOnboardingPrepareError(
            "Linux onboarding preparation input is unavailable."
        ) from None
    if type(value) is not dict or not all(type(key) is str for key in value):
        raise LinuxOnboardingPrepareError(
            "Linux onboarding preparation input is invalid."
        )
    return cast(dict[str, object], value)


def _write_private_json(path: Path, value: Mapping[str, object]) -> None:
    content = canonical_json(value).encode("utf-8") + b"\n"
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    created = False
    try:
        descriptor = os.open(path, flags, 0o600)
        created = True
        try:
            offset = 0
            while offset < len(content):
                offset += os.write(descriptor, content[offset:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.chmod(path, 0o600)
    except OSError:
        if created:
            try:
                path.unlink()
            except OSError:
                pass
        raise LinuxOnboardingPrepareError(
            "Linux onboarding preparation output is unavailable."
        ) from None


def _assert_owner_only(path: Path, *, directory: bool) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        raise LinuxOnboardingPrepareError(
            "Linux onboarding preparation protected path is unavailable."
        ) from None
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        path.is_symlink()
        or not expected_type(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise LinuxOnboardingPrepareError(
            "Linux onboarding preparation protected path must be owner-only."
        )


def _environment_value(environment: Mapping[str, str], name: str) -> str | None:
    value = environment.get(name)
    if type(value) is not str or not value.strip():
        return None
    return value.strip()


def _material_provider_class_from_environment(
    environment: Mapping[str, str],
) -> MaterialProviderClass:
    raw = environment.get(MATERIAL_PROVIDER_CLASS_ENV)
    if raw is None:
        return MaterialProviderClass.EXTERNAL_VAULT_LEASE
    try:
        return MaterialProviderClass(raw)
    except (TypeError, ValueError):
        raise LinuxOnboardingPrepareError(
            "Linux onboarding preparation configuration is invalid."
        ) from None


def _optional_mcp_public_url(environment: Mapping[str, str]) -> str | None:
    value = _environment_value(environment, MCP_PUBLIC_URL_ENV)
    if value is None:
        return None
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise LinuxOnboardingPrepareError(
            "Linux onboarding preparation configuration is invalid."
        )
    return value


def _string(mapping: Mapping[str, object], name: str) -> str:
    value = mapping.get(name)
    if type(value) is not str:
        raise LinuxOnboardingPrepareError(
            "Linux onboarding preparation input is invalid."
        )
    return value


def _selector(mapping: Mapping[str, object], name: str) -> str:
    value = _string(mapping, name)
    if (
        not value
        or len(value) > 255
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise LinuxOnboardingPrepareError(
            "Linux onboarding preparation input is invalid."
        )
    return value


def _integer(mapping: Mapping[str, object], name: str) -> int:
    value = mapping.get(name)
    if type(value) is not int:
        raise LinuxOnboardingPrepareError(
            "Linux onboarding preparation input is invalid."
        )
    return value


def _ipv4(mapping: Mapping[str, object], name: str) -> str:
    value = _string(mapping, name)
    try:
        if str(ipaddress.IPv4Address(value)) != value:
            raise ValueError
    except (ipaddress.AddressValueError, ValueError):
        raise LinuxOnboardingPrepareError(
            "Linux onboarding preparation input is invalid."
        ) from None
    return value


def _web_url(mapping: Mapping[str, object], name: str) -> str:
    value = _string(mapping, name)
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or len(value) > 2048
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise LinuxOnboardingPrepareError(
            "Linux onboarding preparation input is invalid."
        )
    return value


def _targets_mcp_route(web_url: str, mcp_public_url: str) -> bool:
    web_parsed = urlsplit(web_url)
    mcp_parsed = urlsplit(mcp_public_url)
    return (
        web_parsed.scheme == mcp_parsed.scheme
        and web_parsed.hostname == mcp_parsed.hostname
        and (web_parsed.port or (443 if web_parsed.scheme == "https" else 80))
        == (mcp_parsed.port or (443 if mcp_parsed.scheme == "https" else 80))
        and (
            web_parsed.path == mcp_parsed.path.rstrip("/")
            or web_parsed.path.startswith(f"{mcp_parsed.path.rstrip('/')}/")
        )
    )


def _ref(mapping: Mapping[str, object], name: str) -> str:
    try:
        return require_ref(_string(mapping, name), name)
    except ValueError:
        raise LinuxOnboardingPrepareError(
            "Linux onboarding preparation input is invalid."
        ) from None


def _digest(mapping: Mapping[str, object], name: str) -> str:
    try:
        return require_digest(_string(mapping, name), name)
    except ValueError:
        raise LinuxOnboardingPrepareError(
            "Linux onboarding preparation input is invalid."
        ) from None


def main() -> None:
    try:
        prepare_linux_onboarding_bundle(settings_from_environment(os.environ))
    except LinuxOnboardingPrepareError:
        sys.stderr.write('{"status":"failed"}\n')
        raise SystemExit(1) from None
    sys.stdout.write('{"status":"prepared"}\n')


if __name__ == "__main__":
    main()


__all__ = [
    "ACCESS_BINDING_NAME",
    "DRAFT_INPUT_NAME",
    "LinuxOnboardingPrepareError",
    "LinuxOnboardingPrepareSettings",
    "MATERIAL_PROVIDER_CLASS_ENV",
    "OUTPUT_DIRECTORY_ENV",
    "PROFILE_CONTRACT",
    "PROFILE_PATH_ENV",
    "PROFILE_VERSION",
    "SECRET_OUTPUT_DIRECTORY_ENV",
    "SECRET_PROFILE_CONTRACT",
    "SECRET_PROFILE_PATH_ENV",
    "SECRET_PROFILE_VERSION",
    "REFERENCE_INPUT_NAME",
    "SECRET_BINDING_NAME",
    "prepare_linux_onboarding_bundle",
    "settings_from_environment",
]
