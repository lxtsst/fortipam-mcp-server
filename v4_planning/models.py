"""Immutable models for the non-executable FortiPAM V4 planner."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import re
from typing import Mapping

from .canonical import CanonicalValue, canonical_digest, normalize


class PlanningContractError(ValueError):
    """Raised when M2 planning input violates a closed contract."""


class SchemeId(StrEnum):
    BULK_ONBOARDING = "BulkOnboardingScheme"
    ACCESS_DOMAIN = "AccessDomainScheme"
    APPROVAL_AND_OBSERVE = "ApprovalAndObserveScheme"
    IDENTITY_LIFECYCLE = "IdentityLifecycleScheme"
    SECRET_ONBOARDING = "SecretOnboardingScheme"


class ObjectClass(StrEnum):
    DISCOVERY_SOURCE_METADATA = "DiscoverySourceMetadata"
    PUBLIC_FOLDER = "PublicFolder"
    ACCESS_GRANT = "AccessGrant"
    CLASSIFICATION_BINDING = "ClassificationBinding"
    FOLDER_POLICY_BINDING = "FolderPolicyBinding"
    FOLDER_BINDING = "FolderBinding"
    TARGET = "Target"
    TEMPLATE_BINDING = "TemplateBinding"
    SECRET_METADATA = "SecretMetadata"
    WEB_SECRET_METADATA = "WebSecretMetadata"
    DOMAIN_TARGET_BINDING = "DomainTargetBinding"
    DOMAIN_SECRET_METADATA = "DomainSecretMetadata"
    WEB_TARGET_BINDING = "WebTargetBinding"
    TARGET_BOUND_WEB_SECRET_METADATA = "TargetBoundWebSecretMetadata"
    WINRM_COLLECTOR_METADATA = "WinrmCollectorMetadata"
    LAUNCHER_BINDING = "LauncherBinding"
    POLICY_BINDING = "PolicyBinding"
    RDP_EVENT_FILTER_BINDING = "RdpEventFilterBinding"
    APPROVAL_PROFILE_BINDING = "ApprovalProfileBinding"
    SECRET_APPROVAL_BINDING = "SecretApprovalBinding"
    SECRET_SESSION_CONTROLS_BINDING = "SecretSessionControlsBinding"
    WEB_SECRET_SERVICE_BINDING = "WebSecretServiceBinding"
    SPONSORED_GROUP = "SponsoredGroup"
    SPONSORED_GROUP_MEMBER = "SponsoredGroupMember"


class FieldKind(StrEnum):
    BOOLEAN = "boolean"
    ENUM = "enum"
    REFERENCE = "reference"
    DIGEST = "digest"
    POSITIVE_INTEGER = "positive_integer"


class ChangeKind(StrEnum):
    CREATE = "create"
    UPDATE = "update"
    REVOKE = "revoke"
    NO_OP = "no_op"


class SummaryState(StrEnum):
    AWAITING_CONFIRMATION = "awaiting_confirmation"
    CONFIRMED = "confirmed"
    INVALIDATED = "invalidated"


class PlanState(StrEnum):
    PREPARED_NON_EXECUTABLE = "prepared_non_executable"
    INVALIDATED = "invalidated"


class PreWriteStatus(StrEnum):
    MATCH = "match"
    INVALIDATED = "invalidated"
    UNKNOWN = "unknown"


class PostWriteStatus(StrEnum):
    EXPECTED_STATE_MATCHES = "expected_state_matches"
    EXPECTED_STATE_MISMATCH = "expected_state_mismatch"
    COMPARISON_UNKNOWN = "comparison_unknown"


_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_CODE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
_FORBIDDEN_FIELD_PARTS = (
    "password",
    "private_key",
    "secret_value",
    "token",
    "credential",
    "binding_handle",
    "vendor_locator",
    "url",
    "path",
    "command",
    "payload",
)


def require_ref(value: str, field: str) -> str:
    if _REF.fullmatch(value) is None:
        raise PlanningContractError(f"{field} must be an opaque bounded reference.")
    return value


def require_version(value: str, field: str) -> str:
    if _VERSION.fullmatch(value) is None:
        raise PlanningContractError(f"{field} must be a semantic version.")
    return value


def require_digest(value: str, field: str) -> str:
    if _DIGEST.fullmatch(value) is None:
        raise PlanningContractError(f"{field} must be a SHA-256 digest.")
    return value


def require_code(value: str, field: str) -> str:
    if _CODE.fullmatch(value) is None:
        raise PlanningContractError(f"{field} must be a bounded code.")
    return value


@dataclass(frozen=True, slots=True)
class AuthenticatedRequester:
    """Identity supplied by a trusted transport, never from Scheme content."""

    subject_ref: str
    principal_class: str
    identity_authority_ref: str | None = None
    subject_namespace: str | None = None

    def __post_init__(self) -> None:
        require_ref(self.subject_ref, "subject_ref")
        if self.principal_class != "operator":
            raise PlanningContractError(
                "M2 confirmation requires an authenticated human operator requester."
            )
        if (self.identity_authority_ref is None) is not (
            self.subject_namespace is None
        ):
            raise PlanningContractError(
                "Requester identity binding must be complete."
            )
        if (
            self.identity_authority_ref is not None
            and self.subject_namespace is not None
        ):
            require_ref(
                self.identity_authority_ref,
                "requester identity_authority_ref",
            )
            require_ref(self.subject_namespace, "requester subject_namespace")

    @property
    def digest(self) -> str:
        content: dict[str, CanonicalValue] = {
            "subject_ref": self.subject_ref,
            "principal_class": self.principal_class,
        }
        if self.identity_authority_ref is not None:
            content["identity_authority_ref"] = self.identity_authority_ref
            content["subject_namespace"] = self.subject_namespace
        return canonical_digest(content)

    @property
    def identity_digest(self) -> str | None:
        """Return a comparable human-identity digest only for a full binding."""

        if self.identity_authority_ref is None or self.subject_namespace is None:
            return None
        return canonical_digest(
            {
                "identity_authority_ref": self.identity_authority_ref,
                "subject_namespace": self.subject_namespace,
                "subject_ref": self.subject_ref,
            }
        )


@dataclass(frozen=True, slots=True)
class VerifiedReferenceDecision:
    """Value-free decision returned by a trusted C2 reference authority."""

    reference_digest: str
    reference_kind: str
    authority_ref: str
    requester_digest: str
    environment_digest: str
    scope_digest: str
    authorized: bool
    checked_at: int
    expires_at: int

    def __post_init__(self) -> None:
        require_digest(self.reference_digest, "reference_digest")
        require_code(self.reference_kind, "reference_kind")
        require_ref(self.authority_ref, "reference authority_ref")
        require_digest(self.requester_digest, "reference requester_digest")
        require_digest(self.environment_digest, "reference environment_digest")
        require_digest(self.scope_digest, "reference scope_digest")
        if type(self.authorized) is not bool:
            raise PlanningContractError("Reference authorization decision is invalid.")
        if (
            type(self.checked_at) is not int
            or type(self.expires_at) is not int
            or self.expires_at <= self.checked_at
        ):
            raise PlanningContractError("Reference authorization lifetime is invalid.")

    def as_dict(self) -> dict[str, CanonicalValue]:
        return {
            "authority_ref": self.authority_ref,
            "authorized": self.authorized,
            "checked_at": self.checked_at,
            "environment_digest": self.environment_digest,
            "expires_at": self.expires_at,
            "reference_digest": self.reference_digest,
            "reference_kind": self.reference_kind,
            "requester_digest": self.requester_digest,
            "scope_digest": self.scope_digest,
        }


@dataclass(frozen=True, slots=True)
class FieldRule:
    name: str
    kind: FieldKind
    enum_values: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        require_code(self.name, "field rule name")
        if any(part in self.name for part in _FORBIDDEN_FIELD_PARTS):
            raise PlanningContractError("Field rule may expose prohibited material.")
        if self.kind is FieldKind.ENUM:
            if not self.enum_values or len(set(self.enum_values)) != len(self.enum_values):
                raise PlanningContractError("Enum field needs unique values.")
            for item in self.enum_values:
                require_code(item, "enum value")
        elif self.enum_values:
            raise PlanningContractError("Only enum fields may declare values.")

    def validate(self, value: object) -> bool | str | int:
        if self.kind is FieldKind.BOOLEAN:
            if type(value) is not bool:
                raise PlanningContractError(f"{self.name} must be boolean.")
            return value
        if self.kind is FieldKind.POSITIVE_INTEGER:
            if type(value) is not int or not 0 < value <= 2_147_483_647:
                raise PlanningContractError(
                    f"{self.name} must be a bounded positive integer."
                )
            return value
        if type(value) is not str:
            raise PlanningContractError(f"{self.name} must be a string.")
        if self.kind is FieldKind.ENUM:
            if value not in self.enum_values:
                raise PlanningContractError(f"{self.name} has an unsupported enum value.")
            return value
        if self.kind is FieldKind.DIGEST:
            return require_digest(value, self.name)
        return require_ref(value, self.name)


@dataclass(frozen=True, slots=True)
class ProjectionContract:
    contract_id: str
    version: str
    source_ref: str
    object_class: ObjectClass
    field_rules: tuple[FieldRule, ...]
    max_age_seconds: int

    def __post_init__(self) -> None:
        require_ref(self.contract_id, "projection contract_id")
        require_version(self.version, "projection contract version")
        require_ref(self.source_ref, "projection source_ref")
        if not self.field_rules or len(self.field_rules) > 16:
            raise PlanningContractError("Projection contract needs bounded fields.")
        names = [rule.name for rule in self.field_rules]
        if len(names) != len(set(names)) or "exists" not in names:
            raise PlanningContractError("Projection fields must be unique and include exists.")
        if not 30 <= self.max_age_seconds <= 3600:
            raise PlanningContractError("Projection freshness bound is invalid.")

    @property
    def rules(self) -> dict[str, FieldRule]:
        return {rule.name: rule for rule in self.field_rules}

    def validate_fields(self, values: Mapping[str, object], *, complete: bool) -> tuple[tuple[str, bool | str | int], ...]:
        if set(values) - set(self.rules):
            raise PlanningContractError("Projection contains an undeclared field.")
        if complete:
            expected = {"exists"} if values.get("exists") is False else set(self.rules)
            if set(values) != expected:
                raise PlanningContractError("Projection is missing a declared field.")
        return tuple((name, self.rules[name].validate(values[name])) for name in sorted(values))

    def as_dict(self) -> dict[str, CanonicalValue]:
        return {
            "contract_id": self.contract_id,
            "field_rules": [
                {
                    "enum_values": list(rule.enum_values),
                    "kind": rule.kind.value,
                    "name": rule.name,
                }
                for rule in self.field_rules
            ],
            "max_age_seconds": self.max_age_seconds,
            "object_class": self.object_class.value,
            "source_ref": self.source_ref,
            "version": self.version,
        }


@dataclass(frozen=True, slots=True)
class AuthoritativeProjection:
    contract: ProjectionContract
    object_ref: str
    observed_at: int
    fresh_until: int
    fields: tuple[tuple[str, bool | str | int], ...]
    authoritative: bool = True
    complete: bool = True
    contradictory: bool = False
    c3_included: bool = False
    raw_response_included: bool = False

    def __post_init__(self) -> None:
        require_ref(self.object_ref, "projection object_ref")
        if type(self.observed_at) is not int or type(self.fresh_until) is not int:
            raise PlanningContractError("Projection timestamps must be integers.")
        if self.fresh_until <= self.observed_at:
            raise PlanningContractError("Projection freshness interval is invalid.")
        if self.fresh_until - self.observed_at > self.contract.max_age_seconds:
            raise PlanningContractError("Projection exceeds its freshness contract.")
        values = dict(self.fields)
        if len(values) != len(self.fields):
            raise PlanningContractError("Projection contains duplicate fields.")
        validated = self.contract.validate_fields(values, complete=self.complete)
        if validated != self.fields:
            raise PlanningContractError("Projection fields are not canonically ordered.")

    @classmethod
    def from_mapping(
        cls,
        *,
        contract: ProjectionContract,
        object_ref: str,
        observed_at: int,
        fresh_until: int,
        fields: Mapping[str, object],
        authoritative: bool = True,
        complete: bool = True,
        contradictory: bool = False,
        c3_included: bool = False,
        raw_response_included: bool = False,
    ) -> "AuthoritativeProjection":
        validated = contract.validate_fields(fields, complete=complete)
        return cls(
            contract=contract,
            object_ref=object_ref,
            observed_at=observed_at,
            fresh_until=fresh_until,
            fields=validated,
            authoritative=authoritative,
            complete=complete,
            contradictory=contradictory,
            c3_included=c3_included,
            raw_response_included=raw_response_included,
        )

    @property
    def values(self) -> dict[str, bool | str | int]:
        return dict(self.fields)

    @property
    def digest(self) -> str:
        return canonical_digest(self.as_dict())

    @property
    def state_digest(self) -> str:
        """Digest the reduced state while excluding freshness timestamps."""

        return canonical_digest(
            {
                "contract": self.contract.as_dict(),
                "fields": dict(self.fields),
                "object_ref": self.object_ref,
            }
        )

    def as_dict(self) -> dict[str, CanonicalValue]:
        return {
            "authoritative": self.authoritative,
            "c3_included": self.c3_included,
            "complete": self.complete,
            "contradictory": self.contradictory,
            "contract": self.contract.as_dict(),
            "fields": dict(self.fields),
            "fresh_until": self.fresh_until,
            "object_ref": self.object_ref,
            "observed_at": self.observed_at,
            "raw_response_included": self.raw_response_included,
        }


@dataclass(frozen=True, slots=True)
class DesiredObject:
    object_ref: str
    object_class: ObjectClass
    desired_exists: bool
    desired_fields: tuple[tuple[str, bool | str | int], ...]

    def __post_init__(self) -> None:
        require_ref(self.object_ref, "desired object_ref")
        values = dict(self.desired_fields)
        if len(values) != len(self.desired_fields):
            raise PlanningContractError("Desired object fields are duplicated.")
        if self.desired_exists and not values:
            raise PlanningContractError("An existing desired object needs fields.")
        if not self.desired_exists and values:
            raise PlanningContractError("A removed desired object cannot carry fields.")
        if tuple(sorted(self.desired_fields)) != self.desired_fields:
            raise PlanningContractError("Desired object fields are not canonically ordered.")


@dataclass(frozen=True, slots=True)
class MaterialReferenceMetadata:
    provider_class: str
    purpose: str
    lifecycle: str

    def __post_init__(self) -> None:
        if self.provider_class not in {
            "fortipam_managed_material",
            "central_lab_inventory_reference",
            "external_vault_lease",
        }:
            raise PlanningContractError("Material provider class is not allowed.")
        if self.purpose not in {"initial_onboarding", "credential_rotation", "jit_delivery"}:
            raise PlanningContractError("Material purpose is not allowed.")
        if self.lifecycle not in {"available", "pending", "unavailable"}:
            raise PlanningContractError("Material lifecycle is not allowed.")

    def as_dict(self) -> dict[str, CanonicalValue]:
        return {
            "lifecycle": self.lifecycle,
            "provider_class": self.provider_class,
            "purpose": self.purpose,
        }


@dataclass(frozen=True, slots=True)
class SchemeDraft:
    scheme_id: SchemeId
    scheme_version: str
    registry_schema_version: str
    blueprint_ref: str
    environment_ref: str
    scope_ref: str
    owner_ref: str
    audience_ref: str
    outcome_code: str
    desired_objects: tuple[DesiredObject, ...]
    approval_class: str
    separation_required: bool
    risk_class: str
    external_effects: tuple[str, ...]
    assumption_codes: tuple[str, ...]
    excluded_scope_codes: tuple[str, ...]
    verification_codes: tuple[str, ...]
    stop_codes: tuple[str, ...]
    evidence_policy: str
    maintenance_class: str
    reversibility_class: str
    evidence_refs: tuple[str, ...]
    unresolved_gap_codes: tuple[str, ...]
    reconciliation_strategy: str
    summary_ttl_seconds: int
    material_reference_metadata: MaterialReferenceMetadata | None = None

    def __post_init__(self) -> None:
        require_version(self.scheme_version, "scheme_version")
        require_version(self.registry_schema_version, "registry_schema_version")
        require_ref(self.blueprint_ref, "blueprint_ref")
        for field, value in (
            ("environment_ref", self.environment_ref),
            ("scope_ref", self.scope_ref),
            ("owner_ref", self.owner_ref),
            ("audience_ref", self.audience_ref),
        ):
            require_ref(value, field)
        require_code(self.outcome_code, "outcome_code")
        if not self.desired_objects or len(self.desired_objects) > 19:
            raise PlanningContractError("Scheme needs a bounded desired object set.")
        object_refs = [item.object_ref for item in self.desired_objects]
        if len(object_refs) != len(set(object_refs)):
            raise PlanningContractError("Scheme object references must be unique.")
        if self.approval_class not in {"owner_approval", "independent_approval"}:
            raise PlanningContractError("approval_class is not allowed.")
        if self.risk_class not in {"low", "medium", "high"}:
            raise PlanningContractError("risk_class is not allowed.")
        if self.reconciliation_strategy != "reconcile_or_manual":
            raise PlanningContractError("reconciliation_strategy is not allowed.")
        if self.evidence_policy != "redacted_contract_evidence":
            raise PlanningContractError("evidence_policy is not allowed.")
        if self.maintenance_class not in {"none", "maintenance_window_required"}:
            raise PlanningContractError("maintenance_class is not allowed.")
        if self.reversibility_class not in {
            "compensating_action_required",
            "manual_reconciliation_only",
        }:
            raise PlanningContractError("reversibility_class is not allowed.")
        if not 60 <= self.summary_ttl_seconds <= 1800:
            raise PlanningContractError("Summary TTL is outside the M2 bound.")
        for field, values in (
            ("external_effects", self.external_effects),
            ("assumption_codes", self.assumption_codes),
            ("excluded_scope_codes", self.excluded_scope_codes),
            ("verification_codes", self.verification_codes),
            ("stop_codes", self.stop_codes),
            ("unresolved_gap_codes", self.unresolved_gap_codes),
        ):
            if len(values) > 16:
                raise PlanningContractError(f"{field} exceeds the M2 bound.")
            if len(values) != len(set(values)):
                raise PlanningContractError(f"{field} contains duplicates.")
            for value in values:
                require_code(value, field)
        for field, values in (
            ("external_effects", self.external_effects),
            ("excluded_scope_codes", self.excluded_scope_codes),
            ("verification_codes", self.verification_codes),
            ("stop_codes", self.stop_codes),
        ):
            if not values:
                raise PlanningContractError(f"{field} must be explicit and non-empty.")
        if (
            not self.evidence_refs
            or len(self.evidence_refs) > 16
            or len(self.evidence_refs) != len(set(self.evidence_refs))
        ):
            raise PlanningContractError("evidence_refs must be non-empty and unique.")
        for value in self.evidence_refs:
            require_ref(value, "evidence_ref")


@dataclass(frozen=True, slots=True)
class ObjectChange:
    object_ref: str
    object_class: ObjectClass
    change_kind: ChangeKind
    current_fields: tuple[tuple[str, bool | str | int], ...]
    proposed_fields: tuple[tuple[str, bool | str | int], ...]
    expected_fields: tuple[tuple[str, bool | str | int], ...]
    current_projection_digest: str
    expected_projection_digest: str
    projection_contract_ref: str
    projection_contract_version: str
    projection_source_ref: str
    observed_at: int
    fresh_until: int

    def __post_init__(self) -> None:
        require_ref(self.object_ref, "change object_ref")
        require_digest(self.current_projection_digest, "current_projection_digest")
        require_digest(self.expected_projection_digest, "expected_projection_digest")
        require_ref(self.projection_contract_ref, "projection_contract_ref")
        require_version(self.projection_contract_version, "projection_contract_version")
        require_ref(self.projection_source_ref, "projection_source_ref")
        if self.fresh_until <= self.observed_at:
            raise PlanningContractError("Object change projection freshness is invalid.")
        for field_name, fields in (
            ("current_fields", self.current_fields),
            ("proposed_fields", self.proposed_fields),
            ("expected_fields", self.expected_fields),
        ):
            names = tuple(name for name, _value in fields)
            if len(names) != len(set(names)) or fields != tuple(sorted(fields)):
                raise PlanningContractError(
                    f"Object change {field_name} must be unique and canonically ordered."
                )

    def as_dict(self) -> dict[str, CanonicalValue]:
        return {
            "change_kind": self.change_kind.value,
            "current_fields": dict(self.current_fields),
            "current_projection_digest": self.current_projection_digest,
            "expected_fields": dict(self.expected_fields),
            "expected_projection_digest": self.expected_projection_digest,
            "object_class": self.object_class.value,
            "object_ref": self.object_ref,
            "projected_changes": dict(self.proposed_fields),
            "projection_contract_ref": self.projection_contract_ref,
            "projection_contract_version": self.projection_contract_version,
            "projection_source_ref": self.projection_source_ref,
            "observed_at": self.observed_at,
            "fresh_until": self.fresh_until,
        }


@dataclass(frozen=True, slots=True)
class FinalIntentSummary:
    summary_ref: str
    revision: int
    state: SummaryState
    requester_digest: str
    requester_class: str
    audience_ref: str
    scheme_id: SchemeId
    scheme_version: str
    registry_schema_version: str
    blueprint_ref: str
    action_family_ref: str
    action_family_version: str
    environment_ref: str
    scope_ref: str
    owner_ref: str
    outcome_code: str
    object_changes: tuple[ObjectChange, ...]
    unchanged_boundary: tuple[str, ...]
    facts: tuple[str, ...]
    assumptions: tuple[str, ...]
    excluded_scope: tuple[str, ...]
    verification_codes: tuple[str, ...]
    stop_codes: tuple[str, ...]
    evidence_policy: str
    maintenance_class: str
    reversibility_class: str
    unresolved_gaps: tuple[str, ...]
    risk_class: str
    external_effects: tuple[str, ...]
    approval_class: str
    separation_required: bool
    reconciliation_strategy: str
    material_reference_metadata: MaterialReferenceMetadata | None
    reference_authority_ref: str
    reference_authorization_digest: str
    reference_authorization_expires_at: int
    created_at: int
    expires_at: int
    current_state_digest: str
    proposed_changes_digest: str
    expected_state_digest: str
    summary_digest: str

    def canonical_content(self) -> dict[str, CanonicalValue]:
        return {
            "action_family_ref": self.action_family_ref,
            "action_family_version": self.action_family_version,
            "approval_class": self.approval_class,
            "assumptions": list(self.assumptions),
            "audience_ref": self.audience_ref,
            "blueprint_ref": self.blueprint_ref,
            "created_at": self.created_at,
            "current_state_digest": self.current_state_digest,
            "environment_ref": self.environment_ref,
            "expected_state_digest": self.expected_state_digest,
            "expires_at": self.expires_at,
            "excluded_scope": list(self.excluded_scope),
            "external_effects": list(self.external_effects),
            "facts": list(self.facts),
            "evidence_policy": self.evidence_policy,
            "material_reference_metadata": (
                self.material_reference_metadata.as_dict()
                if self.material_reference_metadata is not None
                else None
            ),
            "object_changes": [change.as_dict() for change in self.object_changes],
            "outcome_code": self.outcome_code,
            "owner_ref": self.owner_ref,
            "proposed_changes_digest": self.proposed_changes_digest,
            "reconciliation_strategy": self.reconciliation_strategy,
            "reference_authority_ref": self.reference_authority_ref,
            "reference_authorization_digest": self.reference_authorization_digest,
            "reference_authorization_expires_at": self.reference_authorization_expires_at,
            "registry_schema_version": self.registry_schema_version,
            "requester_class": self.requester_class,
            "requester_digest": self.requester_digest,
            "revision": self.revision,
            "reversibility_class": self.reversibility_class,
            "risk_class": self.risk_class,
            "scheme_id": self.scheme_id.value,
            "scheme_version": self.scheme_version,
            "scope_ref": self.scope_ref,
            "separation_required": self.separation_required,
            "summary_ref": self.summary_ref,
            "stop_codes": list(self.stop_codes),
            "unchanged_boundary": list(self.unchanged_boundary),
            "unresolved_gaps": list(self.unresolved_gaps),
            "verification_codes": list(self.verification_codes),
            "maintenance_class": self.maintenance_class,
        }

    def __post_init__(self) -> None:
        require_ref(self.summary_ref, "summary_ref")
        require_ref(self.action_family_ref, "action_family_ref")
        require_version(self.action_family_version, "action_family_version")
        require_code(self.outcome_code, "outcome_code")
        for field, values in (
            ("external_effects", self.external_effects),
            ("excluded_scope", self.excluded_scope),
            ("verification_codes", self.verification_codes),
            ("stop_codes", self.stop_codes),
        ):
            if not values or len(values) != len(set(values)):
                raise PlanningContractError(f"{field} must be explicit and unique.")
            for value in values:
                require_code(value, field)
        if self.evidence_policy != "redacted_contract_evidence":
            raise PlanningContractError("evidence_policy is not allowed.")
        if self.maintenance_class not in {"none", "maintenance_window_required"}:
            raise PlanningContractError("maintenance_class is not allowed.")
        if self.reversibility_class not in {
            "compensating_action_required",
            "manual_reconciliation_only",
        }:
            raise PlanningContractError("reversibility_class is not allowed.")
        require_digest(self.requester_digest, "requester_digest")
        require_digest(self.current_state_digest, "current_state_digest")
        require_digest(self.proposed_changes_digest, "proposed_changes_digest")
        require_digest(self.expected_state_digest, "expected_state_digest")
        require_digest(self.summary_digest, "summary_digest")
        require_ref(self.reference_authority_ref, "reference_authority_ref")
        require_digest(
            self.reference_authorization_digest,
            "reference_authorization_digest",
        )
        if self.summary_digest != canonical_digest(self.canonical_content()):
            raise PlanningContractError("Final Intent Summary digest is invalid.")
        if (
            self.revision < 1
            or self.expires_at <= self.created_at
            or self.reference_authorization_expires_at < self.expires_at
        ):
            raise PlanningContractError("Final Intent Summary lifetime is invalid.")

    def as_dict(self) -> dict[str, CanonicalValue]:
        content = dict(self.canonical_content())
        content.update(
            {
                "current_state_digest": self.current_state_digest,
                "expected_state_digest": self.expected_state_digest,
                "proposed_changes_digest": self.proposed_changes_digest,
                "state": self.state.value,
                "summary_digest": self.summary_digest,
            }
        )
        return normalize(content)  # type: ignore[return-value]


@dataclass(frozen=True, slots=True)
class VerifiedConfirmationInteraction:
    """Bound result from a trusted human-confirmation interaction adapter.

    M2 defines the contract only.  It does not implement or expose such an
    adapter through MCP, HTTP, or any product integration.
    """

    interaction_ref: str
    interaction_type: str
    nonce_digest: str
    requester_digest: str
    audience_ref: str
    summary_ref: str
    summary_revision: int
    summary_digest: str
    decision: str
    confirmed_at: int
    expires_at: int

    def __post_init__(self) -> None:
        require_ref(self.interaction_ref, "interaction_ref")
        if self.interaction_type != "authenticated_human_confirmation":
            raise PlanningContractError("Confirmation interaction type is invalid.")
        require_digest(self.nonce_digest, "nonce_digest")
        require_digest(self.requester_digest, "requester_digest")
        require_ref(self.audience_ref, "audience_ref")
        require_ref(self.summary_ref, "summary_ref")
        require_digest(self.summary_digest, "summary_digest")
        if self.decision not in {"affirm", "deny"}:
            raise PlanningContractError("Confirmation decision is invalid.")
        if self.summary_revision < 1 or self.expires_at <= self.confirmed_at:
            raise PlanningContractError("Confirmation interaction lifetime is invalid.")


@dataclass(frozen=True, slots=True)
class ConfirmationRecord:
    confirmation_ref: str
    requester_digest: str
    audience_ref: str
    summary_ref: str
    summary_revision: int
    summary_digest: str
    interaction_ref_digest: str
    interaction_type: str
    nonce_digest: str
    confirmed_at: int
    expires_at: int
    state: str
    record_digest: str

    def canonical_content(self) -> dict[str, CanonicalValue]:
        return {
            "audience_ref": self.audience_ref,
            "confirmation_ref": self.confirmation_ref,
            "confirmed_at": self.confirmed_at,
            "expires_at": self.expires_at,
            "interaction_ref_digest": self.interaction_ref_digest,
            "interaction_type": self.interaction_type,
            "nonce_digest": self.nonce_digest,
            "requester_digest": self.requester_digest,
            "state": self.state,
            "summary_digest": self.summary_digest,
            "summary_ref": self.summary_ref,
            "summary_revision": self.summary_revision,
        }

    def __post_init__(self) -> None:
        require_ref(self.confirmation_ref, "confirmation_ref")
        for field, value in (
            ("requester_digest", self.requester_digest),
            ("summary_digest", self.summary_digest),
            ("interaction_ref_digest", self.interaction_ref_digest),
            ("nonce_digest", self.nonce_digest),
            ("record_digest", self.record_digest),
        ):
            require_digest(value, field)
        require_ref(self.audience_ref, "audience_ref")
        require_ref(self.summary_ref, "summary_ref")
        if self.interaction_type != "authenticated_human_confirmation":
            raise PlanningContractError("Confirmation record interaction type is invalid.")
        if self.state != "confirmed" or self.expires_at <= self.confirmed_at:
            raise PlanningContractError("Confirmation record is invalid.")
        if self.record_digest != canonical_digest(self.canonical_content()):
            raise PlanningContractError("Confirmation record digest is invalid.")


@dataclass(frozen=True, slots=True)
class PlanLine:
    line_ref: str
    action_family_ref: str
    action_family_version: str
    target_ref: str
    target_class: ObjectClass
    change_kind: ChangeKind
    expected_current_digest: str
    expected_state_digest: str
    projection_contract_ref: str
    depends_on: tuple[str, ...]
    dispatchable: bool = False
    adapter: str = "none"

    def __post_init__(self) -> None:
        require_ref(self.line_ref, "line_ref")
        require_ref(self.action_family_ref, "action_family_ref")
        require_version(self.action_family_version, "action_family_version")
        require_ref(self.target_ref, "target_ref")
        require_digest(self.expected_current_digest, "expected_current_digest")
        require_digest(self.expected_state_digest, "expected_state_digest")
        require_ref(self.projection_contract_ref, "projection_contract_ref")
        for dependency in self.depends_on:
            require_ref(dependency, "depends_on")
        if self.dispatchable is not False or self.adapter != "none":
            raise PlanningContractError("M2 plan lines must remain non-dispatchable.")

    def as_dict(self) -> dict[str, CanonicalValue]:
        return {
            "action_family_ref": self.action_family_ref,
            "action_family_version": self.action_family_version,
            "adapter": self.adapter,
            "change_kind": self.change_kind.value,
            "depends_on": list(self.depends_on),
            "dispatchable": self.dispatchable,
            "expected_current_digest": self.expected_current_digest,
            "expected_state_digest": self.expected_state_digest,
            "line_ref": self.line_ref,
            "projection_contract_ref": self.projection_contract_ref,
            "target_class": self.target_class.value,
            "target_ref": self.target_ref,
        }


@dataclass(frozen=True, slots=True)
class PreparedPlan:
    plan_ref: str
    revision: int
    state: PlanState
    summary_ref: str
    summary_revision: int
    summary_digest: str
    confirmation_ref: str
    confirmation_digest: str
    requester_digest: str
    environment_ref: str
    scope_ref: str
    scheme_id: SchemeId
    scheme_version: str
    registry_schema_version: str
    created_at: int
    expires_at: int
    lines: tuple[PlanLine, ...]
    dispatchable: bool
    adapter_registry_bound: bool
    planner_runtime_packaged: bool
    planner_mcp_exposed: bool
    executor_runtime_packaged: bool
    executor_mcp_exposed: bool
    plan_digest: str

    def canonical_content(self) -> dict[str, CanonicalValue]:
        return {
            "adapter_registry_bound": self.adapter_registry_bound,
            "confirmation_digest": self.confirmation_digest,
            "confirmation_ref": self.confirmation_ref,
            "created_at": self.created_at,
            "dispatchable": self.dispatchable,
            "environment_ref": self.environment_ref,
            "expires_at": self.expires_at,
            "lines": [line.as_dict() for line in self.lines],
            "executor_mcp_exposed": self.executor_mcp_exposed,
            "executor_runtime_packaged": self.executor_runtime_packaged,
            "plan_ref": self.plan_ref,
            "planner_mcp_exposed": self.planner_mcp_exposed,
            "planner_runtime_packaged": self.planner_runtime_packaged,
            "registry_schema_version": self.registry_schema_version,
            "requester_digest": self.requester_digest,
            "revision": self.revision,
            "scheme_id": self.scheme_id.value,
            "scheme_version": self.scheme_version,
            "scope_ref": self.scope_ref,
            "summary_digest": self.summary_digest,
            "summary_ref": self.summary_ref,
            "summary_revision": self.summary_revision,
        }

    def __post_init__(self) -> None:
        require_ref(self.plan_ref, "plan_ref")
        require_ref(self.summary_ref, "summary_ref")
        require_digest(self.summary_digest, "summary_digest")
        require_ref(self.confirmation_ref, "confirmation_ref")
        require_digest(self.confirmation_digest, "confirmation_digest")
        require_digest(self.requester_digest, "requester_digest")
        require_digest(self.plan_digest, "plan_digest")
        if self.plan_digest != canonical_digest(self.canonical_content()):
            raise PlanningContractError("Prepared plan digest is invalid.")
        if not self.lines or len(self.lines) > 19:
            raise PlanningContractError("Prepared plan line count is invalid.")
        if (
            self.dispatchable
            or self.adapter_registry_bound
            or self.executor_runtime_packaged
            or self.executor_mcp_exposed
        ):
            raise PlanningContractError(
                "Prepared plan widened the non-executable runtime boundary."
            )
        if not self.planner_runtime_packaged:
            raise PlanningContractError(
                "Prepared plan does not truthfully declare plan-only packaging."
            )


@dataclass(frozen=True, slots=True)
class PreWriteEvaluation:
    plan_ref: str
    status: PreWriteStatus
    reason_codes: tuple[str, ...]
    evaluated_at: int
    observed_state_digest: str | None


@dataclass(frozen=True, slots=True)
class PostWriteEvaluation:
    plan_ref: str
    status: PostWriteStatus
    reason_codes: tuple[str, ...]
    evaluated_at: int
    actual_state_digest: str | None
    expected_state_digest: str
    mutation_observed: bool = False
    operational_success: bool = False

    def __post_init__(self) -> None:
        if self.mutation_observed or self.operational_success:
            raise PlanningContractError(
                "M2 post-write evaluation cannot claim a mutation or operational success."
            )
