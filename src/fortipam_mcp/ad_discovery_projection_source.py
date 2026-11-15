"""Fixed five-object, non-executable BP014 AD Source planning projection."""

from dataclasses import dataclass
from urllib.parse import quote

from v4_planning import (
    AuthenticatedRequester, AuthoritativeProjection, FieldKind, FieldRule,
    ObjectClass, PlanningContractError, ProjectionContract, SchemeDraft, SchemeId,
    canonical_digest,
)
from v4_planning.models import require_ref

from .discovery_entry_create_http_transport import (
    FortiPamDiscoveryEntryCreateHttpTransport, inspect_ad_credential_dependency,
)
from .discovery_entry_create_contract import DisabledAdDiscoveryCreateInput
from .discovery_entry_m4_adapter import DiscoveryEntryBinding
from .domain_secret_projection_reader import DomainSecretPlanningBinding, domain_secret_binding_digest
from .owner_session_metadata import OwnerSessionMetadataTransport
from .secret_metadata_http_transport import UTILITY_ID_PATH, _path_for_url
from .secret_onboarding_projection_source import secret_onboarding_projection_contract


CONTRACT_ID = "fortipam-ad-discovery-source-observation-v1"
CONTRACT_VERSION = "1.0.0"
SOURCE_REF = "fortipam-700-build29-ad-discovery-projection"
OUTCOME = "create_disabled_ad_discovery_source"
_UNAVAILABLE = "The fixed AD Discovery planning projection is unavailable."
_CLASSES = {
    ObjectClass.FOLDER_BINDING, ObjectClass.DOMAIN_TARGET_BINDING,
    ObjectClass.TEMPLATE_BINDING, ObjectClass.DOMAIN_SECRET_METADATA,
    ObjectClass.DISCOVERY_SOURCE_METADATA,
}


def ad_discovery_projection_contract(object_class: ObjectClass) -> ProjectionContract:
    if object_class not in _CLASSES:
        raise PlanningContractError(_UNAVAILABLE)
    rules = (
        FieldRule("exists", FieldKind.BOOLEAN),
        FieldRule("source_type", FieldKind.ENUM, ("active_directory",)),
        FieldRule("account_discovery", FieldKind.BOOLEAN),
        FieldRule("domain_secret_ref", FieldKind.REFERENCE),
        FieldRule("periodic_scanning_disabled", FieldKind.BOOLEAN),
        FieldRule("auto_onboarding_disabled", FieldKind.BOOLEAN),
        FieldRule("existing_secret_method", FieldKind.BOOLEAN),
        FieldRule("no_scan_timestamp", FieldKind.BOOLEAN),
    ) if object_class is ObjectClass.DISCOVERY_SOURCE_METADATA else secret_onboarding_projection_contract(object_class).field_rules
    return ProjectionContract(
        contract_id=CONTRACT_ID, version=CONTRACT_VERSION, source_ref=SOURCE_REF,
        object_class=object_class, field_rules=rules, max_age_seconds=300,
    )


@dataclass(frozen=True, slots=True, repr=False)
class AdDiscoveryPlanningBinding:
    """Private source intent and its four already-qualified Domain anchors."""

    source: DiscoveryEntryBinding
    domain: DomainSecretPlanningBinding
    source_object_ref: str

    def __post_init__(self) -> None:
        try:
            if (type(self.source) is not DiscoveryEntryBinding
                or type(self.source.request) is not DisabledAdDiscoveryCreateInput
                or type(self.domain) is not DomainSecretPlanningBinding
                or self.source.domain_binding != self.domain.create_binding):
                raise ValueError
            require_ref(self.source_object_ref, "AD Source object reference")
            if self.source_object_ref in self.domain.expected_objects():
                raise ValueError
        except Exception:
            raise PlanningContractError(_UNAVAILABLE) from None

    def expected_objects(self) -> dict[str, tuple[ObjectClass, dict[str, bool | str]]]:
        return {
            **self.domain.expected_objects(),
            self.source_object_ref: (ObjectClass.DISCOVERY_SOURCE_METADATA, {
                "source_type": "active_directory", "account_discovery": True,
                "domain_secret_ref": self.domain.secret_object_ref,
                "periodic_scanning_disabled": True, "auto_onboarding_disabled": True,
                "existing_secret_method": True, "no_scan_timestamp": True,
            }),
        }

    def validate_intent(self, draft: SchemeDraft, requester: AuthenticatedRequester) -> None:
        try:
            expected = self.expected_objects()
            if (draft.scheme_id is not SchemeId.BULK_ONBOARDING
                or draft.scheme_version != "1.0.0" or draft.blueprint_ref != "FPA-BP-014"
                or draft.outcome_code != OUTCOME or draft.material_reference_metadata is not None
                or requester.digest != self.domain.requester_digest
                or draft.environment_ref != self.domain.environment_ref
                or draft.scope_ref != self.domain.scope_ref
                or len(draft.desired_objects) != 5
                or {item.object_ref for item in draft.desired_objects} != set(expected)
                or any(item.desired_exists is not True
                    or (item.object_class, dict(item.desired_fields)) != expected[item.object_ref]
                    for item in draft.desired_objects)):
                raise ValueError
            for item in draft.desired_objects:
                ad_discovery_projection_contract(item.object_class).validate_fields(
                    {"exists": item.desired_exists, **dict(item.desired_fields)}, complete=True,
                )
        except Exception:
            raise PlanningContractError(_UNAVAILABLE) from None

    def __repr__(self) -> str:
        return "<AdDiscoveryPlanningBinding protected>"


class AdDiscoveryPlanningSource:
    """One Owner read lifetime plus a separately pinned bearer Source read."""

    mode = "source_backed"
    contract_registered = True

    def __init__(self, binding: AdDiscoveryPlanningBinding,
                 owner: OwnerSessionMetadataTransport,
                 source_transport: FortiPamDiscoveryEntryCreateHttpTransport) -> None:
        if (type(binding) is not AdDiscoveryPlanningBinding
            or type(owner) is not OwnerSessionMetadataTransport
            or type(source_transport) is not FortiPamDiscoveryEntryCreateHttpTransport):
            raise PlanningContractError(_UNAVAILABLE)
        self._binding, self._owner, self._source_transport = binding, owner, source_transport
        self._validate_transports()

    def _validate_transports(self) -> None:
        b, owner, writer = self._binding.domain.create_binding, self._owner, self._source_transport._config
        if (owner._config.base_url != writer.base_url or owner._config.ca_file != writer.ca_file
            or owner._owner_name != b.target_owner_name or owner._bound_secret_name != b.secret_name
            or owner._secret_lookup_path != UTILITY_ID_PATH + "/" + _path_for_url(b.folder_path + "/" + b.secret_name)
            or "/api/v2/cmdb/secret/target/" + quote(b.target_name, safe="") not in owner._allowed_paths
            or owner._allow_secret_create or owner._allow_collector_credential_repair):
            raise PlanningContractError(_UNAVAILABLE)

    def inspect_private_binding_digest(self, draft: SchemeDraft, requester: AuthenticatedRequester) -> str:
        """For a future private promoter only; never part of a public projection."""
        self._binding.validate_intent(draft, requester)
        self._validate_transports()
        b = self._binding
        d = b.domain
        return canonical_digest({
            "contract": CONTRACT_ID, "source_ref": b.source_object_ref,
            "source_parameters_digest": b.source.parameters_digest,
            "domain_parameters_digest": domain_secret_binding_digest(d.create_binding,
                d.secret_object_ref, dependency_refs=(d.folder_object_ref, d.target_object_ref,
                                                      d.template_object_ref, d.secret_object_ref)),
        })

    def project(self, draft: SchemeDraft, requester: AuthenticatedRequester, *, now_epoch: int) -> tuple[AuthoritativeProjection, ...]:
        try:
            self._binding.validate_intent(draft, requester)
            self._validate_transports()
            if type(now_epoch) is not int or now_epoch < 0:
                raise ValueError
            b = self._binding
            if type(b.source.request) is not DisabledAdDiscoveryCreateInput:
                raise ValueError
            with self._owner.authenticated():
                inspect_ad_credential_dependency(b.source.request, b.domain.create_binding, self._owner)
                observed = self._source_transport.inspect_current(b.source.request)
                if observed is not None and (not observed.create_readback_verified or not observed.active_directory_account_source):
                    raise ValueError
            return tuple(AuthoritativeProjection.from_mapping(
                contract=ad_discovery_projection_contract(cls), object_ref=ref,
                observed_at=now_epoch, fresh_until=now_epoch + 300,
                fields={"exists": False} if cls is ObjectClass.DISCOVERY_SOURCE_METADATA
                       and observed is None else {"exists": True, **fields},
            ) for ref, (cls, fields) in b.expected_objects().items())
        except Exception:
            raise PlanningContractError(_UNAVAILABLE) from None
