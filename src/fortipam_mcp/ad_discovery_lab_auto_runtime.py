"""Fixed standing-lab authorization for one BP014 AD Source create candidate."""

from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
import hashlib
import hmac
import json

from v4_planning import (
    AuthoritativeProjection, ChangeKind, M4AuthorizationDenied,
    M4ExecutionAuthorization, M4ExecutionPlan, ObjectClass, PlanState,
    PreparedPlan, SchemeDraft, SchemeId, canonical_digest,
)
from v4_planning.models import require_ref

from .ad_discovery_projection_source import (
    AdDiscoveryPlanningBinding, AdDiscoveryPlanningSource, CONTRACT_ID,
    ad_discovery_projection_contract,
)
from .discovery_entry_create_http_transport import FortiPamDiscoveryEntryCreateHttpTransport
from .discovery_entry_m4_adapter import ACTION_ID, ACTION_VERSION
from .discovery_entry_m4_runtime import DiscoveryEntryExecutionBinding
from .m4_execution_store import PersistentM4ExecutionStateStore
from .onboarding_action_coordinator import BoundFixedActionRunner, FixedActionResolutionError
from .owner_discovery_runtime import OwnerAuthenticatedAdDiscoveryRuntime
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from .v4_plan_runtime import V4PlanningPrincipal


AD_DISCOVERY_LAB_AUTHORITY_REF = "ad-discovery-standing-lab-authority-v1"
AD_DISCOVERY_LAB_POLICY = "fixed_ad_source_create_lab_auto"
_TTL_SECONDS = 300
_DENIED = "Fixed AD Discovery standing lab authorization is unavailable."


@dataclass(frozen=True, slots=True, repr=False)
class AdDiscoveryLabAutoArtifacts:
    plan: M4ExecutionPlan
    authorization: M4ExecutionAuthorization
    discovery_binding_digest: str
    policy_decision_digest: str
    scope_digest: str
    audience_digest: str


def _source_state(binding: AdDiscoveryPlanningBinding, *, exists: bool) -> str:
    fields = binding.expected_objects()[binding.source_object_ref][1]
    return AuthoritativeProjection.from_mapping(
        contract=ad_discovery_projection_contract(ObjectClass.DISCOVERY_SOURCE_METADATA),
        object_ref=binding.source_object_ref, observed_at=0, fresh_until=1,
        fields={"exists": True, **fields} if exists else {"exists": False},
    ).state_digest


class AdDiscoveryLabAutoPromoter:
    """An explicit server-held lab authority; confirmation grants no write rights."""

    def __init__(self, authority_key: bytes, *, projection_source: AdDiscoveryPlanningSource,
                 authorized_environment_ref: str, authorized_scope_ref: str,
                 standing_lab_authorization: bool = False,
                 authority_ref: str = AD_DISCOVERY_LAB_AUTHORITY_REF) -> None:
        try:
            if (type(authority_key) is not bytes or len(authority_key) < 32
                or type(projection_source) is not AdDiscoveryPlanningSource
                or type(standing_lab_authorization) is not bool):
                raise ValueError
            require_ref(authority_ref, "AD standing authority reference")
            require_ref(authorized_environment_ref, "AD authorized environment")
            require_ref(authorized_scope_ref, "AD authorized scope")
            binding = projection_source._binding
            if (binding.domain.environment_ref != authorized_environment_ref
                or binding.domain.scope_ref != authorized_scope_ref):
                raise ValueError
        except Exception:
            raise FixedActionResolutionError("fixed_action_runner_promotion_context", _DENIED) from None
        self._key = bytes(authority_key)
        self._source = projection_source
        self._binding = binding
        self._environment = authorized_environment_ref
        self._scope = authorized_scope_ref
        self._authority = authority_ref
        self._standing = standing_lab_authorization

    def __repr__(self) -> str:
        return "<AdDiscoveryLabAutoPromoter protected>"

    def _mac(self, purpose: str, values: Mapping[str, object]) -> str:
        body = json.dumps(values, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        return hmac.new(self._key, b"fortipam-ad-discovery-lab-auto-v1\x00" + purpose.encode()
                        + b"\x00" + body, hashlib.sha256).hexdigest()

    def promote(self, plan: PreparedPlan, line_ref: str, principal: V4PlanningPrincipal, *,
                draft: SchemeDraft, discovery_binding: AdDiscoveryPlanningBinding,
                now_epoch: int) -> AdDiscoveryLabAutoArtifacts:
        try:
            if not self._standing:
                raise ValueError
            if (type(plan) is not PreparedPlan or type(principal) is not V4PlanningPrincipal
                or type(discovery_binding) is not AdDiscoveryPlanningBinding
                or discovery_binding != self._binding or self._source._binding != self._binding
                or plan.plan_digest != canonical_digest(plan.canonical_content())
                or plan.state is not PlanState.PREPARED_NON_EXECUTABLE
                or plan.scheme_id is not SchemeId.BULK_ONBOARDING or plan.scheme_version != "1.0.0"
                or plan.environment_ref != self._environment or plan.scope_ref != self._scope
                or plan.registry_schema_version != draft.registry_schema_version
                or plan.requester_digest != principal.requester.digest
                or plan.dispatchable or plan.adapter_registry_bound
                or plan.executor_runtime_packaged or plan.executor_mcp_exposed
                or draft.risk_class != "medium" or len(plan.lines) != 1):
                raise ValueError
            digest = self._source.inspect_private_binding_digest(draft, principal.requester)
            line = plan.lines[0]
            if (line.line_ref != line_ref or line.target_class is not ObjectClass.DISCOVERY_SOURCE_METADATA
                or line.target_ref != discovery_binding.source_object_ref
                or line.change_kind is not ChangeKind.CREATE or line.depends_on
                or line.action_family_ref != "discovery-and-smart-association-plan"
                or line.action_family_version != "1.0.0" or line.dispatchable or line.adapter != "none"
                or line.projection_contract_ref != CONTRACT_ID
                or line.expected_current_digest != _source_state(discovery_binding, exists=False)
                or line.expected_state_digest != _source_state(discovery_binding, exists=True)):
                raise ValueError
            expires = min(plan.expires_at, plan.created_at + _TTL_SECONDS)
            if type(now_epoch) is not int or now_epoch < plan.created_at or now_epoch >= expires:
                raise FixedActionResolutionError("fixed_action_runner_promotion_freshness", _DENIED)
            context = {
                "authority_ref": self._authority, "policy_mode": AD_DISCOVERY_LAB_POLICY,
                "standing_lab_authorization": True, "parent_plan_digest": plan.plan_digest,
                "line_ref": line_ref, "source_object_ref": line.target_ref,
                "private_binding_digest": digest, "requester_digest": plan.requester_digest,
                "transport_namespace_digest": principal.transport_namespace_digest,
                "environment_ref": plan.environment_ref, "scope_ref": plan.scope_ref,
                "audience_ref": draft.audience_ref, "expires_at": expires,
                "draft_digest": hashlib.sha256(json.dumps(asdict(draft), sort_keys=True,
                    separators=(",", ":"), allow_nan=False).encode()).hexdigest(),
            }
            policy = self._mac("policy", context)
            approval = self._mac("approval", {**context, "policy_decision_digest": policy})
            source = discovery_binding.source
            # A changed client context must conflict with the same durable claim,
            # rather than creating another namespace for the parent Source line.
            idempotency = self._mac("idempotency", {
                "parent_plan_digest": plan.plan_digest, "line_ref": line_ref,
            })
            values = {
                "plan_ref": plan.plan_ref, "revision": plan.revision, "action_id": ACTION_ID,
                "action_version": ACTION_VERSION, "adapter_ref": source.adapter_ref,
                "target_ref": "discovery-entry", "requester_digest": plan.requester_digest,
                "summary_digest": plan.summary_digest, "confirmation_digest": plan.confirmation_digest,
                "approval_digest": approval, "parameters_digest": source.parameters_digest,
                "expected_current_digest": source.state_digest(exists=False),
                "expected_state_digest": source.state_digest(exists=True),
                "idempotency_digest": idempotency,
                "expires_at": expires, "compensation_ref": None,
            }
            m4_plan = M4ExecutionPlan(
                plan_ref=plan.plan_ref, revision=plan.revision, action_id=ACTION_ID,
                action_version=ACTION_VERSION, adapter_ref=source.adapter_ref,
                target_ref="discovery-entry", requester_digest=plan.requester_digest,
                summary_digest=plan.summary_digest, confirmation_digest=plan.confirmation_digest,
                approval_digest=approval, parameters_digest=source.parameters_digest,
                expected_current_digest=source.state_digest(exists=False),
                expected_state_digest=source.state_digest(exists=True),
                idempotency_digest=idempotency, expires_at=expires,
                compensation_ref=None, plan_digest=canonical_digest(values),
            )
            auth_context = {**context, "m4_plan_digest": m4_plan.plan_digest}
            auth_values = {
                "authorization_ref": "ad-lab-auth-" + self._mac("authorization", auth_context),
                "plan_ref": m4_plan.plan_ref, "plan_digest": m4_plan.plan_digest,
                "requester_digest": plan.requester_digest,
                "confirmation_ref": plan.confirmation_ref, "confirmation_digest": plan.confirmation_digest,
                "approval_ref": "ad-lab-approval-" + self._mac("approval-ref", auth_context),
                "approval_digest": approval, "approver_digest": self._mac("approver", {"authority": self._authority}),
                "issued_at": plan.created_at, "expires_at": expires,
                "one_time": True, "execution_authorized": True,
            }
            authorization = M4ExecutionAuthorization(
                authorization_ref="ad-lab-auth-" + self._mac("authorization", auth_context),
                plan_ref=m4_plan.plan_ref, plan_digest=m4_plan.plan_digest,
                requester_digest=plan.requester_digest,
                confirmation_ref=plan.confirmation_ref, confirmation_digest=plan.confirmation_digest,
                approval_ref="ad-lab-approval-" + self._mac("approval-ref", auth_context),
                approval_digest=approval, approver_digest=self._mac("approver", {"authority": self._authority}),
                issued_at=plan.created_at, expires_at=expires, one_time=True, execution_authorized=True,
                authorization_digest=canonical_digest(auth_values),
            )
            return AdDiscoveryLabAutoArtifacts(m4_plan, authorization, digest, policy,
                canonical_digest(plan.scope_ref), canonical_digest(draft.audience_ref))
        except FixedActionResolutionError:
            raise
        except Exception:
            raise FixedActionResolutionError("fixed_action_runner_promotion", _DENIED) from None


class _FixedResolver:
    def __init__(self, artifacts: AdDiscoveryLabAutoArtifacts, binding: AdDiscoveryPlanningBinding) -> None:
        self._snapshot = DiscoveryEntryExecutionBinding(artifacts.plan, artifacts.authorization, binding.source)

    def resolve_execution_binding(self, authorization_ref: str) -> DiscoveryEntryExecutionBinding:
        if authorization_ref != self._snapshot.authorization.authorization_ref:
            raise M4AuthorizationDenied(_DENIED)
        return self._snapshot


class _StandingLabVerifier:
    def __init__(self, artifacts: AdDiscoveryLabAutoArtifacts) -> None:
        self._artifacts = artifacts

    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        a = self._artifacts
        if (type(plan) is not M4ExecutionPlan or type(authorization) is not M4ExecutionAuthorization
            or plan != a.plan or authorization != a.authorization
            or type(now_epoch) is not int or now_epoch < authorization.issued_at
            or now_epoch >= authorization.expires_at):
            raise M4AuthorizationDenied(_DENIED)


@dataclass(frozen=True, slots=True, repr=False)
class _AdDiscoveryRunner:
    line_ref: str
    depends_on: tuple[str, ...]
    discovery_binding_digest: str
    authorization_ref: str
    runtime: OwnerAuthenticatedAdDiscoveryRuntime
    parameters_digest: str

    def execute_bound(self) -> Mapping[str, object]:
        try:
            return self.runtime.execute_bound(self.authorization_ref,
                expected_binding_digest=self.parameters_digest).as_dict()
        except Exception:
            raise M4AuthorizationDenied(_DENIED) from None


class AdDiscoveryLabAutoRunnerFactory:
    def __init__(self, *, promoter: AdDiscoveryLabAutoPromoter,
                 execution_store: PersistentM4ExecutionStateStore,
                 source_transport: FortiPamDiscoveryEntryCreateHttpTransport,
                 owner_config: SecretMetadataHttpTransportConfig,
                 owner_credentials: Callable[[], tuple[str, str]], clock: Callable[[], int],
                 execution_gate_open: bool = False) -> None:
        if (type(promoter) is not AdDiscoveryLabAutoPromoter
            or type(execution_store) is not PersistentM4ExecutionStateStore
            or type(source_transport) is not FortiPamDiscoveryEntryCreateHttpTransport
            or type(owner_config) is not SecretMetadataHttpTransportConfig
            or type(execution_gate_open) is not bool or not callable(clock)
            or not callable(owner_credentials)
            or source_transport._config.base_url != owner_config.base_url
            or source_transport._config.ca_file != owner_config.ca_file
            or promoter._source._owner._config.base_url != owner_config.base_url
            or promoter._source._owner._config.ca_file != owner_config.ca_file):
            raise FixedActionResolutionError("fixed_action_runner_runtime_binding", _DENIED)
        self._promoter, self._store, self._writer = promoter, execution_store, source_transport
        self._owner_config, self._credentials = owner_config, owner_credentials
        self._clock, self._gate = clock, execution_gate_open

    def bind(self, plan: PreparedPlan, line_ref: str, principal: V4PlanningPrincipal, *,
             draft: SchemeDraft | None = None,
             discovery_binding: AdDiscoveryPlanningBinding | None = None) -> BoundFixedActionRunner:
        if not self._gate or draft is None or discovery_binding is None:
            raise FixedActionResolutionError("fixed_action_runner_promotion", _DENIED)
        planning_origin = self._promoter._source._owner._config
        if (planning_origin.base_url != self._owner_config.base_url
            or planning_origin.ca_file != self._owner_config.ca_file):
            raise FixedActionResolutionError("fixed_action_runner_runtime_binding", _DENIED)
        artifacts = self._promoter.promote(plan, line_ref, principal, draft=draft,
            discovery_binding=discovery_binding, now_epoch=self._clock())
        try:
            runtime = OwnerAuthenticatedAdDiscoveryRuntime(
                _FixedResolver(artifacts, discovery_binding), _StandingLabVerifier(artifacts),
                self._store, self._writer, self._owner_config, self._credentials,
                source_binding=discovery_binding.source, authenticated_requester_digest=plan.requester_digest,
                clock=self._clock, execution_gate_open=self._gate,
            )
            return _AdDiscoveryRunner(line_ref, (), artifacts.discovery_binding_digest,
                artifacts.authorization.authorization_ref, runtime, discovery_binding.source.parameters_digest)
        except Exception:
            raise FixedActionResolutionError("fixed_action_runner_runtime_binding", _DENIED) from None
