"""Protected, default-off build-29 approval M4 adapter and direct composition.

This distinct candidate neither promotes the 1.9.1 planning source nor issues
authorization. A future qualified protected provider must supply the exact
build-29 plan/authorization and authenticate ACK, native preservation, Profile,
and permission qualification for this binding. No main factory is inferred.
"""

from collections.abc import Callable
from dataclasses import dataclass
import time
from typing import Literal, Protocol

from v4_planning import (
    M4AdapterAmbiguous, M4AdapterDenied, M4AuthorizationDenied,
    M4AuthorizationVerifier, M4ExecutionAdapter, M4ExecutionAuthorization,
    M4ExecutionKernel, M4ExecutionPlan, M4ExecutionResult, M4ExecutionStateStore,
    canonical_digest,
)
from v4_planning.models import require_digest, require_ref

from .secret_approval_build29_contract import CONTRACT, compile_secret_approval_build29_enable_body
from .secret_approval_build29_http_transport import (
    FortiPamSecretApprovalBuild29HttpTransport, SecretApprovalBuild29PrivateState,
    SecretApprovalBuild29Readback, SecretApprovalBuild29WebFieldsBinding,
    SecretApprovalBuild29LinuxFieldsBinding,
    WEB_FIELDS_CONTRACT, _digest,
)
from .target_contract import DEFAULT_TEMPLATE


ACTION_ID = "secret-approval-build29-enable"
RESTORE_ACTION_ID = "secret-approval-build29-restore"
ACTION_VERSION = "0.1.0"
ADAPTER_REF = "fortipam-700-build29-secret-approval-http-candidate-v1"
_UNAVAILABLE = "Protected build-29 Secret approval execution is unavailable."


class SecretApprovalBuild29QualificationVerifier(Protocol):
    """Protected source authority, independent of the M4 intent authorizer.

    It must authenticate current ACK/native-preservation/Profile/permission
    evidence for the exact private binding and plan. Unknown evidence denies;
    callbacks, configuration, names and schema proof alone confer no maturity.
    """

    def verify(
        self, *, binding_digest: str, plan_digest: str, now_epoch: int,
    ) -> None: ...


class DenyAllSecretApprovalBuild29QualificationVerifier:
    def verify(
        self, *, binding_digest: str, plan_digest: str, now_epoch: int,
    ) -> None:
        del binding_digest, plan_digest, now_epoch
        raise M4AdapterDenied(_UNAVAILABLE)


@dataclass(frozen=True, slots=True, repr=False)
class SecretApprovalBuild29M4ExecutionBinding:
    """One sealed transport/target/baseline paired with existing M4 records."""

    plan: M4ExecutionPlan
    authorization: M4ExecutionAuthorization
    target_ref: str
    baseline: SecretApprovalBuild29PrivateState
    transport: FortiPamSecretApprovalBuild29HttpTransport
    operation: Literal["enable", "restore"] = "enable"


def secret_approval_build29_binding_digest(
    binding: SecretApprovalBuild29M4ExecutionBinding,
) -> str:
    """Bind every private transport selector; return no selector or material."""
    return secret_approval_build29_transport_binding_digest(binding.transport, binding.target_ref)


def secret_approval_build29_transport_binding_digest(
    transport: FortiPamSecretApprovalBuild29HttpTransport, target_ref: str,
) -> str:
    """Bind a sealed producer before promoting its signed planning chain."""
    require_ref(target_ref, "target_ref")
    mutation = transport._mutation
    if mutation is None:
        raise M4AuthorizationDenied(_UNAVAILABLE)
    payload = {
        "contract": CONTRACT, "target_ref": target_ref,
        "endpoint": transport._owner._config.base_url,
        "owner_name": transport._owner._owner_name,
        "identity_digest": _digest(transport._identity),
        "serial": transport._serial, "folder_path": transport._folder_path,
        "profile": mutation.approval_profile_name, "schema_digest": _digest(transport._schema),
        "web_fields": None if mutation.web_fields is None else {
            "contract": WEB_FIELDS_CONTRACT,
            "routing_digest": _digest({"template": "Web Account", "target": "", "web_url": mutation.web_fields.web_url}),
        },
    }
    if mutation.linux_fields is not None:
        if (type(mutation.linux_fields) is not SecretApprovalBuild29LinuxFieldsBinding
                or mutation.web_fields is not None
                or transport._linux_target_name != mutation.linux_fields.target_name):
            raise M4AuthorizationDenied(_UNAVAILABLE)
        acl_digest = mutation.expected_folder_acl_digest
        if not isinstance(acl_digest, str):
            raise M4AuthorizationDenied(_UNAVAILABLE)
        require_digest(acl_digest, "linux_folder_acl_digest")
        payload["linux_fields"] = {
            "contract": "fortipam-700-build29-linux-retained-fields-v1",
            "folder_acl_digest": acl_digest,
            "routing_digest": _digest({"template": DEFAULT_TEMPLATE,
                "target": transport._linux_target_name,
                "target_ipv4_address": mutation.linux_fields.target_ipv4_address}),
        }
    return canonical_digest(payload)


def secret_approval_build29_parameters_digest(binding_digest: str) -> str:
    require_digest(binding_digest, "binding_digest")
    return canonical_digest({
        "action_id": ACTION_ID, "action_version": ACTION_VERSION,
        "adapter_ref": ADAPTER_REF, "binding_digest": binding_digest,
        "need-approval": "enable", "need-approval-job": "disable",
        "bypass-approval": "preserve-current", "approval_profile_attached": True,
    })


def secret_approval_build29_restore_parameters_digest(
    binding_digest: str, original_state_digest: str,
) -> str:
    require_digest(binding_digest, "binding_digest")
    require_digest(original_state_digest, "original_state_digest")
    return canonical_digest({
        "action_id": RESTORE_ACTION_ID, "action_version": ACTION_VERSION,
        "adapter_ref": ADAPTER_REF, "binding_digest": binding_digest,
        "operation": "restore-owned-original", "original_state_digest": original_state_digest,
    })


class _SecretApprovalBuild29M4Adapter(M4ExecutionAdapter):
    def __init__(
        self, binding: SecretApprovalBuild29M4ExecutionBinding,
        check_qualification: Callable[[], None], check_postqualification: Callable[[], None],
        clock: Callable[[], int],
    ) -> None:
        self._binding = binding
        self._check = check_qualification
        self._check_post = check_postqualification
        self._clock = clock
        self._current: SecretApprovalBuild29PrivateState | None = None

    def read_current(self, plan: M4ExecutionPlan) -> str:
        del plan
        self._check()
        try:
            self._current = self._binding.transport.inspect_transition()
            return self._current.state_digest
        except Exception:
            raise M4AdapterAmbiguous(_UNAVAILABLE) from None

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        self._check()
        if self._current is None:
            raise M4AdapterDenied(_UNAVAILABLE)
        try:
            transport = self._binding.transport
            dispatch = (transport.restore_and_readback if self._binding.operation == "restore"
                        else transport.enable_and_readback)
            result = dispatch(
                self._current, expires_at=float(plan.expires_at),
                clock=lambda: float(self._clock()),
            )
            if type(result) is not SecretApprovalBuild29Readback or not result.verified:
                raise ValueError
        except Exception:
            # No automatic restore: a consumed/uncertain dispatch is reconciled.
            raise M4AdapterAmbiguous(_UNAVAILABLE) from None

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        del plan
        # Successful restore consumes ownership; qualification and the kernel's
        # exact original-state readback still apply after that consumption.
        self._check_post()
        try:
            return self._binding.transport.inspect_transition().state_digest
        except Exception:
            raise M4AdapterAmbiguous(_UNAVAILABLE) from None


class ProtectedSecretApprovalBuild29M4Runtime:
    def __init__(
        self, binding: SecretApprovalBuild29M4ExecutionBinding, *,
        authorization_verifier: M4AuthorizationVerifier,
        execution_store: M4ExecutionStateStore, authenticated_requester_digest: str,
        qualification_verifier: SecretApprovalBuild29QualificationVerifier | None = None,
        execution_enabled: bool = False, clock: Callable[[], int] | None = None,
    ) -> None:
        self._binding = binding
        self._authorizer = authorization_verifier
        self._store = execution_store
        self._requester = authenticated_requester_digest
        self._qualifier = qualification_verifier or DenyAllSecretApprovalBuild29QualificationVerifier()
        self._enabled = execution_enabled
        self._clock = clock or (lambda: int(time.time()))
        require_digest(authenticated_requester_digest, "authenticated_requester_digest")
        if type(execution_enabled) is not bool:
            raise M4AuthorizationDenied(_UNAVAILABLE)
        self._validate()
        self._binding_digest = secret_approval_build29_binding_digest(binding)

    def _validate(self) -> None:
        binding = self._binding
        if (type(binding) is not SecretApprovalBuild29M4ExecutionBinding
                or type(binding.transport) is not FortiPamSecretApprovalBuild29HttpTransport
                or type(binding.baseline) is not SecretApprovalBuild29PrivateState
                or type(binding.plan) is not M4ExecutionPlan
                or type(binding.authorization) is not M4ExecutionAuthorization):
            raise M4AuthorizationDenied(_UNAVAILABLE)
        require_ref(binding.target_ref, "target_ref")
        plan = binding.plan
        if binding.operation not in {"enable", "restore"}:
            raise M4AuthorizationDenied(_UNAVAILABLE)
        digest = secret_approval_build29_binding_digest(binding)
        transport = binding.transport
        mutation = transport._mutation
        assert mutation is not None
        try:
            proposed = compile_secret_approval_build29_enable_body(
                transport._projection(binding.baseline.approval_values), schema=transport._schema,
                identity=transport._identity, approval_profile_name=mutation.approval_profile_name,
            )
            if proposed != {
                "need-approval": "enable", "need-approval-job": "disable",
                "bypass-approval": binding.baseline.approval_values[2],
                "approval-profile": mutation.approval_profile_name,
            }:
                raise ValueError
        except Exception:
            raise M4AuthorizationDenied(_UNAVAILABLE) from None
        restore = binding.operation == "restore"
        parameters = (secret_approval_build29_restore_parameters_digest(digest, binding.baseline.state_digest)
                      if restore else secret_approval_build29_parameters_digest(digest))
        if (plan.action_id != (RESTORE_ACTION_ID if restore else ACTION_ID) or plan.action_version != ACTION_VERSION
                or plan.adapter_ref != ADAPTER_REF or plan.target_ref != binding.target_ref
                or plan.requester_digest != self._requester or plan.compensation_ref is not None
                or (plan.expected_state_digest if restore else plan.expected_current_digest) != binding.baseline.state_digest
                or plan.expected_state_digest == plan.expected_current_digest
                or plan.parameters_digest != parameters):
            raise M4AuthorizationDenied(_UNAVAILABLE)

    def inspect_execution_plan(self, authorization_ref: str) -> M4ExecutionPlan:
        if authorization_ref != self._binding.authorization.authorization_ref:
            raise M4AuthorizationDenied(_UNAVAILABLE)
        self._validate()
        return self._binding.plan

    def inspect_binding_digest(self, authorization_ref: str) -> str:
        self.inspect_execution_plan(authorization_ref)
        return self._binding_digest

    def _check_qualification(self, *, require_ownership: bool = True) -> None:
        self._validate()
        transport = self._binding.transport
        if (self._enabled is not True or transport._execution_enabled is not True
                or transport._mutation is None or transport._mutation.ack_verifier is None
                or not (
                    transport._linux_target_name is None
                    and type(transport._mutation.web_fields) is SecretApprovalBuild29WebFieldsBinding
                    and transport._mutation.linux_fields is None
                    or transport._linux_target_name is not None
                    and type(transport._mutation.linux_fields) is SecretApprovalBuild29LinuxFieldsBinding
                    and transport._mutation.linux_fields.target_name == transport._linux_target_name
                    and transport._mutation.web_fields is None
                )
                or secret_approval_build29_binding_digest(self._binding) != self._binding_digest):
            raise M4AdapterDenied(_UNAVAILABLE)
        if self._binding.operation == "restore" and require_ownership:
            ownership = transport._ownership
            if (ownership is None or ownership[0] != self._binding.baseline
                    or ownership[1].state_digest != self._binding.plan.expected_current_digest):
                raise M4AdapterDenied(_UNAVAILABLE)
        now = self._clock()
        if type(now) is not int or now < 0:
            raise M4AdapterDenied(_UNAVAILABLE)
        try:
            self._qualifier.verify(binding_digest=self._binding_digest,
                                   plan_digest=self._binding.plan.plan_digest, now_epoch=now)
        except Exception:
            raise M4AdapterDenied(_UNAVAILABLE) from None

    def execute_bound(
        self, authorization_ref: str, *, expected_binding_digest: str,
    ) -> M4ExecutionResult:
        self.inspect_execution_plan(authorization_ref)
        if expected_binding_digest != self._binding_digest:
            raise M4AuthorizationDenied(_UNAVAILABLE)
        # Reject unavailable product qualification before reserving an M4 claim
        # or invoking any Owner read. The adapter repeats this boundary at each step.
        self._check_qualification()
        return M4ExecutionKernel(
            _SecretApprovalBuild29M4Adapter(
                self._binding, self._check_qualification,
                lambda: self._check_qualification(require_ownership=False), self._clock,
            ),
            self._authorizer, self._store, clock=self._clock,
        ).execute(self._binding.plan, self._binding.authorization)


def assemble_secret_approval_build29_m4_runtime(
    binding: SecretApprovalBuild29M4ExecutionBinding, *,
    authorization_verifier: M4AuthorizationVerifier,
    execution_store: M4ExecutionStateStore, authenticated_requester_digest: str,
    qualification_verifier: SecretApprovalBuild29QualificationVerifier | None = None,
    execution_enabled: bool = False, clock: Callable[[], int] | None = None,
) -> ProtectedSecretApprovalBuild29M4Runtime:
    """Real direct composition; never issue authority or enable/register a Tool."""
    return ProtectedSecretApprovalBuild29M4Runtime(
        binding, authorization_verifier=authorization_verifier, execution_store=execution_store,
        authenticated_requester_digest=authenticated_requester_digest,
        qualification_verifier=qualification_verifier, execution_enabled=execution_enabled, clock=clock,
    )
