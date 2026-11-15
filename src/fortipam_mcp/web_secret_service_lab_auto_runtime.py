"""Protected BP007 Web-service runner factory for the existing onboarding entry."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from urllib.parse import urlsplit

from v4_planning import (
    M4AuthorizationDenied,
    M4ExecutionAuthorization,
    M4ExecutionPlan,
    M4ExecutionStateStore,
    ObjectClass,
    canonical_digest,
)
from v4_planning.canonical import CanonicalValue
from v4_planning.models import (
    ConfirmationRecord,
    FinalIntentSummary,
    PreparedPlan,
    SchemeDraft,
    require_ref,
)

from .approval_profile_ssh_transport import (
    ApprovalProfileSshTransportConfig,
    _read_password_file,
    _value_for_prefix,
)
from .m4_execution_store import PersistentM4ExecutionStateStore
from .onboarding_action_coordinator import BoundFixedActionRunner
from .secret_approval_m4_authorization import SecretApprovalPlanningChainReader
from .secret_create_lab_auto_runtime import _read_owner_only_authority_key
from .secret_onboarding_projection_source import (
    SecretOnboardingProductBinding,
    WebSecretOnboardingBinding,
)
from .v4_plan_runtime import V4PlanningPrincipal
from .web_secret_service_m4_adapter import WebSecretServiceBinding, WebServiceReader
from .web_secret_service_m4_composition import ExactWebSecretServiceM4RunnerFactory
from .web_secret_service_m4_authorization import validate_web_secret_service_lab_auto_source
from .web_secret_service_m4_runtime import (
    ProtectedWebSecretServiceM4Runtime,
    WebSecretServiceExecutionBinding,
)
from .web_secret_service_m4_adapter import ACTION_ID, ACTION_VERSION, ADAPTER_REF, parameters_digest, state_digest
from .web_secret_service_ssh_transport import (
    API_UNAVAILABLE_REASON,
    FortiPamWebSecretServiceSshTransport,
)


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_WEB_SECRET_SERVICE_"
_UNAVAILABLE = "Web Secret service lab-auto composition is unavailable."


class WebSecretServiceLabAutoConfigurationError(ValueError):
    """Raised for an incomplete private BP007 fallback configuration."""


def _required(environment: Mapping[str, str], suffix: str) -> str:
    value = _value_for_prefix(environment, ENV_PREFIX, suffix)
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError
    return value


def _absolute_path(environment: Mapping[str, str], suffix: str) -> Path:
    path = Path(_required(environment, suffix))
    if not path.is_absolute():
        raise ValueError
    return path


def _metadata_target_matches_ssh_host(
    metadata_base_url: str, environment: Mapping[str, str],
) -> bool:
    """Require the REST observer and fixed writer to address the same appliance."""

    try:
        read_host = urlsplit(metadata_base_url).hostname
        write_host = _required(environment, "SSH_HOST")
        return (
            isinstance(read_host, str)
            and read_host.rstrip(".").casefold() == write_host.rstrip(".").casefold()
        )
    except (TypeError, ValueError):
        return False


def load_web_secret_service_ssh_transport(
    environment: Mapping[str, str] | None = None,
) -> FortiPamWebSecretServiceSshTransport:
    """Load only the named API-unavailable SSH fallback for the fixed action."""

    env = os.environ if environment is None else environment
    try:
        if _value_for_prefix(env, ENV_PREFIX, "ENABLED") != "true":
            raise ValueError
        if _value_for_prefix(env, ENV_PREFIX, "API_UNAVAILABLE_REASON") != API_UNAVAILABLE_REASON:
            raise ValueError
        host = _value_for_prefix(env, ENV_PREFIX, "SSH_HOST")
        username = _value_for_prefix(env, ENV_PREFIX, "SSH_USERNAME")
        password_file = _value_for_prefix(env, ENV_PREFIX, "SSH_PASSWORD_FILE")
        known_hosts_file = _value_for_prefix(env, ENV_PREFIX, "SSH_KNOWN_HOSTS_FILE")
        port = int(_value_for_prefix(env, ENV_PREFIX, "SSH_PORT") or "22")
        timeout = float(_value_for_prefix(env, ENV_PREFIX, "SSH_TIMEOUT_SECONDS") or "15")
        if not all(
            isinstance(value, str)
            for value in (host, username, password_file, known_hosts_file)
        ):
            raise ValueError
        assert isinstance(host, str)
        assert isinstance(username, str)
        assert isinstance(password_file, str)
        assert isinstance(known_hosts_file, str)
        config = ApprovalProfileSshTransportConfig(
            host=host, port=port, username=username,
            password=_read_password_file(Path(password_file)),
            known_hosts_file=Path(known_hosts_file), timeout_seconds=timeout,
        )
        return FortiPamWebSecretServiceSshTransport(
            config, enabled=True, api_unavailable_reason=API_UNAVAILABLE_REASON,
        )
    except Exception as exc:
        raise WebSecretServiceLabAutoConfigurationError(_UNAVAILABLE) from exc


LAB_AUTO_WEB_SECRET_SERVICE_AUTHORITY_REF = "fortipam-mcp-lab-auto-web-secret-service"
LAB_AUTO_WEB_SECRET_SERVICE_TTL_SECONDS = 60


@dataclass(frozen=True, slots=True, repr=False)
class _LabAutoArtifacts:
    binding: WebSecretServiceExecutionBinding
    audit_attributes: Mapping[str, bool]


class LabAutoWebSecretServicePromoter:
    """Derive one fixed BP007 M4 record from trusted C/P/E state only."""

    def __init__(self, authority_key: bytes, *, authorized_environment_ref: str,
                 authorized_scope_ref: str) -> None:
        try:
            if type(authority_key) is not bytes or len(authority_key) < 32:
                raise ValueError
            self._environment_ref = require_ref(authorized_environment_ref, "environment_ref")
            self._scope_ref = require_ref(authorized_scope_ref, "scope_ref")
        except Exception:
            raise M4AuthorizationDenied(_UNAVAILABLE) from None
        self._authority_key = bytes(authority_key)

    def promote(self, summary: FinalIntentSummary, confirmation: ConfirmationRecord,
                plan: PreparedPlan, service: WebSecretServiceBinding, *,
                onboarding_binding: WebSecretOnboardingBinding, now_epoch: int) -> _LabAutoArtifacts:
        try:
            if type(now_epoch) is not int or plan.environment_ref != self._environment_ref or plan.scope_ref != self._scope_ref:
                raise ValueError
            validate_web_secret_service_lab_auto_source(
                summary, confirmation, plan, service, onboarding_binding, now_epoch=now_epoch,
            )
            expires_at = min(
                now_epoch + LAB_AUTO_WEB_SECRET_SERVICE_TTL_SECONDS,
                plan.expires_at, summary.expires_at, confirmation.expires_at,
                *(change.fresh_until for change in summary.object_changes),
            )
            if now_epoch >= expires_at:
                raise ValueError
            line = plan.lines[0]
            context = {
                "confirmation_digest": plan.confirmation_digest,
                "plan_digest": plan.plan_digest,
                "requester_digest": plan.requester_digest,
                "target_ref": line.target_ref,
            }
            approval_digest = self._mac("policy-approval", context)
            idempotency_digest = self._mac("idempotency", context)
            values: dict[str, CanonicalValue] = {
                "action_id": ACTION_ID, "action_version": ACTION_VERSION,
                "adapter_ref": ADAPTER_REF, "approval_digest": approval_digest,
                "compensation_ref": None, "confirmation_digest": plan.confirmation_digest,
                "expected_current_digest": state_digest(service, enabled=False),
                "expected_state_digest": state_digest(service, enabled=True),
                "expires_at": expires_at, "idempotency_digest": idempotency_digest,
                "parameters_digest": parameters_digest(service), "plan_ref": plan.plan_ref,
                "requester_digest": plan.requester_digest, "revision": plan.revision,
                "summary_digest": plan.summary_digest, "target_ref": line.target_ref,
            }
            m4_plan = M4ExecutionPlan(
                plan_ref=plan.plan_ref, revision=plan.revision, action_id=ACTION_ID,
                action_version=ACTION_VERSION, adapter_ref=ADAPTER_REF,
                target_ref=line.target_ref, requester_digest=plan.requester_digest,
                summary_digest=plan.summary_digest, confirmation_digest=plan.confirmation_digest,
                approval_digest=approval_digest, parameters_digest=parameters_digest(service),
                expected_current_digest=state_digest(service, enabled=False),
                expected_state_digest=state_digest(service, enabled=True),
                idempotency_digest=idempotency_digest, expires_at=expires_at,
                compensation_ref=None, plan_digest=canonical_digest(values),
            )
            authorization_ref = "lab-auto-web-service-auth-" + self._mac(
                "authorization", {"plan": m4_plan.plan_digest},
            )
            approver_digest = self._mac(
                "authority", {"ref": LAB_AUTO_WEB_SECRET_SERVICE_AUTHORITY_REF},
            )
            authorization_values: dict[str, CanonicalValue] = {
                "approval_digest": approval_digest,
                "approval_ref": LAB_AUTO_WEB_SECRET_SERVICE_AUTHORITY_REF,
                "approver_digest": approver_digest,
                "authorization_ref": authorization_ref,
                "confirmation_digest": plan.confirmation_digest,
                "confirmation_ref": plan.confirmation_ref, "execution_authorized": True,
                "expires_at": expires_at, "issued_at": now_epoch, "one_time": True,
                "plan_digest": m4_plan.plan_digest, "plan_ref": m4_plan.plan_ref,
                "requester_digest": m4_plan.requester_digest,
            }
            authorization = M4ExecutionAuthorization(
                authorization_ref=authorization_ref, plan_ref=m4_plan.plan_ref,
                plan_digest=m4_plan.plan_digest, requester_digest=m4_plan.requester_digest,
                confirmation_ref=plan.confirmation_ref, confirmation_digest=plan.confirmation_digest,
                approval_ref=LAB_AUTO_WEB_SECRET_SERVICE_AUTHORITY_REF,
                approval_digest=approval_digest,
                approver_digest=approver_digest,
                issued_at=now_epoch, expires_at=expires_at, one_time=True,
                execution_authorized=True,
                authorization_digest=canonical_digest(authorization_values),
            )
            return _LabAutoArtifacts(
                WebSecretServiceExecutionBinding(m4_plan, authorization, service),
                MappingProxyType({"lab_auto": True}),
            )
        except M4AuthorizationDenied:
            raise
        except Exception:
            raise M4AuthorizationDenied(_UNAVAILABLE) from None

    def _mac(self, purpose: str, value: Mapping[str, object]) -> str:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        return hmac.new(
            self._authority_key,
            b"fortipam-web-secret-service-lab-auto-v1\x00" + purpose.encode() + b"\x00" + encoded,
            hashlib.sha256,
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class _FixedBindingResolver:
    binding: WebSecretServiceExecutionBinding

    def resolve_execution_binding(self, authorization_ref: str) -> WebSecretServiceExecutionBinding:
        if authorization_ref != self.binding.authorization.authorization_ref:
            raise M4AuthorizationDenied(_UNAVAILABLE)
        return self.binding


class _PinnedLabAutoAuthorizationVerifier:
    def __init__(self, binding: WebSecretServiceExecutionBinding) -> None:
        self._binding = binding

    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        expected = self._binding
        if (
            type(now_epoch) is not int or plan != expected.plan
            or authorization != expected.authorization
            or canonical_digest(plan.canonical_content()) != plan.plan_digest
            or canonical_digest(authorization.canonical_content()) != authorization.authorization_digest
            or now_epoch < authorization.issued_at or now_epoch >= authorization.expires_at
            or now_epoch >= plan.expires_at
        ):
            raise M4AuthorizationDenied(_UNAVAILABLE)


def _assemble_lab_auto_web_secret_service_m4_runner_factory(
    *, planning: SecretApprovalPlanningChainReader,
    promoter: LabAutoWebSecretServicePromoter,
    onboarding_binding: WebSecretOnboardingBinding,
    service_binding: WebSecretServiceBinding,
    source_plan_ref: str, authenticated_requester_digest: str,
    read_transport: WebServiceReader, write_transport: FortiPamWebSecretServiceSshTransport,
    execution_store: M4ExecutionStateStore, clock: Callable[[], int],
) -> ExactWebSecretServiceM4RunnerFactory:
    try:
        now_epoch = clock()
        if type(now_epoch) is not int:
            raise ValueError
        plan = planning.get_plan(source_plan_ref)
        if plan.requester_digest != authenticated_requester_digest:
            raise ValueError
        artifacts = promoter.promote(
            planning.get_summary(plan.summary_ref, plan.summary_revision),
            planning.get_confirmation(plan.confirmation_ref), plan, service_binding,
            onboarding_binding=onboarding_binding, now_epoch=now_epoch,
        )
        runtime = ProtectedWebSecretServiceM4Runtime(
            _FixedBindingResolver(artifacts.binding),
            _PinnedLabAutoAuthorizationVerifier(artifacts.binding), execution_store,
            read_transport, write_transport,
            authenticated_requester_digest=authenticated_requester_digest, clock=clock,
        )
        return ExactWebSecretServiceM4RunnerFactory(plan, onboarding_binding, artifacts.binding, runtime)
    except M4AuthorizationDenied:
        raise
    except Exception:
        raise M4AuthorizationDenied(_UNAVAILABLE) from None


class LabAutoWebSecretServiceRunnerFactory:
    """Derive one local-policy BP007 runner only after C/P/E resolution."""

    def __init__(
        self, *, planning: SecretApprovalPlanningChainReader,
        promoter: LabAutoWebSecretServicePromoter, reader: WebServiceReader,
        writer: FortiPamWebSecretServiceSshTransport,
        execution_store: M4ExecutionStateStore,
        authorized_environment_ref: str, authorized_scope_ref: str,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._planning = planning
        self._promoter = promoter
        self._reader = reader
        self._writer = writer
        self._store = execution_store
        self._environment_ref = authorized_environment_ref
        self._scope_ref = authorized_scope_ref
        self._clock = clock or (lambda: int(time.time()))

    def bind(
        self, plan: PreparedPlan, line_ref: str, principal: V4PlanningPrincipal,
        *, draft: SchemeDraft | None = None,
        onboarding_binding: SecretOnboardingProductBinding | None = None,
    ) -> BoundFixedActionRunner:
        try:
            if (
                not isinstance(onboarding_binding, WebSecretOnboardingBinding)
                or onboarding_binding.service_object_ref is None
                or onboarding_binding.existing_secret_id is None
                or draft is None or plan.requester_digest != principal.requester.digest
                or plan.environment_ref != self._environment_ref
                or plan.scope_ref != self._scope_ref
                or len(plan.lines) != 1 or plan.lines[0].line_ref != line_ref
            ):
                raise ValueError
            service = _service_from_confirmed_summary(
                self._planning.get_summary(plan.summary_ref, plan.summary_revision),
                onboarding_binding,
            )
            factory = _assemble_lab_auto_web_secret_service_m4_runner_factory(
                planning=self._planning, promoter=self._promoter,
                onboarding_binding=onboarding_binding, service_binding=service,
                source_plan_ref=plan.plan_ref,
                authenticated_requester_digest=principal.requester.digest, read_transport=self._reader,
                write_transport=self._writer, execution_store=self._store,
                clock=self._clock,
            )
            if factory.source_plan != plan:
                raise ValueError
            return factory.bind(plan, line_ref, principal, draft=draft,
                                onboarding_binding=onboarding_binding)
        except Exception:
            raise M4AuthorizationDenied(_UNAVAILABLE) from None


def _service_from_confirmed_summary(
    summary: FinalIntentSummary, onboarding: WebSecretOnboardingBinding,
) -> WebSecretServiceBinding:
    try:
        changes = [
            item for item in summary.object_changes
            if item.object_class is ObjectClass.WEB_SECRET_SERVICE_BINDING
        ]
        if (
            len(changes) != 1 or onboarding.service_object_ref is None
            or onboarding.existing_secret_id is None
            or changes[0].object_ref != onboarding.service_object_ref
            or dict(changes[0].current_fields) != {
                "exists": True, "http_service_enabled": False,
            }
            or dict(changes[0].expected_fields) != {
                "exists": True, "http_service_enabled": True,
            }
        ):
            raise ValueError
        return WebSecretServiceBinding(
            onboarding.service_object_ref, onboarding.folder_path,
            onboarding.secret_name, onboarding.existing_secret_id,
        )
    except Exception:
        raise M4AuthorizationDenied(_UNAVAILABLE) from None


def build_lab_auto_web_secret_service_runner_factory(
    environment: Mapping[str, str], *, planning: SecretApprovalPlanningChainReader,
    reader: WebServiceReader, metadata_base_url: str,
    clock: Callable[[], int] | None = None,
) -> LabAutoWebSecretServiceRunnerFactory:
    """Load local lab authority, persistent ledger, and fixed SSH fallback."""

    try:
        if not _metadata_target_matches_ssh_host(metadata_base_url, environment):
            raise ValueError
        authority_key = _read_owner_only_authority_key(
            _absolute_path(environment, "AUTHORITY_KEY_FILE")
        )
        database = _absolute_path(environment, "EXECUTION_STATE_DB")
        key = _absolute_path(environment, "EXECUTION_STATE_HMAC_KEY_FILE")
        if len({_absolute_path(environment, "AUTHORITY_KEY_FILE"), database, key}) != 3:
            raise ValueError
        environment_ref = require_ref(
            _required(environment, "AUTHORIZED_ENVIRONMENT_REF"),
            "authorized_secret_environment_ref",
        )
        scope_ref = require_ref(
            _required(environment, "AUTHORIZED_SCOPE_REF"),
            "authorized_secret_scope_ref",
        )
        return LabAutoWebSecretServiceRunnerFactory(
            planning=planning,
            promoter=LabAutoWebSecretServicePromoter(
                authority_key,
                authorized_environment_ref=environment_ref,
                authorized_scope_ref=scope_ref,
            ),
            reader=reader, writer=load_web_secret_service_ssh_transport(environment),
            execution_store=PersistentM4ExecutionStateStore(database, key),
            authorized_environment_ref=environment_ref, authorized_scope_ref=scope_ref,
            clock=clock,
        )
    except Exception:
        raise M4AuthorizationDenied(_UNAVAILABLE) from None


__all__ = [
    "ENV_PREFIX", "LabAutoWebSecretServiceRunnerFactory",
    "WebSecretServiceLabAutoConfigurationError",
    "build_lab_auto_web_secret_service_runner_factory",
    "load_web_secret_service_ssh_transport",
]
