"""Opt-in same-process Web fixture composition for the existing onboarding entry.

The original factory retains C3/M4 creation and ACK capture. This wrapper owns
one resulting runner and its pre-association baseline until fixed recovery.
It adds no Tool, environment loader, main activation or source qualification.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
import hashlib
import http.client
from threading import RLock
import time
from typing import Any, Literal, TYPE_CHECKING

import httpx

from v4_planning import PreparedPlan, SchemeDraft
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_ref
from .m4_execution_store import PersistentM4ExecutionStateStore
from .onboarding_action_coordinator import BoundFixedActionRunner, FixedActionResolutionError
from .secret_approval_build29_totp_boundary import _pinned_tokens
from .secret_instruction_build29_api_preservation import _credential_pinned_tokens
from .secret_create_lab_auto_runtime import (FortiPam191LabAutoSecretCreateRunnerFactory,
    LAB_AUTO_SECRET_CREATE_WEB_700_CANDIDATE_PROFILE, LabAutoSecretCreatePromoter)
from .secret_metadata_http_transport import FortiPamSecretMetadataHttpTransport, SecretMetadataHttpTransportConfig
from .secret_onboarding_projection_source import WebSecretOnboardingBinding
from .v4_plan_runtime import V4PlanningPrincipal
from .web_secret_create_ack import WebSecretCreateAckCapture
from .web_secret_fixture_creation_capture import WebSecretFixtureCaptureRunner, WebSecretFixtureCaptureSettings
from .web_secret_fixture_recovery_authority import WebSecretFixtureRecoveryAuthority
from .web_secret_fixture_recovery_guard import WebSecretFixtureRecoveryGuard
from .web_secret_fixture_recovery_runtime import WebSecretFixtureRecoveryRuntime

if TYPE_CHECKING:
    from .onboarding_execution_mcp_action import ProtectedSecretOnboardingMcpAction
    from .secret_onboarding_projection_source import FortiPamSecretOnboardingProjectionSource
    from .v4_runtime_host import V4PlanHostComponents

_ERROR = "The private Web fixture lifecycle is unavailable."


class WebSecretFixtureLifecycleError(ValueError):
    """Categorical refusal; original consumed records are never adopted."""


class WebSecretFixtureLifecycleFactory(_OpaqueC3Object):
    """Existing onboarding factory protocol, one privately retained lab runner.

    Startup must provide separately qualified clear-source envelope templates
    (without a Secret selector) and the exact native DELETE status. The selector
    comes solely from the acknowledged creation. These pins are constraints,
    not evidence that live source qualification or object rights are satisfied.
    """
    def __init__(self, factory: FortiPam191LabAutoSecretCreateRunnerFactory, *,
            authority_key: bytes, environment_ref: str, scope_ref: str, audience_ref: str,
            credential_envelope: Mapping[str, str | int], totp_envelope: Mapping[str, str | int],
            delete_status: Literal["OK", "success"], execution_enabled: bool = False,
            client_factory: Callable[..., httpx.Client] = httpx.Client,
            connection_factory: Callable[..., Any] = http.client.HTTPSConnection,
            http_clock: Callable[[], float] = time.monotonic) -> None:
        try:
            if (type(factory) is not FortiPam191LabAutoSecretCreateRunnerFactory
                    or type(authority_key) is not bytes or not 32 <= len(authority_key) <= 4096
                    or type(execution_enabled) is not bool or type(delete_status) is not str
                    or delete_status not in {"OK", "success"}
                    or not all(callable(value) for value in (client_factory, connection_factory, http_clock))):
                raise ValueError
            for value in (environment_ref, scope_ref, audience_ref):
                if type(value) is not str: raise ValueError
                require_ref(value, "namespace_ref")
            capture = factory._web_fixture_capture
            if (type(capture) is not WebSecretFixtureCaptureSettings
                    or type(capture.ack_capture) is not WebSecretCreateAckCapture
                    or capture.ack_capture.observe_source
                    or capture.ack_capture.serial_digest != capture.serial_digest
                    or type(factory._execution_store) is not PersistentM4ExecutionStateStore
                    or factory._owner_credentials is not None
                    or factory._promoter.product_profile != LAB_AUTO_SECRET_CREATE_WEB_700_CANDIDATE_PROFILE
                    or (factory._promoter._environment_ref, factory._promoter._scope_ref) !=
                       (environment_ref, scope_ref)):
                raise ValueError
            self._factory: FortiPam191LabAutoSecretCreateRunnerFactory = factory
            self._capture: WebSecretFixtureCaptureSettings = capture
            self._store: PersistentM4ExecutionStateStore = factory._execution_store
            self._config: SecretMetadataHttpTransportConfig = factory._transport_config
            self._promoter: LabAutoSecretCreatePromoter = factory._promoter
            self._clock: Callable[[], int] = factory._clock
            self._credential: dict[str, str | int] = self._envelope(credential_envelope, capture.serial_digest, credential=True)
            self._totp: dict[str, str | int] = self._envelope(totp_envelope, capture.serial_digest)
            self._key: bytes = authority_key
            self._namespace: tuple[str, str, str] = environment_ref, scope_ref, audience_ref
            self._status: Literal["OK", "success"] = delete_status
            self._enabled: bool = execution_enabled
            self._client_factory: Callable[..., httpx.Client] = client_factory
            self._connection_factory: Callable[..., Any] = connection_factory
            self._http_clock: Callable[[], float] = http_clock
            self._runner: _FixtureRunner | None = None
            self._http_action: ProtectedSecretOnboardingMcpAction | None = None
            self._http_source: FortiPamSecretOnboardingProjectionSource | None = None
            self._http_transport: FortiPamSecretMetadataHttpTransport | None = None
            self._started: bool = False
            self._lock: RLock = RLock()
        except Exception:
            raise WebSecretFixtureLifecycleError(_ERROR) from None

    @staticmethod
    def _envelope(value: Mapping[str, str | int], serial_digest: str, *,
            credential: bool = False) -> dict[str, str | int]:
        if not isinstance(value, Mapping): raise ValueError
        pins = dict(value)
        required = {"http_method": "POST", "http_status": 200, "status": "OK"}
        if ("secret-id" in pins or "msg" not in pins
                or any(type(pins.get(key)) is not type(expected) or pins[key] != expected
                       for key, expected in required.items())):
            raise ValueError
        if credential:
            _credential_pinned_tokens(pins)
        else:
            _pinned_tokens(pins)
        if "serial" in pins and (type(pins["serial"]) is not str
                or hashlib.sha256(str(pins["serial"]).encode()).hexdigest() != serial_digest):
            raise ValueError
        return pins

    def _current(self) -> None:
        factory = self._factory
        if (not self._enabled or factory._web_fixture_capture is not self._capture
                or factory._execution_store is not self._store or factory._transport_config != self._config
                or factory._promoter is not self._promoter or factory._clock is not self._clock
                or factory._owner_credentials is not None
                or factory._promoter.product_profile != LAB_AUTO_SECRET_CREATE_WEB_700_CANDIDATE_PROFILE
                or (factory._promoter._environment_ref, factory._promoter._scope_ref) != self._namespace[:2]):
            raise ValueError
        if self._http_source is not None and (
                self._http_source._secret_transport is not self._http_transport
                or self._http_transport is None or self._http_transport._config != self._config):
            raise ValueError

    def execution_preflight_available(self) -> bool:
        try:
            self._current()
            return self._factory.execution_preflight_available()
        except Exception:
            return False

    def bind_http_actions(self, components: V4PlanHostComponents) -> tuple[None, ProtectedSecretOnboardingMcpAction]:
        """Use the existing trusted HTTP factory injection, without new tools."""
        from .onboarding_execution_mcp_action import ProtectedSecretOnboardingMcpAction
        from .secret_onboarding_projection_source import FortiPamSecretOnboardingProjectionSource
        from .v4_runtime_host import V4PlanHostComponents

        with self._lock:
            try:
                self._current()
                if (type(components) is not V4PlanHostComponents or self._http_action is not None
                        or self._started or components.access_domain_projection_source is not None):
                    raise ValueError
                source = components.secret_onboarding_projection_source
                if (type(source) is not FortiPamSecretOnboardingProjectionSource
                        or type(source._secret_transport) is not FortiPamSecretMetadataHttpTransport
                        or source._secret_transport._config != self._config):
                    raise ValueError
                action = ProtectedSecretOnboardingMcpAction(
                    components.plan_services, components.bind_secret_onboarding_action_coordinator(self),
                    authorized_environment_ref=self._namespace[0], authorized_scope_ref=self._namespace[1],
                    execution_enabled=True, policy_mode="lab_auto")
                components.plan_services.bind_secret_create_execution_preflight_probe(self.execution_preflight_available)
                self._http_source, self._http_transport = source, source._secret_transport
                self._http_action = action
                return None, action
            except Exception:
                raise WebSecretFixtureLifecycleError(_ERROR) from None

    def bind(self, plan: PreparedPlan, line_ref: str, principal: V4PlanningPrincipal, *,
            draft: SchemeDraft | None = None,
            onboarding_binding: object | None = None) -> BoundFixedActionRunner:
        with self._lock:
            try:
                self._current()
                if (self._started or type(plan) is not PreparedPlan or type(principal) is not V4PlanningPrincipal
                        or (plan.environment_ref, plan.scope_ref) != self._namespace[:2]
                        or plan.requester_digest != principal.requester.digest
                        or type(onboarding_binding) is not WebSecretOnboardingBinding):
                    raise ValueError
                self._started = True
                capture = self._factory.bind(plan, line_ref, principal, draft=draft,
                    onboarding_binding=onboarding_binding)
                if type(capture) is not WebSecretFixtureCaptureRunner: raise ValueError
                self._runner = _FixtureRunner(self, capture, principal)
                self._current()
                return self._runner
            except Exception:
                raise FixedActionResolutionError("fixed_action_runner_runtime_binding") from None

    def recover_once(self, principal: V4PlanningPrincipal) -> Mapping[str, object]:
        """Trusted acceptance code calls this for the same authenticated actor."""
        try:
            self._current()
            runner = self._runner
            if runner is None: raise ValueError
            return runner.recover_once(principal)
        except Exception:
            raise WebSecretFixtureLifecycleError(_ERROR) from None

    def bind_instruction_profile(self, reference: str, principal: V4PlanningPrincipal) -> None:
        """Bind a read constraint only; Profile custody/write authority are separate."""
        self._instruction_step(principal, "bind", reference)

    def check_instruction_applied_once(self, principal: V4PlanningPrincipal) -> None:
        self._instruction_step(principal, "applied")

    def check_instruction_restored_once(self, principal: V4PlanningPrincipal) -> None:
        self._instruction_step(principal, "restored")

    def _instruction_step(self, principal: V4PlanningPrincipal,
            phase: Literal["bind", "applied", "restored"], reference: str = "") -> None:
        try:
            self._current()
            if self._runner is None: raise ValueError
            self._runner.check_instruction_step(principal, phase, reference)
        except Exception:
            raise WebSecretFixtureLifecycleError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._enabled = False
            self._key = b""
            runner = self._runner
            if self._http_action is not None:
                self._http_action._execution_enabled = False
        if runner is not None: runner.close()


class _FixtureRunner(_OpaqueC3Object):
    def __init__(self, owner: WebSecretFixtureLifecycleFactory, capture: WebSecretFixtureCaptureRunner,
            principal: V4PlanningPrincipal) -> None:
        self.line_ref, self.depends_on = capture.line_ref, capture.depends_on
        self._owner, self._capture, self._principal = owner, capture, principal
        self._guard_source: WebSecretFixtureRecoveryGuard | None = None
        self._authority: WebSecretFixtureRecoveryAuthority | None = None
        self._runtime: WebSecretFixtureRecoveryRuntime | None = None
        self._result: dict[str, object] | None = None
        self._state = "bound"
        self._lock = RLock()

    def execute_bound(self) -> Mapping[str, object]:
        with self._lock:
            try:
                self._owner._current()
                if self._state in {"baseline", "recovered"} and self._result is not None:
                    return {**self._result, "idempotent_replay": True}
                if self._state != "bound": raise ValueError
                self._state = "creating"
                result = dict(self._capture.execute_bound())
                self._owner._current()
                if result != {"outcome": "succeeded", "verification": "verified",
                        "compensation": "not_requested", "idempotent_replay": False}:
                    self._state = "failed"
                    return result
                record = self._capture._record
                original = record.read_acknowledged_creation()
                if record._execution_store is not self._owner._store: raise ValueError
                identifier = original.creation.native_secret_id
                owner = self._owner
                guard = WebSecretFixtureRecoveryGuard(record,
                    credential_envelope={**owner._credential, "secret-id": identifier},
                    totp_envelope={**owner._totp, "secret-id": identifier},
                    client_factory=owner._client_factory, http_clock=owner._http_clock, clock=owner._clock)
                self._guard_source = guard
                authority = WebSecretFixtureRecoveryAuthority(guard, authority_key=owner._key,
                    environment_ref=owner._namespace[0], scope_ref=owner._namespace[1],
                    audience_ref=owner._namespace[2], requester_digest=self._principal.requester.digest,
                    transport_digest=self._principal.transport_namespace_digest, execution_enabled=True)
                self._authority = authority
                self._runtime = WebSecretFixtureRecoveryRuntime(guard, authorization_verifier=authority,
                    delete_status=owner._status, execution_enabled=True, connection_factory=owner._connection_factory)
                guard.capture_baseline_once()
                self._owner._current()
                self._result = result
                self._state = "baseline"
                return result
            except Exception:
                if self._state == "creating": self._state = "failed"
                raise WebSecretFixtureLifecycleError(_ERROR) from None

    def recover_once(self, principal: V4PlanningPrincipal) -> Mapping[str, object]:
        with self._lock:
            try:
                self._owner._current()
                if (self._state != "baseline" or self._runtime is None or self._authority is None
                        or type(principal) is not V4PlanningPrincipal
                        or (principal.requester.digest, principal.transport_namespace_digest) !=
                           (self._principal.requester.digest, self._principal.transport_namespace_digest)):
                    raise ValueError
                self._state = "recovering"
                issued = self._authority.issue(self._runtime, requester_digest=principal.requester.digest,
                    transport_digest=principal.transport_namespace_digest)
                result = self._runtime.execute(issued.plan, issued.authorization).as_dict()
                self._state = "recovered" if result["outcome"] == "succeeded" else "reconciliation"
                return result
            except Exception:
                if self._state == "recovering": self._state = "failed"
                raise WebSecretFixtureLifecycleError(_ERROR) from None

    def check_instruction_step(self, principal: V4PlanningPrincipal,
            phase: Literal["bind", "applied", "restored"], reference: str) -> None:
        with self._lock:
            guard = self._guard_source
            expected_state = "applied" if phase == "restored" else "baseline"
            if (guard is None or self._state != expected_state or phase not in {"bind", "applied", "restored"}
                    or type(principal) is not V4PlanningPrincipal
                    or (principal.requester.digest, principal.transport_namespace_digest) !=
                       (self._principal.requester.digest, self._principal.transport_namespace_digest)):
                raise WebSecretFixtureLifecycleError(_ERROR) from None
            self._owner._current()
            if phase == "bind":
                guard.bind_instruction_profile(reference)
                self._owner._current()
                return
            reader = guard._restored if phase == "restored" else guard._applied
            if reader is None or reader._started:
                raise WebSecretFixtureLifecycleError(_ERROR) from None
            self._state = "checking-restored" if phase == "restored" else "checking-applied"
            try:
                if phase == "restored": guard.check_instruction_restored_once()
                else: guard.check_instruction_applied_once()
                self._owner._current()
                self._state = "baseline" if phase == "restored" else "applied"
            except Exception:
                self._state = "failed"
                raise WebSecretFixtureLifecycleError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._state = "closed"
            authority = self._authority
        if authority is not None: authority.close()
