"""Unregistered Web-service runtime using the shared authorized M4 kernel."""

from dataclasses import dataclass
from typing import Callable, Protocol

from v4_planning import (
    M4AuthorizationDenied, M4AuthorizationVerifier, M4ExecutionAuthorization,
    M4ExecutionKernel, M4ExecutionPlan, M4ExecutionResult, M4ExecutionStateStore,
)
from .web_secret_service_m4_adapter import (
    WebSecretServiceBinding, WebSecretServiceM4Adapter, WebServiceReader,
    parameters_digest,
)
from .web_secret_service_ssh_transport import FortiPamWebSecretServiceSshTransport

_UNAVAILABLE = "Authorized Web Secret service execution is unavailable."


@dataclass(frozen=True, slots=True, repr=False)
class WebSecretServiceExecutionBinding:
    plan: M4ExecutionPlan
    authorization: M4ExecutionAuthorization
    service: WebSecretServiceBinding


class WebServiceBindingResolver(Protocol):
    def resolve_execution_binding(self, authorization_ref: str) -> WebSecretServiceExecutionBinding: ...


class ProtectedWebSecretServiceM4Runtime:
    """Resolve one protected binding; never issue or synthesize authorization."""

    def __init__(
        self, resolver: WebServiceBindingResolver,
        authorization_verifier: M4AuthorizationVerifier,
        execution_store: M4ExecutionStateStore,
        reader: WebServiceReader, writer: FortiPamWebSecretServiceSshTransport,
        *, authenticated_requester_digest: str, clock: Callable[[], int],
    ) -> None:
        if not isinstance(writer, FortiPamWebSecretServiceSshTransport):
            raise M4AuthorizationDenied(_UNAVAILABLE)
        self._resolver = resolver
        self._verifier = authorization_verifier
        self._store = execution_store
        self._reader = reader
        self._writer = writer
        self._requester = authenticated_requester_digest
        self._clock = clock

    def execute_bound(
        self, authorization_ref: str, *, expected_binding_digest: str,
    ) -> M4ExecutionResult:
        try:
            binding = self._resolver.resolve_execution_binding(authorization_ref)
            if (
                not isinstance(binding, WebSecretServiceExecutionBinding)
                or binding.authorization.authorization_ref != authorization_ref
                or binding.plan.requester_digest != self._requester
                or binding.authorization.requester_digest != self._requester
                or parameters_digest(binding.service) != expected_binding_digest
            ):
                raise ValueError
            adapter = WebSecretServiceM4Adapter(binding.service, self._reader, self._writer)
            adapter._validate_plan(binding.plan)
        except Exception:
            raise M4AuthorizationDenied(_UNAVAILABLE) from None
        return M4ExecutionKernel(
            adapter, self._verifier, self._store, clock=self._clock,
        ).execute(binding.plan, binding.authorization)
