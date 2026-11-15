"""Private AD runtime composition with one scoped read-only Owner session."""

from collections.abc import Callable
import threading

from v4_planning import (
    M4AuthorizationDenied, M4AuthorizationVerifier, M4ExecutionAuthorization,
    M4ExecutionPlan, M4ExecutionResult,
)

from .discovery_entry_create_contract import DisabledAdDiscoveryCreateInput
from .discovery_entry_create_http_transport import FortiPamDiscoveryEntryCreateHttpTransport
from .discovery_entry_m4_adapter import DiscoveryEntryBinding, DiscoveryEntryM4Adapter
from .discovery_entry_m4_runtime import (
    DiscoveryEntryBindingResolver, DiscoveryEntryExecutionBinding,
    ProtectedDiscoveryEntryM4Runtime,
)
from .m4_execution_store import PersistentM4ExecutionStateStore
from .owner_domain_runtime import owner_domain_transport
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig


_UNAVAILABLE = "The private AD Discovery Owner composition is unavailable."


class _PinnedDiscoveryResolver:
    """Keep the external resolver's immutable snapshot throughout execution."""

    def __init__(self, binding: DiscoveryEntryExecutionBinding) -> None:
        self._binding = binding

    def resolve_execution_binding(self, authorization_ref: str) -> DiscoveryEntryExecutionBinding:
        if authorization_ref != self._binding.authorization.authorization_ref:
            raise M4AuthorizationDenied(_UNAVAILABLE)
        return self._binding


class OwnerAuthenticatedAdDiscoveryRuntime:
    """Compose fixed AD execution; Owner reads confer no Source write rights."""

    def __init__(
        self, resolver: DiscoveryEntryBindingResolver,
        authorization_verifier: M4AuthorizationVerifier,
        execution_store: PersistentM4ExecutionStateStore,
        source_transport: FortiPamDiscoveryEntryCreateHttpTransport,
        owner_config: SecretMetadataHttpTransportConfig,
        owner_credentials: Callable[[], tuple[str, str]],
        *, source_binding: DiscoveryEntryBinding,
        authenticated_requester_digest: str, clock: Callable[[], int],
        execution_gate_open: bool = False,
    ) -> None:
        if (
            type(source_binding) is not DiscoveryEntryBinding
            or type(source_binding.request) is not DisabledAdDiscoveryCreateInput
            or source_binding.domain_binding is None
            or type(execution_store) is not PersistentM4ExecutionStateStore
            or type(source_transport) is not FortiPamDiscoveryEntryCreateHttpTransport
            or type(owner_config) is not SecretMetadataHttpTransportConfig
            or type(execution_gate_open) is not bool
            or not callable(owner_credentials)
        ):
            raise M4AuthorizationDenied(_UNAVAILABLE)
        self._resolver = resolver
        self._verifier = authorization_verifier
        self._store = execution_store
        self._source_transport = source_transport
        self._owner_config = owner_config
        self._credentials = owner_credentials
        self._source = source_binding
        self._requester = authenticated_requester_digest
        self._clock = clock
        self._gate_open = execution_gate_open
        self._lock = threading.Lock()
        self._require_same_device_and_trust()

    def _require_same_device_and_trust(self) -> None:
        # These private peers must qualify and write on the same TLS origin.
        writer = self._source_transport._config
        if (type(writer) is not SecretMetadataHttpTransportConfig
            or writer.base_url != self._owner_config.base_url
            or writer.ca_file != self._owner_config.ca_file):
            raise M4AuthorizationDenied(_UNAVAILABLE)

    def _resolve_snapshot(
        self, authorization_ref: str, expected_binding_digest: str,
    ) -> DiscoveryEntryExecutionBinding:
        try:
            binding = self._resolver.resolve_execution_binding(authorization_ref)
            if (
                type(binding) is not DiscoveryEntryExecutionBinding
                or type(binding.plan) is not M4ExecutionPlan
                or type(binding.authorization) is not M4ExecutionAuthorization
                or type(binding.source) is not DiscoveryEntryBinding
                or binding.source != self._source
                or binding.source.parameters_digest != expected_binding_digest
                or binding.plan.parameters_digest != expected_binding_digest
                or binding.plan.requester_digest != self._requester
                or binding.authorization.requester_digest != self._requester
                or binding.authorization.authorization_ref != authorization_ref
                or binding.authorization.plan_ref != binding.plan.plan_ref
                or binding.authorization.plan_digest != binding.plan.plan_digest
            ):
                raise ValueError
            return binding
        except Exception:
            raise M4AuthorizationDenied(_UNAVAILABLE) from None

    def execute_bound(
        self, authorization_ref: str, *, expected_binding_digest: str,
    ) -> M4ExecutionResult:
        if not self._gate_open or not self._lock.acquire(blocking=False):
            raise M4AuthorizationDenied(_UNAVAILABLE)
        try:
            self._require_same_device_and_trust()
            snapshot = self._resolve_snapshot(authorization_ref, expected_binding_digest)
            domain = self._source.domain_binding
            assert domain is not None
            owner = owner_domain_transport(
                self._owner_config, domain, self._credentials, allow_secret_create=False,
            )
            # Validate the fixed plan before login or credential-provider access.
            DiscoveryEntryM4Adapter(
                snapshot.plan, snapshot.source, self._source_transport,
                domain_read_transport=owner,
            )
            runtime = ProtectedDiscoveryEntryM4Runtime(
                _PinnedDiscoveryResolver(snapshot), self._verifier, self._store,
                self._source_transport, authenticated_requester_digest=self._requester,
                clock=self._clock, execution_gate_open=self._gate_open,
                domain_read_transport=owner,
            )
            with owner.authenticated():
                return runtime.execute_bound(
                    authorization_ref, expected_binding_digest=expected_binding_digest,
                )
        finally:
            self._lock.release()
