"""Unregistered M4 adapter for one protected disabled-scan Discovery source."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import json
import re
from typing import TYPE_CHECKING, Protocol

from v4_planning import (
    M4AdapterAmbiguous,
    M4AdapterDenied,
    M4AdapterFailure,
    M4ExecutionPlan,
    canonical_digest,
)

from .discovery_entry_create_contract import DisabledAdDiscoveryCreateInput
from .discovery_entry_create_http_transport import (
    DiscoveryCreateInput,
    DiscoveryEntryCreateResult,
    DiscoveryEntryCreateHttpTransportError,
    _DISPOSABLE_NAME,
    _expected_source_type,
    _ad_credential_dependency_digest,
    inspect_ad_credential_dependency,
)
from .discovery_entry_projection import DiscoveryEntryReadback
from .secret_create_191_private_adapter import SecretCreate700DomainBinding

if TYPE_CHECKING:
    from .domain_secret_projection_reader import DomainSecretReadTransport


ACTION_ID = "discovery-entry-create"
ACTION_VERSION = "1.0.0"
ADAPTER_REF = "fortipam-700-build29-disabled-ad-discovery-candidate"
UNIX_ADAPTER_REF = "fortipam-700-build29-disabled-unix-discovery-candidate"
_UNAVAILABLE = "The Discovery source candidate is unavailable."
_NONCE = re.compile(r"\A[0-9a-f]{64}\Z")


@dataclass(frozen=True, slots=True, repr=False)
class DiscoveryEntryBinding:
    """Protected source/Secret binding with an opaque digest salt."""

    request: DiscoveryCreateInput
    private_nonce: str
    domain_binding: SecretCreate700DomainBinding | None = None

    def __post_init__(self) -> None:
        try:
            _expected_source_type(self.request)
        except DiscoveryEntryCreateHttpTransportError:
            raise ValueError(_UNAVAILABLE) from None
        if (
            _DISPOSABLE_NAME.fullmatch(self.request.source_name) is None
            or not isinstance(self.private_nonce, str)
            or _NONCE.fullmatch(self.private_nonce) is None
        ):
            raise ValueError(_UNAVAILABLE)
        if type(self.request) is DisabledAdDiscoveryCreateInput:
            try:
                if self.domain_binding is None:
                    raise DiscoveryEntryCreateHttpTransportError(_UNAVAILABLE)
                _ad_credential_dependency_digest(self.request, self.domain_binding)
            except DiscoveryEntryCreateHttpTransportError:
                raise ValueError(_UNAVAILABLE) from None
        elif self.domain_binding is not None:
            raise ValueError(_UNAVAILABLE)

    @property
    def adapter_ref(self) -> str:
        return (
            ADAPTER_REF if type(self.request) is DisabledAdDiscoveryCreateInput
            else UNIX_ADAPTER_REF
        )

    @property
    def parameters_digest(self) -> str:
        values: dict[str, object] = {
            "contract": self.adapter_ref,
            "body_digest": hashlib.sha256(json.dumps(
                self.request.body(), sort_keys=True, separators=(",", ":"),
            ).encode()).hexdigest(),
            "private_nonce": self.private_nonce,
        }
        if type(self.request) is DisabledAdDiscoveryCreateInput:
            values["credential_dependency_digest"] = self.credential_dependency_digest
        return canonical_digest(values)

    @property
    def credential_dependency_digest(self) -> str:
        if type(self.request) is not DisabledAdDiscoveryCreateInput or self.domain_binding is None:
            raise ValueError(_UNAVAILABLE)
        return _ad_credential_dependency_digest(self.request, self.domain_binding)

    def state_digest(self, *, exists: bool) -> str:
        return canonical_digest({
            "contract": self.adapter_ref,
            "parameters_digest": self.parameters_digest,
            "exists": exists,
            "disabled_account_source": exists,
        })

    def __repr__(self) -> str:
        return "<DiscoveryEntryBinding protected>"


class DiscoveryEntryTransport(Protocol):
    """One exact read and one consumed POST; no generic REST operation."""

    def inspect_current(
        self, request: DiscoveryCreateInput
    ) -> DiscoveryEntryReadback | None: ...

    def create_and_readback(
        self, request: DiscoveryCreateInput, *,
        domain_binding: SecretCreate700DomainBinding | None = None,
        domain_read_transport: DomainSecretReadTransport | None = None,
        before_dispatch: Callable[[], None] | None = None,
    ) -> DiscoveryEntryCreateResult: ...


class DiscoveryEntryM4Adapter:
    """Bind M4 plan digests to the one protected source and Secret reference."""

    def __init__(
        self,
        plan: M4ExecutionPlan,
        binding: DiscoveryEntryBinding,
        transport: DiscoveryEntryTransport,
        *, domain_read_transport: DomainSecretReadTransport | None = None,
        before_dispatch: Callable[[], None] | None = None,
    ) -> None:
        if (type(binding) is not DiscoveryEntryBinding
            or (before_dispatch is not None and not callable(before_dispatch))
            or (type(binding.request) is DisabledAdDiscoveryCreateInput
                and not callable(getattr(domain_read_transport, "inspect_domain_account_projection", None)))):
            raise M4AdapterDenied(_UNAVAILABLE)
        self._plan = plan
        self._binding = binding
        self._transport = transport
        self._domain_read_transport = domain_read_transport
        self._before_dispatch = before_dispatch
        self._dispatched = False
        self._validate(plan)

    def _validate(self, plan: M4ExecutionPlan) -> None:
        binding = self._binding
        if (
            plan != self._plan
            or plan.action_id != ACTION_ID
            or plan.action_version != ACTION_VERSION
            or plan.adapter_ref != binding.adapter_ref
            or plan.target_ref != "discovery-entry"
            or plan.parameters_digest != binding.parameters_digest
            or plan.expected_current_digest != binding.state_digest(exists=False)
            or plan.expected_state_digest != binding.state_digest(exists=True)
        ):
            raise M4AdapterDenied(_UNAVAILABLE)

    def read_current(self, plan: M4ExecutionPlan) -> str:
        self._validate(plan)
        try:
            if self._transport.inspect_current(self._binding.request) is not None:
                raise ValueError
            if type(self._binding.request) is DisabledAdDiscoveryCreateInput:
                if self._binding.domain_binding is None or self._domain_read_transport is None:
                    raise ValueError
                if inspect_ad_credential_dependency(
                    self._binding.request, self._binding.domain_binding, self._domain_read_transport,
                ) != self._binding.credential_dependency_digest:
                    raise ValueError
            return self._binding.state_digest(exists=False)
        except Exception:
            raise M4AdapterDenied(_UNAVAILABLE) from None

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        self._validate(plan)
        if self._dispatched:
            raise M4AdapterDenied(_UNAVAILABLE)
        self.read_current(plan)
        self._dispatched = True
        try:
            # The kernel performs its own postcondition read even when the
            # transport's immediate readback is inconclusive.
            if type(self._binding.request) is DisabledAdDiscoveryCreateInput:
                self._transport.create_and_readback(
                    self._binding.request, domain_binding=self._binding.domain_binding,
                    domain_read_transport=self._domain_read_transport,
                    before_dispatch=self._before_dispatch,
                )
            else:
                self._transport.create_and_readback(
                    self._binding.request, before_dispatch=self._before_dispatch,
                )
        except Exception:
            raise M4AdapterAmbiguous(_UNAVAILABLE) from None

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        self._validate(plan)
        if not self._dispatched:
            raise M4AdapterFailure(_UNAVAILABLE)
        try:
            result = self._transport.inspect_current(self._binding.request)
            if result is None or not result.create_readback_verified:
                raise ValueError
            return self._binding.state_digest(exists=True)
        except Exception:
            raise M4AdapterFailure(_UNAVAILABLE) from None
