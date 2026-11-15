from __future__ import annotations

from typing import cast

import pytest

from v4_planning.material_provider import (
    C3MaterialBinding,
    MaterialBindingStatus,
    MaterialLease,
    MaterialLeaseCompletion,
    MaterialLeaseRequest,
    MaterialProvider,
    MaterialProviderClass,
    MaterialPurpose,
    MaterialRevocationReason,
)
from v4_planning.material_runtime import (
    InMemoryMaterialUseStateStore,
    MaterialRuntimeError,
    MaterialRuntimeOutcome,
)
from v4_planning.secret_create_adapter import (
    SECRET_CREATE_ACTION_ID,
    SECRET_CREATE_ACTION_VERSION,
    SecretCreateAdapterDenied,
    SecretCreateAdapterOutcome,
    SecretCreatePrivateAdapter,
)
from v4_planning.secret_create_runtime import (
    PackagedDenyAllSecretCreateMaterialRuntime,
    SecretCreateMaterialRuntime,
)


def _request(**changes: object) -> MaterialLeaseRequest:
    values: dict[str, object] = {
        "action_id": SECRET_CREATE_ACTION_ID,
        "action_version": SECRET_CREATE_ACTION_VERSION,
        "plan_digest": "1" * 64,
        "policy_decision_digest": "2" * 64,
        "authorization_digest": "3" * 64,
        "scope_digest": "4" * 64,
        "audience_digest": "5" * 64,
        "provider_class": MaterialProviderClass.EXTERNAL_VAULT_LEASE,
        "purpose": MaterialPurpose.INITIAL_ONBOARDING,
        "requested_at": 1_000,
        "expires_at": 1_120,
    }
    values.update(changes)
    return MaterialLeaseRequest(**values)  # type: ignore[arg-type]


class _Provider:
    def __init__(self) -> None:
        self.events: list[object] = []
        self.lease = MaterialLease()

    def validate_binding(
        self,
        binding: C3MaterialBinding,
        request: MaterialLeaseRequest,
    ) -> MaterialBindingStatus:
        del binding, request
        self.events.append("validate")
        return MaterialBindingStatus.AVAILABLE

    def acquire_lease(
        self,
        binding: C3MaterialBinding,
        request: MaterialLeaseRequest,
    ) -> MaterialLease:
        del binding, request
        self.events.append("acquire")
        return self.lease

    def release_lease(self, lease: MaterialLease) -> MaterialLeaseCompletion:
        assert lease is self.lease
        self.events.append("release")
        return MaterialLeaseCompletion.RELEASED

    def revoke_lease(
        self,
        lease: MaterialLease,
        *,
        reason: MaterialRevocationReason,
    ) -> MaterialLeaseCompletion:
        assert lease is self.lease
        self.events.extend(("revoke", reason))
        return MaterialLeaseCompletion.REVOKED


class _Adapter:
    def __init__(self, outcome: SecretCreateAdapterOutcome) -> None:
        self.outcome = outcome
        self.calls = 0

    def dispatch_create(
        self,
        lease: MaterialLease,
        request: MaterialLeaseRequest,
    ) -> SecretCreateAdapterOutcome:
        assert isinstance(lease, MaterialLease)
        assert request.action_id == SECRET_CREATE_ACTION_ID
        self.calls += 1
        return self.outcome


def _runtime(
    provider: _Provider,
    adapter: SecretCreatePrivateAdapter,
) -> SecretCreateMaterialRuntime:
    return SecretCreateMaterialRuntime(
        cast(MaterialProvider, provider),
        InMemoryMaterialUseStateStore(),
        adapter,
    )


def test_verified_adapter_runs_once_and_terminal_replay_does_not_dispatch() -> None:
    provider = _Provider()
    adapter = _Adapter(SecretCreateAdapterOutcome.VERIFIED_CREATED)
    runtime = _runtime(provider, cast(SecretCreatePrivateAdapter, adapter))

    first = runtime.execute_once(C3MaterialBinding(), _request(), now_epoch=1_001)
    second = runtime.execute_once(C3MaterialBinding(), _request(), now_epoch=1_002)

    assert first is MaterialRuntimeOutcome.VERIFIED_AND_RELEASED
    assert second is MaterialRuntimeOutcome.VERIFIED_AND_RELEASED
    assert adapter.calls == 1
    assert provider.events == ["validate", "acquire", "release", "validate"]


def test_reconciliation_adapter_revokes_and_never_retries() -> None:
    provider = _Provider()
    adapter = _Adapter(SecretCreateAdapterOutcome.RECONCILIATION_REQUIRED)
    runtime = _runtime(provider, cast(SecretCreatePrivateAdapter, adapter))

    first = runtime.execute_once(C3MaterialBinding(), _request(), now_epoch=1_001)
    second = runtime.execute_once(C3MaterialBinding(), _request(), now_epoch=1_002)

    assert first is MaterialRuntimeOutcome.RECONCILIATION_REQUIRED
    assert second is MaterialRuntimeOutcome.RECONCILIATION_REQUIRED
    assert adapter.calls == 1
    assert provider.events == [
        "validate",
        "acquire",
        "revoke",
        MaterialRevocationReason.RECONCILIATION_REQUIRED,
        "validate",
    ]


def test_wrong_action_is_denied_before_provider_or_state_use() -> None:
    provider = _Provider()
    adapter = _Adapter(SecretCreateAdapterOutcome.VERIFIED_CREATED)
    runtime = _runtime(provider, cast(SecretCreatePrivateAdapter, adapter))

    with pytest.raises(SecretCreateAdapterDenied, match="binding is unavailable"):
        runtime.execute_once(
            C3MaterialBinding(),
            _request(action_id="secret-update-metadata"),
            now_epoch=1_001,
        )

    assert provider.events == []
    assert adapter.calls == 0


def test_untyped_or_exception_adapter_outcome_is_never_success() -> None:
    class _UntypedAdapter:
        def dispatch_create(
            self,
            lease: MaterialLease,
            request: MaterialLeaseRequest,
        ) -> SecretCreateAdapterOutcome:
            del lease, request
            return cast(SecretCreateAdapterOutcome, object())

    class _FailingAdapter:
        def dispatch_create(
            self,
            lease: MaterialLease,
            request: MaterialLeaseRequest,
        ) -> SecretCreateAdapterOutcome:
            del lease, request
            raise RuntimeError("product response must not escape")

    for adapter in (_UntypedAdapter(), _FailingAdapter()):
        provider = _Provider()
        result = _runtime(
            provider,
            cast(SecretCreatePrivateAdapter, adapter),
        ).execute_once(C3MaterialBinding(), _request(), now_epoch=1_001)
        assert result is MaterialRuntimeOutcome.RECONCILIATION_REQUIRED
        assert provider.events == [
            "validate",
            "acquire",
            "revoke",
            MaterialRevocationReason.RECONCILIATION_REQUIRED,
        ]


def test_packaged_runtime_is_no_injection_and_deny_all() -> None:
    assert PackagedDenyAllSecretCreateMaterialRuntime.status() == {
        "action_id": SECRET_CREATE_ACTION_ID,
        "action_version": SECRET_CREATE_ACTION_VERSION,
        "adapter_mode": "deny_all",
        "body_builder_available": False,
        "device_access": False,
        "dispatchable": False,
        "material_provider_mode": "deny_all",
        "mcp_exposed": False,
        "private_runtime_packaged": True,
        "product_transport_bound": False,
    }
    with pytest.raises(MaterialRuntimeError, match="lifecycle is unavailable"):
        PackagedDenyAllSecretCreateMaterialRuntime().execute_once(
            C3MaterialBinding(),
            _request(),
            now_epoch=1_001,
        )
