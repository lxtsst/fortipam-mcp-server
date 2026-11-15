from __future__ import annotations

from collections.abc import Callable
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
    MaterialLeaseCoordinator,
    MaterialRuntimeError,
    MaterialRuntimeOutcome,
    MaterialUseOutcome,
)


def _request() -> MaterialLeaseRequest:
    return MaterialLeaseRequest(
        action_id="secret-create-from-reference",
        action_version="1.0.0",
        plan_digest="1" * 64,
        policy_decision_digest="2" * 64,
        authorization_digest="3" * 64,
        scope_digest="4" * 64,
        audience_digest="5" * 64,
        provider_class=MaterialProviderClass.EXTERNAL_VAULT_LEASE,
        purpose=MaterialPurpose.INITIAL_ONBOARDING,
        requested_at=1_000,
        expires_at=1_120,
    )


class RecordingProvider:
    def __init__(
        self,
        *,
        binding_status: MaterialBindingStatus = MaterialBindingStatus.AVAILABLE,
        release_completion: MaterialLeaseCompletion = MaterialLeaseCompletion.RELEASED,
        fail_release: bool = False,
        fail_revoke: bool = False,
    ) -> None:
        self.binding_status = binding_status
        self.release_completion = release_completion
        self.fail_release = fail_release
        self.fail_revoke = fail_revoke
        self.events: list[object] = []
        self.lease = MaterialLease()

    def validate_binding(
        self,
        binding: C3MaterialBinding,
        request: MaterialLeaseRequest,
    ) -> MaterialBindingStatus:
        del binding, request
        self.events.append("validate")
        return self.binding_status

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
        if self.fail_release:
            raise RuntimeError("provider detail must not escape")
        return self.release_completion

    def revoke_lease(
        self,
        lease: MaterialLease,
        *,
        reason: MaterialRevocationReason,
    ) -> MaterialLeaseCompletion:
        assert lease is self.lease
        self.events.extend(("revoke", reason))
        if self.fail_revoke:
            raise RuntimeError("provider detail must not escape")
        return MaterialLeaseCompletion.REVOKED


def _coordinator(provider: RecordingProvider) -> MaterialLeaseCoordinator:
    return MaterialLeaseCoordinator(cast(MaterialProvider, provider))


def test_verified_use_runs_once_in_order_and_releases() -> None:
    provider = RecordingProvider()
    calls = 0

    def consume(lease: MaterialLease) -> MaterialUseOutcome:
        nonlocal calls
        calls += 1
        assert lease is provider.lease
        provider.events.append("consume")
        return MaterialUseOutcome.VERIFIED

    result = _coordinator(provider).execute_once(
        C3MaterialBinding(), _request(), consume, now_epoch=1_001
    )

    assert result is MaterialRuntimeOutcome.VERIFIED_AND_RELEASED
    assert calls == 1
    assert provider.events == ["validate", "acquire", "consume", "release"]

def test_same_coordinator_replays_terminal_outcome_without_reacquiring() -> None:
    provider = RecordingProvider()
    coordinator = _coordinator(provider)
    calls = 0

    def consume(lease: MaterialLease) -> MaterialUseOutcome:
        nonlocal calls
        del lease
        calls += 1
        return MaterialUseOutcome.VERIFIED

    first = coordinator.execute_once(
        C3MaterialBinding(), _request(), consume, now_epoch=1_001
    )
    second = coordinator.execute_once(
        C3MaterialBinding(), _request(), consume, now_epoch=1_002
    )

    assert first is MaterialRuntimeOutcome.VERIFIED_AND_RELEASED
    assert second is MaterialRuntimeOutcome.VERIFIED_AND_RELEASED
    assert calls == 1
    assert provider.events == [
        "validate",
        "acquire",
        "release",
        "validate",
    ]


def test_ambiguous_acquire_is_terminal_reconciliation_without_retry() -> None:
    class AcquireFailureProvider(RecordingProvider):
        def acquire_lease(
            self,
            binding: C3MaterialBinding,
            request: MaterialLeaseRequest,
        ) -> MaterialLease:
            del binding, request
            self.events.append("acquire")
            raise RuntimeError("provider response must not escape")

    provider = AcquireFailureProvider()
    coordinator = _coordinator(provider)

    first = coordinator.execute_once(
        C3MaterialBinding(), _request(), lambda lease: MaterialUseOutcome.VERIFIED,
        now_epoch=1_001,
    )
    second = coordinator.execute_once(
        C3MaterialBinding(), _request(), lambda lease: MaterialUseOutcome.VERIFIED,
        now_epoch=1_002,
    )

    assert first is MaterialRuntimeOutcome.RECONCILIATION_REQUIRED
    assert second is MaterialRuntimeOutcome.RECONCILIATION_REQUIRED
    assert provider.events == ["validate", "acquire", "validate"]


@pytest.mark.parametrize(
    ("outcome", "reason"),
    (
        (
            MaterialUseOutcome.AMBIGUOUS,
            MaterialRevocationReason.RECONCILIATION_REQUIRED,
        ),
        (MaterialUseOutcome.TIMED_OUT, MaterialRevocationReason.PROVIDER_TIMEOUT),
        (MaterialUseOutcome.CANCELLED, MaterialRevocationReason.CANCELLED),
        (
            MaterialUseOutcome.FAILED,
            MaterialRevocationReason.RECONCILIATION_REQUIRED,
        ),
    ),
)
def test_nonverified_use_revokes_without_retry(
    outcome: MaterialUseOutcome,
    reason: MaterialRevocationReason,
) -> None:
    provider = RecordingProvider()
    calls = 0

    def consume(lease: MaterialLease) -> MaterialUseOutcome:
        nonlocal calls
        del lease
        calls += 1
        provider.events.append("consume")
        return outcome

    result = _coordinator(provider).execute_once(
        C3MaterialBinding(), _request(), consume, now_epoch=1_001
    )

    assert result is MaterialRuntimeOutcome.RECONCILIATION_REQUIRED
    assert calls == 1
    assert provider.events == ["validate", "acquire", "consume", "revoke", reason]


def test_consumer_exception_is_redacted_and_revoked() -> None:
    provider = RecordingProvider()

    def fail(lease: MaterialLease) -> MaterialUseOutcome:
        del lease
        provider.events.append("consume")
        raise RuntimeError("material-derived product response")

    result = _coordinator(provider).execute_once(
        C3MaterialBinding(), _request(), fail, now_epoch=1_001
    )

    assert result is MaterialRuntimeOutcome.RECONCILIATION_REQUIRED
    assert provider.events == [
        "validate",
        "acquire",
        "consume",
        "revoke",
        MaterialRevocationReason.RECONCILIATION_REQUIRED,
    ]


@pytest.mark.parametrize("now_epoch", [999, 1_120, True])
def test_invalid_or_expired_time_denies_before_provider_use(now_epoch: int) -> None:
    provider = RecordingProvider()

    with pytest.raises(MaterialRuntimeError) as captured:
        _coordinator(provider).execute_once(
            C3MaterialBinding(),
            _request(),
            cast(Callable[[MaterialLease], MaterialUseOutcome], lambda lease: None),
            now_epoch=now_epoch,
        )

    assert str(captured.value) == "The private material lifecycle is unavailable."
    assert provider.events == []


def test_unavailable_binding_denies_before_acquire_or_consume() -> None:
    provider = RecordingProvider(binding_status=MaterialBindingStatus.UNAVAILABLE)

    with pytest.raises(MaterialRuntimeError, match="lifecycle is unavailable"):
        _coordinator(provider).execute_once(
            C3MaterialBinding(),
            _request(),
            cast(Callable[[MaterialLease], MaterialUseOutcome], lambda lease: None),
            now_epoch=1_001,
        )

    assert provider.events == ["validate"]


@pytest.mark.parametrize(
    "provider",
    (
        RecordingProvider(release_completion=MaterialLeaseCompletion.UNKNOWN),
        RecordingProvider(fail_release=True),
    ),
)
def test_release_uncertainty_never_reports_success(provider: RecordingProvider) -> None:
    result = _coordinator(provider).execute_once(
        C3MaterialBinding(),
        _request(),
        lambda lease: MaterialUseOutcome.VERIFIED,
        now_epoch=1_001,
    )

    assert result is MaterialRuntimeOutcome.RECONCILIATION_REQUIRED
    assert provider.events == ["validate", "acquire", "release"]


def test_revoke_failure_still_returns_reconciliation_required() -> None:
    provider = RecordingProvider(fail_revoke=True)

    result = _coordinator(provider).execute_once(
        C3MaterialBinding(),
        _request(),
        lambda lease: MaterialUseOutcome.AMBIGUOUS,
        now_epoch=1_001,
    )

    assert result is MaterialRuntimeOutcome.RECONCILIATION_REQUIRED
    assert provider.events[-2:] == [
        "revoke",
        MaterialRevocationReason.RECONCILIATION_REQUIRED,
    ]


def test_untyped_consumer_result_revokes_and_fails_closed() -> None:
    provider = RecordingProvider()

    with pytest.raises(MaterialRuntimeError) as captured:
        _coordinator(provider).execute_once(
            C3MaterialBinding(),
            _request(),
            cast(
                Callable[[MaterialLease], MaterialUseOutcome],
                lambda lease: "verified",
            ),
            now_epoch=1_001,
        )

    assert str(captured.value) == "The private material lifecycle is unavailable."
    assert provider.events == [
        "validate",
        "acquire",
        "revoke",
        MaterialRevocationReason.RECONCILIATION_REQUIRED,
    ]
