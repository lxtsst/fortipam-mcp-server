from __future__ import annotations

import copy
from collections.abc import Callable
from dataclasses import asdict, replace
import pickle
from threading import Event, Thread
import traceback
from typing import Any, cast

import pytest

from fortipam_mcp.ldap_server_contract import LdapServerCreateBinding, LdapServerCreateOutcome
from fortipam_mcp.ldap_server_material_provider import (
    LdapServerLeaseTransport,
    LdapServerMaterialProvider,
)
from v4_planning.material_provider import (
    MaterialAccessDenied,
    MaterialBindingStatus,
    MaterialLease,
    MaterialLeaseCompletion,
    MaterialLeaseRequest,
    MaterialProviderClass,
    MaterialPurpose,
    MaterialRevocationReason,
)
from v4_planning.material_runtime import (
    MaterialLeaseCoordinator,
    MaterialRuntimeOutcome,
    MaterialUseOutcome,
)


NOW = 1_000


def _binding() -> LdapServerCreateBinding:
    return LdapServerCreateBinding(
        "mcp-v4-ldap-example", "dc.example.test", "OU=Example,DC=example,DC=test",
        "example-ca", "synthetic@example.test", "a" * 64, "c" * 64,
    )


def _request() -> MaterialLeaseRequest:
    return MaterialLeaseRequest(
        "ldap-server-create", "1.0.0", "1" * 64, "2" * 64, "3" * 64,
        "4" * 64, "5" * 64, MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE,
        MaterialPurpose.INITIAL_ONBOARDING, NOW, NOW + 60,
    )


class _Loader:
    def __init__(self) -> None:
        self.username = bytearray(_binding().username, "ascii")
        self.password = bytearray([82] * 18)
        self.validate_calls = 0
        self.load_calls = 0
        self.status = MaterialBindingStatus.AVAILABLE
        self.on_validate: Callable[[], None] = lambda: None
        self.on_load: Callable[[], None] = lambda: None

    def validate_prebound(self) -> MaterialBindingStatus:
        self.validate_calls += 1
        self.on_validate()
        return self.status

    def load_secret_create_material_once(self) -> tuple[bytearray, bytearray]:
        self.load_calls += 1
        self.on_load()
        return self.username, self.password


class _Transport:
    def __init__(self) -> None:
        self.calls = 0
        self.views: tuple[memoryview, memoryview] | None = None
        self.child_view: memoryview | None = None
        self.outcome = LdapServerCreateOutcome.VERIFIED_CREATED
        self.on_call: Callable[[], None] = lambda: None

    def _create_and_verify_with_material(self, binding: LdapServerCreateBinding,
            request: MaterialLeaseRequest, username: memoryview,
            password: memoryview) -> LdapServerCreateOutcome:
        assert binding.parameters_digest == _binding().parameters_digest
        assert request == _request()
        assert username.readonly and password.readonly
        assert len(username) == len(binding.username)
        self.calls += 1
        self.views = (username, password)
        self.child_view = password[:]
        self.on_call()
        return self.outcome


def _setup(*, loader: _Loader | None = None, clock: Callable[[], int] | None = None) -> Any:
    binding, request = _binding(), _request()
    loader = loader if loader is not None else _Loader()
    provider = LdapServerMaterialProvider(
        loader, binding=binding, request=request, clock=clock or (lambda: NOW + 1),
    )
    transport = _Transport()
    bridge = LdapServerLeaseTransport(provider, transport)
    return binding, request, loader, provider, transport, bridge


def _assert_cleared(loader: _Loader, transport: _Transport | None = None) -> None:
    assert not any(loader.username)
    assert not any(loader.password)
    if transport is not None and transport.views is not None:
        for view in transport.views:
            with pytest.raises(ValueError):
                len(view)
        assert not any(cast(memoryview, transport.child_view))
        cast(memoryview, transport.child_view).release()


def test_coordinator_consumes_once_releases_views_and_zeroizes() -> None:
    binding, request, loader, provider, transport, bridge = _setup()
    coordinator = MaterialLeaseCoordinator(provider)
    result = coordinator.execute_once(binding, request, bridge.consume, now_epoch=NOW + 1)
    assert result is MaterialRuntimeOutcome.VERIFIED_AND_RELEASED
    assert loader.load_calls == transport.calls == 1
    _assert_cleared(loader, transport)
    assert bridge.consume(MaterialLease()) is MaterialUseOutcome.FAILED
    with pytest.raises(MaterialAccessDenied):
        provider.acquire_lease(binding, request)
    assert loader.load_calls == transport.calls == 1


_MISMATCHES = [
    ("action_id", "secret-create-from-reference"), ("action_version", "1.0.1"),
    ("plan_digest", "6" * 64), ("policy_decision_digest", "6" * 64),
    ("authorization_digest", "6" * 64), ("scope_digest", "6" * 64),
    ("audience_digest", "6" * 64),
    ("provider_class", MaterialProviderClass.EXTERNAL_VAULT_LEASE),
    ("purpose", MaterialPurpose.CREDENTIAL_ROTATION),
    ("requested_at", NOW - 1), ("expires_at", NOW + 59),
]


@pytest.mark.parametrize("field,value", _MISMATCHES)
def test_every_request_field_is_pinned_before_any_loader_call(field: str, value: Any) -> None:
    binding, request, loader, provider, _, _ = _setup()
    altered = replace(request, **{field: value})
    assert provider.validate_binding(binding, altered) is MaterialBindingStatus.INCOMPATIBLE
    with pytest.raises(MaterialAccessDenied):
        provider.acquire_lease(binding, altered)
    assert loader.validate_calls == loader.load_calls == 0


@pytest.mark.parametrize("change", [
    {"action_id": "secret-create-from-reference"}, {"action_version": "1.0.1"},
    {"provider_class": MaterialProviderClass.EXTERNAL_VAULT_LEASE},
    {"purpose": MaterialPurpose.JIT_DELIVERY}, {"expires_at": NOW + 61},
])
def test_constructor_accepts_only_bounded_ldap_onboarding(change: dict[str, Any]) -> None:
    loader = _Loader()
    with pytest.raises(MaterialAccessDenied):
        LdapServerMaterialProvider(loader, binding=_binding(), request=replace(_request(), **change))
    assert loader.validate_calls == loader.load_calls == 0


def test_binding_identity_and_digest_are_pinned_without_loading() -> None:
    binding, request, loader, provider, _, _ = _setup()
    assert provider.validate_binding(_binding(), request) is MaterialBindingStatus.INCOMPATIBLE
    object.__setattr__(binding, "ca_certificate_sha256", "d" * 64)
    assert provider.validate_binding(binding, request) is MaterialBindingStatus.INCOMPATIBLE
    assert loader.validate_calls == loader.load_calls == 0


def test_request_snapshot_cannot_follow_callers_mutation() -> None:
    binding, request, loader, provider, _, _ = _setup()
    object.__setattr__(request, "audience_digest", "d" * 64)
    assert provider.validate_binding(binding, request) is MaterialBindingStatus.INCOMPATIBLE
    assert loader.validate_calls == loader.load_calls == 0


@pytest.mark.parametrize("invalid", ["username", "empty", "long", "nul", "newline", "alias"])
def test_invalid_loaded_material_is_cleared_and_never_loaded_again(invalid: str) -> None:
    loader = _Loader()
    if invalid == "username":
        loader.username[0] ^= 32
    elif invalid == "empty":
        loader.password.clear()
    elif invalid == "long":
        loader.password = bytearray([82] * 129)
    elif invalid == "nul":
        loader.password[0] = 0
    elif invalid == "newline":
        loader.password[0] = 10
    else:
        loader.password = loader.username
    binding, request, _, provider, _, _ = _setup(loader=loader)
    for _ in range(2):
        with pytest.raises(MaterialAccessDenied):
            provider.acquire_lease(binding, request)
    assert loader.load_calls == 1
    _assert_cleared(loader)


def test_password_at_native_limit_and_opaque_objects() -> None:
    loader = _Loader()
    loader.password = bytearray([82] * 128)
    binding, request, _, provider, _, bridge = _setup(loader=loader)
    lease = provider.acquire_lease(binding, request)
    for value in (binding, lease, provider, bridge):
        assert binding.username not in repr(value)
        assert loader.password.decode() not in str(value)
        assert not hasattr(value, "__dict__")
        with pytest.raises(TypeError):
            asdict(value)
        for copy_function in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(MaterialAccessDenied):
                copy_function(value)
    for accessor in ("read", "value", "bytes", "username", "password", "material"):
        assert not hasattr(lease, accessor)
    assert provider.revoke_lease(lease, reason=MaterialRevocationReason.CANCELLED) is MaterialLeaseCompletion.REVOKED
    _assert_cleared(loader)
    operations: tuple[Callable[[], object], ...] = (
        lambda: provider.release_lease(lease),
        lambda: provider.revoke_lease(lease, reason=MaterialRevocationReason.CANCELLED),
    )
    for operation in operations:
        with pytest.raises(MaterialAccessDenied):
            operation()


@pytest.mark.parametrize("behavior,expected", [
    ("timeout", MaterialUseOutcome.TIMED_OUT), ("error", MaterialUseOutcome.FAILED),
    ("unknown", MaterialUseOutcome.AMBIGUOUS), ("untyped", MaterialUseOutcome.FAILED),
])
def test_transport_failures_are_closed_classes_and_always_clear(behavior: str, expected: MaterialUseOutcome) -> None:
    binding, request, loader, provider, transport, bridge = _setup()
    lease = provider.acquire_lease(binding, request)
    if behavior in ("timeout", "error"):
        def fail() -> None:
            raise (TimeoutError if behavior == "timeout" else RuntimeError)(loader.password.decode())
        transport.on_call = fail
    else:
        transport.outcome = (LdapServerCreateOutcome.RECONCILIATION_REQUIRED
                             if behavior == "unknown" else "verified_created")
    assert bridge.consume(lease) is expected
    _assert_cleared(loader, transport)
    assert bridge.consume(lease) is MaterialUseOutcome.FAILED
    assert transport.calls == 1
    assert provider.revoke_lease(lease, reason=MaterialRevocationReason.RECONCILIATION_REQUIRED) is MaterialLeaseCompletion.REVOKED


def test_loader_exception_is_value_free_and_not_retried() -> None:
    binding, request, loader, provider, _, _ = _setup()
    marker = loader.password.decode()
    def fail() -> None:
        raise RuntimeError(marker)
    loader.on_load = fail
    with pytest.raises(MaterialAccessDenied) as failure:
        provider.acquire_lease(binding, request)
    assert marker not in str(failure.value)
    assert marker not in "".join(traceback.format_exception(failure.value))
    with pytest.raises(MaterialAccessDenied):
        provider.acquire_lease(binding, request)
    assert loader.load_calls == 1
    # On a failing loader, ownership of unreturned buffers remains with it.
    loader.username.clear()
    loader.password.clear()


@pytest.mark.parametrize("stage", ["validate", "load", "consume", "transport"])
def test_expiry_is_checked_before_and_after_owner_calls(stage: str) -> None:
    now = [NOW + 1]
    binding, request, loader, provider, transport, bridge = _setup(clock=lambda: now[0])
    def expire() -> None:
        now[0] = NOW + 60
    if stage in ("validate", "load"):
        if stage == "validate":
            loader.on_validate = expire
        else:
            loader.on_load = expire
        with pytest.raises(MaterialAccessDenied):
            provider.acquire_lease(binding, request)
        assert loader.load_calls == (stage == "load")
        if stage == "load":
            _assert_cleared(loader)
    else:
        lease = provider.acquire_lease(binding, request)
        if stage == "consume":
            expire()
        else:
            transport.on_call = expire
        assert bridge.consume(lease) is MaterialUseOutcome.TIMED_OUT
        assert transport.calls == (stage == "transport")
        _assert_cleared(loader, transport)
        assert provider.release_lease(lease) is MaterialLeaseCompletion.EXPIRED


def test_consume_context_mismatch_is_terminal_and_clears() -> None:
    binding, request, loader, provider, transport, bridge = _setup()
    lease = provider.acquire_lease(binding, request)
    assert bridge.create_and_verify(binding, lease, replace(request, scope_digest="6" * 64)) is LdapServerCreateOutcome.RECONCILIATION_REQUIRED
    assert bridge.consume(lease) is MaterialUseOutcome.FAILED
    assert transport.calls == 0
    _assert_cleared(loader)


def test_expired_reacquisition_clears_the_outstanding_lease_without_reloading() -> None:
    now = [NOW + 1]
    binding, request, loader, provider, transport, bridge = _setup(clock=lambda: now[0])
    lease = provider.acquire_lease(binding, request)
    now[0] = NOW + 60
    with pytest.raises(MaterialAccessDenied):
        provider.acquire_lease(binding, request)
    _assert_cleared(loader)
    assert bridge.consume(lease) is MaterialUseOutcome.TIMED_OUT
    assert loader.load_calls == 1 and transport.calls == 0


def test_coordinator_revokes_after_transport_timeout() -> None:
    binding, request, loader, provider, transport, bridge = _setup()
    def timeout() -> None:
        raise TimeoutError
    transport.on_call = timeout
    result = MaterialLeaseCoordinator(provider).execute_once(
        binding, request, bridge.consume, now_epoch=NOW + 1,
    )
    assert result is MaterialRuntimeOutcome.RECONCILIATION_REQUIRED
    assert provider._lease is None
    _assert_cleared(loader, transport)
    assert loader.load_calls == transport.calls == 1


def test_concurrent_acquisition_cannot_load_twice() -> None:
    binding, request, loader, provider, _, _ = _setup()
    entered, proceed = Event(), Event()
    result = []
    def wait_in_loader() -> None:
        entered.set()
        assert proceed.wait(2)
    loader.on_load = wait_in_loader
    thread = Thread(target=lambda: result.append(provider.acquire_lease(binding, request)))
    thread.start()
    try:
        assert entered.wait(2)
        with pytest.raises(MaterialAccessDenied):
            provider.acquire_lease(binding, request)
        assert provider.validate_binding(binding, request) is MaterialBindingStatus.UNAVAILABLE
    finally:
        proceed.set()
        thread.join(2)
    assert not thread.is_alive()
    assert len(result) == loader.load_calls == 1
    provider.revoke_lease(result[0], reason=MaterialRevocationReason.CANCELLED)
    _assert_cleared(loader)


def test_reentrant_consume_and_revoke_cannot_interrupt_material_use() -> None:
    binding, request, loader, provider, transport, bridge = _setup()
    lease = provider.acquire_lease(binding, request)
    def nested_calls() -> None:
        assert bridge.consume(lease) is MaterialUseOutcome.FAILED
        with pytest.raises(MaterialAccessDenied):
            provider.revoke_lease(lease, reason=MaterialRevocationReason.CANCELLED)
    transport.on_call = nested_calls
    assert bridge.consume(lease) is MaterialUseOutcome.VERIFIED
    assert transport.calls == 1
    _assert_cleared(loader, transport)
    assert provider.release_lease(lease) is MaterialLeaseCompletion.RELEASED
