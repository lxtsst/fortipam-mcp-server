from __future__ import annotations

import inspect
from dataclasses import replace

import pytest

from fortipam_mcp.secret_create_191_private_adapter import (
    FortiPam191SecretCreatePrivateAdapter,
    SecretCreate191TargetBinding,
    SecretCreate191WebBinding,
)
from test_v4_secret_create_runtime import _request
from v4_planning.material_provider import MaterialLease
from v4_planning.secret_create_adapter import (
    SecretCreateAdapterDenied,
    SecretCreateAdapterOutcome,
)


PLAN_DIGEST = "1" * 64


def _binding() -> SecretCreate191TargetBinding:
    return SecretCreate191TargetBinding(
        "fortipam-191-secret-create-private-v1",
        "1.9.1",
        PLAN_DIGEST,
        "Public/private-folder",
        "private-secret-name",
        "Unix Account (SSH Password)",
        "private-target-name",
        "192.0.2.10",
    )


class _Transport:
    def __init__(self, outcome=SecretCreateAdapterOutcome.VERIFIED_CREATED) -> None:
        self.outcome = outcome
        self.calls = 0

    def create_and_verify(self, binding, lease, request):
        assert binding is not None
        assert isinstance(lease, MaterialLease)
        assert request.plan_digest == PLAN_DIGEST
        self.calls += 1
        return self.outcome


def test_fixed_private_transport_has_no_body_or_endpoint_argument() -> None:
    parameters = inspect.signature(_Transport.create_and_verify).parameters
    assert tuple(parameters) == ("self", "binding", "lease", "request")
    rendered = repr(_binding())
    assert "private-folder" not in rendered
    assert "private-secret-name" not in rendered
    assert "private-target-name" not in rendered


@pytest.mark.parametrize(
    "change",
    [
        {"template_name": "Windows Machine"},
        {"rdp_service_enabled": True},
        {"rdp_event_filter_profile_name": "mcp-v4-rdp-event-filter-existing"},
        {"target_product_build": 30},
    ],
)
def test_build29_linux_candidate_rejects_widened_binding(change: dict[str, object]) -> None:
    candidate = replace(
        _binding(),
        contract_ref="fortipam-700-build29-linux-ssh-create-candidate-v1",
        target_product_version="7.0.0",
        target_product_build=29,
    )
    with pytest.raises(SecretCreateAdapterDenied):
        replace(candidate, **change)


def test_web_binding_is_non_rendering_and_rejects_credential_bearing_urls() -> None:
    binding = SecretCreate191WebBinding(
        "fortipam-191-web-secret-create-private-v1",
        "1.9.1",
        PLAN_DIGEST,
        "Public/private-folder",
        "private-web-secret",
        "Web Account",
        "https://app.example.test/login",
        True,
    )

    assert "app.example.test" not in repr(binding)
    with pytest.raises(SecretCreateAdapterDenied):
        SecretCreate191WebBinding(
            "fortipam-191-web-secret-create-private-v1",
            "1.9.1",
            PLAN_DIGEST,
            "Public/private-folder",
            "private-web-secret",
            "Web Account",
            "https://user:password@app.example.test/login",
            True,
        )


@pytest.mark.parametrize("change", [
    {"template_name": "Unix Account (SSH Password)"},
    {"rdp_service_enabled": False},
    {"target_product_version": "1.9.1"},
    {"target_product_build": 30},
])
def test_build29_rdp_candidate_is_pinned_and_rejects_widening(change) -> None:
    candidate = replace(
        _binding(),
        contract_ref="fortipam-700-build29-windows-rdp-create-candidate-v1",
        target_product_version="7.0.0",
        target_product_build=29,
        template_name="Windows Machine",
        rdp_service_enabled=True,
        rdp_event_filter_profile_name="mcp-v4-rdp-event-filter-existing",
    )
    with pytest.raises(SecretCreateAdapterDenied):
        replace(candidate, **change)


def test_exact_binding_returns_only_verified_categorical_outcome() -> None:
    transport = _Transport()
    adapter = FortiPam191SecretCreatePrivateAdapter(_binding(), transport)

    result = adapter.dispatch_create(
        MaterialLease(),
        _request(plan_digest=PLAN_DIGEST),
    )

    assert result is SecretCreateAdapterOutcome.VERIFIED_CREATED
    assert transport.calls == 1


def test_plan_mismatch_stops_before_private_transport() -> None:
    transport = _Transport()
    adapter = FortiPam191SecretCreatePrivateAdapter(_binding(), transport)

    with pytest.raises(SecretCreateAdapterDenied):
        adapter.dispatch_create(
            MaterialLease(),
            _request(plan_digest="9" * 64),
        )
    assert transport.calls == 0


def test_transport_failure_or_untyped_result_is_reconciliation_not_success() -> None:
    class _Failure(_Transport):
        def create_and_verify(self, binding, lease, request):
            del binding, lease, request
            raise RuntimeError("private response")

    for transport in (
        _Transport(SecretCreateAdapterOutcome.RECONCILIATION_REQUIRED),
        _Failure(),
    ):
        adapter = FortiPam191SecretCreatePrivateAdapter(_binding(), transport)
        assert adapter.dispatch_create(
            MaterialLease(),
            _request(plan_digest=PLAN_DIGEST),
        ) is SecretCreateAdapterOutcome.RECONCILIATION_REQUIRED


@pytest.mark.parametrize("contract,version,build", [
    ("fortipam-191-web-secret-create-private-v1", "7.0.0", 29),
    ("fortipam-700-build29-web-secret-create-candidate-v1", "1.9.1", 29),
    ("fortipam-700-build29-web-secret-create-candidate-v1", "7.0.0", 30),
])
def test_web_candidate_requires_exact_contract_version_build(contract, version, build):
    with pytest.raises(SecretCreateAdapterDenied):
        SecretCreate191WebBinding(contract, version, PLAN_DIGEST, "Public/lab", "web", "Web Account", "https://app.example.test", True, build)


def test_target_binding_still_rejects_700():
    with pytest.raises(SecretCreateAdapterDenied):
        replace(_binding(), target_product_version="7.0.0")


@pytest.mark.parametrize("field,value", [("contract_ref", "fortipam-700-build29-web-secret-create-candidate-v1"),
    ("target_product_version", "1.9.1"), ("target_product_build", True), ("template_name", "Windows Machine"),
    ("session_recording", False), ("plan_digest", "bad"), ("folder_path", ""), ("target", None)])
def test_target_bound_web_binding_cannot_masquerade_as_targetless(field, value) -> None:
    from dataclasses import replace
    from fortipam_mcp.secret_create_191_private_adapter import SecretCreate700WebTargetBinding
    from fortipam_mcp.target_contract import WebTargetCreateInput
    binding = SecretCreate700WebTargetBinding(
        "fortipam-700-build29-target-bound-web-create-candidate-v1", "7.0.0", "1" * 64,
        "Public/example", "web-secret", "Web Account",
        WebTargetCreateInput("mcp-v4-target-web-20261003-r1", "https://app.example.test"), True)
    with pytest.raises(SecretCreateAdapterDenied):
        replace(binding, **{field: value})
