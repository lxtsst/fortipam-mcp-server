from dataclasses import replace

import pytest

from fortipam_mcp.secret_metadata_http_transport import SecretMetadataProjectionInspection
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from fortipam_mcp.web_secret_service_m4_composition import assemble_web_secret_service_m4_runner_factory
from fortipam_mcp.web_secret_service_ssh_transport import FortiPamWebSecretServiceSshTransport
from test_m4_execution_store import _store
from test_v4_m3 import ExactApproverAuthority
from test_v4_planning import NOW, _existing_web_service_draft
from test_web_secret_service_m4_authorization import _claimed_chain, _service_binding, _onboarding_binding
from v4_planning import AuthenticatedRequester, M4AuthorizationDenied


class Product:
    """Synthetic appliance state; no network access or credentials."""

    def __init__(self):
        self.state = SecretMetadataProjectionInspection(
            True, True, True, True, True, True, True, False, recording_matches=True,
        )
        self.writes = 0

    def inspect_web_projection(self, folder, name, template, *, expected_secret_id):
        binding = _service_binding()
        assert (folder, name, template, expected_secret_id) == (
            binding.folder_path, binding.secret_name, "Web Account", binding.secret_id,
        )
        return self.state

    def enable_http_service(self, secret_id, *, prewrite):
        assert secret_id == _service_binding().secret_id
        assert prewrite == self.state and not self.state.http_service_enabled
        self.writes += 1
        self.state = replace(self.state, http_service_enabled=True)


def _factory(tmp_path, product):
    planning, authenticator, plan, receipt = _claimed_chain()
    writer = object.__new__(FortiPamWebSecretServiceSshTransport)
    writer.enable_http_service = product.enable_http_service
    factory = assemble_web_secret_service_m4_runner_factory(
        planning=planning, receipt_authenticator=authenticator,
        onboarding_binding=_onboarding_binding(), service_binding=_service_binding(),
        source_plan_ref=plan.plan_ref, approval_receipt_ref=receipt.receipt_ref,
        approver_authority_ref=ExactApproverAuthority.authority_ref,
        authorization_ref="web-service-authorization-ref01",
        read_transport=product, write_transport=writer, execution_store=_store(tmp_path),
        authenticated_requester_digest=plan.requester_digest, clock=lambda: NOW + 5,
    )
    principal = V4PlanningPrincipal(
        AuthenticatedRequester(
            "operator-subject-0001", "operator",
            identity_authority_ref="identity-authority-ref01",
            subject_namespace="workforce-namespace-v1",
        ), "a" * 64,
    )
    return factory, plan, principal


def _runner(factory, plan, principal, **overrides):
    arguments = dict(draft=_existing_web_service_draft(), onboarding_binding=_onboarding_binding())
    arguments.update(overrides)
    return factory.bind(plan, plan.lines[0].line_ref, principal, **arguments)


def test_signed_chain_composition_dispatches_once_across_reconstruction(tmp_path):
    product = Product()
    factory, plan, principal = _factory(tmp_path, product)
    result = _runner(factory, plan, principal).execute_bound()
    assert result["idempotent_replay"] is False
    assert result["outcome"] == "succeeded"
    assert product.writes == 1 and product.state.http_service_enabled
    rebuilt, plan, principal = _factory(tmp_path, product)
    replay = _runner(rebuilt, plan, principal).execute_bound()
    assert replay["idempotent_replay"] is True
    assert replay["outcome"] == result["outcome"]
    assert product.writes == 1


def test_uncertain_signed_dispatch_is_not_retried_after_reconstruction(tmp_path):
    product = Product()
    def uncertain(secret_id, *, prewrite):
        product.writes += 1
        raise OSError("synthetic transport disconnect")
    product.enable_http_service = uncertain
    factory, plan, principal = _factory(tmp_path, product)
    result = _runner(factory, plan, principal).execute_bound()
    assert result["outcome"] == "reconciliation_required"
    rebuilt, plan, principal = _factory(tmp_path, product)
    replay = _runner(rebuilt, plan, principal).execute_bound()
    assert replay["outcome"] == "reconciliation_required"
    assert product.writes == 1


@pytest.mark.parametrize("change", ["binding", "draft", "requester"])
def test_composition_rejects_cross_bound_context_without_dispatch(tmp_path, change):
    product = Product()
    factory, plan, principal = _factory(tmp_path, product)
    overrides = {}
    if change == "binding":
        overrides["onboarding_binding"] = replace(_onboarding_binding(), existing_secret_id=25)
    elif change == "draft":
        overrides["draft"] = replace(_existing_web_service_draft(), scope_ref="other-scope-ref01")
    else:
        principal = replace(principal, requester=replace(principal.requester, subject_ref="other-operator"))
    with pytest.raises(M4AuthorizationDenied):
        _runner(factory, plan, principal, **overrides)
    assert product.writes == 0
