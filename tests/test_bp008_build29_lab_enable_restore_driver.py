"""Offline protected-driver wiring, real browser transport and M3 signatures.

Only the simulated product fixture and protected main capture are supplied by
the test. New restore confirmation uses the actual service HTTP routes; no
VerifiedConfirmationInteraction or AccessToken is manufactured here.
"""

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx2
from mcp.types import CallToolResult
import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from scripts.bp008_build29_lab_enable_restore_driver import (
    Build29LabDriverDenied, Build29LabEnableRestoreDriver, Build29MainLabCapture,
)
from fortipam_mcp.secret_approval_build29_m4_runtime import secret_approval_build29_binding_digest
from fortipam_mcp.v4_confirmation_http import LocalIntentConfirmationService
from fortipam_mcp.local_oauth import LocalOAuthProvider
from fortipam_mcp.http_server import HttpServerSettings, create_http_app
from fortipam_mcp.v4_plan_runtime import V4PlanningAuthorizationSettings, V4PlanningPrincipal
from test_http_server import _local_oauth_environment, _register_public_client, _authorize_and_login
from test_secret_approval_build29_restore import _applied, _chain
from test_secret_approval_build29_runtime_provider import _body, _write, _verifier
from test_v4_confirmation_http import _service, PASSWORD, NAMESPACE
from test_v4_planning import NOW, _approval_and_observe_draft
from v4_planning import AuthenticatedApprover, M4AdapterDenied


def _fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Any, ...]:
    applied = _applied(tmp_path, monkeypatch)
    chain = _chain(applied, tmp_path)
    # A new restore intent; the helper's existing fixture receipt is not reused.
    workflow = chain["workflow"]
    summary = workflow.compile_summary(chain["source"].draft, applied["requester"],
                                       chain["projections"], now_epoch=NOW + 15)
    service, clock, _unused = _service(tmp_path)
    service._summary_reader = workflow._store
    clock.value = NOW + 15
    principal = V4PlanningPrincipal(applied["requester"], NAMESPACE)
    url = service.issue(summary, principal.requester, principal_namespace_digest=NAMESPACE, now_epoch=clock.value)
    reader = chain["planning"]
    reader.get_approval_claim = lambda receipt_ref: workflow._store._claims[receipt_ref]
    factory = SimpleNamespace(_planning=reader, _authenticator=chain["receipt_authenticator"],
        _authority_ref=chain["pins"]["approver_authority_ref"], _store=applied["execution_store"],
        _qualifier=_verifier(tmp_path / "main-qualification.json"),
        _clock=lambda: clock.value, _bound=SimpleNamespace(runner=SimpleNamespace(runtime=SimpleNamespace(_binding=applied["forward"]))))
    driver = object.__new__(Build29LabEnableRestoreDriver)
    driver._factory = factory
    driver._components = SimpleNamespace(confirmation_service=service)
    driver._restore = dict(source=chain["source"], workflow=workflow, principal=principal,
                          summary=summary, url=url, draft_ref="restore-driver-draft-ref01")
    driver._enable_refs = {"plan_ref": applied["forward"].plan.plan_ref, "scheme_draft_ref": "enable-driver-draft-ref01"}
    driver._enable_succeeded = False
    driver._enable_dispatched = False
    return driver, applied, chain, service, clock


def test_actual_reauth_csrf_one_time_receipt_then_independent_approval_restore(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    driver, applied, chain, service, clock = _fixture(tmp_path, monkeypatch)
    approver = AuthenticatedApprover("restore-approver-subject01", identity_authority_ref=applied["requester"].identity_authority_ref,
                                     subject_namespace=applied["requester"].subject_namespace)

    async def run() -> dict[str, object]:
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=Starlette(routes=service.routes())),
                                     base_url="https://mcp.example.com") as client:
            missing_origin = await client.post(driver._restore["url"], data={"csrf_token": "forged", "action": "affirm"})
            assert missing_origin.status_code == 400
            forged_csrf = await client.post(driver._restore["url"], data={"csrf_token": "forged", "action": "affirm"},
                                            headers={"Origin": service._origin})
            assert forged_csrf.status_code == 400
            with pytest.raises(Exception, match="reauthentication failed"):
                await driver.confirm_prepare_restore(client, username="operator", password="wrong-password")
            assert "plan" not in driver._restore
            refs = await driver.confirm_prepare_restore(client, username="operator", password=PASSWORD)
            replay = await client.post(driver._restore["url"], data={"csrf_token": "forged", "action": "affirm"},
                                       headers={"Origin": service._origin})
            assert replay.status_code == 400
            assert refs["plan_ref"] != chain["plan"].plan_ref
            interaction = service.verify(applied["requester"], principal_namespace_digest=NAMESPACE,
                summary_ref=driver._restore["summary"].summary_ref, summary_revision=1, now_epoch=clock.value)
            assert interaction.decision == "affirm" and interaction.nonce_digest
            await driver.approve_claim_promote_restore(approver, authorization_ref="restore-driver-authorization-ref01")
            binding = driver.private_qualification_target("restore")
            assert binding.transport is applied["forward"].transport
            assert binding.authorization.approval_ref != applied["forward"].authorization.approval_ref
            path = tmp_path / "independent-restore-qualification.json"
            qualifier = _verifier(path)
            writes, claims = applied["calls"]["write"], applied["execution_store"].claim_calls
            with pytest.raises(M4AdapterDenied):
                await driver.execute_restore(qualifier)
            assert applied["calls"]["write"] == writes and applied["execution_store"].claim_calls == claims
            assert driver._restore.get("dispatched") is not True
            # Synthetic independent source issuer uses the established manifest
            # contract. Production issuance is not provided by this driver.
            _write(path, {**_body(), "binding_digest": secret_approval_build29_binding_digest(binding),
                         "plan_digest": binding.plan.plan_digest, "issued_at": NOW + 15, "expires_at": NOW + 60})
            with pytest.raises(Build29LabDriverDenied):
                await driver.execute_restore(SimpleNamespace(verify=lambda **_kwargs: None))
            from fortipam_mcp.secret_approval_build29_runtime_provider import OwnerOnlySecretApprovalBuild29QualificationVerifier
            foreign = OwnerOnlySecretApprovalBuild29QualificationVerifier(path, authority_ref="foreign-source-authority01",
                authority_key=b"f" * 32, expected_evidence_digest="c" * 64)
            with pytest.raises(Build29LabDriverDenied, match="qualification authority is unavailable"):
                await driver.execute_restore(foreign)
            result = await driver.execute_restore(qualifier)
            assert result == refs
            with pytest.raises(Build29LabDriverDenied):
                await driver.execute_restore(qualifier)
            return result

    refs = asyncio.run(run())
    assert applied["private"]["current"] == applied["forward"].baseline
    assert applied["forward"].transport._ownership is None
    assert applied["calls"]["write"] == 2 and applied["execution_store"].claim_calls == 2
    public = json.dumps(refs)
    for value in (applied["forward"].baseline.state_digest, applied["forward"].baseline.native_digest,
                  applied["forward"].plan.plan_digest, applied["values"]["expected_binding_digest"]):
        assert value not in public
    assert "protected" in repr(driver) and "password" not in repr(driver)


def test_enable_dispatch_refusal_is_closed_and_uncertain_mcp_is_not_replayed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    driver, applied, _chain_value, _service_value, _clock = _fixture(tmp_path, monkeypatch)
    path = tmp_path / "enable-qualification.json"
    driver._factory._qualifier = _verifier(path)
    calls: list[dict[str, object]] = []

    class Session:
        async def call_tool(self, name: str, arguments: dict[str, object]) -> Any:
            assert name == "execute_v4_approval_and_observe_workflow"
            calls.append(arguments)
            return CallToolResult(content=[], is_error=False,
                                  structured_content={"outcome": "reconciliation_required", "reconciliation_required": True})

    async def run() -> None:
        with pytest.raises(M4AdapterDenied):
            await driver.execute_enable_mcp(Session())
        assert calls == []
        binding = applied["forward"]
        _write(path, {**_body(), "binding_digest": secret_approval_build29_binding_digest(binding),
                     "plan_digest": binding.plan.plan_digest, "issued_at": NOW + 15, "expires_at": NOW + 60})
        with pytest.raises(Build29LabDriverDenied, match="requires reconciliation"):
            await driver.execute_enable_mcp(Session())
        with pytest.raises(Build29LabDriverDenied, match="dispatch is unavailable"):
            await driver.execute_enable_mcp(Session())

    asyncio.run(run())
    assert calls == [driver._enable_refs]
    assert set(calls[0]) == {"plan_ref", "scheme_draft_ref"}


def test_capture_and_driver_reject_foreign_objects() -> None:
    with pytest.raises(Build29LabDriverDenied):
        Build29MainLabCapture(object())
    with pytest.raises(Build29LabDriverDenied):
        Build29LabEnableRestoreDriver(object(), object(), object(), object())


def test_preview_restore_entry_clones_valid_registry_metadata_and_issues_real_confirmation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    driver, applied, chain, service, _clock = _fixture(tmp_path, monkeypatch)
    principal = driver._restore["principal"]
    driver._factory._bound.draft = _approval_and_observe_draft()
    driver._factory._bound.principal = principal
    driver._components.approval_and_observe_projection_source = applied["categorical"]
    driver._components.plan_services = SimpleNamespace(_workflow=chain["workflow"])
    driver._enable_succeeded = True  # The fixture already executed its fake product enable.
    driver._restore = None

    async def authenticated_fixture_principal(raw_token: str) -> V4PlanningPrincipal:
        # This test substitutes only the authenticated transport boundary;
        # genuine provider token validation has separate regressions below.
        assert raw_token == "fixture-authenticated-token"
        return principal

    monkeypatch.setattr(driver, "_principal", authenticated_fixture_principal)

    async def run() -> dict[str, object]:
        refs = await driver.preview_restore("fixture-authenticated-token", ownership_evidence_ref="owned-approval-evidence-ref01")
        assert set(refs) == {"scheme_draft_ref"}
        state = driver._restore
        assert state["workflow"]._planning_engine._registry.schema_version == chain["engine"]._registry.schema_version
        assert state["workflow"]._store is chain["workflow"]._store
        assert state["workflow"]._policy is chain["workflow"]._policy
        assert state["workflow"]._approval_gate is chain["workflow"]._approval_gate
        summary = state["summary"]
        assert summary.outcome_code == "restore_owned_original_approval"
        assert state["workflow"]._store.get_summary(summary.summary_ref, summary.revision) == summary
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=Starlette(routes=service.routes())),
                                     base_url="https://mcp.example.com") as client:
            prepared = await driver.confirm_prepare_restore(client, username="operator", password=PASSWORD)
        assert prepared["scheme_draft_ref"] == refs["scheme_draft_ref"]
        assert set(prepared) == {"plan_ref", "scheme_draft_ref"}
        return prepared

    refs = asyncio.run(run())
    assert applied["calls"]["write"] == 1  # Preview/confirm/prepare never replay enable.
    assert applied["execution_store"].claim_calls == 1
    assert applied["forward"].transport._ownership is not None
    assert applied["forward"].baseline.state_digest not in json.dumps(refs)


@pytest.mark.parametrize("scope", ["fortipam:read fortipam:plan", "fortipam:read fortipam:plan fortipam:operate"])
def test_driver_loads_genuine_oauth_token_and_rejects_missing_operate_or_revocation(tmp_path: Path, scope: str) -> None:
    settings = HttpServerSettings.from_environment(_local_oauth_environment(tmp_path))
    assert settings.local_oauth is not None
    provider = LocalOAuthProvider(settings.local_oauth)
    driver = object.__new__(Build29LabEnableRestoreDriver)
    driver._provider = provider
    driver._authorization = V4PlanningAuthorizationSettings("https://mcp.example.com/fpamcp", b"n" * 32)
    with TestClient(create_http_app(settings), base_url="https://mcp.example.com") as client:
        client_id = _register_public_client(client, scope)
        code, verifier = _authorize_and_login(client, client_id, scope)
        exchange = client.post("/fpamcp/oauth/token", data={
            "grant_type": "authorization_code", "client_id": client_id, "code": code,
            "code_verifier": verifier, "redirect_uri": "https://client.example/callback",
            "resource": "https://mcp.example.com/fpamcp",
        })
        assert exchange.status_code == 200
        raw = exchange.json()["access_token"]
        if "fortipam:operate" not in scope:
            with pytest.raises(Build29LabDriverDenied):
                asyncio.run(driver._principal(raw))
        else:
            principal = asyncio.run(driver._principal(raw))
            assert type(principal) is V4PlanningPrincipal
        token = asyncio.run(provider.load_access_token(raw))
        assert token is not None
        asyncio.run(provider.revoke_token(token))
        with pytest.raises(Build29LabDriverDenied):
            asyncio.run(driver._principal(raw))


@pytest.mark.parametrize("is_error", [False, True])
def test_enable_real_sdk_result_requires_success_without_protocol_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, is_error: bool) -> None:
    driver, applied, _chain_value, _service_value, _clock = _fixture(tmp_path, monkeypatch)
    path = tmp_path / "enable-qualification.json"
    binding = applied["forward"]
    _write(path, {**_body(), "binding_digest": secret_approval_build29_binding_digest(binding),
                 "plan_digest": binding.plan.plan_digest, "issued_at": NOW + 15, "expires_at": NOW + 60})
    driver._factory._qualifier = _verifier(path)

    class Session:
        async def call_tool(self, name: str, arguments: dict[str, object]) -> CallToolResult:
            assert set(arguments) == {"plan_ref", "scheme_draft_ref"}
            return CallToolResult(content=[], is_error=is_error,
                                  structured_content={"outcome": "succeeded", "reconciliation_required": False})

    if is_error:
        with pytest.raises(Build29LabDriverDenied):
            asyncio.run(driver.execute_enable_mcp(Session()))
        assert not driver._enable_succeeded
    else:
        assert asyncio.run(driver.execute_enable_mcp(Session())) == driver._enable_refs
        assert driver._enable_succeeded


@pytest.mark.parametrize('linux,qualified_linux,trusted_linux,accepted', [
    (False, False, False, True), (True, True, True, True),
    (False, True, True, False), (True, False, False, False),
    (True, True, False, False), (False, False, True, False),
])
def test_restore_qualifier_exact_type_follows_transport_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    linux: bool, qualified_linux: bool, trusted_linux: bool, accepted: bool,
) -> None:
    import scripts.bp008_build29_lab_enable_restore_driver as module
    from fortipam_mcp.secret_approval_build29_runtime_provider import (
        OwnerOnlySecretApprovalBuild29QualificationVerifier,
        OwnerOnlySecretApprovalBuild29LinuxQualificationVerifier,
    )
    def qualifier(is_linux: bool) -> Any:
        kind = OwnerOnlySecretApprovalBuild29LinuxQualificationVerifier if is_linux else OwnerOnlySecretApprovalBuild29QualificationVerifier
        return kind(tmp_path / 'unused-qualification.json', authority_ref='test-scope-authority01',
                    authority_key=b'x' * 32, expected_evidence_digest='c' * 64)
    driver = object.__new__(Build29LabEnableRestoreDriver)
    driver._factory = SimpleNamespace(_qualifier=qualifier(trusted_linux), _planning=object(),
        _authenticator=object(), _store=object(), _clock=lambda: NOW)
    driver._restore = {'binding': SimpleNamespace(transport=SimpleNamespace(_linux_target_name='fixed-linux' if linux else None)),
        'source': object(), 'pins': {}, 'principal': SimpleNamespace(requester=SimpleNamespace(digest='a' * 64))}
    reached = []
    class PassedExactScopeBoundary(Exception):
        pass
    def bounded_assembly(*_args: Any, **_kwargs: Any) -> None:
        reached.append(True)
        raise PassedExactScopeBoundary
    monkeypatch.setattr(module, 'PlanningChainSecretApprovalBuild29RestoreAuthorizationVerifier', lambda *_args, **_kwargs: object())
    monkeypatch.setattr(module, 'assemble_secret_approval_build29_m4_runtime', bounded_assembly)
    expected = PassedExactScopeBoundary if accepted else Build29LabDriverDenied
    with pytest.raises(expected):
        asyncio.run(driver.execute_restore(qualifier(qualified_linux)))
    assert bool(reached) is accepted
    assert driver._restore.get('dispatched') is not True
