"""In-process OAuth/MCP build-29 composition; all device evidence is synthetic.

This is a protocol integration regression, not device acceptance or maturity
evidence. The signed planning and qualification receipts use test authorities.
No socket, SSH session, material source, or actual FortiPAM endpoint is used.
"""

from dataclasses import asdict, replace
import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlsplit

from mcp.server.auth.provider import AccessToken
import pytest
from starlette.testclient import TestClient

import fortipam_mcp.secret_approval_build29_m4_composition as composition
from fortipam_mcp.approval_and_observe_execution_mcp_action import (
    V4_APPROVAL_AND_OBSERVE_EXECUTION_FEATURE_ENV,
    V4_APPROVAL_AND_OBSERVE_EXECUTION_TOOL,
)
from fortipam_mcp.http_server import HttpServerSettings, create_http_app
from fortipam_mcp.runtime_profile import RUNTIME_PROFILE_ENV
from fortipam_mcp.secret_approval_build29_m4_authorization import promote_secret_approval_build29_m4_binding
from fortipam_mcp.secret_approval_build29_projection_source import (
    SOURCE_CONTRACT, SOURCE_REF, SOURCE_VERSION, PROJECTION_CONTRACT,
    FortiPamSecretApprovalBuild29ProjectionSource,
    OwnerOnlySecretApprovalBuild29BindingResolver,
    SecretApprovalBuild29ProfileInspection,
    secret_approval_build29_projection_contract,
)
from fortipam_mcp.secret_metadata_http_transport import SecretApprovalProjectionInspection
from fortipam_mcp.v4_plan_runtime import (
    OAuthBoundV4PlanServices, planning_authorization_settings_from_environment,
    requester_from_access_token,
)
from fortipam_mcp.v4_runtime_host import (
    V4_SYNTHETIC_HOST_MODE_ENV, V4PersistentPlanningCheckpointSettings,
    secret_approval_build29_v4_plan_host_factory,
)
from test_http_server import (
    _authorize_and_login, _initialize_payload, _register_public_client,
    _request_headers, _v4_bound_environment,
)
from test_secret_approval_build29_m4_authorization import _inputs, _OverrideReader, _tampered
from test_secret_approval_build29_m4_composition import _Producer, _factory, _allow_fixed_fake_execution
from test_secret_approval_build29_m4_runtime import _Store
from test_secret_approval_build29_runtime_provider import _body, _write, _verifier
from test_secret_approval_build29_projection_source import (
    _BINDING, _draft, _ProfileTransport, _SecretTransport,
)
from test_secret_approval_build29_v4_runtime_host import _settings
from test_secret_approval_m4_authorization import _ClaimedPlanningReader
from test_v4_m3 import ExactApproverAuthority
from test_v4_planning import NOW, Authorizer, Issuer, _approval_and_observe_draft, _interaction, _promoted_registry
from test_v4_runtime_host import _owner_file
from v4_planning import (
    M2PlanningEngine, M3PlanOnlyWorkflowService,
    PersistentApproverAuthorizationAuthority, PersistentApproverCheckpointAuthority,
)
from v4_planning.approval import ApprovalReceiptAuthenticator, AuthenticatedApprover, M3ApprovalGate
from v4_planning.policy import M3PlanPolicy
from v4_planning.store import InMemoryProtectedPlanningStore


_DRAFT_REF = "build29-oauth-draft-ref01"
_SCOPE = "fortipam:read fortipam:plan fortipam:operate"


def _app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, denial: str | None = None) -> tuple[Any, dict[str, Any]]:
    environment, base_settings = _v4_bound_environment(tmp_path)
    environment.update({
        RUNTIME_PROFILE_ENV: "v4-controlled",
        V4_SYNTHETIC_HOST_MODE_ENV: "source-backed-approval-and-observe-build29",
        V4_APPROVAL_AND_OBSERVE_EXECUTION_FEATURE_ENV: "true",
    })
    settings = HttpServerSettings.from_environment(environment)
    authorization = planning_authorization_settings_from_environment(
        environment, expected_resource="https://mcp.example.com/fpamcp",
    )
    # The subject comes from real local OAuth login below; only preprovisioning
    # of its test signed records happens here. Client IDs do not identify humans.
    requester = requester_from_access_token(AccessToken(
        token="test-preprovisioning-only", client_id="test-preprovisioning-client",
        scopes=_SCOPE.split(), expires_at=2_000_000_000,
        resource="https://mcp.example.com/fpamcp", subject="operator",
        claims={"iss": "https://mcp.example.com/fpamcp/oauth"},
    ), authorization)
    if denial == "wrong_principal":
        requester = replace(requester, subject_ref="foreign-operator-subject01")
    values = _inputs(tmp_path, monkeypatch)
    calls = _allow_fixed_fake_execution(values, monkeypatch)
    draft, binding = _approval_and_observe_draft(), values["approval_binding"]
    events: list[str] = []

    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("The protocol fixture must not acquire material or contact a device.")

    # The fake fixed write is the only enabled product boundary. All accidental
    # owner login, native/full raw reads and account-material acquisition fail.
    transport = values["transport"]
    mutation = transport._mutation
    assert mutation is not None and mutation.web_fields is not None
    transport._mutation = replace(mutation, web_fields=replace(mutation.web_fields, username_span_provider=forbidden))
    for name in ("_read_raw", "_read_transition", "_read_private_projection"):
        monkeypatch.setattr(transport, name, forbidden)

    class Profile:
        def readback(self, name: str) -> SecretApprovalBuild29ProfileInspection:
            assert name == binding.approval_profile_name
            events.append("profile")
            return SecretApprovalBuild29ProfileInspection(*([True] * 8))

    class Secret:
        def inspect_approval_projection(self, folder: str, name: str, profile: str, *, expected_secret_id: int) -> SecretApprovalProjectionInspection:
            assert (folder, name, profile, expected_secret_id) == (
                binding.folder_path, binding.secret_name, binding.approval_profile_name, binding.secret_id,
            )
            events.append("projection")
            written = calls["write"] == 1
            return SecretApprovalProjectionInspection(True, written, False, False, written, not written, False)

    state = base_settings.planning_database_path.parent
    host_settings = _settings(state)
    _owner_file(state / "reference.hmac", b"f" * 32)
    _owner_file(state / "draft.hmac", b"d" * 32)
    binding_path = state / "approval-binding.json"
    binding_path.write_text(json.dumps({
        "contract": SOURCE_CONTRACT, "version": SOURCE_VERSION,
        "requester_digest": requester.digest, "environment_ref": draft.environment_ref,
        "scope_ref": draft.scope_ref, **asdict(binding),
    }))
    binding_path.chmod(0o600)
    base_factory = secret_approval_build29_v4_plan_host_factory(
        host_settings, secret_transport=Secret(), approval_profile_transport=Profile(),
        binding_resolver=OwnerOnlySecretApprovalBuild29BindingResolver(binding_path), clock=lambda: NOW + 5,
    )

    class DraftProvider:
        def resolve(self, reference: str, actual: Any) -> Any:
            assert reference == _DRAFT_REF and actual == requester
            return draft

    def host_factory(provider: Any, confirmation: Any) -> Any:
        components = base_factory(provider, confirmation)
        source = components.approval_and_observe_projection_source
        assert type(source) is FortiPamSecretApprovalBuild29ProjectionSource
        assert source.contract_registered is True
        issuer = Issuer()
        engine = M2PlanningEngine(
            _promoted_registry(), issuer, Authorizer((draft,), projection_source_ref=SOURCE_REF),
            projection_contract_resolver=lambda _scheme, kind: secret_approval_build29_projection_contract(kind),
        )
        authenticator = ApprovalReceiptAuthenticator(b"a" * 32)
        store = InMemoryProtectedPlanningStore(clock=lambda: NOW + 5, approval_receipt_authenticator=authenticator)
        gate = M3ApprovalGate(issuer, receipt_authenticator=authenticator, approver_authorizer=ExactApproverAuthority())
        workflow = M3PlanOnlyWorkflowService(engine, store, M3PlanPolicy(issuer), gate)
        projections = source.project(draft, requester, now_epoch=NOW)
        assert all(item.contract.contract_id == PROJECTION_CONTRACT and item.contract.source_ref == SOURCE_REF for item in projections)
        summary = workflow.compile_summary(draft, requester, projections, now_epoch=NOW)
        confirmation_record = workflow.confirm_intent(summary.summary_ref, requester, _interaction(summary, requester), now_epoch=NOW + 1)
        plan = workflow.prepare_plan(summary.summary_ref, confirmation_record.confirmation_ref, requester, now_epoch=NOW + 2)
        decision = M3PlanPolicy(issuer).evaluate(plan, requester, now_epoch=NOW + 3)
        receipt = gate.approve(decision, AuthenticatedApprover(
            "independent-test-approver01", identity_authority_ref=requester.identity_authority_ref,
            subject_namespace=requester.subject_namespace,
        ), now_epoch=NOW + 4, plan=plan, requester=requester)
        store.put_policy_decision(decision)
        store.put_approval_receipt(receipt)
        claim = store.claim_approval(receipt.receipt_ref, plan.plan_ref, requester.digest)
        values.update(planning=_ClaimedPlanningReader(store, claim), receipt_authenticator=authenticator,
                      source_plan_ref=plan.plan_ref, plan=plan, approval_receipt_ref=receipt.receipt_ref,
                      authenticated_requester_digest=requester.digest,
                      authorized_environment_ref=plan.environment_ref, authorized_scope_ref=plan.scope_ref,
                      store=_Store(), clock_value=[NOW + 5])
        # Test issuer is separate from planning/intent/approval keys. The real
        # verifier authenticates exact scope/binding/plan/TTL, not evidence truth.
        promoted = promote_secret_approval_build29_m4_binding(**{
            key: value for key, value in values.items()
            if key not in {"plan", "store", "clock_value"}
        })
        qualification_path = state / "qualification.json"
        _write(qualification_path, {**_body(), "binding_digest": values["expected_binding_digest"],
                                   "plan_digest": promoted.plan.plan_digest, "issued_at": NOW, "expires_at": NOW + 300})
        values["qualifier"] = _verifier(qualification_path)
        services = OAuthBoundV4PlanServices(
            workflow, draft_provider=DraftProvider(), projection_provider=source,
            confirmation_transport=components.confirmation_service, clock=lambda: NOW + 5,
        )
        values.update(source=source, events=events, calls=calls)
        events.clear()
        return replace(components, plan_services=services)

    def execution_factory(components: Any) -> Any:
        if denial == "forged_chain":
            reader = values["planning"]
            receipt = reader.get_approval_receipt(values["approval_receipt_ref"])
            values["planning"] = _OverrideReader(reader, "get_approval_receipt", _tampered(receipt, "receipt_mac", "f" * 64))
        values["producer"] = _Producer(values)
        real_validate = composition.validate_build29_planning_chain

        def validate(*args: Any, **kwargs: Any) -> Any:
            result = real_validate(*args, **kwargs)
            events.append("validated")
            return result

        monkeypatch.setattr(composition, "validate_build29_planning_chain", validate)
        producer = values["producer"]
        real_produce = producer.produce

        def produce(actual: Any) -> Any:
            assert events[:2] == ["profile", "projection"] and "validated" in events
            events.append("produce")
            return real_produce(actual)

        monkeypatch.setattr(producer, "produce", produce)
        factory = _factory(values, qualification_verifier=values["qualifier"], execution_enabled=denial != "default_gate")
        return components.bind_approval_and_observe_execution_mcp_action(
            factory, authorized_environment_ref=draft.environment_ref,
            authorized_scope_ref=draft.scope_ref, execution_enabled=True,
        )

    app = create_http_app(settings, v4_plan_host_factory=host_factory,
                          v4_approval_and_observe_execution_factory=execution_factory)
    return app, values


def _exercise(client: TestClient, values: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    client_id = _register_public_client(client, _SCOPE)
    code, verifier = _authorize_and_login(client, client_id, _SCOPE)
    token = client.post("/fpamcp/oauth/token", data={
        "grant_type": "authorization_code", "client_id": client_id, "code": code,
        "code_verifier": verifier, "redirect_uri": "https://client.example/callback",
        "resource": "https://mcp.example.com/fpamcp",
    })
    assert token.status_code == 200
    headers = _request_headers(token.json()["access_token"])
    headers["host"] = "mcp.example.com"
    assert client.post("/fpamcp", headers=headers, json=_initialize_payload()).status_code == 200
    tools = client.post("/fpamcp", headers=headers, json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    by_name = {item["name"]: item for item in tools.json()["result"]["tools"]}
    tool = by_name[V4_APPROVAL_AND_OBSERVE_EXECUTION_TOOL]
    assert set(tool["inputSchema"]["properties"]) == {"plan_ref", "scheme_draft_ref"}
    rejected = client.post("/fpamcp", headers=headers, json={
        "jsonrpc": "2.0", "id": "extra-argument", "method": "tools/call",
        "params": {"name": V4_APPROVAL_AND_OBSERVE_EXECUTION_TOOL, "arguments": {
            "plan_ref": values["source_plan_ref"], "scheme_draft_ref": _DRAFT_REF,
            "approval_receipt": "caller-controlled-receipt-ref01",
        }},
    })
    assert rejected.status_code == 200 and rejected.json()["result"]["isError"] is True
    assert values["producer"].calls == values["store"].claim_calls == values["calls"]["write"] == 0
    assert values["events"] == []
    response = client.post("/fpamcp", headers=headers, json={
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": V4_APPROVAL_AND_OBSERVE_EXECUTION_TOOL,
                   "arguments": {"plan_ref": values["source_plan_ref"], "scheme_draft_ref": _DRAFT_REF}},
    })
    assert response.status_code == 200
    return response.json()["result"], by_name


def test_oauth_fixed_two_refs_execute_signed_build29_chain_and_post_projection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    app, values = _app(tmp_path, monkeypatch)
    with TestClient(app, base_url="https://mcp.example.com") as client:
        result, _tools = _exercise(client, values)
    assert result["isError"] is False
    public = result["structuredContent"]
    assert public["outcome"] == "succeeded"
    assert public["pre_write_status"] == "match" and public["post_write_status"] == "expected_state_matches"
    assert public["policy_mode"] == "independent_approval"
    assert values["events"].index("validated") < values["events"].index("produce")
    assert values["events"][-2:] == ["profile", "projection"]
    assert values["producer"].calls == values["store"].claim_calls == values["calls"]["write"] == 1
    encoded = json.dumps(result)
    for private in (values["approval_binding"].secret_name, values["approval_binding"].approval_profile_name,
                    values["approval_binding"].folder_path):
        assert private not in encoded


@pytest.mark.parametrize("denial", ["wrong_principal", "default_gate", "forged_chain"])
def test_oauth_public_boundary_refuses_before_private_producer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, denial: str) -> None:
    app, values = _app(tmp_path, monkeypatch, denial=denial)
    with TestClient(app, base_url="https://mcp.example.com") as client:
        result, _tools = _exercise(client, values)
    assert result["isError"] is True
    assert values["producer"].calls == values["store"].claim_calls == values["calls"]["read"] == values["calls"]["write"] == 0
    assert "produce" not in values["events"]
    if denial == "wrong_principal":
        assert values["events"] == []


def test_native_build29_host_public_preview_confirmation_and_prepare(tmp_path: Path) -> None:
    """Keep the factory's original engine, workflow, and services throughout."""
    environment, base_settings = _v4_bound_environment(tmp_path)
    environment.update({RUNTIME_PROFILE_ENV: "v4-controlled",
                        V4_SYNTHETIC_HOST_MODE_ENV: "source-backed-approval-and-observe-build29"})
    settings = HttpServerSettings.from_environment(environment)
    authorization = planning_authorization_settings_from_environment(
        environment, expected_resource="https://mcp.example.com/fpamcp",
    )
    requester = requester_from_access_token(AccessToken(
        token="test-preprovisioning-only", client_id="test-preprovisioning-client",
        scopes=_SCOPE.split(), expires_at=2_000_000_000,
        resource="https://mcp.example.com/fpamcp", subject="operator",
        claims={"iss": "https://mcp.example.com/fpamcp/oauth"},
    ), authorization)
    draft, state = _draft(), base_settings.planning_database_path.parent
    for name, value in (("reference", b"f"), ("draft", b"d"), ("planning-checkpoint", b"k"),
                        ("approver", b"u"), ("approver-checkpoint", b"z")):
        _owner_file(state / (name + ".hmac"), value * 32)
    binding_path = state / "approval-binding.json"
    binding_path.write_text(json.dumps({
        "contract": SOURCE_CONTRACT, "version": SOURCE_VERSION,
        "requester_digest": requester.digest, "environment_ref": draft.environment_ref,
        "scope_ref": draft.scope_ref, **asdict(_BINDING),
    }))
    binding_path.chmod(0o600)
    host_settings = replace(_settings(state), planning_checkpoint=V4PersistentPlanningCheckpointSettings(
        state / "planning-checkpoint.sqlite3", state / "planning-checkpoint.hmac", "native-build29-planning-store",
    ))
    approver_checkpoint = PersistentApproverCheckpointAuthority(
        state / "approver-checkpoint.sqlite3", state / "approver-checkpoint.hmac",
        authority_ref="native-build29-approver-checkpoint",
    )
    approver_authority = PersistentApproverAuthorizationAuthority(
        state / "approver.sqlite3", state / "approver.hmac",
        authority_ref="native-build29-approver-authority", monotonic_checkpoint=approver_checkpoint,
        checkpoint_store_ref="native-build29-approver-store", clock=lambda: NOW + 5,
    )
    signer = ApprovalReceiptAuthenticator(b"x" * 32)
    profile, secret = _ProfileTransport(), _SecretTransport(SecretApprovalProjectionInspection(
        True, False, False, False, False, True, False,
    ))
    native_factory = secret_approval_build29_v4_plan_host_factory(
        host_settings, secret_transport=secret, approval_profile_transport=profile,
        binding_resolver=OwnerOnlySecretApprovalBuild29BindingResolver(binding_path),
        approval_receipt_authenticator=signer, approver_authorization_authority=approver_authority,
        clock=lambda: NOW + 5,
    )
    captured: dict[str, Any] = {}

    def provision_native_host(provider: Any, confirmation_settings: Any) -> Any:
        components = native_factory(provider, confirmation_settings)
        assert components.reference_authority is not None and components.scheme_draft_authority is not None
        assert components._secret_approval_receipt_authenticator is signer
        # Registration is an existing owner-side operation. Every grant remains
        # tied to the actual OAuth human, environment, scope, and fixed new source.
        references = (
            (SOURCE_REF, "projection_source"), (draft.environment_ref, "environment"),
            (draft.scope_ref, "scope"), (draft.owner_ref, "owner"), (draft.audience_ref, "audience"),
            *((item, "evidence") for item in draft.evidence_refs),
            (_BINDING.approval_profile_object_ref, "object_approval_profile_binding"),
            (_BINDING.secret_approval_object_ref, "object_secret_approval_binding"),
            (_BINDING.approval_profile_ref, "field_profile_ref"),
        )
        components.reference_authority.issue_many(
            references, requester_digest=requester.digest, environment_ref=draft.environment_ref,
            scope_ref=draft.scope_ref, expires_at=NOW + 300, now_epoch=NOW + 5,
        )
        captured["draft_ref"] = components.scheme_draft_authority.issue(
            draft, requester, expires_at=NOW + 300, now_epoch=NOW + 5,
        )
        captured["components"] = components
        captured["native_services"] = components.plan_services
        return components

    app = create_http_app(settings, v4_plan_host_factory=provision_native_host)
    with TestClient(app, base_url="https://mcp.example.com") as client:
        client_id = _register_public_client(client, _SCOPE)
        code, verifier = _authorize_and_login(client, client_id, _SCOPE)
        token = client.post("/fpamcp/oauth/token", data={
            "grant_type": "authorization_code", "client_id": client_id, "code": code,
            "code_verifier": verifier, "redirect_uri": "https://client.example/callback",
            "resource": "https://mcp.example.com/fpamcp",
        })
        assert token.status_code == 200
        headers = {**_request_headers(token.json()["access_token"]), "host": "mcp.example.com"}

        def call(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
            response = client.post("/fpamcp", headers=headers, json={
                "jsonrpc": "2.0", "id": name, "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            })
            assert response.status_code == 200
            result = response.json()["result"]
            assert result["isError"] is False
            return dict(result["structuredContent"])

        status = call("get_v4_plan_status", {})
        for flag in ("projection_contract_registered", "monotonic_checkpoint_protocol_bound",
                     "scheme_draft_issuance_protocol_bound", "reference_authorization_protocol_bound",
                     "approval_receipt_authenticator_protocol_bound", "approver_authorization_protocol_bound",
                     "approver_authority_checkpoint_protocol_bound"):
            assert status[flag] is True
        preview = call("preview_v4_administrative_intent", {"scheme_draft_ref": captured["draft_ref"]})
        confirmation_path = urlsplit(preview["confirmation_url"]).path

        def csrf(text: str) -> str:
            found = re.search(r'name="csrf_token" value="([^"]+)"', text)
            assert found is not None
            return found.group(1)

        page = client.get(confirmation_path)
        assert page.status_code == 200
        review = client.post(confirmation_path, data={
            "csrf_token": csrf(page.text), "username": "operator",
            "password": "correct-horse-battery-staple", "action": "review",
        }, headers={"origin": "https://mcp.example.com"})
        assert review.status_code == 200
        affirmed = client.post(confirmation_path, data={"csrf_token": csrf(review.text), "action": "affirm"},
                                headers={"origin": "https://mcp.example.com"})
        assert affirmed.status_code == 200
        confirmation = call("confirm_v4_administrative_intent", {
            "summary_ref": preview["summary_ref"], "summary_revision": preview["revision"],
        })
        plan = call("prepare_v4_non_executable_plan", {
            "summary_ref": preview["summary_ref"], "confirmation_ref": confirmation["confirmation_ref"],
        })
    assert plan["dispatchable"] is plan["executor_mcp_exposed"] is plan["adapter_registry_bound"] is False
    assert len(plan["lines"]) == 1
    assert (profile.calls, secret.calls) == (1, 1)
    components = captured["components"]
    assert components.plan_services is captured["native_services"]
    assert components.plan_services._facade._projection_provider is components.approval_and_observe_projection_source
    stored_summary = components._secret_approval_planning_reader.get_summary(preview["summary_ref"], preview["revision"])
    assert stored_summary.requester_digest == requester.digest
    assert all(item.projection_source_ref == SOURCE_REF and item.projection_contract_ref == PROJECTION_CONTRACT
               for item in stored_summary.object_changes)
    public = json.dumps((preview, confirmation, plan))
    for private in (_BINDING.secret_name, _BINDING.approval_profile_name, _BINDING.folder_path):
        assert private not in public
