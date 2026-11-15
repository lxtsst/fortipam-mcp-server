"""Full Linux enable/independent restore chain against a synthetic fixed device."""
from dataclasses import replace
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any, cast

import pytest

import fortipam_mcp.secret_approval_build29_private_sources as source_module
import fortipam_mcp.secret_approval_build29_runtime_provider as provider
from fortipam_mcp.secret_approval_build29_m4_composition import SecretApprovalBuild29M4RunnerFactory
from fortipam_mcp.secret_approval_build29_m4_runtime import assemble_secret_approval_build29_m4_runtime
from fortipam_mcp.secret_approval_build29_metadata_reader import (
    SecretApprovalBuild29ProfileReader, SecretApprovalBuild29ProjectionReader,
)
from fortipam_mcp.secret_approval_build29_projection_source import FortiPamSecretApprovalBuild29ProjectionSource
from fortipam_mcp.secret_approval_build29_restore import (
    SecretApprovalBuild29OwnedRestoreSource, PlanningChainSecretApprovalBuild29RestoreAuthorizationVerifier,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from test_secret_approval_build29_http_transport import (
    _LINUX_TARGET, _linux_payload, _LinuxMutationClient, _native_put_ack, _Response,
    _FOLDER, _NAME, _SERIAL,
)
from test_secret_approval_build29_metadata_reader import _PROFILE, _profile_payload
from test_secret_approval_build29_m4_authorization import _claimed_chain
from test_secret_approval_build29_m4_runtime import _Store
from test_secret_approval_build29_runtime_provider import _linux_folder_acl, _linux_acl_digest
from test_secret_approval_build29_runtime_provider_integration import _ScopeOwner, _Sources
from test_secret_approval_build29_restore import _chain, _promote
from test_secret_approval_m4_authorization import _binding
from test_v4_planning import NOW, _approval_and_observe_draft
from v4_planning import M4AdapterDenied, M4Outcome

_KEY = b"linux-chain-independent-source-key"


class _Device(_LinuxMutationClient):
    def stream(self, method: str, path: str, **kwargs: Any) -> _Response:
        if method == "GET" and path == "/api/v2/cmdb/secret/approval-profile/" + _PROFILE:
            self.calls.append((method, path))
            return _Response(json.dumps(_profile_payload()).encode())
        result = super().stream(method, path, **kwargs)
        return _Response(bytes(_native_put_ack())) if method == "PUT" else result


def _qualify(path: Path, binding_digest: str, plan_digest: str, *, web: bool = False) -> None:
    body = {
        "contract": provider.QUALIFICATION_CONTRACT if web else provider.LINUX_QUALIFICATION_CONTRACT,
        "authority_ref": "linux-chain-source-authority", "evidence_digest": "e" * 64,
        "binding_digest": binding_digest, "plan_digest": plan_digest,
        "product_version": "7.0.0", "product_build": 29,
        "scope": provider.QUALIFICATION_SCOPE if web else provider.LINUX_QUALIFICATION_SCOPE,
        "issued_at": NOW, "expires_at": NOW + 100,
    }
    domain = provider._QUALIFICATION_DOMAIN if web else provider._LINUX_QUALIFICATION_DOMAIN
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    signature = hmac.new(_KEY, domain + canonical, hashlib.sha256).hexdigest()
    path.write_text(json.dumps({"body": body, "signature": signature}))
    path.chmod(0o600)


def _setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    reader, authenticator, requester, plan, receipt = _claimed_chain()
    owner = _ScopeOwner(_linux_payload())
    device = _Device(owner.client.response)
    owner.client = device
    sources = _Sources(owner)
    sources._linux_target_name = _LINUX_TARGET
    monkeypatch.setattr(source_module, "SecretApprovalBuild29PrivateSources", _Sources)
    acl = _linux_folder_acl()
    acl_reads: list[str] = []
    def folder_acl(method: str, path: str, body: object, *, query: str) -> tuple[int, object]:
        assert owner._client is not None and method == "GET" and body is None
        assert path == "/api/v2/cmdb/secret/folder/17"
        assert query == "format=id%7Cinherit-permission%7Cuser-permission%7Cgroup-permission"
        acl_reads.append(path)
        return 200, {"results": [acl]}
    monkeypatch.setattr(owner, "_request", folder_acl)
    claims = tmp_path / "claims"
    claims.mkdir(mode=0o700)
    env = tmp_path / "original-linux.env"
    env.write_bytes(b"UNIT_USERNAME=unit-account\nUNIT_PASSWORD=never-extract\n")
    env.chmod(0o600)
    buffers: list[bytearray] = []
    original_read = provider.OwnerOnlySecretApprovalBuild29EnvUsernameSource.read_span
    def read(source: Any) -> memoryview:
        span = original_read(source)
        buffers.append(span.obj)
        return span
    monkeypatch.setattr(provider.OwnerOnlySecretApprovalBuild29EnvUsernameSource, "read_span", read)
    binding = replace(_binding(), folder_path=_FOLDER, secret_name=_NAME, secret_id=24, approval_profile_name=_PROFILE)
    producer = provider.SecretApprovalBuild29RuntimeProducer(
        owner, cast(Any, sources), binding=binding, expected_folder_id=17, expected_serial=_SERIAL,
        linux_target_name=_LINUX_TARGET, linux_target_ipv4_address="192.0.2.10",
        expected_folder_acl_digest=_linux_acl_digest(acl),
        username_source=provider.OwnerOnlySecretApprovalBuild29EnvUsernameSource(env, username_variable="UNIT_USERNAME"),
        claim_directory=claims, execution_enabled=True,
    )
    manifest = tmp_path / "qualification.json"
    qualifier = provider.OwnerOnlySecretApprovalBuild29LinuxQualificationVerifier(
        manifest, authority_ref="linux-chain-source-authority", authority_key=_KEY,
        expected_evidence_digest="e" * 64,
    )
    store = _Store()
    factory = SecretApprovalBuild29M4RunnerFactory(
        planning=reader, receipt_authenticator=authenticator, producer=producer, execution_store=store,
        source_plan_ref=plan.plan_ref, approval_receipt_ref=receipt.receipt_ref,
        approver_authority_ref="approver-authority-ref01", authorization_ref="linux-chain-enable-auth01",
        authorized_environment_ref=plan.environment_ref, authorized_scope_ref=plan.scope_ref,
        qualification_verifier=qualifier, execution_enabled=True, clock=lambda: NOW + 5,
    )
    runner = factory.bind(plan, plan.lines[0].line_ref, V4PlanningPrincipal(requester, "a" * 64),
                          draft=_approval_and_observe_draft(), approval_binding=binding)
    return dict(runner=runner, owner=owner, device=device, sources=sources, store=store, manifest=manifest,
                qualifier=qualifier, requester=requester, authenticator=authenticator, binding=binding,
                claims=claims, buffers=buffers, acl=acl, acl_reads=acl_reads)


def test_linux_real_provider_signed_enable_and_independent_signed_restore_roundtrip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _setup(tmp_path, monkeypatch)
    runner = context["runner"]
    forward = runner.runtime._binding
    transport = forward.transport
    assert context["device"].bodies == [] and context["store"].claim_calls == 0
    assert not context["buffers"]
    _qualify(context["manifest"], runner.binding_digest, forward.plan.plan_digest, web=True)
    with pytest.raises(M4AdapterDenied):
        runner.execute_bound()
    assert context["device"].bodies == [] and context["store"].claim_calls == 0
    _qualify(context["manifest"], runner.binding_digest, forward.plan.plan_digest)
    assert runner.execute_bound()["outcome"] == M4Outcome.SUCCEEDED.value
    assert len(context["device"].bodies) == 1 and context["store"].claim_calls == 1
    assert context["owner"].logout_verified and transport._ownership is not None
    assert transport.inspect_transition().approval_values == ("enable", "disable", "disable", _PROFILE)
    assert context["buffers"] and all(not any(raw) for raw in context["buffers"])

    class Resolver:
        def resolve(self, draft: Any, requester: Any) -> Any:
            assert requester == context["requester"]
            return context["binding"]
    categorical = FortiPamSecretApprovalBuild29ProjectionSource(
        SecretApprovalBuild29ProjectionReader(transport, approval_profile_name=_PROFILE),
        SecretApprovalBuild29ProfileReader(context["owner"], expected_serial=_SERIAL, profile_name=_PROFILE),
        Resolver(), contract_registered=True,
    )
    source = SecretApprovalBuild29OwnedRestoreSource(
        categorical, _approval_and_observe_draft(), context["requester"], forward,
        ownership_evidence_ref="linux-chain-owned-enable-evidence",
    )
    chain = _chain(dict(source=source, requester=context["requester"],
                        values={"receipt_authenticator": context["authenticator"]}), tmp_path)
    restore_binding = _promote(chain)
    assert restore_binding.plan.plan_ref != forward.plan.plan_ref
    assert restore_binding.authorization.approval_ref != forward.authorization.approval_ref
    assert restore_binding.transport is transport
    verifier = PlanningChainSecretApprovalBuild29RestoreAuthorizationVerifier(
        chain["planning"], chain["receipt_authenticator"], chain["source"], **chain["pins"],
        authorization_ref=restore_binding.authorization.authorization_ref,
    )
    restore = assemble_secret_approval_build29_m4_runtime(
        restore_binding, authorization_verifier=verifier, execution_store=context["store"],
        authenticated_requester_digest=context["requester"].digest, qualification_verifier=context["qualifier"],
        execution_enabled=True, clock=lambda: NOW + 15,
    )
    ref = restore_binding.authorization.authorization_ref
    with pytest.raises(M4AdapterDenied):
        restore.execute_bound(ref, expected_binding_digest=runner.binding_digest)
    assert len(context["device"].bodies) == 1 and context["store"].claim_calls == 1
    _qualify(context["manifest"], runner.binding_digest, restore_binding.plan.plan_digest)
    assert restore.execute_bound(ref, expected_binding_digest=runner.binding_digest).outcome is M4Outcome.SUCCEEDED
    assert transport.inspect_transition() == forward.baseline and transport._ownership is None
    assert len(context["device"].bodies) == 2 and context["store"].claim_calls == 2
    assert len(list(context["claims"].glob("*.claim"))) == 2
    assert len(context["buffers"]) == 2 and all(not any(raw) for raw in context["buffers"])
    assert context["owner"].acl_calls == 0 and len(context["acl_reads"]) > 4
    assert context["owner"].logout_verified and context["owner"]._client is None
    with pytest.raises(M4AdapterDenied):
        restore.execute_bound(ref, expected_binding_digest=runner.binding_digest)
    assert len(context["device"].bodies) == 2


@pytest.mark.parametrize("drift", ["mixed_web", "missing_linux", "target", "address", "acl"])
def test_linux_planning_authorization_rejects_scope_and_binding_drift_before_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, drift: str,
) -> None:
    from fortipam_mcp.secret_approval_build29_http_transport import SecretApprovalBuild29WebFieldsBinding
    from fortipam_mcp.secret_approval_build29_m4_authorization import SecretApprovalBuild29M4AuthorizationError
    context = _setup(tmp_path, monkeypatch)
    runner = context["runner"]
    forward = runner.runtime._binding
    transport = forward.transport
    mutation = transport._mutation
    assert mutation is not None and mutation.linux_fields is not None
    if drift == "mixed_web":
        changed = replace(mutation, web_fields=SecretApprovalBuild29WebFieldsBinding(
            "https://unit-web.example.test/", lambda: memoryview(bytearray(b"unit-account")),
        ))
    elif drift == "missing_linux":
        changed = replace(mutation, linux_fields=None)
    elif drift == "target":
        changed = replace(mutation, linux_fields=replace(mutation.linux_fields, target_name="another-fixed-target"))
    elif drift == "address":
        changed = replace(mutation, linux_fields=replace(mutation.linux_fields, target_ipv4_address="192.0.2.11"))
    else:
        changed = replace(mutation, expected_folder_acl_digest="f" * 64)
    transport._mutation = changed
    reads_before = len(context["device"].calls)
    with pytest.raises(SecretApprovalBuild29M4AuthorizationError):
        runner.runtime._authorizer.verify(forward.plan, forward.authorization, now_epoch=NOW + 5)
    assert len(context["device"].calls) == reads_before
    assert context["device"].bodies == [] and context["store"].claim_calls == 0
    assert not context["buffers"]
