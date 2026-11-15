from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from typing import cast

import pytest

from fortipam_mcp.onboarding_action_coordinator import (
    OnboardingActionCoordinatorError,
)
from fortipam_mcp.secret_create_lab_runtime import (
    assemble_fortipam_191_secret_create_lab_runner_factory,
    assemble_secret_create_lab_runner_factory,
)
from fortipam_mcp.secret_create_191_private_adapter import (
    SecretCreate191TargetBinding,
)
from fortipam_mcp.secret_create_m4_binding import (
    SECRET_CREATE_M4_BINDING_CONTRACT,
    SECRET_CREATE_M4_BINDING_VERSION,
)
from fortipam_mcp.secret_create_m4_runtime import SecretCreateM4RuntimeError
from fortipam_mcp.secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig,
)
from fortipam_mcp.secret_onboarding_action_sequence import (
    SECRET_CREATE_RUNNER_BINDING_CONTRACT,
    SECRET_CREATE_RUNNER_BINDING_VERSION,
)
from fortipam_mcp.secret_onboarding_projection_source import secret_onboarding_binding_digest
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from test_secret_create_m4_binding import _MaterialResolver
from test_secret_create_m4_runtime import _Reader
from test_secret_onboarding_action_sequence import _Services, _m4_plan
from test_secret_create_191_projection_reader import _binding as _onboarding_binding
from test_v4_execution_kernel import NOW, _authorization
from test_v4_secret_create_runtime import _Adapter, _Provider, _request, _runtime
from v4_planning import (
    InMemoryM4ExecutionStateStore,
    InMemoryMaterialUseStateStore,
    canonical_digest,
)
from v4_planning.material_provider import MaterialProviderClass
from v4_planning.secret_create_adapter import (
    SECRET_CREATE_ACTION_ID,
    SECRET_CREATE_ACTION_VERSION,
    SecretCreateAdapterOutcome,
    SecretCreatePrivateAdapter,
)


def _owner_file(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    path.chmod(0o600)
    return path


def test_local_lab_assembler_binds_exact_line_and_rejects_reload_drift(
    tmp_path: Path,
) -> None:
    services = _Services()
    line = services.plan.lines[0]
    plan = _m4_plan(services.plan, line)
    base_authorization = _authorization(plan)
    authorization_content = dict(base_authorization.canonical_content())
    authorization_content.update(
        {
            "approval_digest": plan.approval_digest,
            "confirmation_digest": plan.confirmation_digest,
            "requester_digest": plan.requester_digest,
        }
    )
    authorization = replace(
        base_authorization,
        approval_digest=plan.approval_digest,
        confirmation_digest=plan.confirmation_digest,
        requester_digest=plan.requester_digest,
        authorization_digest=canonical_digest(authorization_content),
    )
    request = _request(
        plan_digest=plan.plan_digest,
        authorization_digest=authorization.authorization_digest,
        provider_class=MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE,
        requested_at=NOW,
        expires_at=NOW + 60,
    )
    m4_payload = {
        "contract": SECRET_CREATE_M4_BINDING_CONTRACT,
        "version": SECRET_CREATE_M4_BINDING_VERSION,
        "material_binding_ref": "private-material-binding-ref01",
        "plan": {**plan.canonical_content(), "plan_digest": plan.plan_digest},
        "authorization": {
            **authorization.canonical_content(),
            "authorization_digest": authorization.authorization_digest,
        },
        "lease_request": {
            "action_id": request.action_id,
            "action_version": request.action_version,
            "plan_digest": request.plan_digest,
            "policy_decision_digest": request.policy_decision_digest,
            "authorization_digest": request.authorization_digest,
            "scope_digest": request.scope_digest,
            "audience_digest": request.audience_digest,
            "provider_class": request.provider_class.value,
            "purpose": request.purpose.value,
            "requested_at": request.requested_at,
            "expires_at": request.expires_at,
        },
        "policy_decision_digest": request.policy_decision_digest,
        "scope_digest": request.scope_digest,
        "audience_digest": request.audience_digest,
    }
    m4_path = _owner_file(tmp_path / "secret-m4-binding.json", m4_payload)
    association_path = _owner_file(
        tmp_path / "secret-runner-binding.json",
        {
            "contract": SECRET_CREATE_RUNNER_BINDING_CONTRACT,
            "version": SECRET_CREATE_RUNNER_BINDING_VERSION,
            "scheme_plan_ref": services.plan.plan_ref,
            "scheme_plan_digest": services.plan.plan_digest,
            "line_ref": line.line_ref,
            "requester_digest": services.requester.digest,
            "m4_action_id": SECRET_CREATE_ACTION_ID,
            "m4_action_version": SECRET_CREATE_ACTION_VERSION,
            "authorization_ref": authorization.authorization_ref,
        },
    )
    onboarding_binding = _onboarding_binding()
    material_resolver = _MaterialResolver()
    material_runtime = _runtime(
        _Provider(),
        cast(
            SecretCreatePrivateAdapter,
            _Adapter(SecretCreateAdapterOutcome.VERIFIED_CREATED),
        ),
    )
    factory = assemble_secret_create_lab_runner_factory(
        m4_binding_path=m4_path,
        runner_association_path=association_path,
        authorization_ref=authorization.authorization_ref,
        material_binding_resolver=material_resolver,
        material_runtime=material_runtime,
        projection_reader=_Reader(
            onboarding_binding_digest=secret_onboarding_binding_digest(onboarding_binding),
        ),
        execution_store=InMemoryM4ExecutionStateStore(),
        authenticated_requester_digest=services.requester.digest,
        clock=lambda: NOW,
    )
    principal = V4PlanningPrincipal(services.requester, "a" * 64)

    runner = factory.bind(
        services.plan, line.line_ref, principal,
        onboarding_binding=onboarding_binding,
    )

    assert runner.line_ref == line.line_ref
    assert material_resolver.calls == ["private-material-binding-ref01"] * 3

    with pytest.raises(SecretCreateM4RuntimeError, match="unavailable"):
        assemble_secret_create_lab_runner_factory(
            m4_binding_path=m4_path,
            runner_association_path=association_path,
            authorization_ref="different-authorization-ref01",
            material_binding_resolver=_MaterialResolver(),
            material_runtime=material_runtime,
            projection_reader=_Reader(),
            execution_store=InMemoryM4ExecutionStateStore(),
            authenticated_requester_digest=services.requester.digest,
        )

    changed_digest = "9" * 64
    cast(dict[str, object], m4_payload["lease_request"])[
        "scope_digest"
    ] = changed_digest
    m4_payload["scope_digest"] = changed_digest
    _owner_file(m4_path, m4_payload)
    with pytest.raises(OnboardingActionCoordinatorError, match="unavailable"):
        factory.bind(
            services.plan, line.line_ref, principal,
            onboarding_binding=onboarding_binding,
        )


def test_concrete_191_lab_assembler_binds_without_contacting_device(
    tmp_path: Path,
) -> None:
    services = _Services()
    line = services.plan.lines[0]
    plan = _m4_plan(services.plan, line)
    base_authorization = _authorization(plan)
    authorization_content = dict(base_authorization.canonical_content())
    authorization_content.update(
        {
            "approval_digest": plan.approval_digest,
            "confirmation_digest": plan.confirmation_digest,
            "requester_digest": plan.requester_digest,
        }
    )
    authorization = replace(
        base_authorization,
        approval_digest=plan.approval_digest,
        confirmation_digest=plan.confirmation_digest,
        requester_digest=plan.requester_digest,
        authorization_digest=canonical_digest(authorization_content),
    )
    request = _request(
        plan_digest=plan.plan_digest,
        authorization_digest=authorization.authorization_digest,
        provider_class=MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE,
        requested_at=NOW,
        expires_at=NOW + 60,
    )
    m4_path = _owner_file(
        tmp_path / "secret-m4-binding.json",
        {
            "contract": SECRET_CREATE_M4_BINDING_CONTRACT,
            "version": SECRET_CREATE_M4_BINDING_VERSION,
            "material_binding_ref": "private-material-binding-ref01",
            "plan": {**plan.canonical_content(), "plan_digest": plan.plan_digest},
            "authorization": {
                **authorization.canonical_content(),
                "authorization_digest": authorization.authorization_digest,
            },
            "lease_request": {
                "action_id": request.action_id,
                "action_version": request.action_version,
                "plan_digest": request.plan_digest,
                "policy_decision_digest": request.policy_decision_digest,
                "authorization_digest": request.authorization_digest,
                "scope_digest": request.scope_digest,
                "audience_digest": request.audience_digest,
                "provider_class": request.provider_class.value,
                "purpose": request.purpose.value,
                "requested_at": request.requested_at,
                "expires_at": request.expires_at,
            },
            "policy_decision_digest": request.policy_decision_digest,
            "scope_digest": request.scope_digest,
            "audience_digest": request.audience_digest,
        },
    )
    association_path = _owner_file(
        tmp_path / "secret-runner-binding.json",
        {
            "contract": SECRET_CREATE_RUNNER_BINDING_CONTRACT,
            "version": SECRET_CREATE_RUNNER_BINDING_VERSION,
            "scheme_plan_ref": services.plan.plan_ref,
            "scheme_plan_digest": services.plan.plan_digest,
            "line_ref": line.line_ref,
            "requester_digest": services.requester.digest,
            "m4_action_id": SECRET_CREATE_ACTION_ID,
            "m4_action_version": SECRET_CREATE_ACTION_VERSION,
            "authorization_ref": authorization.authorization_ref,
        },
    )
    credential_bindings = tmp_path / "credential-bindings.local.yaml"
    credential_bindings.write_text(
        "schema_version: credential-bindings-v1\n"
        "bindings:\n"
        "  - id: fixed-secret-create\n"
        "    provider: env-file\n"
        "    variables:\n"
        "      username: FIXED_TEST_USERNAME\n"
        "      password: FIXED_TEST_PASSWORD\n",
        encoding="utf-8",
    )
    credential_bindings.chmod(0o600)
    secret_env = tmp_path / "fortinet-lab.local.env"
    secret_env.write_text(
        "FIXED_TEST_USERNAME=test-user\nFIXED_TEST_PASSWORD=test-password\n",
        encoding="utf-8",
    )
    secret_env.chmod(0o600)
    onboarding_binding = _onboarding_binding()
    target_binding = SecretCreate191TargetBinding(
        "fortipam-191-secret-create-private-v1",
        "1.9.1",
        plan.plan_digest,
        onboarding_binding.folder_path,
        onboarding_binding.secret_name,
        onboarding_binding.template_name,
        onboarding_binding.target_name,
        onboarding_binding.target_ipv4_address,
    )

    factory = assemble_fortipam_191_secret_create_lab_runner_factory(
        credential_bindings_path=credential_bindings,
        secret_env_path=secret_env,
        material_binding_ref="private-material-binding-ref01",
        credential_binding_id="fixed-secret-create",
        lease_request=request,
        target_binding=target_binding,
        onboarding_binding=onboarding_binding,
        transport_config=SecretMetadataHttpTransportConfig(
            "https://fortipam.example.test",
            "test-token",
            5,
            None,
        ),
        material_state_store=InMemoryMaterialUseStateStore(),
        m4_binding_path=m4_path,
        runner_association_path=association_path,
        authorization_ref=authorization.authorization_ref,
        execution_store=InMemoryM4ExecutionStateStore(),
        authenticated_requester_digest=services.requester.digest,
        clock=lambda: NOW,
    )

    runner = factory.bind(
        services.plan,
        line.line_ref,
        V4PlanningPrincipal(services.requester, "a" * 64),
        onboarding_binding=onboarding_binding,
    )
    assert runner.line_ref == line.line_ref
