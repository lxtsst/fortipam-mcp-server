"""Explicit local-lab assembly for one protected Secret-create M4 runner."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from v4_planning import M4ExecutionStateStore
from v4_planning.models import require_digest, require_ref
from v4_planning.material_provider import MaterialLeaseRequest
from v4_planning.material_runtime import MaterialUseStateStore
from v4_planning.secret_create_runtime import SecretCreateMaterialRuntime

from .secret_create_191_http_transport import FortiPam191SecretCreateHttpTransport
from .secret_create_191_private_adapter import (
    FortiPam191SecretCreatePrivateAdapter,
    SecretCreate191TargetBinding,
)
from .secret_create_191_projection_reader import SecretCreate191ProjectionReader
from .secret_create_central_lab_binding import (
    OwnerOnlyCentralLabSecretCreateBindingResolver,
)
from .secret_create_central_lab_provider import (
    CentralLabInventorySecretCreateProvider,
    CentralLabSecretCreate191LeaseTransport,
)
from .secret_create_lab_authorization import SecretCreateLabAuthorizationVerifier
from .secret_create_m4_binding import (
    OwnerOnlySecretCreateM4BindingResolver,
    PrivateMaterialBindingResolver,
)
from .secret_create_m4_runtime import (
    ProtectedSecretCreateM4Runtime,
    SecretCreateM4RuntimeError,
    SecretCreateProjectionReader,
)
from .secret_onboarding_action_sequence import (
    OwnerOnlySecretCreateM4RunnerFactory,
)
from .secret_metadata_http_transport import (
    FortiPamSecretMetadataHttpTransport,
    SecretMetadataHttpTransportConfig,
)
from .secret_onboarding_projection_source import SecretOnboardingBinding


_UNAVAILABLE = "Protected Secret-create local-lab runtime is unavailable."


def assemble_secret_create_lab_runner_factory(
    *,
    m4_binding_path: Path,
    runner_association_path: Path,
    authorization_ref: str,
    material_binding_resolver: PrivateMaterialBindingResolver,
    material_runtime: SecretCreateMaterialRuntime,
    projection_reader: SecretCreateProjectionReader,
    execution_store: M4ExecutionStateStore,
    authenticated_requester_digest: str,
    clock: Callable[[], int] | None = None,
) -> OwnerOnlySecretCreateM4RunnerFactory:
    """Assemble one startup-pinned, source-bound local-lab runner factory."""

    m4_path = Path(m4_binding_path)
    association_path = Path(runner_association_path)
    try:
        if not m4_path.is_absolute() or not association_path.is_absolute():
            raise ValueError("paths must be absolute")
        require_ref(authorization_ref, "Secret-create authorization_ref")
        require_digest(
            authenticated_requester_digest,
            "authenticated_requester_digest",
        )
    except ValueError as exc:
        raise SecretCreateM4RuntimeError(_UNAVAILABLE) from exc

    resolver = OwnerOnlySecretCreateM4BindingResolver(
        m4_path,
        material_binding_resolver,
    )
    startup_binding = resolver.resolve_execution_binding(authorization_ref)
    if startup_binding.plan.requester_digest != authenticated_requester_digest:
        raise SecretCreateM4RuntimeError(_UNAVAILABLE)
    verifier = SecretCreateLabAuthorizationVerifier(startup_binding)
    runtime = ProtectedSecretCreateM4Runtime(
        resolver,
        verifier,
        execution_store,
        material_runtime,
        projection_reader,
        authenticated_requester_digest=authenticated_requester_digest,
        clock=clock,
    )
    return OwnerOnlySecretCreateM4RunnerFactory(association_path, runtime)


def assemble_fortipam_191_secret_create_lab_runner_factory(
    *,
    credential_bindings_path: Path,
    secret_env_path: Path,
    material_binding_ref: str,
    credential_binding_id: str,
    lease_request: MaterialLeaseRequest,
    target_binding: SecretCreate191TargetBinding,
    onboarding_binding: SecretOnboardingBinding,
    transport_config: SecretMetadataHttpTransportConfig,
    material_state_store: MaterialUseStateStore,
    m4_binding_path: Path,
    runner_association_path: Path,
    authorization_ref: str,
    execution_store: M4ExecutionStateStore,
    authenticated_requester_digest: str,
    clock: Callable[[], int] | None = None,
) -> OwnerOnlySecretCreateM4RunnerFactory:
    """Compose the fixed owner-only 8022 -> FortiPAM 1.9.1 path.

    This constructor performs no device call. It binds one credential metadata
    record, one owner-only env source, one action request, and one fixed product
    transport. All execution and registration gates remain external and off by
    default.
    """

    resolver = OwnerOnlyCentralLabSecretCreateBindingResolver(
        credential_bindings_path=credential_bindings_path,
        secret_env_path=secret_env_path,
        binding_ref=material_binding_ref,
        credential_binding_id=credential_binding_id,
        request=lease_request,
    )
    material_binding = resolver.resolve(material_binding_ref, lease_request)
    provider = CentralLabInventorySecretCreateProvider(
        resolver,
        binding=material_binding,
        request=lease_request,
        clock=clock,
    )
    metadata_transport = FortiPamSecretMetadataHttpTransport(
        transport_config,
        bound_secret_name=onboarding_binding.secret_name,
    )
    product_transport = FortiPam191SecretCreateHttpTransport(
        transport_config,
        metadata_transport=metadata_transport,
    )
    adapter = FortiPam191SecretCreatePrivateAdapter(
        target_binding,
        CentralLabSecretCreate191LeaseTransport(provider, product_transport),
    )
    material_runtime = SecretCreateMaterialRuntime(
        provider,
        material_state_store,
        adapter,
    )
    projection_reader = SecretCreate191ProjectionReader(
        onboarding_binding,
        target_binding,
        metadata_transport,
    )
    return assemble_secret_create_lab_runner_factory(
        m4_binding_path=m4_binding_path,
        runner_association_path=runner_association_path,
        authorization_ref=authorization_ref,
        material_binding_resolver=resolver,
        material_runtime=material_runtime,
        projection_reader=projection_reader,
        execution_store=execution_store,
        authenticated_requester_digest=authenticated_requester_digest,
        clock=clock,
    )


__all__ = [
    "assemble_fortipam_191_secret_create_lab_runner_factory",
    "assemble_secret_create_lab_runner_factory",
]
