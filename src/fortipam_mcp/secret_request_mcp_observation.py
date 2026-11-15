"""OAuth-principal-bound MCP projection for one existing Secret request."""

from __future__ import annotations

from collections.abc import Mapping

from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from .secret_request_http_transport import (
    FortiPamSecretRequestHttpTransport,
    OwnerOnlySecretRequestObservationBindingResolver,
    ProtectedSecretRequestObserver,
    SecretRequestHttpTransportError,
)
from .v4_plan_runtime import V4PlanningPrincipal


V4_SECRET_REQUEST_OBSERVATION_TOOL = "observe_v4_bound_secret_request"
V4_SECRET_REQUEST_OBSERVATION_UNAVAILABLE = (
    "FortiPAM V4 Secret request observation is unavailable."
)
V4_SECRET_REQUEST_OBSERVATION_AUTHENTICATION_ENV = (
    "FORTIPAM_MCP_V4_PLAN_SECRET_REQUEST_OBSERVATION_AUTHENTICATION_MODE"
)


def build_v4_secret_request_observation_transport(
    config: SecretMetadataHttpTransportConfig, environment: Mapping[str, str],
) -> FortiPamSecretRequestHttpTransport:
    """Select only one trusted authentication mode; never caller-supplied."""
    mode = environment.get(
        V4_SECRET_REQUEST_OBSERVATION_AUTHENTICATION_ENV, "api-bearer",
    )
    if mode == "api-bearer":
        return FortiPamSecretRequestHttpTransport(config)
    if mode == "bp005-requester-session":
        from .secret_request_requester_session import (
            build_bp005_requester_observation_transport,
        )
        return build_bp005_requester_observation_transport(config, environment)
    raise SecretRequestHttpTransportError(
        V4_SECRET_REQUEST_OBSERVATION_UNAVAILABLE,
    )


class ProtectedSecretRequestMcpObservation:
    """Observe one owner-file-bound request and return categorical state only."""

    def __init__(
        self,
        transport: FortiPamSecretRequestHttpTransport,
        binding_resolver: OwnerOnlySecretRequestObservationBindingResolver,
    ) -> None:
        if (
            not isinstance(transport, FortiPamSecretRequestHttpTransport)
            or not isinstance(
                binding_resolver,
                OwnerOnlySecretRequestObservationBindingResolver,
            )
        ):
            raise RuntimeError(V4_SECRET_REQUEST_OBSERVATION_UNAVAILABLE)
        self._transport = transport
        self._binding_resolver = binding_resolver

    def observe(
        self,
        request_ref: str,
        principal: V4PlanningPrincipal,
    ) -> dict[str, object]:
        if not isinstance(principal, V4PlanningPrincipal):
            raise RuntimeError(V4_SECRET_REQUEST_OBSERVATION_UNAVAILABLE)
        try:
            binding = self._binding_resolver.resolve_bound(
                request_ref,
                requester_digest=principal.requester.digest,
            )
            observation = ProtectedSecretRequestObserver(
                self._transport,
                binding,
                authorized_environment_ref=binding.environment_ref,
                authorized_scope_ref=binding.scope_ref,
            ).observe(
                request_ref,
                requester_digest=principal.requester.digest,
            )
        except SecretRequestHttpTransportError as exc:
            raise RuntimeError(V4_SECRET_REQUEST_OBSERVATION_UNAVAILABLE) from exc
        result: dict[str, object] = {
            "contract": "fortipam-v4-secret-request-observation-v1",
            "request_exists": observation.request_exists,
            "request_type": observation.request_type,
            "lifecycle_state": observation.lifecycle_state,
            "approval_progress": observation.approval_progress,
            "action_status": observation.action_status,
            "raw_values_returned": False,
        }
        if observation.request_type == "job":
            result["deadline_state"] = observation.deadline_state
        return result


__all__ = [
    "ProtectedSecretRequestMcpObservation",
    "V4_SECRET_REQUEST_OBSERVATION_TOOL",
    "V4_SECRET_REQUEST_OBSERVATION_UNAVAILABLE",
    "build_v4_secret_request_observation_transport",
]
