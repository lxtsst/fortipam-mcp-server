"""Private build29 native update-check request; no dispatcher or permission.

The native service sends secret-id/dep-id/action=3 to internal secret-dep.
Action1 is a credential-dependent check, not a metadata read. This module
exposes neither check, update-only, force nor caller-selected actions. A typed
binding/context digest is not source provenance, ownership or authorization.
"""
from __future__ import annotations

from dataclasses import dataclass

from v4_planning.material_provider import _OpaqueC3Object

from .secret_metadata_http_transport import _zeroize_mutable

CONTRACT = "fortipam-build29-service-account-update-request-private-v1"
MAIN_SOURCE_SHA256 = "0c2bf35bb5cde1a5154012d6bf2f529d8d59e782a35aebe0bd29976ca9da434f"
API_MODULE_SHA256 = "34b488e5b2cd225a0f0e9a73bf7eb14a02fdc94bfc1fa9e4c455e4e9ffd056a6"
METHOD = "POST"
PATH = "/api/v2/internal/secret-dep"
_ERROR = "The private service-account update request is unavailable."


class ServiceAccountUpdateContractError(ValueError):
    """Fixed value-free denial; no partial body or bound identifier."""


@dataclass(frozen=True, slots=True, repr=False)
class ServiceAccountUpdateBinding(_OpaqueC3Object):
    """Private selected relation; the owning adapter must qualify it freshly.

    dependency_id is the Secret dependency row's numeric ID, not an Updater
    name, Target name or credential. The context binds the independently read
    Secret/Target/Updater relationship; this class does not attest those reads.
    """
    secret_id: int
    dependency_id: int
    dependency_context_digest: str

    def __post_init__(self) -> None:
        try:
            # Native build29 dependency children permit only IDs1..64.
            for value, maximum in ((self.secret_id, 2_147_483_647), (self.dependency_id, 64)):
                if type(value) is not int or not 0 < value <= maximum:
                    raise ValueError
            digest = self.dependency_context_digest
            if (type(digest) is not str or len(digest) != 64
                    or any(char not in "0123456789abcdef" for char in digest)):
                raise ValueError
        except Exception:
            raise ServiceAccountUpdateContractError(_ERROR) from None


def compile_native_service_account_update(binding: ServiceAccountUpdateBinding) -> bytearray:
    """Own/wipe the returned request in the future protected adapter boundary.

    Native payload has no password, user, service, script or arbitrary endpoint
    argument. Server-side material/target/service effects are still possible;
    compilation permits no I/O, C3 acquisition, service action or retry.
    """
    body = bytearray()
    try:
        if type(binding) is not ServiceAccountUpdateBinding:
            raise ValueError
        binding.__post_init__()
        body.extend(b'{"secret-id":')
        body.extend(str(binding.secret_id).encode("ascii"))
        body.extend(b',"dep-id":')
        body.extend(str(binding.dependency_id).encode("ascii"))
        body.extend(b',"action":3}')
        return body
    except Exception:
        _zeroize_mutable(body)
        raise ServiceAccountUpdateContractError(_ERROR) from None


def service_account_update_source_boundary() -> dict[str, object]:
    """Fixed source facts and missing acceptance, without private bindings."""
    return dict(contract=CONTRACT, source_version="v7.0.0-build29", native_action="update_check",
        maximum_dependency_row_id=64,
        check_is_metadata_only=False, request_contains_credential_fields=False,
        server_side_material_use_qualified=False, selected_relationship_qualified=False,
        native_response_qualified=False, service_effect_verified=False,
        two_sided_credential_consistency_verified=False, restart_or_availability_verified=False,
        independent_recovery_qualified=False, permission_verified=False,
        execution_authorized=False, runtime_registered=False)
