"""Private fixed Web service adapter for the existing M4 execution kernel.

No tools or authorization issuers are registered here. The owning composition
must validate the plan and authenticated authorization before kernel execution.
"""

from dataclasses import dataclass, replace
import time
from typing import Protocol

from v4_planning import M4AdapterAmbiguous, M4AdapterDenied, M4ExecutionPlan, canonical_digest
from v4_planning.models import require_ref
from .secret_metadata_http_transport import SecretMetadataProjectionInspection
from .web_secret_service_ssh_transport import FortiPamWebSecretServiceSshTransport

ACTION_ID = "web-secret-http-service-enable"
ACTION_VERSION = "1.0.0"
ADAPTER_REF = "fortipam-web-secret-http-service-ssh-191-v1"
_UNAVAILABLE = "Web Secret service execution is unavailable."
_POSTCONDITION_READ_LIMIT = 3
_POSTCONDITION_READ_INTERVAL_SECONDS = 5.0


@dataclass(frozen=True, slots=True, repr=False)
class WebSecretServiceBinding:
    object_ref: str
    folder_path: str
    secret_name: str
    secret_id: int

    def __post_init__(self) -> None:
        require_ref(self.object_ref, "Web service object ref")
        if type(self.secret_id) is not int or not 0 < self.secret_id <= 2_147_483_647:
            raise ValueError(_UNAVAILABLE)
        for value, limit in ((self.folder_path, 1024), (self.secret_name, 128)):
            if (not isinstance(value, str) or not value or len(value) > limit
                    or any(ord(char) < 32 or ord(char) == 127 for char in value)):
                raise ValueError(_UNAVAILABLE)


class WebServiceReader(Protocol):
    def inspect_web_projection(
        self, folder_path: str, secret_name: str, template: str, *, expected_secret_id: int,
    ) -> SecretMetadataProjectionInspection: ...


def parameters_digest(binding: WebSecretServiceBinding) -> str:
    return canonical_digest({
        "object_ref": binding.object_ref, "folder_path": binding.folder_path,
        "secret_name": binding.secret_name, "secret_id": binding.secret_id,
        "template": "Web Account", "http_service_enabled": True,
    })


def state_digest(binding: WebSecretServiceBinding, *, enabled: bool) -> str:
    if type(enabled) is not bool:
        raise ValueError(_UNAVAILABLE)
    return canonical_digest({
        "binding_digest": parameters_digest(binding), "http_service_enabled": enabled,
        "recording_enabled": True, "inherit_permission": True, "targetless": True,
    })


class WebSecretServiceM4Adapter:
    def __init__(
        self, binding: WebSecretServiceBinding, reader: WebServiceReader,
        writer: FortiPamWebSecretServiceSshTransport,
    ) -> None:
        self._binding = binding
        self._reader = reader
        self._writer = writer
        self._postwrite_baseline: SecretMetadataProjectionInspection | None = None
        self._prewrite: tuple[SecretMetadataProjectionInspection, str] | None = None

    def _validate_plan(self, plan: M4ExecutionPlan) -> None:
        if (
            plan.action_id != ACTION_ID or plan.action_version != ACTION_VERSION
            or plan.adapter_ref != ADAPTER_REF or plan.target_ref != self._binding.object_ref
            or plan.parameters_digest != parameters_digest(self._binding)
            or plan.expected_current_digest != state_digest(self._binding, enabled=False)
            or plan.expected_state_digest != state_digest(self._binding, enabled=True)
        ):
            raise M4AdapterDenied(_UNAVAILABLE)

    def _read(self) -> SecretMetadataProjectionInspection:
        try:
            value = self._reader.inspect_web_projection(
                self._binding.folder_path, self._binding.secret_name, "Web Account",
                expected_secret_id=self._binding.secret_id,
            )
            if not isinstance(value, SecretMetadataProjectionInspection) or any(
                item is not True for item in (
                    value.secret_exists, value.folder_exists, value.template_exists,
                    value.folder_matches, value.template_matches, value.target_matches,
                    value.inherit_permission_matches, value.recording_matches,
                )
            ) or type(value.http_service_enabled) is not bool:
                raise ValueError
            return value
        except Exception:
            raise M4AdapterAmbiguous("Web Secret service projection is unavailable.") from None

    def read_current(self, plan: M4ExecutionPlan) -> str:
        self._prewrite = None
        self._postwrite_baseline = None
        self._validate_plan(plan)
        value = self._read()
        digest = state_digest(self._binding, enabled=value.http_service_enabled)
        self._prewrite = (value, digest)
        return digest

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        prewrite, self._prewrite = self._prewrite, None
        self._validate_plan(plan)
        if prewrite is None or prewrite[1] != plan.expected_current_digest:
            raise M4AdapterDenied(_UNAVAILABLE)
        # Re-read at the last possible point before the fixed transport writes.
        fresh = self._read()
        if fresh != prewrite[0]:
            raise M4AdapterDenied(_UNAVAILABLE)
        try:
            self._writer.enable_http_service(self._binding.secret_id, prewrite=fresh)
            self._postwrite_baseline = fresh
        except Exception:
            raise M4AdapterAmbiguous("Web Secret service update requires reconciliation.") from None

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        self._validate_plan(plan)
        baseline = self._postwrite_baseline
        if baseline is None:
            raise M4AdapterDenied(_UNAVAILABLE)
        # Only the complete unchanged baseline may settle after the single write.
        for attempt in range(1, _POSTCONDITION_READ_LIMIT + 1):
            value = self._read()
            if replace(value, http_service_enabled=False) != baseline:
                raise M4AdapterAmbiguous("Web Secret service projection changed unexpectedly.")
            actual = state_digest(self._binding, enabled=value.http_service_enabled)
            if actual == plan.expected_state_digest or attempt == _POSTCONDITION_READ_LIMIT:
                return actual
            time.sleep(_POSTCONDITION_READ_INTERVAL_SECONDS)
        raise M4AdapterAmbiguous("Web Secret service verification is unavailable.")
