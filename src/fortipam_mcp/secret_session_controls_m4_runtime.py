"""Protected M4 runtime for fixed controls on one existing Windows Secret.

This candidate is deliberately private and unregistered.  Its only write is
the fixed SSH control fallback; it never accepts Secret fields, credentials, or
caller-selected control values.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import logging
import re
import time
from typing import Protocol

from v4_planning import (
    M4AdapterAmbiguous,
    M4AdapterDenied,
    M4AuthorizationDenied,
    M4AuthorizationVerifier,
    M4ExecutionAdapter,
    M4ExecutionAuthorization,
    M4ExecutionKernel,
    M4ExecutionPlan,
    M4ExecutionResult,
    M4ExecutionStateStore,
    canonical_digest,
)
from v4_planning.models import require_ref

from .secret_metadata_http_transport import SecretSessionControlsProjectionInspection
from .secret_metadata_http_transport import (
    secret_session_controls_event_filter_profile_digest,
)
from .rdp_event_filter_ssh_transport import RdpEventFilterReadback
from .secret_session_controls_ssh_transport import (
    FortiPamSecretSessionControlsSshTransport,
    _mutable_control_changes,
)


SECRET_SESSION_CONTROLS_ACTION_ID = "secret-session-controls-enable"
SECRET_SESSION_CONTROLS_ACTION_VERSION = "1.7.0"
SECRET_SESSION_CONTROLS_ADAPTER_REF = "fortipam-secret-session-controls-ssh-preserving-191-v3"
_UNAVAILABLE = "Protected Secret session-controls execution is unavailable."
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_LOGGER = logging.getLogger(__name__)
_POSTCONDITION_READ_LIMIT = 3
_POSTCONDITION_READ_INTERVAL_SECONDS = 5.0


class SecretSessionControlsM4RuntimeError(RuntimeError):
    """Stable non-disclosing error for an unavailable private binding."""


@dataclass(frozen=True, slots=True, repr=False)
class SecretSessionControlsBinding:
    """Owner-held exact selectors and baseline for a single existing Secret."""

    secret_session_controls_object_ref: str
    folder_ref: str
    folder_path: str
    secret_name: str
    template_ref: str
    template_name: str
    target_ref: str
    target_name: str
    secret_id: int
    rdp_event_filter_profile_ref: str
    rdp_event_filter_profile_name: str
    prewrite_recording_enabled: bool
    prewrite_clipboard_blocking_enabled: bool
    prewrite_rdp_event_filter_enabled: bool
    prewrite_rdp_event_filter_profile_matches: bool
    prewrite_rdp_event_filter_profile_digest: str
    preserved_identity_relations_digest: str

    def __post_init__(self) -> None:
        try:
            for value, field in (
                (self.secret_session_controls_object_ref, "Secret controls object_ref"),
                (self.folder_ref, "Folder ref"),
                (self.template_ref, "Template ref"),
                (self.target_ref, "Target ref"),
                (self.rdp_event_filter_profile_ref, "RDP event-filter ref"),
            ):
                require_ref(value, field)
        except ValueError as exc:
            raise SecretSessionControlsM4RuntimeError(_UNAVAILABLE) from exc
        _bounded_text(self.folder_path, 1024, path=True)
        _bounded_text(self.secret_name, 128)
        _bounded_text(self.template_name, 128)
        _bounded_text(self.target_name, 255)
        _bounded_text(self.rdp_event_filter_profile_name, 128)
        if type(self.secret_id) is not int or not 0 < self.secret_id <= 2_147_483_647:
            raise SecretSessionControlsM4RuntimeError(_UNAVAILABLE)
        if any(
            type(value) is not bool
            for value in (
                self.prewrite_recording_enabled,
                self.prewrite_clipboard_blocking_enabled,
                self.prewrite_rdp_event_filter_enabled,
                self.prewrite_rdp_event_filter_profile_matches,
            )
        ):
            raise SecretSessionControlsM4RuntimeError(_UNAVAILABLE)
        if any(
            not isinstance(value, str) or _DIGEST.fullmatch(value) is None
            for value in (
                self.prewrite_rdp_event_filter_profile_digest,
                self.preserved_identity_relations_digest,
            )
        ):
            raise SecretSessionControlsM4RuntimeError(_UNAVAILABLE)


@dataclass(frozen=True, slots=True, repr=False)
class SecretSessionControlsM4ExecutionBinding:
    """Exact immutable M4 records plus the private existing-Secret binding."""

    plan: M4ExecutionPlan
    authorization: M4ExecutionAuthorization
    session_controls_binding: SecretSessionControlsBinding


class SecretSessionControlsM4BindingResolver(Protocol):
    def resolve_execution_binding(
        self,
        authorization_ref: str,
    ) -> SecretSessionControlsM4ExecutionBinding: ...


class SecretSessionControlsReadTransport(Protocol):
    def inspect_session_controls_projection(
        self,
        folder_path: str,
        secret_name: str,
        expected_template: str,
        expected_target: str,
        expected_rdp_event_filter_profile: str,
        *,
        expected_secret_id: int,
    ) -> SecretSessionControlsProjectionInspection: ...


class SecretSessionControlsWriteTransport(Protocol):
    def enable_controls(
        self,
        secret_id: int,
        rdp_event_filter_profile_name: str,
        *,
        prewrite: SecretSessionControlsProjectionInspection,
    ) -> None: ...


class RdpEventFilterReadTransport(Protocol):
    def readback(self, profile_name: str) -> RdpEventFilterReadback: ...


class _SecretSessionControlsM4Adapter(M4ExecutionAdapter):
    def __init__(
        self,
        binding: SecretSessionControlsM4ExecutionBinding,
        write_transport: SecretSessionControlsWriteTransport,
        read_transport: SecretSessionControlsReadTransport,
        rdp_event_filter_transport: RdpEventFilterReadTransport,
    ) -> None:
        self._binding = binding
        self._write_transport = write_transport
        self._read_transport = read_transport
        self._rdp_event_filter_transport = rdp_event_filter_transport
        self._prewrite: tuple[SecretSessionControlsProjectionInspection, str] | None = None

    def read_current(self, plan: M4ExecutionPlan) -> str:
        self._prewrite = None
        return self._read_digest(plan, capture_prewrite=True)

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        prewrite = self._prewrite
        self._prewrite = None
        if prewrite is None or prewrite[1] != plan.expected_current_digest:
            raise M4AdapterDenied(_UNAVAILABLE)
        binding = self._binding.session_controls_binding
        try:
            self._write_transport.enable_controls(
                binding.secret_id,
                binding.rdp_event_filter_profile_name,
                prewrite=prewrite[0],
            )
        except Exception as exc:
            # A transport failure cannot prove whether its final mutation applied.
            raise M4AdapterAmbiguous(
                "Secret session-controls update requires reconciliation."
            ) from exc

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        # Poll only an unchanged complete baseline before the kernel finalizes.
        # An intermediate state, drift or read error cannot be hidden by polling.
        for attempt in range(1, _POSTCONDITION_READ_LIMIT + 1):
            actual = self._read_digest(plan)
            if actual == plan.expected_state_digest:
                return actual
            unchanged = actual == plan.expected_current_digest
            _LOGGER.warning(
                "Secret session-controls postcondition mismatch: attempt=%d state=%s",
                attempt, "baseline" if unchanged else "unexpected",
            )
            if not unchanged or attempt == _POSTCONDITION_READ_LIMIT:
                return actual
            time.sleep(_POSTCONDITION_READ_INTERVAL_SECONDS)
        raise M4AdapterAmbiguous("Secret session-controls verification is unavailable.")

    def _read_digest(self, plan: M4ExecutionPlan, *, capture_prewrite: bool = False) -> str:
        binding = self._binding.session_controls_binding
        try:
            value = self._read_transport.inspect_session_controls_projection(
                binding.folder_path,
                binding.secret_name,
                binding.template_name,
                binding.target_name,
                binding.rdp_event_filter_profile_name,
                expected_secret_id=binding.secret_id,
            )
        except Exception as exc:
            raise M4AdapterAmbiguous(
                "Secret session-controls projection is unavailable."
            ) from exc
        if not isinstance(value, SecretSessionControlsProjectionInspection):
            raise M4AdapterAmbiguous(
                "Secret session-controls projection is unavailable."
            )
        if (
            value.original_name != binding.secret_name
            or value.original_template != binding.template_name
        ):
            raise M4AdapterDenied(_UNAVAILABLE)
        if not (value.proxy_enabled and value.rdp_tcp_forwarding_disabled):
            raise M4AdapterAmbiguous(
                "Secret session-controls compatibility evidence is unavailable."
            )
        self._require_rdp_event_filter(binding)
        if capture_prewrite:
            try:
                _mutable_control_changes(value, binding.rdp_event_filter_profile_name)
            except Exception:
                raise M4AdapterDenied(_UNAVAILABLE) from None
        digest = secret_session_controls_state_digest(
            binding,
            preserved_identity_relations_digest=value.preserved_identity_relations_digest,
            rdp_event_filter_profile_digest=value.rdp_event_filter_profile_digest,
            recording_enabled=value.recording_enabled,
            clipboard_blocking_enabled=value.clipboard_blocking_enabled,
            rdp_event_filter_enabled=value.rdp_event_filter_enabled,
            rdp_event_filter_profile_matches=value.rdp_event_filter_profile_matches,
            target_ref=plan.target_ref,
        )
        if capture_prewrite:
            self._prewrite = (value, digest)
        return digest

    def _require_rdp_event_filter(
        self,
        binding: SecretSessionControlsBinding,
    ) -> None:
        try:
            readback = self._rdp_event_filter_transport.readback(
                binding.rdp_event_filter_profile_name
            )
        except Exception as exc:
            raise M4AdapterAmbiguous(
                "RDP event-filter verification is unavailable."
            ) from exc
        if not isinstance(readback, RdpEventFilterReadback) or not readback.verified:
            raise M4AdapterAmbiguous("RDP event-filter verification is unavailable.")


class ProtectedSecretSessionControlsM4Runtime:
    """Run one independently authorized fixed existing-Secret control update."""

    def __init__(
        self,
        resolver: SecretSessionControlsM4BindingResolver,
        authorization_verifier: M4AuthorizationVerifier,
        execution_store: M4ExecutionStateStore,
        write_transport: SecretSessionControlsWriteTransport,
        read_transport: SecretSessionControlsReadTransport,
        rdp_event_filter_transport: RdpEventFilterReadTransport,
        *,
        authenticated_requester_digest: str,
        clock: Callable[[], int] | None = None,
    ) -> None:
        if (
            not isinstance(write_transport, FortiPamSecretSessionControlsSshTransport)
            or not callable(getattr(write_transport, "enable_controls", None))
            or not callable(
                getattr(read_transport, "inspect_session_controls_projection", None)
            )
            or not callable(getattr(rdp_event_filter_transport, "readback", None))
        ):
            raise SecretSessionControlsM4RuntimeError(_UNAVAILABLE)
        self._resolver = resolver
        self._authorization_verifier = authorization_verifier
        self._execution_store = execution_store
        self._write_transport = write_transport
        self._read_transport = read_transport
        self._rdp_event_filter_transport = rdp_event_filter_transport
        self._requester_digest = authenticated_requester_digest
        self._clock = clock or (lambda: int(time.time()))

    def inspect_execution_plan(self, authorization_ref: str) -> M4ExecutionPlan:
        return self._resolve_binding(authorization_ref).plan

    def inspect_session_controls_binding_digest(self, authorization_ref: str) -> str:
        """Return the digest used to bind a Scheme record to private selectors."""

        return secret_session_controls_binding_digest(
            self._resolve_binding(authorization_ref).session_controls_binding
        )

    def execute_bound(
        self,
        authorization_ref: str,
        *,
        expected_session_controls_binding_digest: str,
    ) -> M4ExecutionResult:
        binding = self._resolve_binding(authorization_ref)
        if (
            secret_session_controls_binding_digest(binding.session_controls_binding)
            != expected_session_controls_binding_digest
        ):
            raise M4AuthorizationDenied(_UNAVAILABLE)
        adapter = _SecretSessionControlsM4Adapter(
            binding,
            self._write_transport,
            self._read_transport,
            self._rdp_event_filter_transport,
        )
        return M4ExecutionKernel(
            adapter,
            self._authorization_verifier,
            self._execution_store,
            clock=self._clock,
        ).execute(binding.plan, binding.authorization)

    def _resolve_binding(
        self,
        authorization_ref: str,
    ) -> SecretSessionControlsM4ExecutionBinding:
        try:
            binding = self._resolver.resolve_execution_binding(authorization_ref)
            self._validate(binding, authorization_ref)
        except (M4AuthorizationDenied, SecretSessionControlsM4RuntimeError):
            raise
        except Exception as exc:
            raise SecretSessionControlsM4RuntimeError(_UNAVAILABLE) from exc
        return binding

    def _validate(
        self,
        binding: SecretSessionControlsM4ExecutionBinding,
        authorization_ref: str,
    ) -> None:
        if not isinstance(binding, SecretSessionControlsM4ExecutionBinding):
            raise M4AuthorizationDenied(_UNAVAILABLE)
        plan = binding.plan
        authorization = binding.authorization
        controls = binding.session_controls_binding
        if (
            authorization.authorization_ref != authorization_ref
            or plan.requester_digest != self._requester_digest
            or plan.action_id != SECRET_SESSION_CONTROLS_ACTION_ID
            or plan.action_version != SECRET_SESSION_CONTROLS_ACTION_VERSION
            or plan.adapter_ref != SECRET_SESSION_CONTROLS_ADAPTER_REF
            or plan.target_ref != controls.secret_session_controls_object_ref
            or plan.parameters_digest
            != secret_session_controls_parameters_digest(controls)
            or plan.expected_current_digest
            != secret_session_controls_state_digest(
                controls,
                preserved_identity_relations_digest=(
                    controls.preserved_identity_relations_digest
                ),
                rdp_event_filter_profile_digest=(
                    controls.prewrite_rdp_event_filter_profile_digest
                ),
                recording_enabled=controls.prewrite_recording_enabled,
                clipboard_blocking_enabled=(
                    controls.prewrite_clipboard_blocking_enabled
                ),
                rdp_event_filter_enabled=controls.prewrite_rdp_event_filter_enabled,
                rdp_event_filter_profile_matches=(
                    controls.prewrite_rdp_event_filter_profile_matches
                ),
                target_ref=plan.target_ref,
            )
            or plan.expected_state_digest
            != secret_session_controls_state_digest(
                controls,
                preserved_identity_relations_digest=(
                    controls.preserved_identity_relations_digest
                ),
                rdp_event_filter_profile_digest=(
                    secret_session_controls_event_filter_profile_digest(
                        controls.rdp_event_filter_profile_name
                    )
                ),
                recording_enabled=True,
                clipboard_blocking_enabled=True,
                rdp_event_filter_enabled=True,
                rdp_event_filter_profile_matches=True,
                target_ref=plan.target_ref,
            )
        ):
            raise M4AuthorizationDenied(_UNAVAILABLE)


def secret_session_controls_binding_digest(binding: SecretSessionControlsBinding) -> str:
    """Bind every private existing-Secret selector without exposing one."""

    if not isinstance(binding, SecretSessionControlsBinding):
        raise SecretSessionControlsM4RuntimeError(_UNAVAILABLE)
    return canonical_digest(
        {
            "folder_path": binding.folder_path,
            "folder_ref": binding.folder_ref,
            "preserved_identity_relations_digest": (
                binding.preserved_identity_relations_digest
            ),
            "prewrite_rdp_event_filter_profile_digest": (
                binding.prewrite_rdp_event_filter_profile_digest
            ),
            "prewrite_recording_enabled": binding.prewrite_recording_enabled,
            "prewrite_clipboard_blocking_enabled": (
                binding.prewrite_clipboard_blocking_enabled
            ),
            "prewrite_rdp_event_filter_enabled": (
                binding.prewrite_rdp_event_filter_enabled
            ),
            "prewrite_rdp_event_filter_profile_matches": (
                binding.prewrite_rdp_event_filter_profile_matches
            ),
            "rdp_event_filter_profile_name": binding.rdp_event_filter_profile_name,
            "rdp_event_filter_profile_ref": binding.rdp_event_filter_profile_ref,
            "secret_id": binding.secret_id,
            "secret_name": binding.secret_name,
            "secret_session_controls_object_ref": (
                binding.secret_session_controls_object_ref
            ),
            "target_name": binding.target_name,
            "target_ref": binding.target_ref,
            "template_name": binding.template_name,
            "template_ref": binding.template_ref,
        }
    )


def secret_session_controls_parameters_digest(binding: SecretSessionControlsBinding) -> str:
    """Bind only the four enabled session controls and private baseline."""

    return canonical_digest(
        {
            "action_id": SECRET_SESSION_CONTROLS_ACTION_ID,
            "action_version": SECRET_SESSION_CONTROLS_ACTION_VERSION,
            "clipboard_blocking_enabled": True,
            "rdp_event_filter_enabled": True,
            "rdp_event_filter_profile_matches": True,
            "recording_enabled": True,
            "session_controls_binding_digest": secret_session_controls_binding_digest(
                binding
            ),
        }
    )


def secret_session_controls_state_digest(
    binding: SecretSessionControlsBinding,
    *,
    preserved_identity_relations_digest: str,
    rdp_event_filter_profile_digest: str,
    recording_enabled: bool,
    clipboard_blocking_enabled: bool,
    rdp_event_filter_enabled: bool,
    rdp_event_filter_profile_matches: bool,
    target_ref: str,
) -> str:
    """Digest only fixed controls plus the opaque safe preservation claim."""

    if (
        not isinstance(binding, SecretSessionControlsBinding)
        or not isinstance(preserved_identity_relations_digest, str)
        or _DIGEST.fullmatch(preserved_identity_relations_digest) is None
        or not isinstance(rdp_event_filter_profile_digest, str)
        or _DIGEST.fullmatch(rdp_event_filter_profile_digest) is None
        or any(
            type(value) is not bool
            for value in (
                recording_enabled,
                clipboard_blocking_enabled,
                rdp_event_filter_enabled,
                rdp_event_filter_profile_matches,
            )
        )
    ):
        raise SecretSessionControlsM4RuntimeError(_UNAVAILABLE)
    try:
        require_ref(target_ref, "Secret controls target_ref")
    except ValueError as exc:
        raise SecretSessionControlsM4RuntimeError(_UNAVAILABLE) from exc
    return canonical_digest(
        {
            "clipboard_blocking_enabled": clipboard_blocking_enabled,
            "contract": "secret-session-controls-state-v1",
            "preserved_identity_relations_digest": (
                preserved_identity_relations_digest
            ),
            "rdp_event_filter_enabled": rdp_event_filter_enabled,
            "rdp_event_filter_profile_digest": rdp_event_filter_profile_digest,
            "rdp_event_filter_profile_matches": rdp_event_filter_profile_matches,
            "recording_enabled": recording_enabled,
            "target_ref": target_ref,
        }
    )


def _bounded_text(value: str, maximum: int, *, path: bool = False) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise SecretSessionControlsM4RuntimeError(_UNAVAILABLE)
    if path and any(part in {"", ".", ".."} for part in value.split("/")):
        raise SecretSessionControlsM4RuntimeError(_UNAVAILABLE)
    return value


__all__ = [
    "ProtectedSecretSessionControlsM4Runtime",
    "SECRET_SESSION_CONTROLS_ACTION_ID",
    "SECRET_SESSION_CONTROLS_ACTION_VERSION",
    "SECRET_SESSION_CONTROLS_ADAPTER_REF",
    "SecretSessionControlsBinding",
    "SecretSessionControlsM4BindingResolver",
    "SecretSessionControlsM4ExecutionBinding",
    "SecretSessionControlsM4RuntimeError",
    "SecretSessionControlsReadTransport",
    "SecretSessionControlsWriteTransport",
    "RdpEventFilterReadTransport",
    "secret_session_controls_binding_digest",
    "secret_session_controls_parameters_digest",
    "secret_session_controls_state_digest",
]
