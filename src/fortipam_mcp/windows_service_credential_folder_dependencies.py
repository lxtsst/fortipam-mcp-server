"""Fixed original Folder/Policy admission for the nonprivileged service profile.

This entry consumes only original successful Policy/Folder M4 custody and a
fresh zero-reference window. It binds their independently compiled context to
the service profile without changing the old owned-Target profile or any
Folder writer. It proves no Secret absence, material, activity or authority.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from threading import RLock

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from .target_preservation_contract import _digest
from .windows_execution_folder_custody import WindowsExecutionFolderCustody
from .windows_execution_folder_sources import WindowsExecutionFolderSources, WindowsFolderSourceObservation
from .windows_service_credential_contract import WindowsServiceCredentialBinding

_CONTRACT = "fortipam-build29-service-credential-explicit-folder-before-create-v1"
_ERROR = "The private Windows service credential Folder dependency is unavailable."


class WindowsServiceCredentialFolderDependencyError(ValueError):
    """No selectors, original identifiers or partial authorization in failures."""


def service_credential_folder_context_digest(*, requester_digest: str,
        sources: WindowsExecutionFolderSources,
        original_folder: WindowsExecutionFolderCustody) -> str:
    """Compile original custody before the profile; perform no native reads.

    This stable lineage digest is distinct from the later fresh observation.
    A merely present Folder or an old deleted fixture supplies no live proof.
    """
    try:
        if (type(sources) is not WindowsExecutionFolderSources
                or type(original_folder) is not WindowsExecutionFolderCustody):
            raise ValueError
        require_digest(requester_digest, "service_folder_requester")
        request = sources._request
        request.validate()
        folder = original_folder.inspect_created_state()
        policy = sources._original.inspect_created_state()
        source = sources.source_context_digest
        if (original_folder._request != request
                or folder.original_outcome != "succeeded" or folder.original_verification != "verified"
                or policy.original_outcome != "succeeded" or policy.original_verification != "verified"
                or folder.created_state_digest is None or policy.created_state_digest is None
                or folder.source_context_digest != source
                or request.binding.policy_custody_digest != policy.custody_digest
                or request.binding.policy_state_digest != policy.created_state_digest
                or request.binding.policy_source_context_digest != policy.source_context_digest
                or original_folder._plan.requester_digest != requester_digest
                or sources._original._plan.requester_digest != requester_digest):
            raise ValueError
        return canonical_digest({"contract": _CONTRACT, "requester": requester_digest,
            "source": source, "request": request.request_digest,
            "serial": request.binding.policy_request.binding.serial_digest,
            "folder_id": folder.native_folder_id, "folder_context": folder.context_digest,
            "folder_creation": folder.custody_digest, "folder_state": folder.created_state_digest,
            "policy_context": policy.context_digest, "policy_creation": policy.custody_digest,
            "policy_state": policy.created_state_digest})
    except Exception:
        raise WindowsServiceCredentialFolderDependencyError(_ERROR) from None


@dataclass(frozen=True, slots=True, repr=False)
class WindowsServiceCredentialFolderObservation(_OpaqueC3Object):
    binding_digest: str
    source_context_digest: str
    policy_creation_digest: str
    folder_creation_digest: str
    policy_state_digest: str
    folder_state_digest: str
    current_digest: str
    observed_at: float
    expires_at: float


class WindowsServiceCredentialFolderDependencies(_OpaqueC3Object):
    """One read-only pre-create window; the caller owns borrowed sources."""

    def __init__(self, profile: WindowsServiceCredentialBinding, *, requester_digest: str,
            sources: WindowsExecutionFolderSources, original_folder: WindowsExecutionFolderCustody) -> None:
        try:
            if (type(profile) is not WindowsServiceCredentialBinding
                    or type(sources) is not WindowsExecutionFolderSources
                    or type(original_folder) is not WindowsExecutionFolderCustody):
                raise ValueError
            profile.__post_init__()
            require_digest(requester_digest, "windows_secret_folder_requester")
            self._profile, self._sources, self._original = profile, sources, original_folder
            self._requester = requester_digest
            self._source = sources.source_context_digest
            self._folder = original_folder.inspect_created_state()
            self._policy = sources._original.inspect_created_state()
            self._binding = self._context()
            self._used = self._failed = self._closed = False
            self._current: WindowsServiceCredentialFolderObservation | None = None
            self._seal: str | None = None
            self._observed: WindowsFolderSourceObservation | None = None
            self._lock = RLock()
        except Exception:
            raise WindowsServiceCredentialFolderDependencyError(_ERROR) from None

    def _context(self) -> str:
        p, s, f = self._profile, self._sources, self._original
        p.__post_init__()
        request = s._request
        request.validate()
        folder = f.inspect_created_state()
        policy = s._original.inspect_created_state()
        if (s.source_context_digest != self._source or f._request != request
                or folder != self._folder or policy != self._policy
                or folder.original_outcome != "succeeded" or folder.original_verification != "verified"
                or policy.original_outcome != "succeeded" or policy.original_verification != "verified"
                or folder.created_state_digest is None or policy.created_state_digest is None
                or folder.source_context_digest != self._source
                or folder.native_folder_id != p.folder_id
                or request.binding.policy_request.binding.serial_digest != p.serial_digest
                or request.binding.policy_custody_digest != policy.custody_digest
                or request.binding.policy_state_digest != policy.created_state_digest
                or request.binding.policy_source_context_digest != policy.source_context_digest
                or f._plan.requester_digest != self._requester
                or s._original._plan.requester_digest != self._requester):
            raise ValueError
        if p.folder_context_digest != service_credential_folder_context_digest(
                requester_digest=self._requester, sources=s, original_folder=f):
            raise ValueError
        return canonical_digest({"contract": _CONTRACT, "profile": p.parameters_digest,
            "source": self._source, "requester": self._requester,
            "folder_request": request.request_digest, "folder_context": folder.context_digest,
            "folder_creation": folder.custody_digest, "folder_state": folder.created_state_digest,
            "policy_context": policy.context_digest, "policy_creation": policy.custody_digest,
            "policy_state": policy.created_state_digest, "phase": "before-secret-create",
            "folder_references": 0, "policy_references": 1})

    def _guard(self) -> None:
        if self._closed or self._failed or self._context() != self._binding:
            raise ValueError

    def _check(self, observation: WindowsServiceCredentialFolderObservation) -> None:
        self._guard()
        current = self._observed
        if (type(observation) is not WindowsServiceCredentialFolderObservation
                or observation is not self._current or current is None
                or self._seal != _digest(asdict(observation))):
            raise ValueError
        self._sources.check_current(current)
        if (current.absent or current.native_folder_id != self._profile.folder_id
                or current.state_digest != self._folder.created_state_digest
                or current.policy_reference_count != 1
                or observation.binding_digest != self._binding
                or observation.current_digest != current.current_digest):
            raise ValueError
        self._guard()

    def read_once(self) -> WindowsServiceCredentialFolderObservation:
        """Qualify an empty original Folder; never adopt a merely present row."""
        try:
            with self._lock:
                self._guard()
                if self._used:
                    raise ValueError
                self._used = True
                current = self._sources.observe_owned(self._original)
                self._guard()
                assert self._policy.created_state_digest is not None
                assert self._folder.created_state_digest is not None
                observation = WindowsServiceCredentialFolderObservation(self._binding, self._source,
                    self._policy.custody_digest, self._folder.custody_digest,
                    self._policy.created_state_digest, self._folder.created_state_digest,
                    current.current_digest, current.observed_at, current.expires_at)
                self._observed, self._current = current, observation
                self._seal = _digest(asdict(observation))
                self._check(observation)
                return observation
        except BaseException as error:
            self._failed, self._current, self._observed, self._seal = True, None, None, None
            if isinstance(error, Exception):
                raise WindowsServiceCredentialFolderDependencyError(_ERROR) from None
            raise

    def check_current(self, observation: WindowsServiceCredentialFolderObservation) -> None:
        try:
            with self._lock:
                self._check(observation)
        except Exception:
            self._failed, self._current, self._observed, self._seal = True, None, None, None
            raise WindowsServiceCredentialFolderDependencyError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._current, self._observed, self._seal = None, None, None
