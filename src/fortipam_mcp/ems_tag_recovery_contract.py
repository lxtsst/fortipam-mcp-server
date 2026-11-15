"""Read-only original-owned recovery admission for one disabled EMS Tag.

No issuer or delete is exposed. A readonly original verified M4, identical full
birth state, same actor/instance and a genuinely different owner/API session
are mandatory. Restored graph evidence covers the native Tag API surface only;
hidden child deletion and downstream synchronization remain separate evidence.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
from threading import RLock

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from .ems_tag_contract import EmsTagCatalog, EmsTagFullScope, _canonical, matches_disabled_process_tag
from .ems_tag_custody import EmsTagOriginalCustody
from .ems_tag_http_transport import NativeEmsTagHttpTransport
from .ems_tag_sources import EmsTagSources, EmsTagSourceObservation

RECOVERY_CONTRACT = "ems-7.4.8.2245-original-owned-tag-recovery-source-v1"
_ERROR = "The private original-owned EMS tag recovery source is unavailable."


class EmsTagRecoveryError(ValueError):
    """No new ownership, mutation or replay authority on refusal."""


@dataclass(frozen=True, slots=True, repr=False)
class EmsTagRecoveryObservation(_OpaqueC3Object):
    source_context_digest: str
    original_custody_digest: str
    current_digest: str
    expected_digest: str
    owner_session_digest: str
    full_scope: EmsTagFullScope
    observed_at: int
    expires_at: int


def _without_candidate(scope: EmsTagFullScope, identifier: int) -> EmsTagFullScope:
    scope.__post_init__()
    kept = [i for i, value in enumerate(scope.catalog._ids) if value != identifier]
    catalog = EmsTagCatalog(tuple(scope.catalog._rows[i] for i in kept),
        tuple(scope.catalog._ids[i] for i in kept), tuple(scope.catalog._names[i] for i in kept))
    return EmsTagFullScope(catalog, tuple(detail for detail in scope.details if detail._id != identifier))


class EmsTagOwnedRecoveryScope(_OpaqueC3Object):
    def __init__(self, *, transport: NativeEmsTagHttpTransport, sources: EmsTagSources,
                 original: EmsTagOriginalCustody, requester_digest: str,
                 caller_transport_digest: str) -> None:
        try:
            if (type(transport) is not NativeEmsTagHttpTransport or type(sources) is not EmsTagSources
                    or type(original) is not EmsTagOriginalCustody or original._store._read_only is not True):
                raise ValueError
            require_digest(requester_digest, "ems_recovery_requester")
            require_digest(caller_transport_digest, "ems_recovery_transport")
            sources.require_phase("recover", requester_digest)
            self._transport, self._sources, self._original = transport, sources, original
            self._requester, self._caller_transport = requester_digest, caller_transport_digest
            self._birth = original.inspect_created_scope()
            if (requester_digest != original._plan.requester_digest
                    or caller_transport_digest == self._birth.actor_binding.caller_transport_digest
                    or sources._checked_context_digest() != self._birth.source_context_digest
                    or sources._draft.parameters_digest != original._draft.parameters_digest):
                raise ValueError
            self._session = transport.session_binding_digest(sources._key)
            if self._session == self._birth.actor_binding.owner_session_digest:
                raise ValueError
            self._source = sources._checked_context_digest()
            self._context = canonical_digest(self._context_fields())
            self._expected = canonical_digest({"context": self._context,
                "postcondition": "original-native-tag-catalog-and-full-prior-states-restored"})
            self._current: EmsTagRecoveryObservation | None = None
            self._source_observation: EmsTagSourceObservation | None = None
            self._current_mac: str | None = None
            self._closed, self._lock = False, RLock()
            self._pins()
        except Exception:
            raise EmsTagRecoveryError(_ERROR) from None

    def _context_fields(self) -> dict[str, object]:
        return {"contract": RECOVERY_CONTRACT, "source": self._source,
            "original": self._birth.custody_digest, "original_actor": self._birth.actor_binding.digest,
            "requester": self._requester, "caller_transport": self._caller_transport,
            "owner_session": self._session, "baseline": self._original._baseline}

    def _pins(self) -> None:
        self._sources.require_phase("recover", self._requester)
        reader_owner = getattr(self._sources._get, "__self__", None)
        if (self._closed or type(reader_owner) is not NativeEmsTagHttpTransport
                or reader_owner is not self._transport
                or getattr(self._sources._get, "__func__", None) is not NativeEmsTagHttpTransport.get_json
                or self._sources._instance != self._transport._binding
                or self._sources._owner != self._transport._owner
                or self._sources._checked_context_digest() != self._source
                or self._original._store._read_only is not True
                or self._original.inspect_created_scope() != self._birth
                or self._requester != self._original._plan.requester_digest
                or self._caller_transport == self._birth.actor_binding.caller_transport_digest
                or canonical_digest(self._context_fields()) != self._context
                or self._sources._draft.parameters_digest != self._original._draft.parameters_digest
                or self._transport.session_binding_digest(self._sources._key) != self._session):
            raise ValueError
        self._transport._pins()

    def _mac(self, observed: EmsTagRecoveryObservation) -> str:
        return hmac.new(self._sources._key, b"ems-original-owned-recovery-observation/v1\x00" + _canonical({
            "context": self._context, "source": observed.source_context_digest,
            "original": observed.original_custody_digest, "current": observed.current_digest,
            "expected": observed.expected_digest, "owner_session": observed.owner_session_digest,
            "scope": observed.full_scope.digest, "observed_at": observed.observed_at,
            "expires_at": observed.expires_at}), hashlib.sha256).hexdigest()

    def observe_owned(self) -> EmsTagRecoveryObservation:
        try:
            with self._lock:
                self._pins()
                observed = self._sources.observe()
                self._pins()
                candidate = observed.full_scope._candidate(self._sources._draft)
                if (observed.full_scope.digest != self._birth.created_scope_digest
                        or candidate.digest != self._birth.created_state_digest
                        or not matches_disabled_process_tag(candidate, self._sources._draft)
                        or _without_candidate(observed.full_scope, candidate._id).digest != self._original._baseline):
                    raise ValueError
                current = canonical_digest({"context": self._context, "scope": observed.full_scope.digest,
                    "original_state": self._birth.created_state_digest})
                result = EmsTagRecoveryObservation(self._source, self._birth.custody_digest,
                    current, self._expected, self._session, observed.full_scope,
                    observed.observed_at, observed.expires_at)
                self._source_observation, self._current, self._current_mac = observed, result, self._mac(result)
                return result
        except Exception:
            self.close()
            raise EmsTagRecoveryError(_ERROR) from None

    def check_current(self, observed: EmsTagRecoveryObservation) -> None:
        try:
            with self._lock:
                self._pins()
                if (type(observed) is not EmsTagRecoveryObservation or observed is not self._current
                        or self._source_observation is None
                        or observed.source_context_digest != self._source
                        or observed.original_custody_digest != self._birth.custody_digest
                        or observed.expected_digest != self._expected or observed.owner_session_digest != self._session
                        or self._current_mac != self._mac(observed)):
                    raise ValueError
                self._sources.check_current(self._source_observation)
                if observed.full_scope.digest != self._source_observation.full_scope.digest:
                    raise ValueError
        except Exception:
            self.close()
            raise EmsTagRecoveryError(_ERROR) from None

    def observe_restored_api_graph(self) -> str:
        """Read only; this is not delete authority or hidden-child qualification."""
        try:
            with self._lock:
                self._pins()
                observed = self._sources.observe()
                self._pins()
                if (observed.full_scope.digest != self._original._baseline
                        or observed.full_scope.catalog.contains_draft(self._sources._draft)):
                    raise ValueError
                self._sources.check_current(observed)
                self._source_observation, self._current, self._current_mac = observed, None, None
                return self._expected
        except Exception:
            self.close()
            raise EmsTagRecoveryError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._closed, self._current, self._source_observation, self._current_mac = True, None, None, None
