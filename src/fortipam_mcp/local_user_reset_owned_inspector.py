"""Read-only reset baseline from this version's successful original creation.

This inspector neither issues authority nor resolves credentials. It cannot
interpret legacy UNKNOWN provenance or supply the legacy material protocol.
"""
from __future__ import annotations

from threading import RLock

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object

from .local_user_reset_fixture_custody import LocalResetFixtureAckCustody
from .local_user_reset_fixture_material import LocalResetInitialMaterialSource, _USED
from .local_user_reset_fixture_sources import LocalResetFixtureSources
from .local_user_reset_http_transport import LocalUserResetBaseline, LocalUserResetBinding

_ERROR = "The private original-owned reset baseline is unavailable."
_CONTRACT = "fortipam-build29-original-owned-reset-baseline/v1"
_USE_KEYS = {"context_digest","reference","plan_digest","authorization_digest","claimed_at"}


class LocalResetFixtureOwnedInspector(_OpaqueC3Object):
    def __init__(self, sources: LocalResetFixtureSources, original: LocalResetFixtureAckCustody,
            initial: LocalResetInitialMaterialSource) -> None:
        try:
            if (type(sources) is not LocalResetFixtureSources or type(original) is not LocalResetFixtureAckCustody
                    or type(initial) is not LocalResetInitialMaterialSource or original._enabled
                    or original._store._read_only is not True or initial._enabled
                    or initial._sources is not sources or initial._store is not original._store):raise ValueError
            self._sources,self._original,self._initial=sources,original,initial
            self._config=sources._config
            self._sealed=original.inspect_original_full_state();self._absence=original.inspect_original_absence()
            self._source=sources.source_context_digest
            self._material_ref=initial.reference
            self._use=initial._record(_USED,_USE_KEYS)
            self._closed=self._failed=False;self._lock=RLock()
            self._creation_digest=canonical_digest(dict(contract=_CONTRACT,original=self._sealed.custody_digest,
                original_absence=self._absence.custody_digest,initial_material_ref=self._material_ref,
                original_material_use_digest=canonical_digest(self._use)))
            self._pins()
        except Exception:raise ValueError(_ERROR) from None

    def _pins(self) -> None:
        original,source,initial=self._original,self._sources,self._initial
        if (self._closed or self._failed or original._enabled or initial._enabled or original._store._read_only is not True
                or initial._sources is not source or initial._store is not original._store
                or source._config is not self._config or source.source_context_digest!=self._source
                or original.inspect_original_full_state()!=self._sealed or original.inspect_original_absence()!=self._absence
                or initial.reference!=self._material_ref or initial._record(_USED,_USE_KEYS)!=self._use
                or self._material_ref!=original._pins.material_ref
                or (self._sealed.original_ack.original_outcome,self._sealed.original_ack.original_verification)!=("succeeded","verified")
                or self._absence.source_context_digest!=self._source
                or self._absence.state_source_digest!=source._state._context()
                or self._sealed.source_context_digest!=self._absence.state_source_digest
                or original._pins.username!=source._state._draft.username
                or original._pins.body_digest!=source._state._draft.nonmaterial_request_digest
                or original._pins.serial_digest!=source._state._serial or original._pins.actor_context_digest!=source._state._actor
                or self._use["reference"]!=self._material_ref or self._use["plan_digest"]!=original._plan.plan_digest
                or self._use["authorization_digest"]!=original._authorization.authorization_digest
                or type(self._use["claimed_at"]) is not int
                or not original._authorization.issued_at<=self._use["claimed_at"]<original._authorization.expires_at):raise ValueError

    def read_nonmaterial_baseline(self) -> LocalUserResetBaseline:
        try:
            with self._lock:
                self._pins()
                graph=self._sources._current
                if graph is None:raise ValueError
                self._sources.check_current(graph)
                if (graph.absent or graph.namespace_digest!=self._absence.presence_namespace_digest
                        or graph.state_digest!=self._sealed.state_digest
                        or graph.admin_count!=self._absence.admin_count+1 or graph.api_user_count!=self._absence.api_user_count):raise ValueError
                observed=self._sources._state.read_created();self._sources._state.check_current(observed)
                if (observed.state_digest!=self._sealed.state_digest or observed.user_id!=self._sealed.user_id
                        or observed.nonmaterial_state_digest!=self._sealed.nonmaterial_state_digest
                        or observed.definition_digest!=self._sealed.definition_digest):raise ValueError
                self._sources.check_current(graph);self._pins()
                baseline=LocalUserResetBaseline(username=self._sources._state._draft.username,status="enable",is_local=True,
                    access_profile="Guest",sponsor_group="",schedule="",guest_auth="disable",
                    nonmaterial_state_digest=observed.nonmaterial_state_digest,fixture_creation_digest=self._creation_digest,
                    reported_reference_count=0,usage_entry_count=0,product_version="7.0.0",product_build=29)
                LocalUserResetBinding(baseline)
                return baseline
        except Exception:
            self._failed=True;raise ValueError(_ERROR) from None

    def close(self) -> None:
        with self._lock:self._closed=True
