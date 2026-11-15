"""Typed read-only User dependency for the associated pair recovery M4."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast
from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from .radius_remote_user_live_workflow import RadiusRemoteUserLiveWorkflow
from .radius_server_pair_http_transport import FortiPamRadiusPairHttpTransport, _Connection
from .radius_remote_user_preparation_reader import RadiusRemoteUserPreparationReader

_ERROR = "The associated RADIUS User absence dependency is unavailable."


class RadiusRemoteUserAbsenceGuard(_OpaqueC3Object):
    __slots__ = ("_reader", "_pin", "_original_pair", "_creator_namespace")
    _reader: RadiusRemoteUserLiveWorkflow | RadiusRemoteUserPreparationReader
    _pin: str
    _original_pair: str
    _creator_namespace: str | None

    def __init__(self, recovery: RadiusRemoteUserLiveWorkflow | RadiusRemoteUserPreparationReader) -> None:
        try:
            reader: RadiusRemoteUserLiveWorkflow | RadiusRemoteUserPreparationReader
            if type(recovery) is RadiusRemoteUserPreparationReader:
                reader = recovery.clone()
            else:
                if not isinstance(recovery, RadiusRemoteUserLiveWorkflow): raise ValueError
                reader = self._clone_user(recovery)
            object.__setattr__(self, "_reader", reader)
            object.__setattr__(self, "_original_pair", reader._target._original_execution())
            creator = canonical_digest(reader._reader._read_state("user-create.runtime.json")) if reader._reader._exists("user-create.runtime.json") else None
            object.__setattr__(self, "_creator_namespace", creator)
            object.__setattr__(self, "_pin", canonical_digest({"composition": reader._composition,
                "namespace": reader._namespace_pin, "target_handoff": reader._target._handoff_digest,
                "original_pair": self._original_pair, "creator_namespace": self._creator_namespace}))
        except Exception:
            raise RuntimeError(_ERROR) from None

    @staticmethod
    def _clone_user(recovery: RadiusRemoteUserLiveWorkflow) -> RadiusRemoteUserLiveWorkflow:
        try:
            if (type(recovery) is not RadiusRemoteUserLiveWorkflow or recovery._operation != "remove"
                    or recovery._target._handoff_digest is None): raise ValueError
            recovery._gate(execute=False)
            ns = recovery._namespace
            reader = RadiusRemoteUserLiveWorkflow(recovery._binding, recovery._reader._config,
                target=recovery._target, state_directory=recovery._reader._directory,
                operation="remove", execution_store=recovery._store,
                original_create_store=recovery._original_store, authority_key=recovery._key,
                original_create_authority_key=recovery._original_key,
                environment_ref=ns["environment_ref"], scope_ref=ns["scope_ref"], audience_ref=ns["audience_ref"],
                allowed_requester_digest=ns["requester_digest"], allowed_transport_digest=ns["transport_digest"],
                execution_enabled=False, existing_only=True, clock=recovery._now,
                connection_factory=cast(Callable[..., _Connection], recovery._reader._factory))
            return reader
        except Exception:
            raise RuntimeError(_ERROR) from None

    def __setattr__(self, name: str, value: object) -> None: raise ValueError(_ERROR)
    def __delattr__(self, name: str) -> None: raise ValueError(_ERROR)

    def pin_for(self, pair: FortiPamRadiusPairHttpTransport, namespace: dict[str, Any]) -> str:
        try:
            reader = self._reader
            reader._gate(execute=False)
            if (reader._enabled or reader._initial_enabled or reader._issued is not None
                    or pair._binding is not reader._binding.radius
                    or pair._config is not reader._reader._config
                    or pair._directory != reader._target._target._directory
                    or pair._directory_identity != reader._target._target._directory_identity
                    or pair._serial != reader._reader._serial
                    or any(namespace[name] != reader._namespace[name] for name in
                        ("environment_ref", "audience_ref", "requester_digest", "transport_digest"))
                    or namespace["scope_ref"] == reader._namespace["scope_ref"]
                    or reader._target._original_execution() != self._original_pair
                    or (canonical_digest(reader._reader._read_state("user-create.runtime.json")) if reader._reader._exists("user-create.runtime.json") else None) != self._creator_namespace
                    or self._pin != canonical_digest({"composition": reader._composition,
                        "namespace": reader._namespace_pin, "target_handoff": reader._target._handoff_digest,
                        "original_pair": self._original_pair, "creator_namespace": self._creator_namespace})):
                raise ValueError
            return self._pin
        except Exception:
            raise RuntimeError(_ERROR) from None

    def inspect(self) -> None:
        try:
            w = self._reader
            result = w.inspect_cleanup_absence(requester_digest=w._namespace["requester_digest"],
                transport_digest=w._namespace["transport_digest"])
            if result["user_absence_verified"] is not True: raise ValueError
        except Exception:
            raise RuntimeError(_ERROR) from None

    def revoke(self) -> None: self._reader.revoke()

    def close(self) -> None: self._reader.close()
