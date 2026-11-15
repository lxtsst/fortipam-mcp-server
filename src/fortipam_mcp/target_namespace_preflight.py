"""Join fresh same-Bearer witnesses and same-device global Target names."""
from __future__ import annotations

from dataclasses import dataclass
from threading import RLock

from v4_planning.material_provider import _OpaqueC3Object
from . import target_preservation_contract as c
from .target_api_dependency_reader import (
    TargetApiDependencyReader, TargetApiDependencyObservation, TargetApiNamesObservation,
)
from .target_qualified_namespace_reader import (
    FortiPamTargetQualifiedNamespaceReader, TargetNameNamespaceObservation,
)
from .target_reference_ssh_transport import _target_name

_ERROR = 'Protected Target namespace preflight unavailable.'


class TargetNamespacePreflightError(ValueError):
    """Fixed private-source failure, never partial namespace evidence."""


@dataclass(frozen=True, slots=True, repr=False)
class TargetNamespacePreflightObservation(_OpaqueC3Object):
    candidate_digest: str
    source_context_digest: str
    dependency_digest: str
    namespace_digest: str
    api_witness_digest: str
    target_count: int
    candidate_absent: bool


class TargetNamespacePreflight(_OpaqueC3Object):
    """Private read composition; no M4, ownership, dispatch or runtime Tool.

    The trusted runtime owns both exact readers and their credentials. SSH
    observes global names only; actual Bearer permissions remain API evidence.
    Reader clocks need not share an epoch: each reader enforces its own expiry.
    """

    def __init__(self, api: TargetApiDependencyReader,
                 namespace: FortiPamTargetQualifiedNamespaceReader) -> None:
        try:
            if (type(api) is not TargetApiDependencyReader
                or type(namespace) is not FortiPamTargetQualifiedNamespaceReader
                or api._serial != namespace._serial):
                raise ValueError
            self._api = api
            self._namespace = namespace
            self._serial = api._serial
            self._source = api._source
            self._lock = RLock()
            self._closed = False
            self._current: TargetNamespacePreflightObservation | None = None
            self._evidence: tuple[TargetApiDependencyObservation, TargetApiNamesObservation,
                                  TargetNameNamespaceObservation, str] | None = None
        except Exception:
            raise TargetNamespacePreflightError(_ERROR) from None

    def _sources(self) -> None:
        if (self._closed or self._serial != self._api._serial
            or self._serial != self._namespace._serial or self._source != self._api._source):
            raise ValueError

    def observe(self, candidate_name: str,
                coordinates: tuple[c.TargetCoordinates, ...]) -> TargetNamespacePreflightObservation:
        with self._lock:
            self._current = None
            self._evidence = None
            try:
                self._sources()
                candidate = _target_name(candidate_name)
                before = self._api.observe(coordinates)
                names_before = self._api.observe_names(before)
                self._api.check_names_current(names_before)
                global_names = self._namespace.read_namespace(candidate, api_names=names_before.names)
                # Refuse an expired first bracket even if a later read could succeed.
                self._api.check_names_current(names_before)
                after = self._api.observe(coordinates)
                if (before.dependencies.dependency_digest != after.dependencies.dependency_digest
                    or before.source_context_digest != after.source_context_digest):
                    raise ValueError
                names_after = self._api.observe_names(after)
                if names_before.names != names_after.names:
                    raise ValueError
                self._sources()
                self._namespace.check_current(global_names, candidate_name=candidate,
                                              api_names=names_after.names)
                self._api.check_names_current(names_after)
                result = TargetNamespacePreflightObservation(global_names.candidate_digest,
                    after.source_context_digest, after.dependencies.dependency_digest,
                    global_names.namespace_digest, names_after.names_digest,
                    global_names.target_count, global_names.candidate_absent)
                if global_names.api_witness_digest != result.api_witness_digest:
                    raise ValueError
                self._evidence = (after, names_after, global_names, candidate)
                self._current = result
                return result
            except Exception:
                raise TargetNamespacePreflightError(_ERROR) from None

    def check_current(self, observation: TargetNamespacePreflightObservation,
                      *, candidate_name: str) -> None:
        with self._lock:
            try:
                self._sources()
                if (type(observation) is not TargetNamespacePreflightObservation
                    or observation is not self._current or self._evidence is None):
                    raise ValueError
                dependency, names, namespace, candidate = self._evidence
                if _target_name(candidate_name) != candidate:
                    raise ValueError
                self._api.check_current(dependency)
                self._namespace.check_current(namespace, candidate_name=candidate, api_names=names.names)
                self._api.check_names_current(names)
            except Exception:
                raise TargetNamespacePreflightError(_ERROR) from None

    def check_transport_source(self, observation: TargetNamespacePreflightObservation,
                               *, candidate_name: str, transport: object) -> None:
        with self._lock:
            try:
                self.check_current(observation, candidate_name=candidate_name)
                if self._evidence is None:
                    raise ValueError
                self._api.check_transport_source(self._evidence[0], transport)
                self.check_current(observation, candidate_name=candidate_name)
            except Exception:
                raise TargetNamespacePreflightError(_ERROR) from None

    def close(self) -> None:
        # Readers belong to the caller; closing this composition does not close them.
        with self._lock:
            self._closed = True
            self._current = None
            self._evidence = None
