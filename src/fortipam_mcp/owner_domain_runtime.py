"""Reuse the scoped Owner session for one exact build-29 Domain binding."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict
import re
from typing import TYPE_CHECKING

from .owner_session_metadata import OwnerSessionMetadataTransport
from .secret_create_191_private_adapter import SecretCreate700DomainBinding
from .secret_metadata_http_transport import (
    FortiPamSecretMetadataHttpTransport, SecretMetadataHttpTransportConfig,
    SecretMetadataHttpTransportError, UTILITY_ID_PATH, _path_for_url,
)

if TYPE_CHECKING:
    from .secret_namespace_ssh_reader import SecretNamespaceObservation


_UNAVAILABLE = "The Domain Owner transport is unavailable."
_DIGEST = re.compile(r"\A[0-9a-f]{64}\Z")


def _selectors(binding: SecretCreate700DomainBinding) -> dict[str, object]:
    values = asdict(binding)
    values.pop("plan_digest")
    return values


class _NamespaceQualifiedDomainOwnerTransport(OwnerSessionMetadataTransport):
    """A pinned private namespace observer, after exact Owner Folder ACL."""

    def __init__(
        self, config: SecretMetadataHttpTransportConfig,
        binding: SecretCreate700DomainBinding, credentials: Callable[[], tuple[str, str]],
        observer: Callable[[SecretCreate700DomainBinding, int], SecretNamespaceObservation],
        *, allow_secret_create: bool,
    ) -> None:
        super().__init__(
            config, owner_name=binding.target_owner_name, credentials=credentials,
            folder_path=binding.folder_path, secret_name=binding.secret_name,
            target_name=binding.target_name,
            witness=FortiPamSecretMetadataHttpTransport(config, bound_secret_name=binding.secret_name),
            allow_secret_create=allow_secret_create,
        )
        self._namespace_binding = binding
        self._namespace_observer = observer

    def _domain_secret_globally_absent(
        self, binding: SecretCreate700DomainBinding, folder_id: int,
    ) -> bool:
        # Keep the SSH reader graph out of shared metadata module initialization.
        from .secret_namespace_ssh_reader import SecretNamespaceObservation
        try:
            bound = self._namespace_binding
            if (type(binding) is not SecretCreate700DomainBinding
                or _selectors(binding) != _selectors(bound)
                or self._bound_secret_name != bound.secret_name
                or self._owner_name != bound.target_owner_name
                or self._folder_lookup_path != UTILITY_ID_PATH + "/" + _path_for_url(bound.folder_path)
                or type(folder_id) is not int or not 0 < folder_id <= 2_147_483_647
                or type(self._folder_id) is not int or folder_id != self._folder_id
                or self._verify_collector_folder_acl(folder_id, bound.target_owner_name) is not True):
                raise ValueError
            observed = self._namespace_observer(binding, folder_id)
            if (type(observed) is not SecretNamespaceObservation
                or type(observed.status) is not str
                or observed.status not in {"name_absent", "name_present"}
                or type(observed.global_name_absent) is not bool
                or observed.global_name_absent is not (observed.status == "name_absent")
                or type(observed.secret_count) is not int
                or type(observed.positive_witness_count) is not int
                or not 2 <= observed.positive_witness_count <= observed.secret_count <= 2_147_483_647
                or type(observed.namespace_digest) is not str
                or _DIGEST.fullmatch(observed.namespace_digest) is None):
                raise ValueError
            return observed.global_name_absent
        except Exception:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE) from None


def owner_domain_transport(
    config: SecretMetadataHttpTransportConfig,
    binding: SecretCreate700DomainBinding,
    credentials: Callable[[], tuple[str, str]],
    *, allow_secret_create: bool = False,
    namespace_observer: Callable[[SecretCreate700DomainBinding, int], SecretNamespaceObservation] | None = None,
) -> OwnerSessionMetadataTransport:
    """Pin reads and optional one-time create to the same private selectors."""
    if (type(binding) is not SecretCreate700DomainBinding or not callable(credentials)
        or (namespace_observer is not None and not callable(namespace_observer))):
        raise ValueError(_UNAVAILABLE)
    if namespace_observer is not None:
        return _NamespaceQualifiedDomainOwnerTransport(
            config, binding, credentials, namespace_observer,
            allow_secret_create=allow_secret_create,
        )
    return OwnerSessionMetadataTransport(
        config, owner_name=binding.target_owner_name, credentials=credentials,
        folder_path=binding.folder_path, secret_name=binding.secret_name,
        target_name=binding.target_name,
        witness=FortiPamSecretMetadataHttpTransport(
            config, bound_secret_name=binding.secret_name,
        ),
        allow_secret_create=allow_secret_create,
    )
