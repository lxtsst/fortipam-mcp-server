"""Private fixed subscription client using the retained BP005 requester login.

The transport still owns its fixed routes, drift check and durable dispatch.
This dependency authenticates the bound current user and verifies logout; it
never forwards the bearer header into the cookie session or copies material.
"""
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any

from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from .secret_request_requester_session import build_bp005_requester_session

_PREFIX = "FORTIPAM_MCP_V4_LOCAL_USER_CREATE_ACTION_BP005_"
_UNAVAILABLE = "The fixed subscription requester session is unavailable."


class SecretEventSubscriptionRequesterSessionError(RuntimeError):
    """Keep private identities, paths, credentials and cookies out of errors."""


class SecretEventSubscriptionRequesterClient:
    def __init__(
        self, config: SecretMetadataHttpTransportConfig, *, owner_name: str,
        environment: Mapping[str, str],
        session_builder: Callable[..., Any] = build_bp005_requester_session,
    ) -> None:
        try:
            references = {key: environment[_PREFIX + key]
                          for key in ("USERNAME", "MATERIAL_DIRECTORY")}
            if (type(config) is not SecretMetadataHttpTransportConfig
                    or references["USERNAME"] != owner_name
                    or not Path(references["MATERIAL_DIRECTORY"]).is_absolute()
                    or not callable(session_builder)):
                raise ValueError
            self._environment = MappingProxyType({_PREFIX + key: value
                                                 for key, value in references.items()})
            self._config, self._owner = config, owner_name
            self._builder = session_builder
        except Exception:
            raise SecretEventSubscriptionRequesterSessionError(_UNAVAILABLE) from None

    def __call__(self, **options: Any) -> Any:
        """Accept only the fixed transport's origin and connection policy.

        Its bearer header is deliberately not passed to the requester session.
        TLS and timeout are provided by the existing strict session builder.
        """
        if (options.get("base_url") != self._config.base_url
                or options.get("follow_redirects") is not False
                or options.get("trust_env") is not False):
            raise SecretEventSubscriptionRequesterSessionError(_UNAVAILABLE)
        return self._authenticated()

    @contextmanager
    def _authenticated(self) -> Iterator[Any]:
        session = None
        failed = closed = False
        try:
            session = self._builder(self._config, self._environment)
            if session._requester != self._owner:
                raise ValueError
            session.inspect(self._owner)
            client, csrf = session._client, session._csrf
            if (client is None or "authorization" in client.headers
                    or type(csrf) is not str
                    or re.fullmatch(r"[A-Za-z0-9._~-]{1,256}", csrf) is None):
                raise ValueError
            client.headers["X-Requested-With"] = "XMLHttpRequest"
            client.headers["X-CSRFTOKEN"] = csrf
            yield client
        except Exception:
            failed = True
        finally:
            if session is not None:
                try:
                    closed = session.finalize() is True
                except Exception:
                    closed = False
        if failed or not closed:
            raise SecretEventSubscriptionRequesterSessionError(_UNAVAILABLE) from None
