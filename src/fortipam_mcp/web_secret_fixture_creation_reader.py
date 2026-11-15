"""Inactive one-GET Web fixture creation reader, with original M4 preflight.

No device password authentication, selector argument, mutation or MCP Tool is
exposed. Configuration and all creation bindings are private startup inputs.
"""
from __future__ import annotations

from collections.abc import Callable
import math
import re
import ssl
import time
from urllib.parse import urlsplit

import httpx

from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_create_191_http_transport import FortiPam191SecretCreateHttpTransport
from .secret_create_191_private_adapter import SecretCreate191WebBinding
from .secret_create_m4_runtime import SecretCreateM4ExecutionBinding
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig, _ssl_context, _zeroize_mutable
from .target_api_dependency_reader import _private_http_logs
from .web_secret_fixture_creation import (WebSecretFixtureCreationEvidence, _qualify_original_web_creation,
                                          join_web_secret_fixture_creation)

_ROUTE = ("/api/v2/cmdb/secret/database?format=id%7Cname%7Cfolder%7Ctemplate%7Ctarget%7C"
          "inherit-permission%7Crecording%7Chttp-service-status%7Cuuid%7Cinstruction-profile&with_meta=true")
_LIMIT = 524_288
_ERROR = "The private Web fixture creation source is unavailable."


class WebSecretFixtureCreationReadError(ValueError):
    """Categorical refusal without configuration, response or partial evidence."""


def read_web_secret_fixture_creation(config: SecretMetadataHttpTransportConfig, *,
        transport: FortiPam191SecretCreateHttpTransport, create_binding: SecretCreate191WebBinding,
        execution_binding: SecretCreateM4ExecutionBinding, execution_store: PersistentM4ExecutionStateStore,
        serial_digest: str, expected_store_digest: str,
        client_factory: Callable[..., httpx.Client] = httpx.Client,
        clock: Callable[[], float] = time.monotonic) -> WebSecretFixtureCreationEvidence:
    """Check original creation, read one fixed GET, close resources, then join.

    The reader must use the same exact private configuration as the original
    POST. A terminal record alone never imports another transport's observation.
    A successful read grants no fixture admission, association or cleanup rights.
    """
    raw = bytearray()
    client: httpx.Client | None = None
    response: httpx.Response | None = None
    previous: float | None = None
    try:
        if (type(config) is not SecretMetadataHttpTransportConfig
                or type(serial_digest) is not str or re.fullmatch(r"[a-f0-9]{64}", serial_digest) is None):
            raise ValueError
        config.__post_init__()
        origin = urlsplit(config.base_url)
        if (not origin.hostname or origin.username is not None or origin.password is not None
                or type(transport) is not FortiPam191SecretCreateHttpTransport or config != transport._config):
            raise ValueError
        context = _ssl_context(config)
        if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
            raise ValueError
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        def now() -> float:
            nonlocal previous
            value = clock()
            if (type(value) not in (int, float) or not math.isfinite(value) or value < 0
                    or previous is not None and value < previous):
                raise ValueError
            previous = value
            return value

        deadline = now() + min(30.0, config.timeout_seconds)

        def remaining() -> float:
            value = deadline - now()
            if value <= 0:
                raise ValueError
            return min(10.0, value)

        observation, _ = _qualify_original_web_creation(transport=transport, create_binding=create_binding,
            execution_binding=execution_binding, execution_store=execution_store,
            expected_store_digest=expected_store_digest)
        if observation.origin != config.base_url:
            raise ValueError
        remaining()
        with _private_http_logs(), client_factory(verify=context, timeout=remaining(),
                follow_redirects=False, trust_env=False) as client:
            try:
                client.cookies.clear()
                with client.stream("GET", config.base_url.rstrip("/") + _ROUTE,
                        headers={"Authorization": "Bearer " + config.bearer_token, "Accept": "application/json",
                                 "Accept-Encoding": "identity", "Cache-Control": "no-store", "Connection": "close",
                                 "User-Agent": "fortipam-mcp-web-fixture-creation/1"}, timeout=remaining()) as response:
                    remaining()
                    if (response.status_code != 200
                            or response.headers.get("content-type", "").split(";")[0].lower() != "application/json"
                            or response.headers.get("content-encoding", "identity") not in ("", "identity")):
                        raise ValueError
                    iterator = response.iter_raw()
                    while True:
                        remaining()
                        try:
                            chunk = next(iterator)
                        except StopIteration:
                            remaining()
                            break
                        remaining()
                        if len(raw) + len(chunk) > _LIMIT:
                            raise ValueError
                        raw.extend(chunk)
            finally:
                client.cookies.clear()
        remaining()
        if not client.is_closed or len(client.cookies) or response is None or not response.is_closed:
            raise ValueError
        evidence = join_web_secret_fixture_creation(transport=transport, create_binding=create_binding,
            execution_binding=execution_binding, execution_store=execution_store, response=raw,
            serial_digest=serial_digest, expected_store_digest=expected_store_digest)
        remaining()
        return evidence
    except Exception:
        raise WebSecretFixtureCreationReadError(_ERROR) from None
    finally:
        _zeroize_mutable(raw)
