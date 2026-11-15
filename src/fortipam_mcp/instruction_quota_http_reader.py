"""Inactive fixed schema/configuration/usage reader for quota reallocation.

No mutation, authentication, generic route or MCP Tool is exposed here.
"""
from __future__ import annotations

from collections.abc import Callable
import math
import ssl
import time
from urllib.parse import urlsplit
from typing import Literal

import httpx

from .secret_bulk_import_metadata import _InvalidJsonUtf8
from .instruction_feature_contract import _require_digest
from .instruction_quota_contract import (
    InstructionQuotaState, _quota_schema_binding, read_instruction_quota_state,
)
from .instruction_resource_usage import InstructionResourceUsage, project_instruction_resource_usage
from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig, _ssl_context, _zeroize_mutable,
)
from .target_api_dependency_reader import _private_http_logs

_ROUTES = ("/api/v2/cmdb/secret/setting?action=schema&with_meta=true",
           "/api/v2/cmdb/secret/setting?with_meta=true",
           "/api/v2/cmdb/system/global?format=pam-video-storage-limit",
           "/api/v2/monitor/log/current-disk-usage")
_LIMIT = 524288
_ERROR = "The private Instruction quota source is unavailable."


class InstructionQuotaReadError(ValueError):
    """Stable refusal without configuration, response or partial state."""

    def __init__(self, stage: str, category: Literal["invalid_utf8", "transport", "invalid_source"]) -> None:
        super().__init__(_ERROR)
        self.stage = stage
        self.category = category


def read_instruction_quota_context(config: SecretMetadataHttpTransportConfig, *,
        serial_digest: str, client_factory: Callable[..., httpx.Client] = httpx.Client,
        clock: Callable[[], float] = time.monotonic) -> tuple[InstructionQuotaState, InstructionResourceUsage]:
    """Read the fixed quota context; retry malformed UTF-8 schema at most twice.

    A rejected schema is erased and never contributes to a state binding. All
    requests share the original deadline; each remaining route is requested only once.
    """
    buffers: list[bytearray] = []
    responses: list[httpx.Response] = []
    client: httpx.Client | None = None
    previous: float | None = None
    stage = "configuration"
    try:
        _require_digest(serial_digest)
        if type(config) is not SecretMetadataHttpTransportConfig:
            raise ValueError
        config.__post_init__()
        origin = urlsplit(config.base_url)
        if (origin.scheme != "https" or not origin.hostname
                or origin.username is not None or origin.password is not None
                or origin.path not in ("", "/") or origin.query or origin.fragment):
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

        with _private_http_logs(), client_factory(verify=context, timeout=remaining(),
                follow_redirects=False, trust_env=False) as client:
            try:
                def fetch(route: str) -> bytearray:
                    nonlocal stage
                    stage = ("schema_http", "setting_http", "video_http", "usage_http")[_ROUTES.index(route)]
                    client.cookies.clear()
                    raw = bytearray()
                    buffers.append(raw)
                    with client.stream("GET", config.base_url.rstrip("/") + route,
                            headers={"Authorization": "Bearer " + config.bearer_token,
                                     "Accept": "application/json", "Accept-Encoding": "identity",
                                     "Cache-Control": "no-store", "Connection": "close",
                                     "User-Agent": "fortipam-mcp-target-lifecycle/1"},
                            timeout=remaining()) as response:
                        responses.append(response)
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
                    return raw

                for attempt in range(3):
                    raw = fetch(_ROUTES[0])
                    try:
                        stage = "schema_validation"
                        _quota_schema_binding(raw, serial_digest)
                        remaining()
                        break
                    except _InvalidJsonUtf8:
                        _zeroize_mutable(raw)
                        buffers.pop()
                        if attempt == 2:
                            raise
                        remaining()
                for route in _ROUTES[1:]:
                    fetch(route)
                remaining()
                stage = "configuration_validation"
                state = read_instruction_quota_state(buffers[0], buffers[1], buffers[2], serial_digest=serial_digest)
                stage = "usage_validation"
                usage = project_instruction_resource_usage(buffers[3], serial_digest=serial_digest)
                remaining()
            finally:
                client.cookies.clear()
        stage = "closure"
        remaining()
        if not client.is_closed or len(client.cookies) or any(not response.is_closed for response in responses):
            raise ValueError
        return state, usage
    except Exception as error:
        category: Literal["invalid_utf8", "transport", "invalid_source"] = (
            "invalid_utf8" if isinstance(error, _InvalidJsonUtf8) else
            "transport" if isinstance(error, httpx.HTTPError) else "invalid_source")
        raise InstructionQuotaReadError(stage, category) from None
    finally:
        for raw in buffers:
            _zeroize_mutable(raw)
