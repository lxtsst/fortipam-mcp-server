"""Fixed FortiPAM 1.9.1 HTTPS transport for password Secret creation.

The transport receives material only through the protected C3 bridge. It sends
one exact source-backed Host/Username/Password body for the accepted Linux SSH
or Windows Machine profile, or URL/Username/Password for the accepted Web
Account profile, or four fields for the private build-29 AD candidate after
exact Target and Template preflight. No AD MCP profile is registered here.
By default it never parses the potentially material-bearing POST response,
clears its mutable request buffer, and leaves independent metadata-only
verification to the M4 projection reader. An explicit private build29 Web
capture may consume fixed native ACK metadata without decoding material.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import http.client
import logging
import math
from typing import Protocol, cast
from urllib.parse import urlsplit

from v4_planning.material_provider import MaterialLeaseRequest, MaterialPurpose
from v4_planning.secret_create_adapter import (
    SECRET_CREATE_ACTION_ID,
    SECRET_CREATE_ACTION_VERSION,
    SecretCreateAdapterOutcome,
)

from .mutable_json_buffer import _MutableJSONBuffer
from .secret_create_191_private_adapter import (
    SecretCreate191Binding,
    SecretCreate191TargetBinding,
    SecretCreate191WebBinding,
    SecretCreate700WinrmBinding,
    SecretCreate700DomainBinding,
    SecretCreate700WebTargetBinding,
)
from .secret_metadata_http_transport import (
    COLLECTION_PATH,
    FortiPamSecretMetadataHttpTransport,
    SecretMetadataHttpTransportConfig,
    SecretMetadataProjectionInspection,
    _ssl_context,
)
from .web_secret_create_ack import (WebSecretCreateAckCapture, WebSecretCreateAcknowledgement,
                                    _AckResponse, read_web_secret_create_ack)


_UNAVAILABLE = "The FortiPAM 1.9.1 Secret-create transport is unavailable."


@dataclass(frozen=True, slots=True, repr=False)
class WebSecretCreateDispatchObservation:
    """Private HTTP observation, not ownership or permission to recover a Secret.

    The original POST body and response body are never retained. An independent
    exact metadata readback and the original verified M4 record are still needed
    before any durable fixture admission. An optional native ACK comes only from
    the original explicitly captured response; absent ACK never implies an ID.
    """

    binding: SecretCreate191WebBinding
    request: MaterialLeaseRequest
    origin: str
    native_folder_id: int
    create_uuid: str
    native_ack: WebSecretCreateAcknowledgement | None = None

    def __repr__(self) -> str:
        return "<WebSecretCreateDispatchObservation redacted>"

    __str__ = __repr__


class _HttpResponse(Protocol):
    status: int

    def close(self) -> None: ...


class _HttpsConnection(Protocol):
    def request(
        self,
        method: str,
        url: str,
        body: memoryview,
        headers: dict[str, str],
    ) -> None: ...

    def getresponse(self) -> _HttpResponse: ...

    def close(self) -> None: ...


class _FolderIdResolver(Protocol):
    def read_product_version(self) -> str: ...

    def read_product_version_and_build(self) -> tuple[str, int]: ...

    def resolve_folder_id(self, folder_path: str) -> int: ...

    def resolve_secret_create_uuid(self) -> str: ...


class FortiPam191SecretCreateHttpTransport:
    """Send one source-pinned Secret POST and return only its acknowledgement."""

    __slots__ = (
        "_config",
        "_connection_factory",
        "_last_failure_stage",
        "_last_http_status",
        "_metadata_transport",
        "_web_create_observation",
        "_web_ack_capture",
    )

    def __init__(
        self,
        config: SecretMetadataHttpTransportConfig,
        *,
        connection_factory: Callable[..., _HttpsConnection] | None = None,
        metadata_transport: _FolderIdResolver | None = None,
        web_ack_capture: WebSecretCreateAckCapture | None = None,
    ) -> None:
        if not isinstance(config, SecretMetadataHttpTransportConfig):
            raise ValueError(_UNAVAILABLE)
        if web_ack_capture is not None:
            if (type(web_ack_capture) is not WebSecretCreateAckCapture
                    or type(config.timeout_seconds) not in (int, float)
                    or not math.isfinite(config.timeout_seconds)
                    or not 1 <= config.timeout_seconds <= 60):
                raise ValueError(_UNAVAILABLE)
            web_ack_capture.__post_init__()
            config.__post_init__()
            origin = urlsplit(config.base_url)
            if origin.username is not None or origin.password is not None:
                raise ValueError(_UNAVAILABLE)
        self._config = config
        self._connection_factory = connection_factory
        self._last_failure_stage: str | None = None
        self._last_http_status: int | None = None
        self._web_create_observation: WebSecretCreateDispatchObservation | None = None
        self._web_ack_capture = web_ack_capture
        self._metadata_transport = metadata_transport or FortiPamSecretMetadataHttpTransport(
            config
        )

    @property
    def last_failure_stage(self) -> str | None:
        """Return only the fixed failed stage, never a product response."""

        return self._last_failure_stage

    @property
    def last_http_status(self) -> int | None:
        """Return only a rejected POST status code."""

        return self._last_http_status

    def read_web_create_dispatch_observation(
        self, binding: SecretCreate191WebBinding, request: MaterialLeaseRequest,
    ) -> WebSecretCreateDispatchObservation | None:
        """Read only this instance's latest exact build29 Web POST observation.

        Adapter success or a caller-supplied record cannot populate this state.
        This method dispatches nothing and adds no cleanup or replay authority.
        """

        observation = self._web_create_observation
        if (type(binding) is not SecretCreate191WebBinding
                or type(request) is not MaterialLeaseRequest
                or observation is None
                or observation.binding != binding or observation.request != request):
            return None
        return observation

    def _create_and_verify_with_material(
        self,
        binding: SecretCreate191Binding,
        request: MaterialLeaseRequest,
        username: memoryview,
        password: memoryview,
    ) -> SecretCreateAdapterOutcome:
        body = bytearray()
        connection: _HttpsConnection | None = None
        body_view: memoryview | None = None
        pending_observation: WebSecretCreateDispatchObservation | None = None
        self._web_create_observation = None
        try:
            self._last_failure_stage = "secret_create_prewrite"
            self._last_http_status = None
            if (self._web_ack_capture is not None
                    and (type(binding) is not SecretCreate191WebBinding
                         or binding.contract_ref != "fortipam-700-build29-web-secret-create-candidate-v1"
                         or binding.target_product_version != "7.0.0" or binding.target_product_build != 29)):
                raise ValueError
            if (
                not isinstance(
                    binding,
                    (SecretCreate191TargetBinding, SecretCreate191WebBinding, SecretCreate700WinrmBinding, SecretCreate700DomainBinding, SecretCreate700WebTargetBinding),
                )
                or not isinstance(request, MaterialLeaseRequest)
                or request.action_id != SECRET_CREATE_ACTION_ID
                or request.action_version != SECRET_CREATE_ACTION_VERSION
                or request.plan_digest != binding.plan_digest
                or not _valid_material_view(username)
                or not _valid_material_view(password)
            ):
                raise ValueError
            self._last_failure_stage = "secret_create_version"
            if binding.target_product_build is not None:
                if self._metadata_transport.read_product_version_and_build() != (
                    binding.target_product_version, binding.target_product_build,
                ):
                    raise ValueError
            elif self._metadata_transport.read_product_version() != binding.target_product_version:
                raise ValueError
            self._last_failure_stage = "secret_create_prewrite"
            if isinstance(binding, SecretCreate700WebTargetBinding):
                preflight = getattr(self._metadata_transport, "inspect_target_bound_web_projection", None)
                if not callable(preflight):
                    raise ValueError
                inspection = preflight(
                    binding.folder_path, binding.secret_name, target=binding.target,
                )
                if (type(inspection) is not SecretMetadataProjectionInspection
                        or inspection.secret_exists or not inspection.folder_exists
                        or not inspection.template_exists or inspection.field_values_attached
                        or inspection.folder_matches or inspection.template_matches
                        or inspection.target_matches or inspection.inherit_permission_matches):
                    raise ValueError
            if isinstance(binding, SecretCreate700DomainBinding):
                preflight = getattr(self._metadata_transport, "verify_domain_account_preflight", None)
                if not callable(preflight) or preflight(binding.target_name, binding.target_ipv4_address,
                    binding.domain_dns_root, binding.target_owner_name,
                    expected_classification_tag=binding.target_classification_tag) is not True:
                    raise ValueError
            if isinstance(binding, SecretCreate700WinrmBinding):
                preflight = getattr(self._metadata_transport, "verify_winrm_collector_preflight", None)
                if not callable(preflight) or preflight(
                    binding.folder_path, binding.secret_name, binding.folder_owner_name,
                    binding.witness_folder_path, binding.witness_secret_name, binding.target_name,
                    binding.target_ipv4_address,
                ) is not True:
                    raise ValueError
            folder_id = self._metadata_transport.resolve_folder_id(binding.folder_path)
            create_uuid = self._metadata_transport.resolve_secret_create_uuid()
            body = _secret_create_body(
                binding,
                folder_id,
                create_uuid,
                username,
                password,
            )
            parsed = urlsplit(self._config.base_url)
            if parsed.hostname is None:
                raise ValueError
            factory = self._connection_factory or http.client.HTTPSConnection
            connection = factory(
                parsed.hostname,
                parsed.port or 443,
                timeout=(self._config.timeout_seconds if self._web_ack_capture is None
                         else min(10.0, self._config.timeout_seconds)),
                context=_ssl_context(self._config),
            )
            body_view = memoryview(body).toreadonly()
            self._last_failure_stage = "secret_create_post"
            connection.request(
                "POST",
                COLLECTION_PATH,
                body_view,
                {
                    "Accept": "application/json",
                    "Authorization": f"Bearer {self._config.bearer_token}",
                    "Connection": "close",
                    "Content-Type": "application/json",
                    "User-Agent": "fortipam-mcp-v4-secret-create/1",
                    **({"Accept-Encoding": "identity"} if self._web_ack_capture is not None else {}),
                },
            )
            response = connection.getresponse()
            try:
                status = response.status
                native_ack = None
                if self._web_ack_capture is not None:
                    if type(status) is not int or status != 200:
                        raise ValueError
                    self._last_failure_stage = "secret_create_ack"
                    native_ack = read_web_secret_create_ack(cast(_AckResponse, response),
                        capture=self._web_ack_capture, timeout_seconds=self._config.timeout_seconds)
            finally:
                response.close()
            if status == 200:
                self._last_failure_stage = None
                if (type(status) is int and type(binding) is SecretCreate191WebBinding
                        and binding.contract_ref == "fortipam-700-build29-web-secret-create-candidate-v1"
                        and binding.target_product_version == "7.0.0"
                        and binding.target_product_build == 29
                        and request.purpose is MaterialPurpose.INITIAL_ONBOARDING
                        and parsed.username is None and parsed.password is None
                        and type(folder_id) is int and 0 < folder_id <= 2**31 - 1):
                    pending_observation = WebSecretCreateDispatchObservation(
                        binding, request, self._config.base_url, folder_id, create_uuid, native_ack,
                    )
            else:
                self._last_http_status = int(status)
                logging.getLogger(__name__).warning(
                    "Secret create transport rejected: stage=%s http_status=%d",
                    self._last_failure_stage, self._last_http_status,
                )
            return (
                SecretCreateAdapterOutcome.VERIFIED_CREATED
                if status == 200
                else SecretCreateAdapterOutcome.RECONCILIATION_REQUIRED
            )
        except Exception:
            # Never log exception text, response bodies, selectors or material.
            logging.getLogger(__name__).warning(
                "Secret create transport exception: stage=%s", self._last_failure_stage
            )
            return SecretCreateAdapterOutcome.RECONCILIATION_REQUIRED
        finally:
            if body_view is not None:
                body_view.release()
            _zeroize(body)
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pending_observation = None
            # Publish only after response closure, body zeroization and connection
            # closure. Missing cleanup evidence must not mint a fixture anchor.
            self._web_create_observation = pending_observation


def _secret_create_body(
    binding: SecretCreate191Binding,
    folder_id: int,
    create_uuid: str,
    username: memoryview,
    password: memoryview,
) -> bytearray:
    with _MutableJSONBuffer() as body:
        body.extend(b'{"id":0,"name":')
        _append_text(body, binding.secret_name)
        if isinstance(binding, SecretCreate700WebTargetBinding):
            body.extend(b',"target":')
            _append_text(body, binding.target.target_name)
        if isinstance(binding, (SecretCreate191TargetBinding, SecretCreate700WinrmBinding, SecretCreate700DomainBinding)):
            body.extend(b',"target":')
            _append_text(body, binding.target_name)
        body.extend(b',"inherit-permission":"enable","folder":')
        body.extend(str(folder_id).encode("ascii"))
        body.extend(b',"template":')
        _append_text(body, binding.template_name)
        body.extend(
            b',"approval-profile":"","av-profile":"","av-scan":"disable"'
            b',"bypass-ssh-filter-for-owner":"disable","dlp-sensor":""'
            b',"dlp-status":"disable","need-approval":"disable"'
            b',"need-approval-job":"disable","pwd-chg-sch-frequency":"month"'
            b',"pwd-chg-sch-interval":1,"pwd-chg-sch-month-day":"1"'
            b',"pwd-chg-sch-month-type":"specific","pwd-chg-sch-week-day":""'
            b',"rdp-event-filter":'
        )
        event_filter_profile = (
            binding.rdp_event_filter_profile_name
            if isinstance(binding, (SecretCreate191TargetBinding, SecretCreate700WinrmBinding))
            else None
        )
        _append_text(body, "enable" if event_filter_profile is not None else "disable")
        body.extend(b',"rdp-event-filter-profile":')
        _append_text(body, event_filter_profile or "")
        body.extend(
            b',"secret-auth":"disable","secret-auth-duration":60'
            b',"secret-auth-server":"","server-info":"Inherit"'
            b',"ssh-filter":"disable","ssh-filter-profile":""'
            b',"winappfilter":"disable","winappfilter-profile":""'
        )
        if isinstance(binding, SecretCreate700WinrmBinding):
            body.extend(
                b',"recording":"enable","target-privilege-account":"enable","rdp-service-status":"up"'
                b',"ssh-service-status":"down","http-service-status":"down"'
                b',"samba-service-status":"down","telnet-service-status":"down"'
            )
        elif isinstance(binding, SecretCreate700DomainBinding):
            body.extend(b',"target-privilege-account":"disable","rdp-service-status":"down"'
                b',"ssh-service-status":"down","sftp-service-status":"down","http-service-status":"down"'
                b',"samba-service-status":"down","telnet-service-status":"down"')
        else:
            body.extend(b',"target-privilege-account":"disable"')
        if isinstance(binding, (SecretCreate191WebBinding, SecretCreate700WebTargetBinding)):
            body.extend(b',"recording":"enable","http-service-status":"up"')
        if isinstance(binding, SecretCreate700WebTargetBinding):
            body.extend(b',"proxy":"enable"')
        if isinstance(binding, SecretCreate191TargetBinding) and binding.rdp_service_enabled:
            body.extend(b',"rdp-service-status":"up"')
        if isinstance(binding, SecretCreate191TargetBinding) and binding.contract_ref == "fortipam-700-build29-windows-rdp-create-candidate-v1":
            body.extend(b',"recording":"enable","block-clipboard":"enable"'
                        b',"proxy":"enable","rdp-tcp-forward":"disable"')
        if isinstance(binding, SecretCreate191TargetBinding) and binding.target_product_build == 29 and not binding.rdp_service_enabled:
            body.extend(b',"ssh-service-status":"up"')
            if binding.contract_ref == "fortipam-700-build29-linux-ssh-sftp-recording-create-candidate-v2":
                body.extend(b',"sftp-service-status":"up","recording":"enable"')
        body.extend(b',"uuid":')
        _append_text(body, create_uuid)
        if isinstance(binding, (SecretCreate700WebTargetBinding, SecretCreate700DomainBinding)):
            body.extend(b',"field":[{"id":0,"name":"Password","value":')
            _append_material(body, password)
            body.extend(b'},{"id":0,"name":"Username","value":')
            _append_material(body, username)
            body.extend(b'}]}')
            return body.finish()
        body.extend(b',"field":[{"id":0,"name":')
        if isinstance(binding, (SecretCreate191TargetBinding, SecretCreate700WinrmBinding)):
            _append_text(body, "Host")
            body.extend(b',"value":')
            _append_text(body, binding.target_ipv4_address)
        else:
            _append_text(body, "URL")
            body.extend(b',"value":')
            _append_text(body, binding.web_url)
        body.extend(b'},{"id":0,"name":"Username","value":')
        _append_material(body, username)
        body.extend(b'},{"id":0,"name":"Password","value":')
        _append_material(body, password)
        body.extend(b'}]}')
        return body.finish()


def _quoted_material(value: memoryview) -> bytearray:
    with _MutableJSONBuffer() as target:
        _append_material(target, value)
        return target.finish()


def _quoted_text(value: str) -> bytearray:
    with _MutableJSONBuffer() as target:
        _append_text(target, value)
        return target.finish()


def _append_text(target: _MutableJSONBuffer, value: str) -> None:
    encoded = bytearray(value.encode("utf-8"))
    view = memoryview(encoded).toreadonly()
    try:
        _append_material(target, view)
    finally:
        view.release()
        _zeroize(encoded)


def _append_material(target: _MutableJSONBuffer, value: memoryview) -> None:
    if type(target) is not _MutableJSONBuffer:
        raise ValueError("The private encoder requires an owned mutable buffer.")
    target.append(34)
    for byte in value:
        if byte in {34, 92}:
            target.append(92)
            target.append(byte)
        elif byte < 32:
            target.extend(f"\\u00{byte:02x}".encode("ascii"))
        else:
            target.append(byte)
    target.append(34)


def _valid_material_view(value: object) -> bool:
    if not isinstance(value, memoryview) or value.ndim != 1 or value.nbytes == 0:
        return False
    return (
        value.nbytes <= 4096
        and all(byte not in {0, 10, 13} for byte in value)
        and _valid_utf8(value)
    )


def _valid_utf8(value: memoryview) -> bool:
    remaining = 0
    lower = 0x80
    upper = 0xBF
    for byte in value:
        if remaining:
            if byte < lower or byte > upper:
                return False
            remaining -= 1
            lower, upper = 0x80, 0xBF
            continue
        if byte <= 0x7F:
            continue
        if 0xC2 <= byte <= 0xDF:
            remaining = 1
        elif byte == 0xE0:
            remaining, lower = 2, 0xA0
        elif 0xE1 <= byte <= 0xEC or 0xEE <= byte <= 0xEF:
            remaining = 2
        elif byte == 0xED:
            remaining, upper = 2, 0x9F
        elif byte == 0xF0:
            remaining, lower = 3, 0x90
        elif 0xF1 <= byte <= 0xF3:
            remaining = 3
        elif byte == 0xF4:
            remaining, upper = 3, 0x8F
        else:
            return False
    return remaining == 0


def _zeroize(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0


__all__ = ["FortiPam191SecretCreateHttpTransport"]
