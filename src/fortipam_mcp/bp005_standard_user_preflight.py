"""Fixed strict-TLS preflight for the BP005 Standard User create contract."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import http.client
import json
import ssl
from typing import Any
from urllib.parse import urlsplit

from v4_planning.material_provider import C3MaterialBinding

from .mutable_json_buffer import _take_mutable_prefix, _erase_transfer_storage
from .bp005_standard_user_create_contract import (
    Bp005StandardUserCreateDraft,
    prepare_bp005_standard_user_create,
)
from .local_user_reset_fixture_create import BP005_STANDARD_USERNAME_PATTERN
from .local_user_reset_fixture_preflight import _actor_context, _identity
from .local_user_reset_name_reader import _QUERIES, _project_names
from .local_user_reset_metadata_reader import (
    LocalUserResetMetadataReadError,
    LocalUserResetReadFailure as Failure,
)
from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig,
    _json_value_end,
    _skip_json_space,
    _ssl_context,
    _zeroize_mutable,
)

_MAX_BYTES = 1_048_576
_ACTOR = "/api/v2/monitor/web-ui/state"
_PROFILE = "/api/v2/cmdb/system/accprofile/pam_standard_user?format=name&with_meta=true"
_SCHEMA = "/api/v2/cmdb/system/admin?action=schema&with_meta=true"
_DEFAULT = "/api/v2/cmdb/system/admin?action=default&with_meta=true"


@dataclass(frozen=True, slots=True, repr=False)
class Bp005StandardUserPreflight(C3MaterialBinding):
    """Private absence, actor, built-in Role and fixed create-default binding."""

    draft: Bp005StandardUserCreateDraft
    name_check_digest: str
    actor_context_digest: str
    profile_identity_digest: str
    state_digest: str


class FortiPamBp005StandardUserPreflightReader:
    """Read one exact new username and the built-in Standard User profile."""

    def __init__(
        self,
        config: SecretMetadataHttpTransportConfig,
        *,
        username: str,
        api_principal: str,
        connection_factory: Callable[..., Any] = http.client.HTTPSConnection,
    ) -> None:
        try:
            if (
                type(config) is not SecretMetadataHttpTransportConfig
                or type(username) is not str
                or BP005_STANDARD_USERNAME_PATTERN.fullmatch(username) is None
                or type(api_principal) is not str
                or not 0 < len(api_principal) <= 255
                or any(ord(character) < 32 or ord(character) == 127 for character in api_principal)
                or username.lower() == api_principal.lower()
                or not callable(connection_factory)
            ):
                raise ValueError
            origin = urlsplit(config.base_url)
            port = 443 if origin.port is None else origin.port
            if (
                origin.scheme != "https" or not origin.hostname
                or origin.username is not None or origin.password is not None
                or origin.path not in {"", "/"} or origin.query or origin.fragment
                or not 1 <= port <= 65535
            ):
                raise ValueError
            context = _ssl_context(config)
            if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
                raise ValueError
            self._config = config
            self._username, self._principal = username, api_principal
            self._host, self._port = origin.hostname, port
            self._context, self._factory = context, connection_factory
        except Exception:
            raise LocalUserResetMetadataReadError(Failure.UNQUALIFIED_RESPONSE) from None

    def read_preflight(self) -> Bp005StandardUserPreflight:
        buffers: list[bytearray] = []
        try:
            name_check_digest = self._read_name_observation()
            actor = self._read(_ACTOR)
            buffers.append(actor)
            actor_digest = _actor_context(actor, expected_name=self._principal)
            profile = self._read(_PROFILE)
            buffers.append(profile)
            profile_digest = _identity(
                profile, table="accprofile", expected_name="pam_standard_user",
            )
            schema = self._read(_SCHEMA)
            buffers.append(schema)
            defaults = self._read(_DEFAULT)
            buffers.append(defaults)
            draft = prepare_bp005_standard_user_create(
                defaults, json.loads(schema), username=self._username,
            )
            state_digest = hashlib.sha256(json.dumps({
                "contract": "bp005-standard-user-preflight-v1",
                "host": self._host,
                "port": self._port,
                "username": self._username,
                "api_principal": self._principal,
                "name_check": name_check_digest,
                "actor_context": actor_digest,
                "profile_identity": profile_digest,
                "desired_access_profile": "pam_standard_user",
                "desired_status": "enable",
                "selected_defaults": draft.source_defaults_digest,
                "proposed_request": draft.nonmaterial_request_digest,
            }, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")).hexdigest()
            return Bp005StandardUserPreflight(
                draft, name_check_digest, actor_digest, profile_digest, state_digest,
            )
        except LocalUserResetMetadataReadError:
            raise
        except Exception:
            raise LocalUserResetMetadataReadError(Failure.UNQUALIFIED_RESPONSE) from None
        finally:
            for content in buffers:
                _zeroize_mutable(content)

    def _read_name_observation(self) -> str:
        names: dict[str, list[str]] = {}
        for table, body in _QUERIES:
            content = self._read_name_query(table, body)
            try:
                names[table] = _project_names(content, table=table)
            except Exception:
                raise LocalUserResetMetadataReadError(Failure.UNQUALIFIED_RESPONSE) from None
            finally:
                _zeroize_mutable(content)
        admin_names, api_names = names["admin"], names["api-user"]
        if (
            not admin_names
            or any(name.lower() == self._username.lower() for name in admin_names)
            or any(name.lower() == self._username.lower() for name in api_names)
            or api_names.count(self._principal) != 1
            or sum(name.lower() == self._principal.lower() for name in api_names) != 1
        ):
            raise LocalUserResetMetadataReadError(Failure.UNQUALIFIED_RESPONSE)
        return hashlib.sha256(json.dumps({
            "contract": "bp005-standard-user-name-check-v1",
            "host": self._host,
            "port": self._port,
            "username": self._username,
            "api_principal": self._principal,
            "local_user_collision": False,
            "api_user_collision": False,
            "api_principal_visible": True,
        }, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()

    def _read_name_query(self, table: str, body: bytes) -> bytearray:
        content = bytearray()
        try:
            content = bytearray(_MAX_BYTES + 1)
            response = connection = None
            transfer = False
            try:
                if (table, body) not in _QUERIES:
                    raise ValueError
                connection = self._factory(
                    self._host, self._port, timeout=self._config.timeout_seconds,
                    context=self._context,
                )
                connection.request(
                    "POST", f"/api/v2/cmdb/system/{table}?format=name&with_meta=true",
                    body=body,
                    headers={
                        "X-HTTP-Method-Override": "GET",
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                        "Accept-Encoding": "identity",
                        "Connection": "close",
                        "Authorization": "Bearer " + self._config.bearer_token,
                        "Cache-Control": "no-cache, no-store",
                        "User-Agent": "fortipam-bp005-standard-user-preflight/1",
                    },
                )
                response = connection.getresponse()
                if response.status in {401, 403}:
                    raise LocalUserResetMetadataReadError(Failure.AUTHORIZATION_DENIED)
                if response.status == 404:
                    raise LocalUserResetMetadataReadError(Failure.NOT_FOUND)
                if (
                    type(response.status) is not int
                    or response.status != 200
                    or response.getheader("content-type", "").split(";", 1)[0].strip().lower() != "application/json"
                    or response.getheader("content-encoding", "identity").strip().lower() != "identity"
                ):
                    raise ValueError
                total = 0
                while total < len(content):
                    with memoryview(content)[total:] as view:
                        count = response.readinto(view)
                    if type(count) is not int or not 0 <= count <= len(content) - total:
                        raise ValueError
                    if count == 0:
                        break
                    total += count
                if total > _MAX_BYTES:
                    raise ValueError
                content = _take_mutable_prefix(content, total)
                _require_one_json_value(content)
                transfer = True
                return content
            except LocalUserResetMetadataReadError:
                raise
            except TimeoutError:
                raise LocalUserResetMetadataReadError(Failure.TIMED_OUT) from None
            except (OSError, http.client.HTTPException):
                raise LocalUserResetMetadataReadError(Failure.TRANSPORT_UNAVAILABLE) from None
            except Exception:
                raise LocalUserResetMetadataReadError(Failure.UNQUALIFIED_RESPONSE) from None
            finally:
                if not transfer:
                    _zeroize_mutable(content)
                for resource in (response, connection):
                    if resource is not None:
                        try:
                            resource.close()
                        except Exception:
                            pass
        except BaseException:
            _erase_transfer_storage(content)
            raise

    def _read(self, path: str) -> bytearray:
        content = bytearray()
        try:
            content = bytearray(_MAX_BYTES + 1)
            response = connection = None
            transfer = False
            try:
                if path not in {_ACTOR, _PROFILE, _SCHEMA, _DEFAULT}:
                    raise ValueError
                connection = self._factory(
                    self._host, self._port, timeout=self._config.timeout_seconds,
                    context=self._context,
                )
                connection.request("GET", path, headers={
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                    "Connection": "close",
                    "Authorization": "Bearer " + self._config.bearer_token,
                    "Cache-Control": "no-cache, no-store",
                    "User-Agent": "fortipam-bp005-standard-user-preflight/1",
                })
                response = connection.getresponse()
                if response.status in {401, 403}:
                    raise LocalUserResetMetadataReadError(Failure.AUTHORIZATION_DENIED)
                if response.status == 404:
                    raise LocalUserResetMetadataReadError(Failure.NOT_FOUND)
                if (
                    type(response.status) is not int
                    or response.status != 200
                    or response.getheader("content-type", "").split(";", 1)[0].strip().lower() != "application/json"
                    or response.getheader("content-encoding", "identity").strip().lower() != "identity"
                ):
                    raise ValueError
                total = 0
                while total < len(content):
                    with memoryview(content)[total:] as view:
                        count = response.readinto(view)
                    if type(count) is not int or not 0 <= count <= len(content) - total:
                        raise ValueError
                    if count == 0:
                        break
                    total += count
                if total > _MAX_BYTES:
                    raise ValueError
                content = _take_mutable_prefix(content, total)
                _require_one_json_value(content)
                transfer = True
                return content
            except LocalUserResetMetadataReadError:
                raise
            except TimeoutError:
                raise LocalUserResetMetadataReadError(Failure.TIMED_OUT) from None
            except (OSError, http.client.HTTPException):
                raise LocalUserResetMetadataReadError(Failure.TRANSPORT_UNAVAILABLE) from None
            except Exception:
                raise LocalUserResetMetadataReadError(Failure.UNQUALIFIED_RESPONSE) from None
            finally:
                if not transfer:
                    _zeroize_mutable(content)
                for resource in (response, connection):
                    if resource is not None:
                        try:
                            resource.close()
                        except Exception:
                            pass
        except BaseException:
            _erase_transfer_storage(content)
            raise


def _require_one_json_value(content: bytearray) -> None:
    if type(content) is not bytearray or not content:
        raise ValueError
    start = _skip_json_space(content, 0)
    end = _json_value_end(content, start)
    if _skip_json_space(content, end) != len(content):
        raise ValueError


__all__ = ["Bp005StandardUserPreflight", "FortiPamBp005StandardUserPreflightReader"]
