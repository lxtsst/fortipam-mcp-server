"""Fixed build-29 fixture preflight, not a create writer or authority issuer.

Bind the actual name check, API actor's empty Sponsor context, existing Guest
profile identity, and freshly projected create defaults to one private digest.
The profile digest attests identity only, not its complete permission policy.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import hmac
import http.client
import json
from typing import Any

from v4_planning.material_provider import C3MaterialBinding

from .mutable_json_buffer import _take_mutable_prefix, _erase_transfer_storage
from .local_user_reset_fixture_create import LocalUserResetFixtureCreateDraft, prepare_local_user_reset_fixture_create
from .local_user_reset_metadata_reader import (
    LocalUserResetMetadataReadError, LocalUserResetReadFailure as Failure, _monitor_results, _validate_value,
)
from .local_user_reset_name_reader import FortiPamLocalUserResetNameReader, _ENVELOPE, _ROW
from .local_user_reset_projection import _object_spans, _string_or_empty
from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig, _json_value_end, _skip_json_space, _zeroize_mutable,
)

_MAX_BYTES = 1_048_576
_SCHEMA = "/api/v2/cmdb/system/admin?action=schema&with_meta=true"
_DEFAULT = "/api/v2/cmdb/system/admin?action=default&with_meta=true"
_PROFILE = "/api/v2/cmdb/system/accprofile/Guest?format=name&with_meta=true"
_ACTOR = "/api/v2/monitor/web-ui/state"


@dataclass(frozen=True, slots=True, repr=False)
class LocalUserResetFixturePreflight(C3MaterialBinding):
    """Fresh private C/P/E inputs; no password, create receipt or reset authority."""

    draft: LocalUserResetFixtureCreateDraft
    name_check_digest: str
    actor_context_digest: str
    profile_identity_digest: str
    state_digest: str


class FortiPamLocalUserResetFixturePreflightReader:
    """Read one bound new-name/Guest/API-actor context, accepting no public inputs."""

    def __init__(
        self, config: SecretMetadataHttpTransportConfig, *, username: str, api_principal: str,
        connection_factory: Callable[..., Any] = http.client.HTTPSConnection,
    ) -> None:
        # Reuse exactly the qualified name reader's binding and strict-TLS
        # validation; all six requests use the same actor, origin and factory.
        self._names = FortiPamLocalUserResetNameReader(
            config, username=username, api_principal=api_principal, connection_factory=connection_factory,
        )
        self._config, self._username, self._principal = config, username, api_principal
        self._host, self._port, self._context = self._names._host, self._names._port, self._names._context
        self._factory = connection_factory
        self._actor = _ACTOR

    def read_preflight(self) -> LocalUserResetFixturePreflight:
        """Do not turn a clear name check into permission or creation evidence."""
        buffers: list[bytearray] = []
        try:
            names = self._names.read_observation()
            if not names.source_name_check_clear or names.local_user_collision or names.api_user_collision:
                raise ValueError
            actor = self._read(self._actor); buffers.append(actor)
            actor_digest = _actor_context(actor, expected_name=self._principal)
            profile = self._read(_PROFILE); buffers.append(profile)
            profile_digest = _identity(profile, table="accprofile", expected_name="Guest")
            schema = self._read(_SCHEMA); buffers.append(schema)
            defaults = self._read(_DEFAULT); buffers.append(defaults)
            draft = prepare_local_user_reset_fixture_create(
                defaults, json.loads(schema), username=self._username, access_profile="Guest",
            )
            state_digest = _digest({
                "contract": "bp002-build29-fixture-preflight/v1", "host": self._host, "port": self._port,
                "username": self._username, "api_principal": self._principal,
                "name_check": names.state_digest, "actor_context": actor_digest, "profile_identity": profile_digest,
                "selected_defaults": draft.source_defaults_digest, "proposed": draft.nonmaterial_request_digest,
            })
            return LocalUserResetFixturePreflight(draft, names.state_digest, actor_digest, profile_digest, state_digest)
        except LocalUserResetMetadataReadError:
            raise
        except Exception:
            raise LocalUserResetMetadataReadError(Failure.UNQUALIFIED_RESPONSE) from None
        finally:
            for content in buffers:
                _zeroize_mutable(content)

    def _read(self, path: str) -> bytearray:
        content = bytearray()
        try:
            content = bytearray(_MAX_BYTES + 1)
            response = connection = None
            transfer = False
            try:
                if path not in {self._actor, _PROFILE, _SCHEMA, _DEFAULT}:
                    raise ValueError
                connection = self._factory(self._host, self._port, timeout=self._config.timeout_seconds,
                                           context=self._context)
                connection.request("GET", path, headers={
                    "Accept": "application/json", "Accept-Encoding": "identity", "Connection": "close",
                    "Authorization": f"Bearer {self._config.bearer_token}", "Cache-Control": "no-cache, no-store",
                    "User-Agent": "fortipam-bp002-fixture-preflight/1",
                })
                response = connection.getresponse()
                if response.status in {401, 403}:
                    raise LocalUserResetMetadataReadError(Failure.AUTHORIZATION_DENIED)
                if response.status == 404:
                    raise LocalUserResetMetadataReadError(Failure.NOT_FOUND)
                if (type(response.status) is not int or response.status != 200
                    or response.getheader("content-type", "").split(";", 1)[0].strip().lower() != "application/json"
                    or response.getheader("content-encoding", "identity").strip().lower() != "identity"):
                    raise ValueError
                total = 0
                while total < len(content):
                    with memoryview(content)[total:] as view:
                        count = response.readinto(view)
                    if type(count) is not int or not 0 <= count <= len(content) - total:
                        raise ValueError
                    if not count:
                        break
                    total += count
                if total > _MAX_BYTES:
                    raise ValueError
                content = _take_mutable_prefix(content, total)
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


def _actor_context(content: bytearray, *, expected_name: str) -> str:
    """Use the frontend's current-actor source, not an API User CMDB row.

    AppStateService (73006) resolves results.admin; Admin.getSponsorGrp()
    reads sponsored_group_name. Require explicit empty context, never its GUI
    missing-value fallback. Unrelated state values are not decoded or exported.
    This identity/context check is not a create-permission decision.
    """
    left, right = _monitor_results(content, expected_route="web-ui/state")
    state = _object_spans(content, left, right)
    actor_left, actor_right = state["admin"]
    _validate_value(content, actor_left, actor_right, depth=0)
    actor = _object_spans(content, actor_left, actor_right)
    expected = {"name": expected_name, "login_name": expected_name,
                "sponsored_group_name": "", "guest_admin": False}
    for key, value in expected.items():
        with memoryview(content)[slice(*actor[key])] as token:
            if token != json.dumps(value, ensure_ascii=True).encode("ascii"):
                raise ValueError
    return _digest({"source": "web-ui/state.results.admin", **expected})


def _identity(content: bytearray, *, table: str, expected_name: str) -> str:
    """Validate only exact Role identity; decode no object values."""
    left = _skip_json_space(content, 0)
    right = _json_value_end(content, left)
    if _skip_json_space(content, right) != len(content):
        raise ValueError
    envelope = _object_spans(content, left, right)
    if not envelope.keys() <= _ENVELOPE | {"mkey"}:
        raise ValueError
    _validate_value(content, left, right, depth=0)
    for key, value in {
        "http_method": "GET", "http_status": 200, "status": "success", "version": "v7.0.0",
        "build": 29, "path": "system", "name": table,
    }.items():
        with memoryview(content)[slice(*envelope[key])] as token:
            if token != json.dumps(value).encode("ascii"):
                raise ValueError
    for key in ("serial", "revision", "vdom", "action"):
        if key in envelope:
            with memoryview(content)[slice(*envelope[key])] as token:
                _string_or_empty(token)
                if key == "action" and not hmac.compare_digest(token, b'""'):
                    raise ValueError
    if "mkey" in envelope:
        with memoryview(content)[slice(*envelope["mkey"])] as token:
            if token != json.dumps(expected_name, ensure_ascii=True).encode("ascii"):
                raise ValueError
    left, right = envelope["results"]
    if content[left] == 91:
        left = _skip_json_space(content, left + 1)
        end = _json_value_end(content, left)
        if _skip_json_space(content, end) != right - 1:
            raise ValueError
        right = end
    row = _object_spans(content, left, right)
    if not row.keys() <= _ROW:
        raise ValueError
    for key in ("name", "q_origin_key"):
        if key == "q_origin_key" and key not in row:
            continue
        with memoryview(content)[slice(*row[key])] as token:
            if token != json.dumps(expected_name, ensure_ascii=True).encode("ascii"):
                raise ValueError
    return _digest({"table": table, "name": expected_name})


def _digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True, allow_nan=False).encode("utf-8")).hexdigest()
