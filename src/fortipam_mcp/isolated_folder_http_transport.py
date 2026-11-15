"""Fixed private reads and CREATE for the unregistered isolated Folder candidate."""
from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
import re
from typing import Any
from urllib.parse import quote
import httpx
from v4_planning import canonical_digest
from .folder_acl_live_workflow import _relations
from .folder_http_transport import FolderTransportConfig, FortiPamFolderHttpTransport, _isolated_child_body
from .folder_namespace_candidate import NamespaceObserver
from .folder_namespace_ssh_reader import FolderNamespaceObservation
from .local_user_reset_fixture_preflight import _actor_context
from .local_user_reset_metadata_reader import _validate_value
from .isolated_folder_creation_ownership import IsolatedFolderCreationSnapshot
from .isolated_folder_m4_adapter import InitialRdpPolicyBinding, initial_rdp_policy_child_body
from .policy_assignment_definition import consume_policy_assignment_definition
from .target_api_dependency_reader import _private_http_logs
from .owner_session_metadata import OwnerSessionMetadataTransport
from .secret_metadata_http_transport import (
    MAX_RESPONSE_BYTES, UTILITY_ID_PATH, SecretMetadataHttpTransportConfig,
    FortiPamSecretMetadataHttpTransport, _path_for_url, _record, _response_id, _zeroize_mutable,
    _json_value_end, _redact_json_field_values, _skip_json_space,
)

_UNAVAILABLE = "The isolated Folder transport is unavailable."
_FOLDER_FIELDS = "id|name|folder-type|parent-folder|inherit-policy|inherit-permission|inherit-folder-ztna|secret-policy|ztna-ems-tag|ztna-tags-match-logic|user-permission|group-permission"


class IsolatedFolderHttpTransport:
    """Parent path is private-bound and re-resolved to its exact id before use."""
    def __init__(self, config: SecretMetadataHttpTransportConfig, *, parent_path: str,
                 child_name: str | None = None, owner_name: str | None = None,
                 owner_credentials: Callable[[], tuple[str, str]] | None = None,
                 owner_client_factory: Callable[..., Any] = httpx.Client,
                 namespace_observer: NamespaceObserver | None = None) -> None:
        if (not isinstance(parent_path, str) or not parent_path or parent_path.startswith("/")
            or any(part in {"", ".", ".."} for part in parent_path.split("/"))):
            raise ValueError(_UNAVAILABLE)
        self._parent_path = parent_path
        self._metadata = FortiPamSecretMetadataHttpTransport(config)
        self._folders = FortiPamFolderHttpTransport(FolderTransportConfig(
            config.base_url, config.bearer_token, config.timeout_seconds, config.ca_file,
            explicitly_enabled=True))
        self._owner_session: OwnerSessionMetadataTransport | None = None
        self._child_name, self._owner_name = child_name, owner_name
        if namespace_observer is not None and (
            not callable(namespace_observer) or child_name is None or owner_name is None or owner_credentials is None
        ):
            raise ValueError(_UNAVAILABLE)
        self._namespace_observer = namespace_observer
        if any(value is not None for value in (child_name, owner_name, owner_credentials)):
            if child_name is None or owner_name is None or owner_credentials is None:
                raise ValueError(_UNAVAILABLE)
            _isolated_child_body(child_name, 1, owner_name)
            self._owner_session = OwnerSessionMetadataTransport(
                config, owner_name=owner_name, credentials=owner_credentials,
                folder_path=parent_path + "/" + child_name,
                secret_name="isolated-folder-readback", target_name="isolated-folder-readback",
                witness=self._metadata, client_factory=owner_client_factory,
            )

    @contextmanager
    def _child_reader(self, name: str) -> Iterator[FortiPamSecretMetadataHttpTransport]:
        """Use the explicitly bound Owner for child reads, never as a fallback."""
        if self._owner_session is None:
            yield self._metadata
            return
        if name != self._child_name:
            raise ValueError(_UNAVAILABLE)
        raw = bytearray()
        try:
            with self._owner_session.authenticated():
                with self._owner_session._client.stream("GET", "/api/v2/monitor/web-ui/state") as response:
                    if response.status_code != 200 or "json" not in response.headers.get("content-type", "").lower():
                        raise ValueError
                    for chunk in response.iter_bytes():
                        if len(raw) + len(chunk) > MAX_RESPONSE_BYTES:
                            raise ValueError
                        raw.extend(chunk)
                assert self._owner_name is not None
                _actor_context(raw, expected_name=self._owner_name)
                yield self._owner_session
        except Exception:
            raise ValueError(_UNAVAILABLE) from None
        finally:
            _zeroize_mutable(raw)

    def read_product_version_and_build(self) -> tuple[str, int]:
        return self._metadata.read_product_version_and_build()

    def _parent_matches(self, parent_folder_id: int) -> None:
        if type(parent_folder_id) is not int or parent_folder_id <= 0 or self._metadata.resolve_folder_id(self._parent_path) != parent_folder_id:
            raise ValueError(_UNAVAILABLE)

    def _detail(self, folder_id: int, reader: FortiPamSecretMetadataHttpTransport | None = None) -> dict[str, object]:
        if type(folder_id) is not int or folder_id <= 0:
            raise ValueError(_UNAVAILABLE)
        status, payload = (self._metadata if reader is None else reader)._request("GET", f"/api/v2/cmdb/secret/folder/{folder_id}", None,
            query="format=" + quote(_FOLDER_FIELDS, safe=""))
        if isinstance(reader, OwnerSessionMetadataTransport) and (
            not isinstance(payload, dict) or payload.get("version") != "v7.0.0"
            or type(payload.get("build")) is not int or payload["build"] != 29
            or type(payload.get("http_status")) is not int or payload["http_status"] != 200
            or payload.get("http_method") != "GET" or payload.get("path") != "secret"
            or payload.get("name") != "folder" or payload.get("status") not in {"OK", "success"}
            or ("error" in payload and (type(payload["error"]) is not int or payload["error"] != 0))
        ):
            raise ValueError(_UNAVAILABLE)
        record = _record(payload)
        if (status != 200 or record is None or type(record.get("id")) is not int
            or record.get("id") != folder_id or record.get("folder-type") != "public"
            or not set(_FOLDER_FIELDS.split("|")) <= set(record)):
            raise ValueError(_UNAVAILABLE)
        return {key: record[key] for key in _FOLDER_FIELDS.split("|")}

    def read_parent_digest(self, parent_folder_id: int) -> str:
        self._parent_matches(parent_folder_id)
        return canonical_digest(self._detail(parent_folder_id))

    def owner_is_available(self, owner_name: str) -> bool:
        _isolated_child_body("validation", 1, owner_name)
        if self._owner_session is not None and owner_name != self._owner_name:
            raise ValueError(_UNAVAILABLE)
        status, payload = self._metadata._request("GET", "/api/v2/cmdb/system/admin/" + quote(owner_name, safe=""), None,
            query="format=name%7Cstatus%7Cremote-auth%7Cwildcard")
        record = _record(payload)
        return bool(status == 200 and record is not None and record.get("name") == owner_name
            and record.get("status") == "enable" and record.get("remote-auth") == "disable"
            and record.get("wildcard") == "disable")

    def find_child_ids(self, name: str, parent_folder_id: int) -> tuple[int, ...]:
        _isolated_child_body(name, parent_folder_id, "validation")
        self._parent_matches(parent_folder_id)
        if self._observe_namespace(name, parent_folder_id) is True:
            return ()
        # Build-29 utility 404 may mean either denied access or a missing object.
        # Only the independent qualified global namespace can prove absence.
        # Every utility 404 still fails closed, including after a present proof.
        with self._child_reader(name) as reader:
            status, payload = reader._request(
                "GET", UTILITY_ID_PATH + "/" + _path_for_url(self._parent_path + "/" + name),
                None, query="type=folder",
            )
            identifier = _response_id(payload)
            if status != 200 or identifier is None:
                raise ValueError(_UNAVAILABLE)
            record = self._detail(identifier, reader)
            if record.get("name") != name or type(record.get("parent-folder")) is not int or record.get("parent-folder") != parent_folder_id:
                raise ValueError(_UNAVAILABLE)
            return (identifier,)

    def _observe_namespace(self, name: str, parent_folder_id: int) -> bool | None:
        if self._namespace_observer is None:
            return None
        try:
            if name != self._child_name or self._owner_name is None:
                raise ValueError
            observation = self._namespace_observer(name, parent_folder_id, self._owner_name)
            if (not isinstance(observation, FolderNamespaceObservation)
                or type(observation.global_name_absent) is not bool
                or observation.status != ("name_absent" if observation.global_name_absent else "name_present")
                or type(observation.folder_count) is not int or type(observation.positive_witness_count) is not int
                or not 2 <= observation.positive_witness_count <= observation.folder_count
                or not isinstance(observation.namespace_digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", observation.namespace_digest) is None):
                raise ValueError
            return observation.global_name_absent
        except Exception:
            raise ValueError(_UNAVAILABLE) from None

    def create_isolated_child(self, *, name: str, parent_folder_id: int, owner_name: str,
                              empty_inactive_policy: bool = False,
                              before_dispatch: Callable[[], None] | None = None) -> dict[str, object]:
        if type(empty_inactive_policy) is not bool or before_dispatch is not None and not callable(before_dispatch):
            raise ValueError(_UNAVAILABLE)
        if self._owner_session is not None and (name != self._child_name or owner_name != self._owner_name):
            raise ValueError(_UNAVAILABLE)
        self._parent_matches(parent_folder_id)
        if self._observe_namespace(name, parent_folder_id) is False:
            raise ValueError(_UNAVAILABLE)
        if before_dispatch is not None:
            before_dispatch()
        if empty_inactive_policy:
            return dict(self._folders.create_isolated_child(name=name, parent_folder_id=parent_folder_id,
                owner_name=owner_name, empty_inactive_policy=True))
        return dict(self._folders.create_isolated_child(name=name, parent_folder_id=parent_folder_id, owner_name=owner_name))

    def initial_rdp_policy_matches(self, policy: InitialRdpPolicyBinding) -> bool:
        """Fresh complete Policy tokens, pinned build/serial and required controls."""
        raw = bytearray()
        try:
            if type(policy) is not InitialRdpPolicyBinding or self._owner_session is None or self._child_name is None:
                raise ValueError
            policy.__post_init__()
            with self._child_reader(self._child_name):
                session = self._owner_session
                serial = self._creation_owner_role()["serial"]
                if (session._client is None or session._clock() >= session._expires_at
                    or type(serial) is not str or hashlib.sha256(serial.encode("ascii")).hexdigest() != policy.serial_digest):
                    raise ValueError
                route = "/api/v2/cmdb/secret/policy/" + quote(policy.name, safe="") + "?with_meta=true&vdom=root"
                with _private_http_logs(), session._client.stream("GET", route, headers={"Accept": "application/json"}) as response:
                    if response.status_code != 200 or "json" not in response.headers.get("content-type", "").lower():
                        raise ValueError
                    for chunk in response.iter_bytes():
                        if len(raw) + len(chunk) > MAX_RESPONSE_BYTES:
                            raise ValueError
                        raw.extend(chunk)
                observed = consume_policy_assignment_definition(raw, policy_name=policy.name,
                    serial_digest=policy.serial_digest)
                matches = (observed.configuration_digest == policy.configuration_digest
                           and observed.controls[:2] == ("enable", "enable"))
            if not session.logout_verified:
                raise ValueError
            return matches
        except Exception:
            raise ValueError(_UNAVAILABLE) from None
        finally:
            _zeroize_mutable(raw)

    def create_initial_rdp_policy_child(self, *, name: str, parent_folder_id: int, owner_name: str,
            policy: InitialRdpPolicyBinding, before_dispatch: Callable[[], None]) -> dict[str, object]:
        """Separate fixed CREATE grammar; no existing Folder or Policy update."""
        from .folder_http_transport import _mapping_payload
        if (self._owner_session is None or self._namespace_observer is None or name != self._child_name
            or owner_name != self._owner_name or not callable(before_dispatch)):
            raise ValueError(_UNAVAILABLE)
        body = initial_rdp_policy_child_body(name, parent_folder_id, owner_name, policy)
        self._parent_matches(parent_folder_id)
        if self._observe_namespace(name, parent_folder_id) is not True or self.initial_rdp_policy_matches(policy) is not True:
            raise ValueError(_UNAVAILABLE)
        encoded = json.dumps(body, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")
        before_dispatch()
        response = self._folders._request("POST", "/api/v2/cmdb/secret/folder", encoded)
        if (response.status_code != 200 or not isinstance(response.data, Mapping)
            or type(response.data.get("http_status")) is not int or response.data["http_status"] != 200):
            raise ValueError(_UNAVAILABLE)
        payload = _mapping_payload(response)
        serial = payload.get("serial")
        if (payload.get("version") != "v7.0.0" or type(payload.get("build")) is not int or payload["build"] != 29
            or type(serial) is not str or hashlib.sha256(serial.encode("ascii")).hexdigest() != policy.serial_digest
            or payload.get("status") not in {"OK", "success"} or payload.get("path") != "secret"
            or payload.get("name") != "folder" or payload.get("http_method") != "POST"
            or type(payload.get("http_status")) is not int or payload["http_status"] != 200
            or payload.get("vdom") != "root" or "schema_errors" in payload
            or "action" in payload and payload["action"] != ""
            or "error" in payload and (type(payload["error"]) is not int or payload["error"] != 0)):
            raise ValueError(_UNAVAILABLE)
        return {"http_status": payload.get("http_status"), "mkey": payload.get("mkey")}

    def verify_initial_rdp_policy_child(self, folder_id: int, *, name: str, parent_folder_id: int,
            owner_name: str, policy: InitialRdpPolicyBinding) -> bool:
        from .isolated_folder_creation_ownership import validate_creation_snapshot
        from .isolated_folder_m4_adapter import IsolatedFolderBinding
        snapshot = self.read_created_folder_snapshot(folder_id, name=name,
            parent_folder_id=parent_folder_id, owner_name=owner_name)
        if hashlib.sha256(snapshot.serial.encode("ascii")).hexdigest() != policy.serial_digest:
            raise ValueError(_UNAVAILABLE)
        binding = IsolatedFolderBinding(name, parent_folder_id, owner_name,
            self.read_parent_digest(parent_folder_id), initial_rdp_policy=policy)
        validate_creation_snapshot(snapshot, expected_serial=snapshot.serial, folder_id=folder_id, binding=binding)
        return self.initial_rdp_policy_matches(policy)

    def verify_isolated_child(self, folder_id: int, *, name: str, parent_folder_id: int, owner_name: str,
                              empty_inactive_policy: bool = False) -> bool:
        if type(empty_inactive_policy) is not bool:
            raise ValueError(_UNAVAILABLE)
        self._parent_matches(parent_folder_id)
        if self._owner_session is not None:
            if owner_name != self._owner_name:
                raise ValueError(_UNAVAILABLE)
            with self._child_reader(name) as reader:
                if reader._lookup_id("folder", self._parent_path + "/" + name) != folder_id:
                    raise ValueError(_UNAVAILABLE)
                record = self._detail(folder_id, reader)
                owners = _relations(record, principal_key="user-name")
                return bool(record.get("name") == name and type(record.get("parent-folder")) is int
                    and (not empty_inactive_policy or record.get("secret-policy") == "")
                    and record.get("parent-folder") == parent_folder_id
                    and record.get("inherit-policy") == "enable" and record.get("inherit-folder-ztna") == "enable"
                    and record.get("inherit-permission") == "disable" and record.get("group-permission") == []
                    and len(owners) == 1 and owners[0].relation_id > 0 and owners[0].names == (owner_name,)
                    and owners[0].folder_permission == "owner" and owners[0].secret_permission == "owner")
        record = self._detail(folder_id)
        return bool(record.get("name") == name and type(record.get("parent-folder")) is int
            and (not empty_inactive_policy or record.get("secret-policy") == "")
            and record.get("parent-folder") == parent_folder_id
            and record.get("inherit-policy") == "enable" and record.get("inherit-folder-ztna") == "enable"
            and self._folders.verify_owner_only_folder(folder_id, owner_name))

    def read_created_folder_snapshot(self, folder_id: int, *, name: str,
                                    parent_folder_id: int, owner_name: str) -> IsolatedFolderCreationSnapshot:
        """Private fixed baseline observation; this GET cannot establish creation ownership.

        Only the opted-in create workflow may attach this observation to its
        independently verified fresh dispatch. The ordinary path is unchanged.
        """
        try:
            if (self._owner_session is None or name != self._child_name or owner_name != self._owner_name
                or type(folder_id) is not int or not 0 < folder_id <= 2_147_483_647):
                raise ValueError
            self._parent_matches(parent_folder_id)
            session = self._owner_session
            with self._child_reader(name):
                role = self._creation_owner_role()
                if session._lookup_id("folder", self._parent_path + "/" + name) != folder_id:
                    raise ValueError
                payload = self._read_creation_payload(
                    f"/api/v2/cmdb/secret/folder/{folder_id}?format=" + quote(_FOLDER_FIELDS, safe=""),
                    path="secret", table="folder",
                )
                record = _record(payload)
                serial = payload["serial"]
                if (serial != role["serial"] or not isinstance(record, Mapping)
                    or not set(_FOLDER_FIELDS.split("|")) <= set(record)
                    or type(record.get("id")) is not int or record["id"] != folder_id
                    or record.get("name") != name or type(record.get("parent-folder")) is not int
                    or record["parent-folder"] != parent_folder_id):
                    raise ValueError
                if "mkey" in payload and (type(payload["mkey"]) not in {int, str}
                    or payload["mkey"] not in {folder_id, str(folder_id)}):
                    raise ValueError
                projection = deepcopy({key: record[key] for key in _FOLDER_FIELDS.split("|")})
            if not session.logout_verified or type(serial) is not str:
                raise ValueError
            return IsolatedFolderCreationSnapshot(serial, projection)
        except Exception:
            raise ValueError(_UNAVAILABLE) from None

    def read_creation_device_serial(self) -> str:
        """Fresh same-Owner device identity for opted-in pre-dispatch checks."""
        try:
            if self._owner_session is None or self._child_name is None:
                raise ValueError
            session = self._owner_session
            with self._child_reader(self._child_name):
                serial = self._creation_owner_role()["serial"]
            if not session.logout_verified or type(serial) is not str:
                raise ValueError
            return serial
        except Exception:
            raise ValueError(_UNAVAILABLE) from None

    def _creation_owner_role(self) -> dict[str, object]:
        owner_name = self._owner_name
        if owner_name is None:
            raise ValueError
        role = self._read_creation_payload(
            "/api/v2/cmdb/system/admin/" + quote(owner_name, safe="")
            + "?format=name%7Caccprofile%7Cstatus%7Cremote-auth%7Cwildcard",
            path="system", table="admin",
        )
        row = _record(role)
        expected = {"name": owner_name, "accprofile": "super_admin", "status": "enable",
                    "remote-auth": "disable", "wildcard": "disable"}
        if (not isinstance(row, Mapping) or not set(expected) <= set(row)
            or not set(row) <= set(expected) | {"q_origin_key"}
            or any(type(row.get(key)) is not type(value) or row.get(key) != value
                   for key, value in expected.items())
            or "q_origin_key" in row and row["q_origin_key"] != owner_name
            or "mkey" in role and (type(role["mkey"]) is not str or role["mkey"] != owner_name)):
            raise ValueError
        return role

    def _read_creation_payload(self, route: str, *, path: str, table: str) -> dict[str, object]:
        """Internal compiled role/detail requests with strict recursive JSON checks."""
        raw = bytearray()
        try:
            session = self._owner_session
            if session is None or session._client is None or session._clock() >= session._expires_at:
                raise ValueError
            with session._client.stream("GET", route, headers={"Accept": "application/json"}) as response:
                if response.status_code != 200 or "json" not in response.headers.get("content-type", "").lower():
                    raise ValueError
                for chunk in response.iter_bytes():
                    if len(raw) + len(chunk) > MAX_RESPONSE_BYTES:
                        raise ValueError
                    raw.extend(chunk)
            _redact_json_field_values(raw)
            start = _skip_json_space(raw, 0)
            end = _json_value_end(raw, start)
            if _skip_json_space(raw, end) != len(raw):
                raise ValueError
            _validate_value(raw, start, end, depth=0)
            payload = json.loads(raw)
            expected = {"version": "v7.0.0", "build": 29, "http_method": "GET", "http_status": 200,
                        "vdom": "root", "path": path, "name": table}
            if (type(payload) is not dict
                or any(type(payload.get(key)) is not type(value) or payload.get(key) != value
                       for key, value in expected.items())
                or type(payload.get("serial")) is not str
                or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", payload["serial"]) is None
                or payload.get("status") not in {"OK", "success"}
                or "action" in payload and (type(payload["action"]) is not str or payload["action"] != "")
                or "error" in payload and (type(payload["error"]) is not int or payload["error"] != 0)
                or payload.get("limit_reached", False) is not False
                or any(key in payload for key in ("next_idx", "next_index", "total", "total_count"))
                or any(type(payload[key]) is not int or payload[key] != 1
                       for key in ("size", "matched_count") if key in payload)):
                raise ValueError
            return payload
        finally:
            _zeroize_mutable(raw)
