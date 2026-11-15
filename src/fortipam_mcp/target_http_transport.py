"""API-first transport for one bounded FortiPAM IPv4 SSH Target creation.

The Target action normally writes through the FortiPAM REST API.  This module
contains only the compiled Target detail/default GET, fixed Owner-principal GET,
and collection POST routes; it is not a generic HTTP relay.  SSH remains a
separate diagnostic/fallback adapter.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import stat
import time
from typing import Any, Literal, cast
from urllib.parse import quote, urlsplit

from .classification_tag_assign_contract import (
    ClassificationTagAssignInspection,
    ClassificationTagAssignReadback,
)
from .target_namespace_ssh_reader import TargetNamespaceObservation
from .target_contract import (
    DEFAULT_TEMPLATE,
    WEB_TEMPLATE,
    WEB_TEMPLATE_FIELD_TYPES,
    WebTargetCreateInput,
    WebTargetReadback,
    DOMAIN_TEMPLATE,
    DOMAIN_TEMPLATE_FIELD_TYPES,
    DomainTargetCreateInput,
    DomainTargetReadback,
    TARGET_CLASS,
    WEB_PROXY_STATUS,
    TargetInspection,
    TargetReadback,
    TargetUpdateInspection,
    TargetUpdateReadback,
    TargetWebProxyEnableInspection,
    TargetWebProxyEnableReadback,
)


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_TARGET_API_"
_COLLECTION_PATH = "/api/v2/cmdb/secret/target"
_DEFAULT_PATH = f"{_COLLECTION_PATH}?action=default"
_ADMIN_COLLECTION_PATH = "/api/v2/cmdb/system/admin"
_GROUP_COLLECTION_PATH = "/api/v2/cmdb/user/group"
_CLASSIFICATION_TAG_COLLECTION_PATH = "/api/v2/cmdb/secret/classification-tag"
_SYSTEM_STATUS_PATH = "/api/v2/monitor/system/status"
_WEB_PROXY_STATUS_PATH = "/api/v2/monitor/web-proxy-status"
_MAX_RESPONSE_BYTES = 1_048_576
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_DEFAULT_CREATE_SECRET_GROUP = "everyone"
_DENIED_MESSAGE = "FortiPAM V4 Target API transport is unavailable."
_SUPPORTED_TARGET_PROFILES = frozenset({("1.9.1", 1758), ("7.0.0", 29)})


class TargetHttpTransportConfigurationError(ValueError):
    """Raised when the dedicated Target API configuration is unsafe."""


class TargetHttpTransportError(RuntimeError):
    """Raised for a bounded Target API transport failure."""

    def __init__(
        self,
        message: str = _DENIED_MESSAGE,
        *,
        failure_stage: str | None = None,
        http_status: int | None = None,
        product_error_code: int | None = None,
        product_status: str | None = None,
        product_error_class: str | None = None,
    ) -> None:
        super().__init__(message)
        self.failure_stage = failure_stage
        self.http_status = http_status
        self.product_error_code = product_error_code
        self.product_status = product_status
        self.product_error_class = product_error_class


@dataclass(frozen=True, slots=True)
class TargetHttpTransportConfig:
    """Dedicated HTTPS and bearer-token settings held only in process memory."""

    base_url: str
    bearer_token: str = field(repr=False)
    timeout_seconds: float
    ca_file: str | None
    owner_username: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        parsed = urlsplit(self.base_url)
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise TargetHttpTransportConfigurationError(
                "A dedicated HTTPS API target is required."
            )
        if not self.bearer_token or any(
            ord(character) < 32 or ord(character) == 127
            for character in self.bearer_token
        ):
            raise TargetHttpTransportConfigurationError(
                "A dedicated bearer token is required."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise TargetHttpTransportConfigurationError("The Target API timeout is invalid.")
        if self.owner_username is not None:
            _validate_owner_username(self.owner_username)
        if self.ca_file is not None and not Path(self.ca_file).is_file():
            raise TargetHttpTransportConfigurationError(
                "The configured certificate authority file is unavailable."
            )


def load_target_http_transport_config(
    environment: Mapping[str, str] | None = None,
) -> TargetHttpTransportConfig:
    """Load the independent API-first Target transport configuration."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise TargetHttpTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    base_url = _value(env, "BASE_URL") or _value(env, "HOST")
    token = _value(env, "API_TOKEN")
    timeout_raw = _value(env, "TIMEOUT_SECONDS") or "15"
    ca_file = _value(env, "CA_FILE")
    owner_username = _value(env, "OWNER_USERNAME")
    if base_url is None or token is None:
        raise TargetHttpTransportConfigurationError(
            "Dedicated Target API target and bearer token are required."
        )
    try:
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise TargetHttpTransportConfigurationError("The Target API timeout is invalid.") from exc
    normalized_url = base_url if "://" in base_url else f"https://{base_url}"
    return TargetHttpTransportConfig(
        base_url=normalized_url.rstrip("/"),
        bearer_token=token,
        timeout_seconds=timeout,
        ca_file=ca_file,
        owner_username=owner_username,
    )


class FortiPamTargetHttpTransport:
    """Issue only compiled Target detail GET, create POST, and fixed update PUTs."""

    def __init__(
        self,
        config: TargetHttpTransportConfig,
        *,
        client_factory: Callable[..., Any] | None = None,
        web_target_namespace_observer: Callable[[str], TargetNamespaceObservation] | None = None,
    ) -> None:
        if web_target_namespace_observer is not None and not callable(web_target_namespace_observer):
            raise TargetHttpTransportConfigurationError("The bound Target namespace source is unavailable.")
        self._config = config
        self._client_factory = client_factory
        self._web_target_namespace_observer = web_target_namespace_observer

    def inspect(self, target_name: str) -> TargetInspection:
        """Read one Target existence state without returning its configuration."""

        name = _target_name(target_name)
        product_version, product_build = self._read_product_identity()
        if (product_version, product_build) not in _SUPPORTED_TARGET_PROFILES:
            raise TargetHttpTransportError(_DENIED_MESSAGE)
        status, payload = self._request("GET", self._detail_path(name), None)
        if status == 200 and _record(payload) is not None:
            return TargetInspection(True, product_version, product_build)
        if status != 404:
            raise TargetHttpTransportError(_DENIED_MESSAGE)
        owner_username = _required_owner_username(self._config.owner_username)
        self._require_owner_principal(owner_username)
        self._require_create_secret_group()
        return TargetInspection(False, product_version, product_build)

    def create_and_readback(
        self,
        target_name: str,
        address: str,
        *,
        expected_product_version: str,
        expected_product_build: int,
    ) -> TargetReadback:
        """Create one fixed IPv4 SSH Target and verify through API detail GET."""

        name = _target_name(target_name)
        normalized_address = _ipv4(address)
        owner_username = _required_owner_username(self._config.owner_username)
        product_version, product_build = self._read_product_identity()
        if (
            (product_version, product_build) not in _SUPPORTED_TARGET_PROFILES
            or (product_version, product_build)
            != (expected_product_version, expected_product_build)
        ):
            raise TargetHttpTransportError(_DENIED_MESSAGE)
        default_status, default_payload = self._request("GET", _DEFAULT_PATH, None)
        defaults = _record(default_payload)
        defaults_match = (
            _target_defaults_match_70(default_payload)
            if product_version == "7.0.0"
            else _target_defaults_match(default_payload)
        )
        if default_status != 200 or not defaults_match or defaults is None:
            raise TargetHttpTransportError(_DENIED_MESSAGE)
        self._require_owner_principal(owner_username)
        self._require_create_secret_group()
        if product_version == "7.0.0":
            web_proxy_enabled = self._read_global_web_proxy_enabled(
                expected_product_identity=(product_version, product_build)
            )
            body = _target_create_body_70(
                defaults,
                name=name,
                address=normalized_address,
                owner_username=owner_username,
                web_proxy_enabled=web_proxy_enabled,
            )
        else:
            body = {
                "name": name,
                "class": TARGET_CLASS,
                "template": DEFAULT_TEMPLATE,
                "address": normalized_address,
                "domain": "",
                "url": "",
                "service-addrs": [],
                "dynamic-gateway": "disable",
                "gateway": "",
                "gateway-cn": "",
                "user-naming-attribute": "sAMAccountName",
                "user-base": "",
                "description": "",
                "rdp-min-ssl-version": "default",
                "rdp-load-balancing-info": "",
                "kdc-address": "",
                "ldaps-min-ssl-version": "default",
                "ssms-min-ssl-version": "default",
                "ldaps-port": 636,
                "access": "customized",
                "user-permission": [
                    {
                        "id": 1,
                        "user-name": [{"name": owner_username}],
                        "permission": "owner",
                    }
                ],
                "group-permission": [
                    {
                        "id": 1,
                        "group-name": [{"name": _DEFAULT_CREATE_SECRET_GROUP}],
                        "permission": "create-secret",
                    }
                ],
                "web-proxy-status": WEB_PROXY_STATUS,
                "winrm-https": "disable",
                "sql-server-log-status": "disable",
                "sql-log": {},
                "$originalName": name,
            }
        status, payload = self._request("POST", _COLLECTION_PATH, body)
        if status != 200:
            product_error_code, product_status, product_error_class = (
                _categorical_product_error(payload)
            )
            raise TargetHttpTransportError(
                failure_stage="target_create_post",
                http_status=status,
                product_error_code=product_error_code,
                product_status=product_status,
                product_error_class=product_error_class,
            )
        if not _successful_create_response(payload):
            product_error_code, product_status, product_error_class = (
                _categorical_product_error(payload)
            )
            raise TargetHttpTransportError(
                failure_stage="target_create_acknowledgement",
                http_status=status,
                product_error_code=product_error_code,
                product_status=product_status,
                product_error_class=product_error_class,
            )
        detail_status, detail_payload = self._request("GET", self._detail_path(name), None)
        detail = _record(detail_payload)
        if detail_status != 200 or detail is None:
            return TargetReadback(False, False, False, False, False, False, False)
        return TargetReadback(
            target_exists=detail.get("name") == name,
            class_matches=detail.get("class") == TARGET_CLASS,
            template_matches=detail.get("template") == DEFAULT_TEMPLATE,
            address_matches=detail.get("address") == normalized_address,
            web_proxy_disabled=detail.get("web-proxy-status") == WEB_PROXY_STATUS,
            owner_relation_matches=_owner_relation_matches(detail, owner_username),
            create_secret_group_relation_matches=_permission_relation_matches(
                detail,
                collection="group-permission",
                principal_key="group-name",
                principal_name=_DEFAULT_CREATE_SECRET_GROUP,
                permission="create-secret",
            ),
        )

    def _prepare_web_target_create(
        self, request: WebTargetCreateInput, *, claim_path: Path,
    ) -> dict[str, object]:
        """Qualify one absent Web Target and fixed dependencies without writing."""

        if type(request) is not WebTargetCreateInput:
            raise TargetHttpTransportError(_DENIED_MESSAGE)
        _require_target_claim_available(claim_path)
        if self._read_product_identity() != ("7.0.0", 29):
            raise TargetHttpTransportError(_DENIED_MESSAGE)
        owner = _required_owner_username(self._config.owner_username)
        status, missing = self._request("GET", self._detail_path(request.target_name), None)
        if status != 404 or not _target_native_envelope(missing, "GET", 404):
            raise TargetHttpTransportError(_DENIED_MESSAGE)
        # An actor-visible 404 is not appliance-wide absence. A duplicate POST
        # rejection still consumes this operation and requires reconciliation.
        status, template = self._request(
            "GET", "/api/v2/cmdb/secret/template/Web%20Account?vdom=root", None,
        )
        detail = _record(template)
        fields = detail.get("field", detail.get("fields")) if detail is not None else None
        if (status != 200 or detail is None or detail.get("name") != WEB_TEMPLATE
                or not isinstance(template, Mapping) or template.get("version") != "v7.0.0"
                or type(template.get("build")) is not int or template.get("build") != 29
                or not isinstance(fields, list) or len(fields) != 3
                or any(not isinstance(item, Mapping) or not isinstance(item.get("name"), str) for item in fields)
                or {item.get("name"): item.get("type") for item in fields} != dict(WEB_TEMPLATE_FIELD_TYPES)):
            raise TargetHttpTransportError(_DENIED_MESSAGE)
        status, defaults_payload = self._request("GET", _DEFAULT_PATH, None)
        defaults = _record(defaults_payload)
        if (status != 200 or defaults is None or not _target_defaults_match_70(defaults_payload)
                or not isinstance(defaults_payload, Mapping)
                or defaults_payload.get("version") != "v7.0.0"
                or type(defaults_payload.get("build")) is not int or defaults_payload.get("build") != 29
                or defaults.get("address") != "" or defaults.get("ssh-hostkey-verification") != "disable"):
            raise TargetHttpTransportError(_DENIED_MESSAGE)
        self._require_owner_principal(owner)
        self._require_create_secret_group()
        self._require_web_target_namespace(request, absent=True)
        return _web_target_body_70(defaults, request, owner)

    def _require_web_target_namespace(self, request: WebTargetCreateInput, *, absent: bool) -> None:
        """Requalify only the explicitly injected fixed-name candidate source."""
        if self._web_target_namespace_observer is None:
            return
        try:
            observed = self._web_target_namespace_observer(request.target_name)
            if (type(observed) is not TargetNamespaceObservation
                    or not observed.matches_candidate(request.target_name)
                    or type(observed.global_name_absent) is not bool
                    or observed.global_name_absent is not absent
                    or observed.status != ("name_absent" if absent else "name_present")
                    or type(observed.target_count) is not int or not 2 <= observed.target_count <= 128
                    or type(observed.positive_witness_count) is not int
                    or not 2 <= observed.positive_witness_count <= observed.target_count
                    or type(observed.namespace_digest) is not str
                    or re.fullmatch(r"[0-9a-f]{64}", observed.namespace_digest) is None):
                raise ValueError
        except Exception:
            raise TargetHttpTransportError(failure_stage="web_target_namespace_unqualified") from None

    def inspect_web_target_create(
        self, request: WebTargetCreateInput, *, claim_path: Path,
    ) -> str:
        """Return only the qualified request digest for a bound C/P/E preview."""

        return _mapping_digest(self._prepare_web_target_create(request, claim_path=claim_path))

    def create_web_target_and_readback(
        self, request: WebTargetCreateInput, *, claim_path: Path, expected_state_digest: str, expires_at: int,
    ) -> WebTargetReadback:
        """One private build-29 Target create; no Secret or interface mutation."""

        if type(expires_at) is not int or time.time() >= expires_at:
            raise TargetHttpTransportError(_DENIED_MESSAGE)
        expected = _sha256_digest(expected_state_digest)
        body = self._prepare_web_target_create(request, claim_path=claim_path)
        if not hmac.compare_digest(_mapping_digest(body), expected):
            raise TargetHttpTransportError(failure_stage="web_target_prewrite_drift")
        if time.time() >= expires_at:
            raise TargetHttpTransportError(failure_stage="web_target_preview_expired")
        _reserve_target_create_claim(claim_path, body, profile="web")
        if time.time() >= expires_at:
            raise TargetHttpTransportError(failure_stage="web_target_preview_expired")
        status, acknowledgement = self._request("POST", _COLLECTION_PATH, body)
        if status != 200 or not _target_native_envelope(acknowledgement, "POST", 200):
            code, product_status, classification = _categorical_product_error(acknowledgement)
            raise TargetHttpTransportError(
                failure_stage="web_target_create_post" if status != 200 else "web_target_create_acknowledgement",
                http_status=status, product_error_code=code,
                product_status=product_status, product_error_class=classification,
            )
        return self._read_web_target_body(request, body, require_namespace=True)

    def reconcile_web_target_create(
        self, request: WebTargetCreateInput, *, claim_path: Path,
    ) -> WebTargetReadback:
        """Read one retained Target against its consumed request; never dispatch."""

        if type(request) is not WebTargetCreateInput:
            raise TargetHttpTransportError(_DENIED_MESSAGE)
        claim_digest = _read_web_target_claim_digest(claim_path)
        if self._read_product_identity() != ("7.0.0", 29):
            raise TargetHttpTransportError(_DENIED_MESSAGE)
        status, payload = self._request("GET", _DEFAULT_PATH, None)
        defaults = _record(payload)
        if (status != 200 or defaults is None or not _target_defaults_match_70(payload)
                or not isinstance(payload, Mapping) or payload.get("version") != "v7.0.0"
                or type(payload.get("build")) is not int or payload.get("build") != 29):
            raise TargetHttpTransportError(_DENIED_MESSAGE)
        body = _web_target_body_70(defaults, request, _required_owner_username(self._config.owner_username))
        if not hmac.compare_digest(_mapping_digest(body), claim_digest):
            raise TargetHttpTransportError(_DENIED_MESSAGE)
        result = self._read_web_target_body(request, body)
        if not hmac.compare_digest(_read_web_target_claim_digest(claim_path), claim_digest):
            raise TargetHttpTransportError(_DENIED_MESSAGE)
        return result

    def _read_web_target_body(
        self, request: WebTargetCreateInput, body: Mapping[str, object], *, require_namespace: bool = False,
    ) -> WebTargetReadback:
        """Shared fixed detail proof for immediate and independent readback."""

        status, payload = self._request("GET", self._detail_path(request.target_name), None)
        detail = _record(payload)
        if status != 200 or detail is None or not _target_native_envelope(payload, "GET", 200):
            return WebTargetReadback(False, False, False, False)
        if require_namespace:
            self._require_web_target_namespace(request, absent=False)
        # Preserve submitted settings and exact ACLs. Generated identity and
        # inactive SQL subsettings are not part of this relation proof.
        ignored = {"name", "url", "user-permission", "group-permission", "$originalName", "sql-log"}
        return WebTargetReadback(
            target_verified=detail.get("name") == request.target_name and detail.get("template") == WEB_TEMPLATE,
            url_matches=detail.get("url") == request.web_url,
            settings_match=all(detail.get(key) == value for key, value in body.items() if key not in ignored),
            permissions_match=_web_target_acl_matches(detail.get("user-permission"), body["user-permission"])
                and _web_target_acl_matches(detail.get("group-permission"), body["group-permission"]),
        )

    def _prepare_domain_target_create(
        self, request: DomainTargetCreateInput, *, claim_path: Path,
    ) -> tuple[dict[str, object], str]:
        """Read the exact domain binding and defaults without consuming authority."""

        if type(request) is not DomainTargetCreateInput:
            raise TargetHttpTransportError(_DENIED_MESSAGE)
        _require_target_claim_available(claim_path)
        if self._read_product_identity() != ("7.0.0", 29):
            raise TargetHttpTransportError(_DENIED_MESSAGE)
        owner = _required_owner_username(self._config.owner_username)
        status, absent = self._request("GET", self._detail_path(request.target_name), None)
        if status != 404 or not _target_native_envelope(absent, "GET", 404):
            raise TargetHttpTransportError(_DENIED_MESSAGE)
        status, collection = self._request("GET", _COLLECTION_PATH + "?count=200&start=0&vdom=root", None)
        rows = collection.get("results") if isinstance(collection, Mapping) else None
        if (status != 200 or not isinstance(collection, Mapping)
                or not _target_native_envelope(collection, "GET", 200, collection=True)
                or not isinstance(rows, list) or len(rows) >= 200
                or type(collection.get("matched_count")) is not int
                or collection["matched_count"] != len(rows)
                or any(not isinstance(row, Mapping) or not isinstance(row.get("address"), str)
                       or row.get("address") == request.dc_ipv4_address for row in rows)):
            raise TargetHttpTransportError(_DENIED_MESSAGE)
        status, template = self._request("GET", "/api/v2/cmdb/secret/template/" + quote(DOMAIN_TEMPLATE, safe="") + "?vdom=root", None)
        detail = _record(template)
        fields = detail.get("field", detail.get("fields")) if detail is not None else None
        if (status != 200 or detail is None or detail.get("name") != DOMAIN_TEMPLATE
                or not isinstance(template, Mapping) or template.get("version") != "v7.0.0"
                or type(template.get("build")) is not int or template.get("build") != 29
                or not isinstance(fields, list) or len(fields) != 4
                or any(not isinstance(item, Mapping) or not isinstance(item.get("name"), str) for item in fields)
                or {item.get("name"): item.get("type") for item in fields} != dict(DOMAIN_TEMPLATE_FIELD_TYPES)):
            raise TargetHttpTransportError(_DENIED_MESSAGE)
        status, defaults_payload = self._request("GET", _DEFAULT_PATH, None)
        defaults = _record(defaults_payload)
        if status != 200 or defaults is None or not _target_defaults_match_70(defaults_payload):
            raise TargetHttpTransportError(_DENIED_MESSAGE)
        self._require_owner_principal(owner)
        self._require_create_secret_group()
        body = _target_create_body_70(defaults, name=request.target_name,
            address=request.dc_ipv4_address, owner_username=owner,
            web_proxy_enabled=self._read_global_web_proxy_enabled(expected_product_identity=("7.0.0", 29)))
        body.update({"template": DOMAIN_TEMPLATE, "domain": request.domain_dns_root})
        if (body.get("ldaps-port") != 636 or body.get("user-naming-attribute") != "sAMAccountName"
                or body.get("user-base") != "" or body.get("web-proxy-status") != "disable"
                or body.get("sql-server-log-status") != "disable"
                or body.get("ssh-hostkey-verification") != "disable"
                or body.get("winrm-https") != "disable"):
            raise TargetHttpTransportError(_DENIED_MESSAGE)
        # The native build-29 form clears disabled SQL settings; TargetCmdb
        # omits the Web Proxy object when its per-Target switch is disabled.
        # Keep this unaccepted Domain profile separate from accepted Unix bodies.
        body["sql-log"] = {}
        body.pop("web-proxy", None)
        return body, owner

    def create_domain_target_and_readback(
        self, request: DomainTargetCreateInput, *, claim_path: Path,
    ) -> DomainTargetReadback:
        """One privately bound build-29 DC Target; no source, Secret or scan write."""

        body, owner = self._prepare_domain_target_create(request, claim_path=claim_path)
        _reserve_target_create_claim(claim_path, body)
        status, acknowledgement = self._request("POST", _COLLECTION_PATH, body)
        if status != 200 or not _target_native_envelope(acknowledgement, "POST", 200):
            code, product_status, classification = _categorical_product_error(acknowledgement)
            raise TargetHttpTransportError(
                failure_stage="domain_target_create_post" if status != 200 else "domain_target_create_acknowledgement",
                http_status=status,
                product_error_code=code,
                product_status=product_status,
                product_error_class=classification,
            )
        status, payload = self._request("GET", self._detail_path(request.target_name), None)
        detail = _record(payload)
        if status != 200 or detail is None or not _target_native_envelope(payload, "GET", 200):
            return DomainTargetReadback(False, False, False, False, False)
        return DomainTargetReadback(
            target_verified=detail.get("name") == request.target_name and detail.get("address") == request.dc_ipv4_address
                and detail.get("template") == DOMAIN_TEMPLATE and detail.get("class") == TARGET_CLASS
                and detail.get("web-proxy-status") == "disable" and detail.get("access") == "customized"
                and detail.get("sql-server-log-status") == "disable"
                and detail.get("ssh-hostkey-verification") == "disable"
                and detail.get("winrm-https") == "disable" and detail.get("hostkey") == [],
            domain_matches=detail.get("domain") == request.domain_dns_root,
            ldaps_configuration_matches=detail.get("ldaps-port") == 636 and detail.get("user-naming-attribute") == "sAMAccountName"
                and detail.get("user-base") == "",
            owner_relation_matches=_owner_relation_matches(detail, owner),
            create_secret_group_relation_matches=_permission_relation_matches(detail, collection="group-permission",
                principal_key="group-name", principal_name=_DEFAULT_CREATE_SECRET_GROUP, permission="create-secret"),
        )

    def inspect_description_update(
        self,
        target_name: str,
        description: str,
    ) -> TargetUpdateInspection:
        """Read one Target's description state without returning its value."""

        name = _target_name(target_name)
        desired_description = _description(description)
        status, payload = self._request("GET", self._detail_path(name), None)
        if status == 404:
            return TargetUpdateInspection(False, False, _update_state_digest(name, None))
        detail = _record(payload)
        if status != 200 or detail is None:
            raise TargetHttpTransportError(_DENIED_MESSAGE)
        current_description = _detail_description(detail)
        return TargetUpdateInspection(
            exists=True,
            description_matches=current_description == desired_description,
            state_digest=_update_state_digest(name, current_description),
        )

    def update_description_and_readback(
        self,
        target_name: str,
        description: str,
    ) -> TargetUpdateReadback:
        """Update only Target description through REST and verify it by detail GET."""

        name = _target_name(target_name)
        desired_description = _description(description)
        status, payload = self._request(
            "PUT",
            self._detail_path(name),
            {"description": desired_description},
        )
        if status != 200 or not _successful_create_response(payload):
            raise TargetHttpTransportError(_DENIED_MESSAGE)
        detail_status, detail_payload = self._request("GET", self._detail_path(name), None)
        detail = _record(detail_payload)
        if detail_status != 200 or detail is None:
            return TargetUpdateReadback(False, False)
        return TargetUpdateReadback(
            target_exists=detail.get("name") == name,
            description_matches=_detail_description(detail) == desired_description,
        )

    def inspect_web_proxy_enable(
        self,
        target_name: str,
    ) -> TargetWebProxyEnableInspection:
        """Read one Target Web Proxy state without returning Target details."""

        name = _target_name(target_name)
        status, payload = self._request("GET", self._detail_path(name), None)
        if status == 404:
            return TargetWebProxyEnableInspection(
                False,
                False,
                _web_proxy_state_digest(name, None),
            )
        detail = _record(payload)
        if status != 200 or detail is None:
            raise TargetHttpTransportError(_DENIED_MESSAGE)
        web_proxy_status = _detail_web_proxy_status(detail)
        return TargetWebProxyEnableInspection(
            exists=True,
            web_proxy_disabled=web_proxy_status == "disable",
            state_digest=_web_proxy_state_digest(name, web_proxy_status),
        )

    def enable_web_proxy_and_readback(
        self,
        target_name: str,
    ) -> TargetWebProxyEnableReadback:
        """Enable only the compiled Target Web Proxy field and read it back."""

        name = _target_name(target_name)
        status, payload = self._request(
            "PUT",
            self._detail_path(name),
            {"web-proxy-status": "enable"},
        )
        if status != 200 or not _successful_create_response(payload):
            raise TargetHttpTransportError(_DENIED_MESSAGE)
        detail_status, detail_payload = self._request("GET", self._detail_path(name), None)
        detail = _record(detail_payload)
        if detail_status != 200 or detail is None:
            return TargetWebProxyEnableReadback(False, False)
        try:
            web_proxy_enabled = _detail_web_proxy_status(detail) == "enable"
        except TargetHttpTransportError:
            return TargetWebProxyEnableReadback(False, False)
        return TargetWebProxyEnableReadback(
            target_exists=detail.get("name") == name,
            web_proxy_enabled=web_proxy_enabled,
        )

    def inspect_classification_tag_assignment(
        self,
        target_name: str,
        classification_tag_name: str,
    ) -> ClassificationTagAssignInspection:
        """Read one exact Target/Tag assignment baseline without returning payloads."""

        name = _target_name(target_name)
        tag_name = _target_name(classification_tag_name)
        target_status, target_payload = self._request(
            "GET", self._detail_path(name), None
        )
        tag_status, tag_payload = self._request(
            "GET", self._classification_tag_detail_path(tag_name), None
        )
        target_detail = _record(target_payload) if target_status == 200 else None
        tag_detail = _record(tag_payload) if tag_status == 200 else None
        if target_status not in {200, 404} or tag_status not in {200, 404}:
            raise TargetHttpTransportError(_DENIED_MESSAGE)
        if target_status == 200 and (
            target_detail is None or target_detail.get("name") != name
        ):
            raise TargetHttpTransportError(_DENIED_MESSAGE)
        if tag_status == 200 and (tag_detail is None or tag_detail.get("name") != tag_name):
            raise TargetHttpTransportError(_DENIED_MESSAGE)

        target_exists = target_detail is not None
        tag_exists = tag_detail is not None
        current_class_is_other = (
            target_detail is not None
            and _classification_value(target_detail) == TARGET_CLASS
        )
        current_class_matches_tag = (
            target_detail is not None
            and _classification_value(target_detail) == tag_name
        )
        target_digest = _mapping_digest_without_key(target_detail, "class")
        tag_digest = _mapping_digest(tag_detail)
        state_digest = _classification_assignment_state_digest(
            name,
            tag_name,
            target_exists=target_exists,
            tag_exists=tag_exists,
            current_class=(
                _classification_value(target_detail) if target_detail is not None else None
            ),
            target_non_class_state_digest=target_digest,
            classification_tag_state_digest=tag_digest,
        )
        return ClassificationTagAssignInspection(
            target_exists=target_exists,
            classification_tag_exists=tag_exists,
            current_class_is_other=current_class_is_other,
            target_non_class_state_digest=target_digest,
            classification_tag_state_digest=tag_digest,
            state_digest=state_digest,
            current_class_matches_tag=current_class_matches_tag,
        )

    def assign_classification_tag_and_readback(
        self,
        target_name: str,
        classification_tag_name: str,
        *,
        target_non_class_state_digest: str,
        classification_tag_state_digest: str,
    ) -> ClassificationTagAssignReadback:
        """PUT only Target ``class`` and verify Target/Tag preservation by detail GET."""

        name = _target_name(target_name)
        tag_name = _target_name(classification_tag_name)
        expected_target_digest = _sha256_digest(target_non_class_state_digest)
        expected_tag_digest = _sha256_digest(classification_tag_state_digest)
        status, payload = self._request(
            "PUT",
            self._detail_path(name),
            {"class": tag_name},
        )
        if status != 200 or not _successful_create_response(payload):
            raise TargetHttpTransportError(_DENIED_MESSAGE)

        target_status, target_payload = self._request(
            "GET", self._detail_path(name), None
        )
        tag_status, tag_payload = self._request(
            "GET", self._classification_tag_detail_path(tag_name), None
        )
        target_detail = _record(target_payload) if target_status == 200 else None
        tag_detail = _record(tag_payload) if tag_status == 200 else None
        target_exists = target_detail is not None and target_detail.get("name") == name
        tag_exists = tag_detail is not None and tag_detail.get("name") == tag_name
        return ClassificationTagAssignReadback(
            target_exists=target_exists,
            classification_tag_exists=tag_exists,
            target_class_matches=(
                target_detail is not None
                and target_exists
                and _classification_value(target_detail) == tag_name
            ),
            target_non_class_state_preserved=(
                target_exists
                and hmac.compare_digest(
                    _mapping_digest_without_key(target_detail, "class"),
                    expected_target_digest,
                )
            ),
            classification_tag_state_preserved=(
                tag_exists
                and hmac.compare_digest(_mapping_digest(tag_detail), expected_tag_digest)
            ),
        )

    def restore_default_classification_and_readback(
        self,
        target_name: str,
        classification_tag_name: str,
        *,
        target_non_class_state_digest: str,
        classification_tag_state_digest: str,
    ) -> ClassificationTagAssignReadback:
        """Restore only Target ``class=Other`` and prove Target/Tag preservation."""

        name = _target_name(target_name)
        tag_name = _target_name(classification_tag_name)
        expected_target_digest = _sha256_digest(target_non_class_state_digest)
        expected_tag_digest = _sha256_digest(classification_tag_state_digest)
        status, payload = self._request(
            "PUT",
            self._detail_path(name),
            {"class": TARGET_CLASS},
        )
        if status != 200 or not _successful_create_response(payload):
            raise TargetHttpTransportError(_DENIED_MESSAGE)

        target_status, target_payload = self._request(
            "GET", self._detail_path(name), None
        )
        tag_status, tag_payload = self._request(
            "GET", self._classification_tag_detail_path(tag_name), None
        )
        target_detail = _record(target_payload) if target_status == 200 else None
        tag_detail = _record(tag_payload) if tag_status == 200 else None
        target_exists = target_detail is not None and target_detail.get("name") == name
        tag_exists = tag_detail is not None and tag_detail.get("name") == tag_name
        return ClassificationTagAssignReadback(
            target_exists=target_exists,
            classification_tag_exists=tag_exists,
            target_class_matches=(
                target_detail is not None
                and target_exists
                and _classification_value(target_detail) == TARGET_CLASS
            ),
            target_non_class_state_preserved=(
                target_exists
                and hmac.compare_digest(
                    _mapping_digest_without_key(target_detail, "class"),
                    expected_target_digest,
                )
            ),
            classification_tag_state_preserved=(
                tag_exists
                and hmac.compare_digest(_mapping_digest(tag_detail), expected_tag_digest)
            ),
        )

    def _request(
        self,
        method: Literal["GET", "POST", "PUT"],
        path: str,
        body: Mapping[str, object] | None,
    ) -> tuple[int, object | None]:
        try:
            import httpx

            factory = self._client_factory or httpx.Client
            with factory(
                verify=_ssl_context(self._config),
                timeout=self._config.timeout_seconds,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                response = client.request(
                    method,
                    f"{self._config.base_url}{path}",
                    headers={
                        "Accept": "application/json",
                        "Authorization": f"Bearer {self._config.bearer_token}",
                    },
                    json=body,
                )
        except Exception as exc:
            raise TargetHttpTransportError(failure_stage="http_request") from exc
        content_type = response.headers.get("content-type", "")
        if "json" not in content_type.lower():
            raise TargetHttpTransportError(
                failure_stage="http_response_content_type", http_status=int(response.status_code)
            )
        if len(response.content) > _MAX_RESPONSE_BYTES:
            raise TargetHttpTransportError(
                failure_stage="http_response_size", http_status=int(response.status_code)
            )
        try:
            return int(response.status_code), json.loads(response.content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TargetHttpTransportError(
                failure_stage="http_response_json", http_status=int(response.status_code)
            ) from exc

    @staticmethod
    def _detail_path(target_name: str) -> str:
        return f"{_COLLECTION_PATH}/{quote(target_name, safe='')}"

    def _require_owner_principal(self, owner_username: str) -> None:
        status, payload = self._request(
            "GET",
            f"{_ADMIN_COLLECTION_PATH}/{quote(owner_username, safe='')}",
            None,
        )
        record = _record(payload)
        if status != 200 or record is None or record.get("name") != owner_username:
            raise TargetHttpTransportError(_DENIED_MESSAGE)

    def _read_product_identity(self) -> tuple[str, int]:
        status, payload = self._request("GET", _SYSTEM_STATUS_PATH, None)
        if status != 200 or not isinstance(payload, Mapping):
            raise TargetHttpTransportError(_DENIED_MESSAGE)
        version, build = payload.get("version"), payload.get("build")
        if (
            not isinstance(version, str)
            or re.fullmatch(r"v?[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", version) is None
            or type(build) is not int
            or not 0 <= build <= 999999
        ):
            raise TargetHttpTransportError(_DENIED_MESSAGE)
        return version.removeprefix("v"), build

    def _read_global_web_proxy_enabled(
        self,
        *,
        expected_product_identity: tuple[str, int],
    ) -> bool:
        status, payload = self._request("GET", _WEB_PROXY_STATUS_PATH, None)
        if status != 200 or not isinstance(payload, Mapping):
            raise TargetHttpTransportError(_DENIED_MESSAGE)
        results = payload.get("results")
        if results is None:
            response_version = payload.get("version")
            response_identity = (
                (response_version.removeprefix("v"), payload.get("build"))
                if isinstance(response_version, str)
                else None
            )
            if (
                payload.get("status") == "error"
                or response_identity != expected_product_identity
            ):
                raise TargetHttpTransportError(_DENIED_MESSAGE)
            # The retained frontend reads results["web-proxy"]. A same-version
            # status-shaped payload therefore parses to undefined/falsy there.
            return False
        if not isinstance(results, Mapping) or type(results.get("web-proxy")) is not bool:
            raise TargetHttpTransportError(_DENIED_MESSAGE)
        return cast(bool, results["web-proxy"])

    def _require_create_secret_group(self) -> None:
        status, payload = self._request(
            "GET",
            f"{_GROUP_COLLECTION_PATH}/{quote(_DEFAULT_CREATE_SECRET_GROUP, safe='')}",
            None,
        )
        record = _record(payload)
        if (
            status != 200
            or record is None
            or record.get("name") != _DEFAULT_CREATE_SECRET_GROUP
        ):
            raise TargetHttpTransportError(_DENIED_MESSAGE)

    @staticmethod
    def _classification_tag_detail_path(classification_tag_name: str) -> str:
        return (
            f"{_CLASSIFICATION_TAG_COLLECTION_PATH}/"
            f"{quote(classification_tag_name, safe='')}"
        )


def _ssl_context(config: TargetHttpTransportConfig) -> ssl.SSLContext:
    if config.ca_file is not None:
        return ssl.create_default_context(cafile=config.ca_file)
    try:
        import truststore
    except ImportError as exc:  # pragma: no cover - deployment dependency guard.
        raise TargetHttpTransportError(_DENIED_MESSAGE) from exc
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


def _value(environment: Mapping[str, str], suffix: str) -> str | None:
    value = environment.get(f"{ENV_PREFIX}{suffix}")
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _validate_owner_username(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 255
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise TargetHttpTransportConfigurationError(
            "A dedicated Target Owner identity is required."
        )
    return value


def _required_owner_username(value: str | None) -> str:
    if value is None:
        raise TargetHttpTransportConfigurationError(
            "A dedicated Target Owner identity is required."
        )
    return _validate_owner_username(value)


def _target_name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise TargetHttpTransportError(_DENIED_MESSAGE)
    return value


def _ipv4(value: str) -> str:
    if not isinstance(value, str):
        raise TargetHttpTransportError(_DENIED_MESSAGE)
    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError as exc:
        raise TargetHttpTransportError(_DENIED_MESSAGE) from exc


def _description(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 255
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise TargetHttpTransportError(_DENIED_MESSAGE)
    return value


def _record(payload: object) -> Mapping[str, object] | None:
    if not isinstance(payload, Mapping):
        return None
    result = payload.get("results", payload.get("result"))
    if isinstance(result, Mapping):
        return result
    if isinstance(result, list) and len(result) == 1 and isinstance(result[0], Mapping):
        return result[0]
    return None


def _owner_relation_matches(detail: Mapping[str, object], owner_username: str) -> bool:
    return _permission_relation_matches(
        detail,
        collection="user-permission",
        principal_key="user-name",
        principal_name=owner_username,
        permission="owner",
    )


def _permission_relation_matches(
    detail: Mapping[str, object],
    *,
    collection: str,
    principal_key: str,
    principal_name: str,
    permission: str,
) -> bool:
    relations = detail.get(collection)
    if not isinstance(relations, list):
        return False
    for relation in relations:
        if not isinstance(relation, Mapping) or relation.get("permission") != permission:
            continue
        principals = relation.get(principal_key)
        if not isinstance(principals, list):
            continue
        if any(
            isinstance(principal, Mapping) and principal.get("name") == principal_name
            for principal in principals
        ):
            return True
    return False


def _target_defaults_match(payload: object) -> bool:
    detail = _record(payload)
    if detail is None:
        return False
    expected = {
        "domain": "",
        "url": "",
        "service-addrs": [],
        "dynamic-gateway": "disable",
        "gateway": "",
        "gateway-cn": "",
        "user-naming-attribute": "sAMAccountName",
        "user-base": "",
        "description": "",
        "rdp-min-ssl-version": "default",
        "rdp-load-balancing-info": "",
        "kdc-address": "",
        "ldaps-min-ssl-version": "default",
        "ssms-min-ssl-version": "default",
        "ldaps-port": 636,
        "access": "everyone",
        "user-permission": [],
        "group-permission": [],
        "web-proxy-status": "disable",
        "winrm-https": "disable",
        "sql-server-log-status": "disable",
    }
    if any(detail.get(key) != value for key, value in expected.items()):
        return False
    web_proxy = detail.get("web-proxy")
    sql_log = detail.get("sql-log")
    return (
        isinstance(web_proxy, Mapping)
        and web_proxy.get("cred-replacement") == "disable"
        and web_proxy.get("domain-list") == []
        and isinstance(sql_log, Mapping)
        and sql_log.get("log-all") == "disable"
        and sql_log.get("max-log-entry-sz") == 16
        and sql_log.get("monitor-db") == []
    )


_TARGET_DEFAULT_KEYS_70 = frozenset(
    {
        "access", "address", "ca", "class", "creation-time", "description", "domain", "dynamic-gateway",
        "gateway", "gateway-cn", "group-permission", "hostkey", "id", "kdc-address",
        "ldaps-min-ssl-version", "ldaps-port", "name", "rdp-load-balancing-info",
        "rdp-min-ssl-version", "service-addrs", "sql-log", "sql-server-log-status",
        "ssh-hostkey-change-action", "ssh-hostkey-import-method",
        "ssh-hostkey-new-algorithm-action", "ssh-hostkey-verification", "ssms-min-ssl-version",
        "template", "url", "user-base", "user-naming-attribute", "user-permission",
        "uuid", "web-proxy", "web-proxy-status", "winrm-https",
    }
)
_TARGET_UNPARSE_FIELDS_70 = (
    "class", "template", "address", "domain", "url", "service-addrs",
    "dynamic-gateway", "gateway", "gateway-cn", "user-naming-attribute", "user-base",
    "description", "rdp-min-ssl-version", "rdp-load-balancing-info", "kdc-address",
    "ldaps-min-ssl-version", "ssms-min-ssl-version", "ldaps-port", "ca", "access",
    "web-proxy-status", "winrm-https", "sql-server-log-status", "ssh-hostkey-verification",
    "ssh-hostkey-change-action", "ssh-hostkey-import-method", "ssh-hostkey-new-algorithm-action",
)


def _target_defaults_match_70(payload: object) -> bool:
    detail = _record(payload)
    if detail is None or set(detail) != _TARGET_DEFAULT_KEYS_70:
        return False
    if type(detail.get("id")) is not int or detail.get("uuid") != "00000000-0000-0000-0000-000000000000":
        return False
    if not _target_defaults_match({"results": detail}):
        return False
    web_proxy = detail.get("web-proxy")
    sql_log = detail.get("sql-log")
    return (
        isinstance(web_proxy, Mapping)
        and set(web_proxy) == {"auth-scheme", "auth-url", "cred-replacement", "domain-list", "domain-list-access-type", "password-key", "vendor"}
        and isinstance(sql_log, Mapping)
        and set(sql_log) == {"log-all", "log-rpc-parameters", "max-log-entry-sz", "monitor-db"}
        and detail.get("hostkey") == []
        and detail.get("ca") is not None
        and all(isinstance(detail.get(key), str) for key in (
            "ssh-hostkey-change-action", "ssh-hostkey-import-method",
            "ssh-hostkey-new-algorithm-action", "ssh-hostkey-verification",
        ))
    )


def _target_create_body_70(
    defaults: Mapping[str, object],
    *,
    name: str,
    address: str,
    owner_username: str,
    web_proxy_enabled: bool,
) -> dict[str, object]:
    body = {key: defaults[key] for key in _TARGET_UNPARSE_FIELDS_70 if key in defaults}
    body.update(
        {
            "name": name,
            "class": TARGET_CLASS,
            "template": DEFAULT_TEMPLATE,
            "address": address,
            "access": "customized",
            "user-permission": [
                {"id": 1, "user-name": [{"name": owner_username}], "permission": "owner"}
            ],
            "group-permission": [
                {
                    "id": 1,
                    "group-name": [{"name": _DEFAULT_CREATE_SECRET_GROUP}],
                    "permission": "create-secret",
                }
            ],
            "sql-log": {
                "log-all": defaults["sql-log"]["log-all"],  # type: ignore[index]
                "max-log-entry-sz": defaults["sql-log"]["max-log-entry-sz"],  # type: ignore[index]
                "monitor-db": defaults["sql-log"]["monitor-db"],  # type: ignore[index]
            },
            "hostkey": [],
            "$originalName": name,
        }
    )
    if web_proxy_enabled:
        body["web-proxy"] = {"cred-replacement": "disable", "domain-list": []}
    else:
        body["web-proxy"] = defaults["web-proxy"]
    return body


def _detail_description(detail: Mapping[str, object]) -> str:
    value = detail.get("description", "")
    if value is None:
        return ""
    if not isinstance(value, str):
        raise TargetHttpTransportError(_DENIED_MESSAGE)
    return value


def _detail_web_proxy_status(detail: Mapping[str, object]) -> str:
    value = detail.get("web-proxy-status")
    if value not in {"enable", "disable"}:
        raise TargetHttpTransportError(_DENIED_MESSAGE)
    return cast(str, value)


def _update_state_digest(target_name: str, description: str | None) -> str:
    payload = json.dumps(
        {"target_name": target_name, "description": description},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _web_proxy_state_digest(target_name: str, status: str | None) -> str:
    payload = json.dumps(
        {"target_name": target_name, "web_proxy_status": status},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _classification_value(detail: Mapping[str, object]) -> str:
    value = detail.get("class")
    if not isinstance(value, str) or not value:
        raise TargetHttpTransportError(_DENIED_MESSAGE)
    return value


def _mapping_digest(detail: Mapping[str, object] | None) -> str:
    try:
        payload = json.dumps(
            detail,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise TargetHttpTransportError(_DENIED_MESSAGE) from exc
    return hashlib.sha256(payload).hexdigest()


def _mapping_digest_without_key(
    detail: Mapping[str, object] | None,
    excluded_key: str,
) -> str:
    if detail is None:
        return _mapping_digest(None)
    projection = dict(detail)
    projection.pop(excluded_key, None)
    return _mapping_digest(projection)


def _classification_assignment_state_digest(
    target_name: str,
    classification_tag_name: str,
    *,
    target_exists: bool,
    tag_exists: bool,
    current_class: str | None,
    target_non_class_state_digest: str,
    classification_tag_state_digest: str,
) -> str:
    return hashlib.sha256(
        json.dumps(
            {
                "target_name": target_name,
                "classification_tag_name": classification_tag_name,
                "target_exists": target_exists,
                "classification_tag_exists": tag_exists,
                "current_class": current_class,
                "target_non_class_state_digest": target_non_class_state_digest,
                "classification_tag_state_digest": classification_tag_state_digest,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _sha256_digest(value: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise TargetHttpTransportError(_DENIED_MESSAGE)
    return value


def _web_target_body_70(
    defaults: Mapping[str, object], request: WebTargetCreateInput, owner: str,
) -> dict[str, object]:
    body = _target_create_body_70(defaults, name=request.target_name, address="",
                                 owner_username=owner, web_proxy_enabled=False)
    body.update(template=WEB_TEMPLATE, url=request.web_url)
    body.pop("web-proxy", None)
    body["sql-log"] = {}
    return body


def _read_web_target_claim_digest(path: Path) -> str:
    try:
        if not isinstance(path, Path) or not path.is_absolute():
            raise ValueError
        parent = path.parent.lstat()
        if (path.parent.is_symlink() or not stat.S_ISDIR(parent.st_mode)
                or parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) != 0o700):
            raise ValueError
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 4096):
                raise ValueError
            content = os.read(descriptor, 4097)
        finally:
            os.close(descriptor)
        if len(content) > 4096:
            raise ValueError
        claim = json.loads(content)
        if (not isinstance(claim, dict)
                or set(claim) != {"contract", "state", "request_digest", "reserved_at"}
                or claim["contract"] != "fortipam_700_web_target_create_v1"
                or claim["state"] != "post_attempt_reserved"
                or type(claim["reserved_at"]) is not int or claim["reserved_at"] < 0):
            raise ValueError
        return _sha256_digest(claim["request_digest"])
    except Exception:
        raise TargetHttpTransportError(_DENIED_MESSAGE) from None


def _web_target_acl_matches(actual: object, expected: object) -> bool:
    """Match exact ACLs, allowing only native origin keys tied to their own row."""
    if isinstance(expected, list):
        return (isinstance(actual, list) and len(actual) == len(expected)
                and all(_web_target_acl_matches(a, e) for a, e in zip(actual, expected)))
    if isinstance(expected, Mapping):
        if not isinstance(actual, Mapping) or set(actual) - {"q_origin_key"} != set(expected):
            return False
        if "q_origin_key" in actual:
            identity = expected.get("name", expected.get("id"))
            origin = actual["q_origin_key"]
            if type(identity) not in (str, int) or type(origin) not in (str, int) or str(identity) != str(origin):
                return False
        return all(_web_target_acl_matches(actual[key], value) for key, value in expected.items())
    return type(actual) is type(expected) and actual == expected


def _target_native_envelope(payload: object, method: str, status: int, *, collection: bool = False) -> bool:
    if not isinstance(payload, Mapping):
        return False
    return (payload.get("version") == "v7.0.0" and type(payload.get("build")) is int
        and payload.get("build") == 29 and payload.get("http_method") == method
        and payload.get("http_status") == status and payload.get("path") == "secret"
        and payload.get("name") == "target" and payload.get("vdom") == "root"
        and (payload.get("status") == ("Not Found" if status == 404 else "success")
             or collection and method == "GET" and status == 200 and payload.get("status") == "OK")
        and (status != 404 or payload.get("results") in (None, [], {}))
        and (status == 404 or "error" not in payload
             or type(payload["error"]) is int and payload["error"] == 0))


# Retained Domain metadata adapters import this fixed build-29 validator.
_domain_native_envelope = _target_native_envelope


def _require_target_claim_available(path: Path) -> None:
    try:
        if not isinstance(path, Path) or not path.is_absolute():
            raise ValueError
        parent = path.parent.lstat()
        if (path.parent.is_symlink() or not stat.S_ISDIR(parent.st_mode)
                or parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) != 0o700
                or path.exists() or path.is_symlink()):
            raise ValueError
    except Exception:
        raise TargetHttpTransportError(_DENIED_MESSAGE) from None


def _reserve_target_create_claim(
    path: Path, body: Mapping[str, object], *, profile: Literal["domain", "web"] = "domain",
) -> None:
    _require_target_claim_available(path)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(parent)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise TargetHttpTransportError(_DENIED_MESSAGE)
        descriptor = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        with os.fdopen(descriptor, "w") as stream:
            json.dump({"contract": {"domain": "fortipam_700_domain_target_create_v1",
                "web": "fortipam_700_web_target_create_v1"}[profile],
                "state": "post_attempt_reserved", "request_digest": _mapping_digest(body),
                "reserved_at": int(time.time())}, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(parent)
    finally:
        os.close(parent)


def _successful_create_response(payload: object) -> bool:
    if not isinstance(payload, Mapping):
        return False
    reported_status = payload.get("http_status")
    product_status = payload.get("status")
    return reported_status in {None, 200} and product_status in {None, "success"}


def _categorical_product_error(
    payload: object,
) -> tuple[int | None, str | None, str]:
    """Reduce a rejected response to fixed non-disclosing error evidence."""

    if not isinstance(payload, Mapping):
        return None, None, "unclassified"
    raw_code = payload.get("error")
    code = raw_code if type(raw_code) is int else None
    raw_status = payload.get("status")
    status = raw_status if raw_status in {"error", "success"} else None
    strings = tuple(_response_strings(payload))
    normalized = " ".join(strings).casefold()
    if "duplicate" in normalized and "address" in normalized:
        classification = "duplicate_target_address"
    elif "already exists" in normalized and "address" in normalized:
        classification = "duplicate_target_address"
    elif "duplicate" in normalized and "name" in normalized:
        classification = "duplicate_target_name"
    elif "class" in normalized and ("invalid" in normalized or "value" in normalized):
        classification = "invalid_target_class"
    elif "template" in normalized and ("invalid" in normalized or "not found" in normalized):
        classification = "invalid_target_template"
    elif "owner" in normalized and ("invalid" in normalized or "not found" in normalized):
        classification = "invalid_target_owner"
    elif "permission" in normalized and "invalid" in normalized:
        classification = "invalid_permission_relation"
    elif "internal server error" in normalized:
        classification = "internal_server_error"
    else:
        classification = "unclassified"
    return code, cast(str | None, status), classification


def _response_strings(value: object) -> list[str]:
    strings: list[str] = []
    if isinstance(value, str):
        strings.append(value)
    elif isinstance(value, Mapping):
        for item in value.values():
            strings.extend(_response_strings(item))
    elif isinstance(value, list):
        for item in value:
            strings.extend(_response_strings(item))
    return strings


__all__ = [
    "ENV_PREFIX",
    "FortiPamTargetHttpTransport",
    "TargetHttpTransportConfig",
    "TargetHttpTransportConfigurationError",
    "TargetHttpTransportError",
    "load_target_http_transport_config",
]
