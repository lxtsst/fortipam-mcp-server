"""Fixed REST transport for one FortiPAM Password Policy creation action.

Only the exact Password Policy detail GET, collection POST, and detail
readback routes are compiled here. It is not a generic HTTP client and never
returns remote policy data or raw API payloads through MCP; the workflow may
echo its explicit non-secret requested input in the C/P/E preview.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import ssl
from typing import Any, Literal
from urllib.parse import quote, urlsplit


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_PASSWORD_POLICY_API_"
COLLECTION_PATH = "/api/v2/cmdb/secret/password-policy"
PASSWORD_POLICY_NAME_PREFIX = "mcp-v4-password-policy-"
PASSWORD_POLICY_DELETE_NAME = "mcp-v4-password-policy-b28"
MINIMUM_LENGTH = 12
MAXIMUM_LENGTH = 16
PASSWORD_REQUIREMENTS = (
    (1, "lower", 1),
    (2, "upper", 1),
    (3, "number", 1),
    (4, "symbol", 1),
)
MAX_RESPONSE_BYTES = 1_048_576
_NAME = re.compile(r"mcp-v4-password-policy-[A-Za-z0-9][A-Za-z0-9._-]{0,39}\Z")
_UNAVAILABLE = "FortiPAM V4 Password Policy action is unavailable."


class PasswordPolicyHttpTransportConfigurationError(ValueError):
    """Raised when dedicated Password Policy API configuration is unsafe."""


class PasswordPolicyHttpTransportError(RuntimeError):
    """Raised for a bounded Password Policy API transport failure."""


@dataclass(frozen=True, slots=True)
class PasswordPolicyHttpTransportConfig:
    """Dedicated HTTPS and bearer settings held only in process memory."""

    base_url: str
    bearer_token: str
    timeout_seconds: float
    ca_file: str | None

    def __post_init__(self) -> None:
        parsed = urlsplit(self.base_url)
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise PasswordPolicyHttpTransportConfigurationError(
                "A dedicated HTTPS Password Policy API target is required."
            )
        if not self.bearer_token or any(
            ord(character) < 32 or ord(character) == 127
            for character in self.bearer_token
        ):
            raise PasswordPolicyHttpTransportConfigurationError(
                "A dedicated Password Policy API bearer token is required."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise PasswordPolicyHttpTransportConfigurationError(
                "The Password Policy API timeout is invalid."
            )
        if self.ca_file is not None and not Path(self.ca_file).is_file():
            raise PasswordPolicyHttpTransportConfigurationError(
                "The configured certificate authority file is unavailable."
            )


@dataclass(frozen=True, slots=True)
class PasswordPolicyInspection:
    """Private presence-only current-state projection."""

    exists: bool


@dataclass(frozen=True, slots=True)
class PasswordPolicyReadback:
    """Categorical post-write evidence without returning policy data."""

    exists: bool
    name_matches: bool
    length_bounds_match: bool
    requirements_match: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.exists,
                self.name_matches,
                self.length_bounds_match,
                self.requirements_match,
            )
        )


@dataclass(frozen=True, slots=True)
class PasswordPolicyDeleteInspection:
    """Categorical eligibility for the exact accepted b28 recovery target."""

    exists: bool
    eligible_fixed_policy: bool
    target_digest: str


@dataclass(frozen=True, slots=True)
class PasswordPolicyDeleteReadback:
    """Categorical fixed-target absence after DELETE."""

    absent: bool

    @property
    def verified(self) -> bool:
        return self.absent


def load_password_policy_http_transport_config(
    environment: Mapping[str, str] | None = None,
) -> PasswordPolicyHttpTransportConfig:
    """Load independently scoped Password Policy API configuration after opt-in."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise PasswordPolicyHttpTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    base_url = _value(env, "BASE_URL") or _value(env, "HOST")
    token = _value(env, "API_TOKEN")
    timeout_raw = _value(env, "TIMEOUT_SECONDS") or "15"
    ca_file = _value(env, "CA_FILE")
    if base_url is None or token is None:
        raise PasswordPolicyHttpTransportConfigurationError(
            "Dedicated Password Policy API target and bearer token are required."
        )
    try:
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise PasswordPolicyHttpTransportConfigurationError(
            "The Password Policy API timeout is invalid."
        ) from exc
    normalized_url = base_url if "://" in base_url else f"https://{base_url}"
    return PasswordPolicyHttpTransportConfig(
        base_url=normalized_url.rstrip("/"),
        bearer_token=token,
        timeout_seconds=timeout,
        ca_file=ca_file,
    )


class FortiPamPasswordPolicyHttpTransport:
    """Issue only compiled Password Policy detail/create/readback requests."""

    def __init__(
        self,
        config: PasswordPolicyHttpTransportConfig,
        *,
        client_factory: Callable[..., Any] | None = None,
    ) -> None:
        self._config = config
        self._client_factory = client_factory

    def inspect(self, name: str) -> PasswordPolicyInspection:
        """Read one Password Policy presence state without object data."""

        policy_name = _name(name)
        status, payload = self._request("GET", self._detail_path(policy_name), None)
        if status == 404:
            return PasswordPolicyInspection(exists=False)
        if status != 200 or _record(payload) is None:
            raise PasswordPolicyHttpTransportError(_UNAVAILABLE)
        return PasswordPolicyInspection(exists=True)

    def create_and_readback(self, name: str) -> PasswordPolicyReadback:
        """Create the one fixed four-set Password Policy and verify by detail GET."""

        policy_name = _name(name)
        status, payload = self._request("POST", COLLECTION_PATH, _create_body(policy_name))
        if status != 200 or not _successful_response(payload):
            raise PasswordPolicyHttpTransportError(_UNAVAILABLE)
        detail_status, detail_payload = self._request(
            "GET", self._detail_path(policy_name), None
        )
        detail = _record(detail_payload)
        if detail_status != 200 or detail is None:
            return PasswordPolicyReadback(False, False, False, False)
        return PasswordPolicyReadback(
            exists=True,
            name_matches=detail.get("name") == policy_name,
            length_bounds_match=(
                detail.get("minimum-length") == MINIMUM_LENGTH
                and detail.get("maximum-length") == MAXIMUM_LENGTH
            ),
            requirements_match=_requirements_match(detail.get("password-requirement")),
        )

    def inspect_delete_target(self) -> PasswordPolicyDeleteInspection:
        """Read only the exact accepted b28 policy and prove its fixed shape."""

        status, payload = self._request(
            "GET",
            self._detail_path(PASSWORD_POLICY_DELETE_NAME),
            None,
        )
        if status == 404:
            return PasswordPolicyDeleteInspection(False, False, "0" * 64)
        record = _record(payload)
        if status != 200 or record is None:
            raise PasswordPolicyHttpTransportError(_UNAVAILABLE)
        canonical = _canonical_delete_target(record)
        return PasswordPolicyDeleteInspection(
            exists=True,
            eligible_fixed_policy=True,
            target_digest=_policy_digest(canonical),
        )

    def delete_and_readback(
        self,
        expected_target_digest: str,
    ) -> PasswordPolicyDeleteReadback:
        """Delete only the unchanged accepted b28 target and prove absence."""

        if not _digest(expected_target_digest):
            raise PasswordPolicyHttpTransportError(_UNAVAILABLE)
        inspection = self.inspect_delete_target()
        if (
            not inspection.exists
            or not inspection.eligible_fixed_policy
            or not hmac.compare_digest(
                inspection.target_digest,
                expected_target_digest,
            )
        ):
            raise PasswordPolicyHttpTransportError(_UNAVAILABLE)
        status, payload = self._request(
            "DELETE",
            self._detail_path(PASSWORD_POLICY_DELETE_NAME),
            None,
        )
        if status != 200 or not _successful_response(payload):
            raise PasswordPolicyHttpTransportError(_UNAVAILABLE)
        readback_status, _ = self._request(
            "GET",
            self._detail_path(PASSWORD_POLICY_DELETE_NAME),
            None,
        )
        return PasswordPolicyDeleteReadback(absent=readback_status == 404)

    def _request(
        self,
        method: Literal["GET", "POST", "DELETE"],
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
            raise PasswordPolicyHttpTransportError(_UNAVAILABLE) from exc
        content_type = response.headers.get("content-type", "")
        if "json" not in content_type.lower() or len(response.content) > MAX_RESPONSE_BYTES:
            raise PasswordPolicyHttpTransportError(_UNAVAILABLE)
        try:
            return int(response.status_code), json.loads(response.content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PasswordPolicyHttpTransportError(_UNAVAILABLE) from exc

    @staticmethod
    def _detail_path(name: str) -> str:
        return f"{COLLECTION_PATH}/{quote(name, safe='')}"


def _create_body(name: str) -> dict[str, object]:
    return {
        "name": name,
        "minimum-length": MINIMUM_LENGTH,
        "maximum-length": MAXIMUM_LENGTH,
        "password-requirement": [
            {"id": item_id, "char-set": char_set, "minimum-num": minimum_num}
            for item_id, char_set, minimum_num in PASSWORD_REQUIREMENTS
        ],
    }


def _record(payload: object) -> Mapping[str, object] | None:
    if not isinstance(payload, Mapping):
        return None
    result = payload.get("results", payload.get("result"))
    if isinstance(result, Mapping):
        return result
    if isinstance(result, list) and len(result) == 1 and isinstance(result[0], Mapping):
        return result[0]
    return None


def _requirements_match(value: object) -> bool:
    if not isinstance(value, list) or len(value) != len(PASSWORD_REQUIREMENTS):
        return False
    actual: set[tuple[int, str, int]] = set()
    for item in value:
        if not isinstance(item, Mapping):
            return False
        item_id = item.get("id")
        char_set = item.get("char-set")
        minimum_num = item.get("minimum-num")
        if type(item_id) is not int or not isinstance(char_set, str) or type(minimum_num) is not int:
            return False
        actual.add((item_id, char_set, minimum_num))
    return actual == set(PASSWORD_REQUIREMENTS)


def _canonical_delete_target(record: Mapping[str, object]) -> dict[str, object]:
    if set(record) != {
        "name",
        "minimum-length",
        "maximum-length",
        "password-requirement",
        "q_origin_key",
    }:
        raise PasswordPolicyHttpTransportError(_UNAVAILABLE)
    if (
        record.get("name") != PASSWORD_POLICY_DELETE_NAME
        or record.get("minimum-length") != MINIMUM_LENGTH
        or record.get("maximum-length") != MAXIMUM_LENGTH
        or not _requirements_match(record.get("password-requirement"))
    ):
        raise PasswordPolicyHttpTransportError(_UNAVAILABLE)
    origin_key = record.get("q_origin_key")
    if not isinstance(origin_key, str) or not origin_key or len(origin_key) > 256:
        raise PasswordPolicyHttpTransportError(_UNAVAILABLE)
    return _create_body(PASSWORD_POLICY_DELETE_NAME)


def _policy_digest(policy: Mapping[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(
            policy,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _digest(value: str) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _value(environment: Mapping[str, str], suffix: str) -> str | None:
    value = environment.get(f"{ENV_PREFIX}{suffix}")
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise PasswordPolicyHttpTransportError(_UNAVAILABLE)
    return value


def _successful_response(payload: object) -> bool:
    return isinstance(payload, Mapping) and payload.get("http_status") in {None, 200}


def _ssl_context(config: PasswordPolicyHttpTransportConfig) -> ssl.SSLContext:
    if config.ca_file is not None:
        return ssl.create_default_context(cafile=config.ca_file)
    try:
        import truststore
    except ImportError as exc:  # pragma: no cover - deployment dependency guard.
        raise PasswordPolicyHttpTransportError(_UNAVAILABLE) from exc
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


__all__ = [
    "COLLECTION_PATH",
    "ENV_PREFIX",
    "MAXIMUM_LENGTH",
    "MINIMUM_LENGTH",
    "PASSWORD_POLICY_NAME_PREFIX",
    "PASSWORD_POLICY_DELETE_NAME",
    "PASSWORD_REQUIREMENTS",
    "FortiPamPasswordPolicyHttpTransport",
    "PasswordPolicyHttpTransportConfig",
    "PasswordPolicyHttpTransportConfigurationError",
    "PasswordPolicyHttpTransportError",
    "PasswordPolicyInspection",
    "PasswordPolicyDeleteInspection",
    "PasswordPolicyDeleteReadback",
    "PasswordPolicyReadback",
    "load_password_policy_http_transport_config",
]
