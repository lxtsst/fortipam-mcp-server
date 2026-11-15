"""Fixed REST transport for one FortiPAM Character Set creation action.

Only the exact Character Set detail GET, collection POST, accepted-target
DELETE, Password Policy dependency read, and fixed readback routes are compiled
here. This is not a generic HTTP client and never returns a remote object value
or raw API payload through MCP; the create workflow may echo its explicit
non-secret requested input in the C/P/E preview.
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


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_CHARACTER_SET_API_"
COLLECTION_PATH = "/api/v2/cmdb/secret/password-char-set"
PASSWORD_POLICY_COLLECTION_PATH = "/api/v2/cmdb/secret/password-policy"
CHARACTER_SET_NAME_PREFIX = "mcp-v4-char-set-"
CHARACTER_SET_DELETE_NAME = "mcp-v4-char-set-b25"
CHARACTER_SET_VALUE = "!@#$%^&*()"
MAX_RESPONSE_BYTES = 1_048_576
_NAME = re.compile(r"mcp-v4-char-set-[A-Za-z0-9][A-Za-z0-9._-]{0,47}\Z")
_UNAVAILABLE = "FortiPAM V4 Character Set action is unavailable."


class CharacterSetHttpTransportConfigurationError(ValueError):
    """Raised when dedicated Character Set API configuration is unsafe."""


class CharacterSetHttpTransportError(RuntimeError):
    """Raised for a bounded Character Set API transport failure."""


@dataclass(frozen=True, slots=True)
class CharacterSetHttpTransportConfig:
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
            raise CharacterSetHttpTransportConfigurationError(
                "A dedicated HTTPS Character Set API target is required."
            )
        if not self.bearer_token or any(
            ord(character) < 32 or ord(character) == 127
            for character in self.bearer_token
        ):
            raise CharacterSetHttpTransportConfigurationError(
                "A dedicated Character Set API bearer token is required."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise CharacterSetHttpTransportConfigurationError(
                "The Character Set API timeout is invalid."
            )
        if self.ca_file is not None and not Path(self.ca_file).is_file():
            raise CharacterSetHttpTransportConfigurationError(
                "The configured certificate authority file is unavailable."
            )


@dataclass(frozen=True, slots=True)
class CharacterSetInspection:
    """Private presence-only current-state projection."""

    exists: bool


@dataclass(frozen=True, slots=True)
class CharacterSetReadback:
    """Categorical post-write evidence without returning object values."""

    exists: bool
    name_matches: bool
    character_set_matches: bool

    @property
    def verified(self) -> bool:
        return self.exists and self.name_matches and self.character_set_matches


@dataclass(frozen=True, slots=True)
class CharacterSetDeleteInspection:
    """Categorical eligibility for the exact accepted b25 recovery target."""

    exists: bool
    eligible_fixed_character_set: bool
    password_policy_reference_count: int
    target_digest: str


@dataclass(frozen=True, slots=True)
class CharacterSetDeleteReadback:
    """Categorical fixed-target absence after DELETE."""

    absent: bool

    @property
    def verified(self) -> bool:
        return self.absent


def load_character_set_http_transport_config(
    environment: Mapping[str, str] | None = None,
) -> CharacterSetHttpTransportConfig:
    """Load independently scoped Character Set API configuration after opt-in."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise CharacterSetHttpTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    base_url = _value(env, "BASE_URL") or _value(env, "HOST")
    token = _value(env, "API_TOKEN")
    timeout_raw = _value(env, "TIMEOUT_SECONDS") or "15"
    ca_file = _value(env, "CA_FILE")
    if base_url is None or token is None:
        raise CharacterSetHttpTransportConfigurationError(
            "Dedicated Character Set API target and bearer token are required."
        )
    try:
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise CharacterSetHttpTransportConfigurationError(
            "The Character Set API timeout is invalid."
        ) from exc
    normalized_url = base_url if "://" in base_url else f"https://{base_url}"
    return CharacterSetHttpTransportConfig(
        base_url=normalized_url.rstrip("/"),
        bearer_token=token,
        timeout_seconds=timeout,
        ca_file=ca_file,
    )


class FortiPamCharacterSetHttpTransport:
    """Issue only compiled Character Set create/recovery requests."""

    def __init__(
        self,
        config: CharacterSetHttpTransportConfig,
        *,
        client_factory: Callable[..., Any] | None = None,
    ) -> None:
        self._config = config
        self._client_factory = client_factory

    def inspect(self, name: str) -> CharacterSetInspection:
        """Read one Character Set presence state without returning object data."""

        character_set_name = _name(name)
        status, payload = self._request(
            "GET", self._detail_path(character_set_name), None
        )
        if status == 404:
            return CharacterSetInspection(exists=False)
        if status != 200 or _record(payload) is None:
            raise CharacterSetHttpTransportError(_UNAVAILABLE)
        return CharacterSetInspection(exists=True)

    def create_and_readback(self, name: str) -> CharacterSetReadback:
        """Create the one fixed symbol Character Set and verify it by detail GET."""

        character_set_name = _name(name)
        status, payload = self._request(
            "POST",
            COLLECTION_PATH,
            {"name": character_set_name, "char-set": CHARACTER_SET_VALUE},
        )
        if status != 200 or not _successful_response(payload):
            raise CharacterSetHttpTransportError(_UNAVAILABLE)
        detail_status, detail_payload = self._request(
            "GET", self._detail_path(character_set_name), None
        )
        detail = _record(detail_payload)
        if detail_status != 200 or detail is None:
            return CharacterSetReadback(False, False, False)
        return CharacterSetReadback(
            exists=True,
            name_matches=detail.get("name") == character_set_name,
            character_set_matches=detail.get("char-set") == CHARACTER_SET_VALUE,
        )

    def inspect_delete_target(self) -> CharacterSetDeleteInspection:
        """Prove the accepted b25 target shape and zero policy references."""

        status, payload = self._request(
            "GET",
            self._detail_path(CHARACTER_SET_DELETE_NAME),
            None,
        )
        if status == 404:
            return CharacterSetDeleteInspection(False, False, 0, "0" * 64)
        record = _record(payload)
        if status != 200 or record is None:
            raise CharacterSetHttpTransportError(_UNAVAILABLE)
        canonical = _canonical_delete_target(record)
        policy_status, policy_payload = self._request(
            "GET",
            PASSWORD_POLICY_COLLECTION_PATH,
            None,
        )
        policies = _records(policy_payload)
        if policy_status != 200 or policies is None:
            raise CharacterSetHttpTransportError(_UNAVAILABLE)
        reference_count = sum(
            1 for policy in policies if _references_delete_target(policy)
        )
        return CharacterSetDeleteInspection(
            exists=True,
            eligible_fixed_character_set=reference_count == 0,
            password_policy_reference_count=reference_count,
            target_digest=_character_set_digest(canonical),
        )

    def delete_and_readback(
        self,
        expected_target_digest: str,
    ) -> CharacterSetDeleteReadback:
        """Delete only the unchanged unreferenced b25 target and prove absence."""

        if not _digest(expected_target_digest):
            raise CharacterSetHttpTransportError(_UNAVAILABLE)
        inspection = self.inspect_delete_target()
        if (
            not inspection.exists
            or not inspection.eligible_fixed_character_set
            or inspection.password_policy_reference_count != 0
            or not hmac.compare_digest(
                inspection.target_digest,
                expected_target_digest,
            )
        ):
            raise CharacterSetHttpTransportError(_UNAVAILABLE)
        status, payload = self._request(
            "DELETE",
            self._detail_path(CHARACTER_SET_DELETE_NAME),
            None,
        )
        if status != 200 or not _successful_response(payload):
            raise CharacterSetHttpTransportError(_UNAVAILABLE)
        readback_status, _ = self._request(
            "GET",
            self._detail_path(CHARACTER_SET_DELETE_NAME),
            None,
        )
        return CharacterSetDeleteReadback(absent=readback_status == 404)

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
            raise CharacterSetHttpTransportError(_UNAVAILABLE) from exc
        content_type = response.headers.get("content-type", "")
        if "json" not in content_type.lower() or len(response.content) > MAX_RESPONSE_BYTES:
            raise CharacterSetHttpTransportError(_UNAVAILABLE)
        try:
            return int(response.status_code), json.loads(response.content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CharacterSetHttpTransportError(_UNAVAILABLE) from exc

    @staticmethod
    def _detail_path(name: str) -> str:
        return f"{COLLECTION_PATH}/{quote(name, safe='')}"


def _record(payload: object) -> Mapping[str, object] | None:
    if not isinstance(payload, Mapping):
        return None
    result = payload.get("results", payload.get("result"))
    if isinstance(result, Mapping):
        return result
    if isinstance(result, list) and len(result) == 1 and isinstance(result[0], Mapping):
        return result[0]
    return None


def _records(payload: object) -> list[Mapping[str, object]] | None:
    if not isinstance(payload, Mapping):
        return None
    results = payload.get("results", payload.get("result"))
    if not isinstance(results, list) or not all(
        isinstance(item, Mapping) for item in results
    ):
        return None
    return list(results)


def _canonical_delete_target(record: Mapping[str, object]) -> dict[str, object]:
    if set(record) != {"name", "char-set", "q_origin_key"}:
        raise CharacterSetHttpTransportError(_UNAVAILABLE)
    if (
        record.get("name") != CHARACTER_SET_DELETE_NAME
        or record.get("char-set") != CHARACTER_SET_VALUE
    ):
        raise CharacterSetHttpTransportError(_UNAVAILABLE)
    origin_key = record.get("q_origin_key")
    if not isinstance(origin_key, str) or not origin_key or len(origin_key) > 256:
        raise CharacterSetHttpTransportError(_UNAVAILABLE)
    return {
        "name": CHARACTER_SET_DELETE_NAME,
        "char-set": CHARACTER_SET_VALUE,
    }


def _references_delete_target(policy: Mapping[str, object]) -> bool:
    requirements = policy.get("password-requirement")
    if not isinstance(requirements, list):
        return False
    return any(
        isinstance(requirement, Mapping)
        and requirement.get("char-set") == CHARACTER_SET_DELETE_NAME
        for requirement in requirements
    )


def _character_set_digest(character_set: Mapping[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(
            character_set,
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
        raise CharacterSetHttpTransportError(_UNAVAILABLE)
    return value


def _successful_response(payload: object) -> bool:
    return isinstance(payload, Mapping) and payload.get("http_status") in {None, 200}


def _ssl_context(config: CharacterSetHttpTransportConfig) -> ssl.SSLContext:
    if config.ca_file is not None:
        return ssl.create_default_context(cafile=config.ca_file)
    try:
        import truststore
    except ImportError as exc:  # pragma: no cover - deployment dependency guard.
        raise CharacterSetHttpTransportError(_UNAVAILABLE) from exc
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


__all__ = [
    "CHARACTER_SET_DELETE_NAME",
    "CHARACTER_SET_NAME_PREFIX",
    "CHARACTER_SET_VALUE",
    "COLLECTION_PATH",
    "ENV_PREFIX",
    "CharacterSetHttpTransportConfigurationError",
    "CharacterSetHttpTransportConfig",
    "CharacterSetHttpTransportError",
    "CharacterSetInspection",
    "CharacterSetDeleteInspection",
    "CharacterSetDeleteReadback",
    "CharacterSetReadback",
    "FortiPamCharacterSetHttpTransport",
    "load_character_set_http_transport_config",
]
