"""Fixed REST transport for one FortiPAM Windows App Filter Profile.

Only the exact Profile collection/detail/create, fixed accepted-target DELETE,
Secret dependency read, and absence-readback routes are compiled here. The
transport never returns Profile or Secret values through MCP and is not a
generic HTTP client.
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


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_WINDOWS_APP_FILTER_API_"
COLLECTION_PATH = "/api/v2/cmdb/secret/winappfilter-profile"
SECRET_COLLECTION_PATH = "/api/v2/cmdb/secret/database"
WINDOWS_APP_FILTER_NAME_PREFIX = "mcp-v4-winapp-filter-"
WINDOWS_APP_FILTER_DELETE_NAME = "mcp-v4-winapp-filter-b26"
WINDOWS_APP_FILTER_REFRESH_PERIOD = 30
SECRET_PAGE_SIZE = 100
MAX_SECRET_PAGES = 100
MAX_RESPONSE_BYTES = 1_048_576
_NAME = re.compile(r"mcp-v4-winapp-filter-[A-Za-z0-9][A-Za-z0-9._-]{0,41}\Z")
_UNAVAILABLE = "FortiPAM V4 Windows App Filter action is unavailable."


class WindowsAppFilterHttpTransportConfigurationError(ValueError):
    """Raised when dedicated Windows App Filter API configuration is unsafe."""


class WindowsAppFilterHttpTransportError(RuntimeError):
    """Raised for a bounded Windows App Filter API transport failure."""


@dataclass(frozen=True, slots=True)
class WindowsAppFilterHttpTransportConfig:
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
            raise WindowsAppFilterHttpTransportConfigurationError(
                "A dedicated HTTPS Windows App Filter API target is required."
            )
        if not self.bearer_token or any(
            ord(character) < 32 or ord(character) == 127
            for character in self.bearer_token
        ):
            raise WindowsAppFilterHttpTransportConfigurationError(
                "A dedicated Windows App Filter API bearer token is required."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise WindowsAppFilterHttpTransportConfigurationError(
                "The Windows App Filter API timeout is invalid."
            )
        if self.ca_file is not None and not Path(self.ca_file).is_file():
            raise WindowsAppFilterHttpTransportConfigurationError(
                "The configured certificate authority file is unavailable."
            )


@dataclass(frozen=True, slots=True)
class WindowsAppFilterInspection:
    """Private presence-only current-state projection."""

    exists: bool


@dataclass(frozen=True, slots=True)
class WindowsAppFilterReadback:
    """Categorical post-write evidence without returning Profile data."""

    exists: bool
    name_matches: bool

    @property
    def verified(self) -> bool:
        return self.exists and self.name_matches


@dataclass(frozen=True, slots=True)
class WindowsAppFilterDeleteInspection:
    """Categorical eligibility for the exact accepted b27 recovery target."""

    exists: bool
    eligible_fixed_profile: bool
    secret_reference_count: int
    target_digest: str


@dataclass(frozen=True, slots=True)
class WindowsAppFilterDeleteReadback:
    """Categorical fixed-target absence after DELETE."""

    absent: bool

    @property
    def verified(self) -> bool:
        return self.absent


def load_windows_app_filter_http_transport_config(
    environment: Mapping[str, str] | None = None,
) -> WindowsAppFilterHttpTransportConfig:
    """Load independently scoped API configuration after explicit opt-in."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise WindowsAppFilterHttpTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    base_url = _value(env, "BASE_URL") or _value(env, "HOST")
    token = _value(env, "API_TOKEN")
    timeout_raw = _value(env, "TIMEOUT_SECONDS") or "15"
    ca_file = _value(env, "CA_FILE")
    if base_url is None or token is None:
        raise WindowsAppFilterHttpTransportConfigurationError(
            "Dedicated Windows App Filter API target and bearer token are required."
        )
    try:
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise WindowsAppFilterHttpTransportConfigurationError(
            "The Windows App Filter API timeout is invalid."
        ) from exc
    normalized_url = base_url if "://" in base_url else f"https://{base_url}"
    return WindowsAppFilterHttpTransportConfig(
        base_url=normalized_url.rstrip("/"),
        bearer_token=token,
        timeout_seconds=timeout,
        ca_file=ca_file,
    )


class FortiPamWindowsAppFilterHttpTransport:
    """Issue only compiled Profile create and fixed recovery requests."""

    def __init__(
        self,
        config: WindowsAppFilterHttpTransportConfig,
        *,
        client_factory: Callable[..., Any] | None = None,
    ) -> None:
        self._config = config
        self._client_factory = client_factory

    def inspect(self, name: str) -> WindowsAppFilterInspection:
        """Read Profile presence without returning its filters or values."""

        profile_name = _name(name)
        status, payload = self._request("GET", self._detail_path(profile_name), None)
        if status == 404:
            return WindowsAppFilterInspection(exists=False)
        if status != 200 or _record(payload) is None:
            raise WindowsAppFilterHttpTransportError(_UNAVAILABLE)
        return WindowsAppFilterInspection(exists=True)

    def create_and_readback(self, name: str) -> WindowsAppFilterReadback:
        """Create only an empty, unassociated Profile and verify its identity."""

        profile_name = _name(name)
        # The Guide documents an empty Profile as a supported no-restriction
        # workaround.  The catalog establishes POST but not a richer body, so
        # this deliberately sends only the mandatory documented Profile name.
        status, payload = self._request("POST", COLLECTION_PATH, {"name": profile_name})
        if status != 200 or not _successful_response(payload):
            raise WindowsAppFilterHttpTransportError(_UNAVAILABLE)
        detail_status, detail_payload = self._request(
            "GET", self._detail_path(profile_name), None
        )
        detail = _record(detail_payload)
        if detail_status != 200 or detail is None:
            return WindowsAppFilterReadback(False, False)
        return WindowsAppFilterReadback(
            exists=True,
            name_matches=detail.get("name") == profile_name,
        )

    def inspect_delete_target(self) -> WindowsAppFilterDeleteInspection:
        """Prove exact fixed shape and zero Secret references for b27."""

        status, payload = self._request(
            "GET",
            self._detail_path(WINDOWS_APP_FILTER_DELETE_NAME),
            None,
        )
        if status == 404:
            return WindowsAppFilterDeleteInspection(False, False, 0, "0" * 64)
        record = _record(payload)
        if status != 200 or record is None:
            raise WindowsAppFilterHttpTransportError(_UNAVAILABLE)
        canonical = _canonical_delete_target(record)
        reference_count = self._secret_reference_count()
        return WindowsAppFilterDeleteInspection(
            exists=True,
            eligible_fixed_profile=reference_count == 0,
            secret_reference_count=reference_count,
            target_digest=_profile_digest(canonical),
        )

    def delete_and_readback(
        self,
        expected_target_digest: str,
    ) -> WindowsAppFilterDeleteReadback:
        """Delete only the unchanged unreferenced b27 target and prove absence."""

        if not _digest(expected_target_digest):
            raise WindowsAppFilterHttpTransportError(_UNAVAILABLE)
        inspection = self.inspect_delete_target()
        if (
            not inspection.exists
            or not inspection.eligible_fixed_profile
            or inspection.secret_reference_count != 0
            or not hmac.compare_digest(
                inspection.target_digest,
                expected_target_digest,
            )
        ):
            raise WindowsAppFilterHttpTransportError(_UNAVAILABLE)
        status, payload = self._request(
            "DELETE",
            self._detail_path(WINDOWS_APP_FILTER_DELETE_NAME),
            None,
        )
        if status != 200 or not _successful_response(payload):
            raise WindowsAppFilterHttpTransportError(_UNAVAILABLE)
        readback_status, _ = self._request(
            "GET",
            self._detail_path(WINDOWS_APP_FILTER_DELETE_NAME),
            None,
        )
        return WindowsAppFilterDeleteReadback(absent=readback_status == 404)

    def _secret_reference_count(self) -> int:
        reference_count = 0
        for page in range(MAX_SECRET_PAGES):
            status, payload = self._request(
                "GET",
                SECRET_COLLECTION_PATH,
                None,
                query=f"start={page * SECRET_PAGE_SIZE}&count={SECRET_PAGE_SIZE}",
            )
            records = _records(payload)
            if status != 200 or records is None:
                raise WindowsAppFilterHttpTransportError(_UNAVAILABLE)
            reference_count += sum(
                _count_exact_reference(record, WINDOWS_APP_FILTER_DELETE_NAME)
                for record in records
            )
            if len(records) < SECRET_PAGE_SIZE:
                return reference_count
        raise WindowsAppFilterHttpTransportError(_UNAVAILABLE)

    def _request(
        self,
        method: Literal["GET", "POST", "DELETE"],
        path: str,
        body: Mapping[str, object] | None,
        *,
        query: str | None = None,
    ) -> tuple[int, object | None]:
        url = f"{self._config.base_url}{path}"
        if query is not None:
            url = f"{url}?{query}"
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
                    url,
                    headers={
                        "Accept": "application/json",
                        "Authorization": f"Bearer {self._config.bearer_token}",
                    },
                    json=body,
                )
        except Exception as exc:
            raise WindowsAppFilterHttpTransportError(_UNAVAILABLE) from exc
        content_type = response.headers.get("content-type", "")
        if "json" not in content_type.lower() or len(response.content) > MAX_RESPONSE_BYTES:
            raise WindowsAppFilterHttpTransportError(_UNAVAILABLE)
        try:
            return int(response.status_code), json.loads(response.content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WindowsAppFilterHttpTransportError(_UNAVAILABLE) from exc

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
    result = payload.get("results", payload.get("result"))
    if isinstance(result, list) and all(isinstance(item, Mapping) for item in result):
        return list(result)
    if isinstance(result, Mapping):
        return [result]
    return None


def _canonical_delete_target(record: Mapping[str, object]) -> dict[str, object]:
    if set(record) != {"name", "q_origin_key", "refresh-period", "rules"}:
        raise WindowsAppFilterHttpTransportError(_UNAVAILABLE)
    if (
        record.get("name") != WINDOWS_APP_FILTER_DELETE_NAME
        or record.get("q_origin_key") != WINDOWS_APP_FILTER_DELETE_NAME
        or record.get("refresh-period") != WINDOWS_APP_FILTER_REFRESH_PERIOD
        or record.get("rules") != []
    ):
        raise WindowsAppFilterHttpTransportError(_UNAVAILABLE)
    return {
        "name": WINDOWS_APP_FILTER_DELETE_NAME,
        "refresh-period": WINDOWS_APP_FILTER_REFRESH_PERIOD,
        "rules": [],
    }


def _count_exact_reference(value: object, target: str) -> int:
    if isinstance(value, str):
        return int(value == target)
    if isinstance(value, Mapping):
        return sum(_count_exact_reference(item, target) for item in value.values())
    if isinstance(value, list):
        return sum(_count_exact_reference(item, target) for item in value)
    return 0


def _profile_digest(record: Mapping[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(
            record,
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
        raise WindowsAppFilterHttpTransportError(_UNAVAILABLE)
    return value


def _successful_response(payload: object) -> bool:
    return isinstance(payload, Mapping) and payload.get("http_status") in {None, 200}


def _ssl_context(config: WindowsAppFilterHttpTransportConfig) -> ssl.SSLContext:
    if config.ca_file is not None:
        return ssl.create_default_context(cafile=config.ca_file)
    try:
        import truststore
    except ImportError as exc:  # pragma: no cover - deployment dependency guard.
        raise WindowsAppFilterHttpTransportError(_UNAVAILABLE) from exc
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


__all__ = [
    "COLLECTION_PATH",
    "ENV_PREFIX",
    "FortiPamWindowsAppFilterHttpTransport",
    "SECRET_COLLECTION_PATH",
    "WINDOWS_APP_FILTER_DELETE_NAME",
    "WINDOWS_APP_FILTER_NAME_PREFIX",
    "WINDOWS_APP_FILTER_REFRESH_PERIOD",
    "WindowsAppFilterDeleteInspection",
    "WindowsAppFilterDeleteReadback",
    "WindowsAppFilterHttpTransportConfigurationError",
    "WindowsAppFilterHttpTransportConfig",
    "WindowsAppFilterHttpTransportError",
    "WindowsAppFilterInspection",
    "WindowsAppFilterReadback",
    "load_windows_app_filter_http_transport_config",
]
