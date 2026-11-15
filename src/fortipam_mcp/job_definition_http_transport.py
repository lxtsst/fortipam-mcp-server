"""Protected FortiPAM 7.0 transport for one disabled BP008 Job definition.

The caller owns the durable one-use claim before ``post_disabled_once``. This
transport never executes a Job or exposes its script, Secret, or requester.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
import hashlib
import hmac
import json
from typing import Any
from urllib.parse import quote

from .job_definition_create_contract import compile_disabled_job_create_body
from .job_activation_contract import compile_fixed_job_activation_body
from .job_definition_projection import (
    JobDefinitionExpectation,
    JobDefinitionReadback,
    project_job_collection_definition,
    JobExecutionReadback,
    project_job_collection_execution,
)
from .secret_metadata_http_transport import (
    MAX_RESPONSE_BYTES,
    SecretMetadataHttpTransportConfig,
    _ssl_context,
)


_COLLECTION = "/api/v2/cmdb/secret/job"
_SOURCE = "mcp-v4-bp008-job-20260930-r3"
_SCRIPT = "echo BP008_JOB_OK"
_UNAVAILABLE = "The fixed disabled Job transport is unavailable."


class JobDefinitionHttpTransportError(RuntimeError):
    """A protected Job request or exact readback is unavailable."""


@dataclass(frozen=True, slots=True)
class JobCreateInspection:
    body_digest: str
    target_exists: bool


@dataclass(frozen=True, slots=True, repr=False)
class JobActivationInspection:
    body_digest: str
    scheduled_at: datetime

    def __repr__(self) -> str:
        return "<JobActivationInspection redacted>"


class FortiPamDisabledJobHttpTransport:
    """Read one source, send one caller-claimed POST, and verify by collection."""

    def __init__(
        self,
        config: SecretMetadataHttpTransportConfig,
        *,
        target_name: str,
        target_requester: str,
        expected_secret_id: int,
        client_factory: Callable[..., Any] | None = None,
    ) -> None:
        self._config = config
        self._target_name = target_name
        self._target_requester = target_requester
        self._expected_secret_id = expected_secret_id
        self._client_factory = client_factory

    def inspect(self) -> JobCreateInspection:
        """Check the fixed source, private body, and target absence."""

        try:
            body = self._body()
            payload = self._collection()
            source = project_job_collection_definition(
                payload, JobDefinitionExpectation(
                    _SOURCE, "admin", self._expected_secret_id, _SCRIPT,
                ),
            )
            if not source.definition_verified:
                raise ValueError
            rows = payload["results"]
            assert isinstance(rows, list)
            sources = [row for row in rows if row.get("name") == _SOURCE]
            if len(sources) != 1:
                raise ValueError
            _require_created_fields(sources[0], {**body, "name": _SOURCE, "user": "admin"})
            return JobCreateInspection(
                _digest(body),
                any(row.get("name") == self._target_name for row in rows),
            )
        except Exception:
            raise JobDefinitionHttpTransportError(_UNAVAILABLE) from None

    def post_disabled_once(self, expected: JobCreateInspection) -> bool:
        """Send at most one POST after the caller has reserved a durable claim."""

        try:
            if not isinstance(expected, JobCreateInspection) or expected.target_exists:
                raise ValueError
            current = self.inspect()
            if current.target_exists or not hmac.compare_digest(
                current.body_digest, expected.body_digest,
            ):
                raise ValueError
            body = self._body()
            if not hmac.compare_digest(_digest(body), expected.body_digest):
                raise ValueError
            status, payload = self._request("POST", _COLLECTION, body)
            return bool(
                status == 200 and isinstance(payload, Mapping)
                and payload.get("status") == "success"
            )
        except Exception:
            raise JobDefinitionHttpTransportError(_UNAVAILABLE) from None

    def readback(self, *, expected: JobCreateInspection | None = None) -> JobDefinitionReadback:
        """Classify the exact target through the 7.0 collection GET override."""

        try:
            payload = self._collection()
            result = project_job_collection_definition(
                payload,
                JobDefinitionExpectation(
                    self._target_name, self._target_requester,
                    self._expected_secret_id, _SCRIPT,
                ),
            )
            if not result.definition_verified:
                raise ValueError
            if expected is not None:
                if type(expected) is not JobCreateInspection or expected.target_exists:
                    raise ValueError
                body = self._body()
                if not hmac.compare_digest(_digest(body), expected.body_digest):
                    raise ValueError
                rows = payload["results"]
                assert isinstance(rows, list)
                matches = [row for row in rows if row.get("name") == self._target_name]
                if len(matches) != 1:
                    raise ValueError
                _require_created_fields(matches[0], body)
            return result
        except Exception:
            raise JobDefinitionHttpTransportError(_UNAVAILABLE) from None

    def observe_execution(self) -> JobExecutionReadback:
        """Read only categorical execution timing for the exact fixed Job."""

        try:
            return project_job_collection_execution(
                self._collection(),
                JobDefinitionExpectation(
                    self._target_name, self._target_requester,
                    self._expected_secret_id, _SCRIPT,
                ),
            )
        except Exception:
            raise JobDefinitionHttpTransportError(_UNAVAILABLE) from None

    def inspect_activation(
        self, *, scheduled_at: datetime, now: datetime,
    ) -> JobActivationInspection:
        """Check the exact unrun Job and compile a future update without writing."""

        try:
            body = compile_fixed_job_activation_body(
                self._source_detail(), self._collection(),
                target_name=self._target_name,
                target_requester=self._target_requester,
                expected_secret_id=self._expected_secret_id,
                scheduled_at=scheduled_at, now=now,
            )
            return JobActivationInspection(_digest(body), scheduled_at)
        except Exception:
            raise JobDefinitionHttpTransportError(_UNAVAILABLE) from None

    def put_activation_once(
        self, expected: JobActivationInspection, *, now: datetime,
    ) -> bool:
        """Send one caller-claimed PUT only while the exact preview still holds."""

        try:
            if not isinstance(expected, JobActivationInspection):
                raise ValueError
            body = compile_fixed_job_activation_body(
                self._source_detail(), self._collection(),
                target_name=self._target_name,
                target_requester=self._target_requester,
                expected_secret_id=self._expected_secret_id,
                scheduled_at=expected.scheduled_at, now=now,
            )
            if not hmac.compare_digest(_digest(body), expected.body_digest):
                raise ValueError
            status, payload = self._request(
                "PUT", f"{_COLLECTION}/{quote(self._target_name, safe='')}",
                body, query="with_meta=true&vdom=root",
            )
            return bool(
                status == 200 and isinstance(payload, Mapping)
                and payload.get("status") == "success"
            )
        except Exception:
            raise JobDefinitionHttpTransportError(_UNAVAILABLE) from None

    def _body(self) -> dict[str, object]:
        payload = self._source_detail()
        return compile_disabled_job_create_body(
            payload, source_name=_SOURCE, target_name=self._target_name,
            target_requester=self._target_requester,
            expected_secret_id=self._expected_secret_id,
        )

    def _source_detail(self) -> object:
        status, payload = self._request(
            "GET", f"{_COLLECTION}/{quote(_SOURCE, safe='')}", None,
            query="vdom=root",
        )
        if status != 200:
            raise JobDefinitionHttpTransportError(_UNAVAILABLE)
        return payload

    def _collection(self) -> Mapping[str, object]:
        status, payload = self._request(
            "POST", _COLLECTION, {"json_filter": []},
            query="with_meta=true&vdom=root", override="GET",
        )
        if status != 200 or not isinstance(payload, Mapping):
            raise JobDefinitionHttpTransportError(_UNAVAILABLE)
        rows = payload.get("results")
        if (
            payload.get("status") != "OK"
            or not isinstance(rows, list)
            or not all(isinstance(row, Mapping) for row in rows)
        ):
            raise JobDefinitionHttpTransportError(_UNAVAILABLE)
        return payload

    def _request(
        self, method: str, path: str, body: Mapping[str, object] | None,
        *, query: str | None = None, override: str | None = None,
    ) -> tuple[int, object]:
        url = f"{self._config.base_url}{path}"
        if query is not None:
            url += f"?{query}"
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self._config.bearer_token}",
        }
        if override is not None:
            headers["X-Http-Method-Override"] = override
        try:
            import httpx

            factory = self._client_factory or httpx.Client
            with factory(
                verify=_ssl_context(self._config),
                timeout=self._config.timeout_seconds,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                response = client.request(method, url, headers=headers, json=body)
            if (
                "json" not in response.headers.get("content-type", "").lower()
                or len(response.content) > MAX_RESPONSE_BYTES
            ):
                raise ValueError
            return int(response.status_code), json.loads(response.content)
        except Exception:
            raise JobDefinitionHttpTransportError(_UNAVAILABLE) from None


def _require_created_fields(row: Mapping[str, object], body: Mapping[str, object]) -> None:
    # $originalName is a create-only control, never persisted. A formatted
    # table summary cannot substitute for complete configuration evidence.
    persisted = {key: value for key, value in body.items() if key != "$originalName"}
    actual = {key: row[key] for key in persisted}
    if not hmac.compare_digest(_digest(actual), _digest(persisted)):
        raise ValueError


def _digest(body: Mapping[str, object]) -> str:
    return hashlib.sha256(json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")).hexdigest()
