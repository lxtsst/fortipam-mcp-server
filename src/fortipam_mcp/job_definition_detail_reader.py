"""Private build-29 readback of one disabled Job's 22 creation fields.

This reader has no configuration, activation, execution, or MCP registration.
The host supplies an existing scoped Owner and a protected compiled expectation.
"""
from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
from urllib.parse import quote

from .job_definition_create_contract import compile_disabled_job_create_body
from .job_definition_http_transport import _SOURCE, _digest
from .job_definition_projection import JobDefinitionExpectation, JobDefinitionReadback
from .local_user_reset_fixture_preflight import _actor_context
from .local_user_reset_metadata_reader import _validate_value
from .local_user_reset_projection import _object_spans
from .owner_session_metadata import OwnerSessionMetadataTransport
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable
from .target_api_dependency_reader import _private_http_logs

_UNAVAILABLE = "The fixed disabled Job detail read is unavailable."
_LIMIT = 1024 * 1024
_COLLECTION = "/api/v2/cmdb/secret/job?with_meta=true&vdom=root"
_EXECUTION_FIELDS = ("execution-time-start", "execution-time-end", "result-txt")
# Qualified build-29 collection summary omits four fields and transforms six.
# The exact detail always checks all 22; these exclusions apply only to the join.
_SUMMARY_TRANSFORMED = frozenset({
    "ssh-procedure", "web-api-procedure", "web-proxy-port", "web-proxy-server",
    "job-sch-frequency", "job-sch-interval", "job-sch-month-day", "job-sch-month-type",
    "job-sch-start-date", "scheduled-time",
})
_ENVELOPE: dict[str, str | int] = {
    "http_method": "GET", "http_status": 200, "status": "success",
    "version": "v7.0.0", "build": 29, "path": "secret", "name": "job", "vdom": "root",
}
_READ_FAILURE_STAGES = frozenset({
    "unavailable", "reader_context", "actor_context", "read_session",
    "read_collection_headers", "read_transport", "read_response", "read_bounds",
    "read_response_unauthorized", "read_response_forbidden", "read_response_not_found",
    "read_response_rate_limited", "read_response_content_type",
    "detail_envelope", "detail_shape", "detail_definition", "detail_origin",
    "detail_control", "detail_result", "detail_execution", "detail_drift",
    "collection_envelope", "collection_shape", "collection_selection",
    "collection_definition", "collection_execution",
})


class JobDefinitionDetailReaderError(RuntimeError):
    """Non-disclosing failure of a fixed protected read."""

    stage = "unavailable"


def _read_failure(error: Exception, stage: str) -> JobDefinitionDetailReaderError:
    result = JobDefinitionDetailReaderError(_UNAVAILABLE)
    result.stage = (error.stage if isinstance(error, JobDefinitionDetailReaderError)
                    and type(error.stage) is str and error.stage in _READ_FAILURE_STAGES else stage)
    if result.stage not in _READ_FAILURE_STAGES:
        result.stage = "unavailable"
    return result


@dataclass(frozen=True, slots=True)
class JobDefinitionPristineReadback:
    """One exact disabled definition plus bracketed native not-started evidence."""

    definition: JobDefinitionReadback
    not_started: bool
    unreferenced: bool
    nonstatic: bool
    timeout_matches_expectation: bool

    @property
    def verified(self) -> bool:
        return (self.definition.definition_verified and self.not_started and self.unreferenced
                and self.nonstatic and self.timeout_matches_expectation)


class JobDefinitionDetailReader:
    """Read only the privately bound Job; release its session on every exit."""

    def __init__(
        self, owner: OwnerSessionMetadataTransport, *, expected_serial: str,
        expected: JobDefinitionExpectation, expected_create_body: Mapping[str, object],
        expected_max_timeout: int | None = None,
    ) -> None:
        try:
            if (not isinstance(owner, OwnerSessionMetadataTransport)
                    or owner._allow_secret_create or owner._allow_collector_credential_repair
                    or type(expected_serial) is not str or not expected_serial.isascii()
                    or not expected_serial.isalnum() or not 1 <= len(expected_serial) <= 64
                    or type(expected) is not JobDefinitionExpectation):
                raise ValueError
            # Reuse the established fixed compiler; do not admit another script,
            # requester, Secret, enabled state, or partial expected body here.
            body = dict(expected_create_body)
            source = {key: value for key, value in body.items() if key != "$originalName"}
            source.update(name=_SOURCE, user="admin", **{"approval-status": "approved"})
            compiled = compile_disabled_job_create_body(
                {"status": "success", "version": "v7.0.0", "build": 29, "results": source},
                source_name=_SOURCE, target_name=expected.name,
                target_requester=expected.requester, expected_secret_id=expected.secret_id,
            )
            if body != compiled or expected.script != "echo BP008_JOB_OK":
                raise ValueError
            if expected_max_timeout is not None and (type(expected_max_timeout) is not int
                    or not 0 <= expected_max_timeout <= 2**31 - 1):
                raise ValueError
            self._expected_tokens = {
                key: _token(value) for key, value in compiled.items() if key != "$originalName"
            }
            self._expected_tokens["approval-status"] = _token("approved")
            self._create_body_digest = _digest(compiled)
            self._serial_digest = hashlib.sha256(expected_serial.encode("ascii")).hexdigest()
            self._serial_token = _token(expected_serial)
            self._timeout_token = _token(expected_max_timeout) if expected_max_timeout is not None else None
            if expected_max_timeout is not None:
                self._expected_tokens["max-timeout"] = _token(expected_max_timeout)
            self._envelope = {key: _token(value) for key, value in _ENVELOPE.items()}
            self._envelope["serial"] = _token(expected_serial)
            self._name = expected.name
            self._owner = owner
            self._path = "/api/v2/cmdb/secret/job/" + quote(expected.name, safe="") + "?vdom=root"
            self._metadata_path = self._path.removesuffix("?vdom=root") + "?with_meta=true&vdom=root"
            self._last_failure_stage: str | None = None
        except Exception:
            raise JobDefinitionDetailReaderError(_UNAVAILABLE) from None

    def _bound_definition_digests(self) -> tuple[str, str, str]:
        """Recheck protected expected tokens before joining original-ACK custody.

        Reconstruct only host-supplied expected bytes, never returned Job values.
        This private fingerprint supplies no ownership, absence or authority.
        """
        try:
            if ("max-timeout" not in self._expected_tokens
                    or self._envelope["serial"] != self._serial_token
                    or hashlib.sha256(self._serial_token[1:-1]).hexdigest() != self._serial_digest
                    or self._expected_tokens["max-timeout"] != self._timeout_token
                    or self._expected_tokens["approval-status"] != _token("approved")
                    or self._expected_tokens["name"] != _token(self._name)
                    or self._path != "/api/v2/cmdb/secret/job/" + quote(self._name, safe="") + "?vdom=root"
                    or self._metadata_path != self._path.removesuffix("?vdom=root") + "?with_meta=true&vdom=root"):
                raise ValueError
            expected = {key: token for key, token in self._expected_tokens.items()
                        if key not in {"approval-status", "max-timeout"}}
            expected["$originalName"] = b'""'
            body = b"{" + b",".join(_token(key) + b":" + expected[key] for key in sorted(expected)) + b"}"
            if hashlib.sha256(body).hexdigest() != self._create_body_digest:
                raise ValueError
            return (self._create_body_digest, self._serial_digest,
                    hashlib.sha256(self._expected_tokens["max-timeout"]).hexdigest())
        except Exception:
            raise JobDefinitionDetailReaderError(_UNAVAILABLE) from None

    def readback(self) -> JobDefinitionReadback:
        """Return categorical exact-match evidence, never script or selectors."""
        self._last_failure_stage = None
        try:
            with _private_http_logs(), self._owner.authenticated(), self._failure_scope():
                raw = self._read("/api/v2/monitor/web-ui/state")
                try:
                    _actor_context(raw, expected_name=self._owner._owner_name)
                finally:
                    _zeroize_mutable(raw)
                result = self._project(self._read(self._path))
            if self._owner.logout_verified is not True:
                raise ValueError
            return result
        except Exception as error:
            raise _read_failure(error, self._last_failure_stage or "reader_context") from None

    def read_pristine(self) -> JobDefinitionPristineReadback:
        """Join complete details with native zero execution state; never run a Job.

        Re-read the exact detail after the collection so observed execution-field
        bytes and all 22 creation fields must remain stable across the join.
        This is neither global absence nor original-ACK ownership evidence.
        """
        self._last_failure_stage = None
        try:
            if "max-timeout" not in self._expected_tokens:
                raise ValueError
            with _private_http_logs(), self._owner.authenticated(), self._failure_scope():
                result, _ = self._pristine_in_session()
            if self._owner.logout_verified is not True:
                raise ValueError
            return result
        except Exception as error:
            raise _read_failure(error, self._last_failure_stage or "reader_context") from None

    @contextmanager
    def _failure_scope(self) -> Iterator[None]:
        """Retain a fixed category before the Owner wraps the body exception."""
        self._last_failure_stage = None
        try:
            yield
        except Exception as error:
            self._last_failure_stage = _read_failure(error, "reader_context").stage
            raise

    def _pristine_in_session(self) -> tuple[JobDefinitionPristineReadback, str]:
        with self._failure_scope():
            return self._pristine_read_in_session()

    def _pristine_read_in_session(self) -> tuple[JobDefinitionPristineReadback, str]:
        """Share a fixed read with a trusted source's already authenticated Owner.

        The complete row fingerprint includes undecoded extra fields. It cannot
        replace original creation custody or qualify a different Job/identity.
        """
        if self._owner._client is None or "max-timeout" not in self._expected_tokens:
            raise _read_failure(ValueError(), "read_session") from None
        from .target_preservation_contract import _digest, _token_digest
        raw = self._read("/api/v2/monitor/web-ui/state")
        try:
            _actor_context(raw, expected_name=self._owner._owner_name)
        except Exception as error:
            raise _read_failure(error, "actor_context") from None
        finally:
            _zeroize_mutable(raw)

        def snapshot() -> tuple[JobDefinitionReadback, str]:
            data = self._read(self._metadata_path)
            stage = "detail_envelope"
            try:
                envelope = self._envelope_fields(data)
                stage = "detail_shape"
                from .target_lifecycle_dependencies import _one
                row = _one(data, envelope["results"])
                fields = _object_spans(data, *row)
                state = _digest({key: _token_digest(data, span) for key, span in fields.items()})
                result, _ = self._project_detail(data, execution_witness=True)
                return result, state
            except Exception as error:
                raise _read_failure(error, stage) from None
            finally:
                _zeroize_mutable(data)

        _, before = snapshot()
        self._project_not_started(self._read(_COLLECTION, collection=True))
        definition, after = snapshot()
        if before != after:
            raise _read_failure(ValueError(), "detail_drift") from None
        return JobDefinitionPristineReadback(definition, True, True, True, True), after

    def _read(self, path: str, *, collection: bool = False) -> bytearray:
        raw = bytearray()
        stage = "read_session"
        try:
            owner = self._owner
            if owner._client is None or owner._clock() >= owner._expires_at:
                raise ValueError
            headers = {
                "Accept": "application/json", "Accept-Encoding": "identity",
                "Cache-Control": "no-cache, no-store",
            }
            body = None
            if collection:
                stage = "read_collection_headers"
                if path != _COLLECTION:
                    raise ValueError
                csrf = owner._client.cookies.get("ccsrftoken")
                if type(csrf) is not str or not csrf or any(c in csrf for c in "\r\n"):
                    raise ValueError
                headers.update({"X-HTTP-Method-Override": "GET", "X-CSRFTOKEN": csrf.strip('"'),
                                "Content-Type": "application/json"})
                body = b'{"json_filter":[]}'
            stage = "read_transport"
            with owner._client.stream("POST" if collection else "GET", path, headers=headers, content=body) as response:
                stage = "read_response"
                if (type(response.status_code) is not int or response.status_code != 200
                        or response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                        != "application/json"):
                    stage = {401:"read_response_unauthorized",403:"read_response_forbidden",
                        404:"read_response_not_found",429:"read_response_rate_limited"}.get(response.status_code,
                            "read_response_content_type" if response.status_code == 200 else "read_response")
                    raise ValueError
                stage = "read_transport"
                for chunk in response.iter_bytes():
                    if owner._clock() >= owner._expires_at:
                        raise _read_failure(ValueError(), "read_session") from None
                    if len(raw) + len(chunk) > _LIMIT:
                        raise _read_failure(ValueError(), "read_bounds") from None
                    raw.extend(chunk)
            if owner._clock() >= owner._expires_at:
                raise _read_failure(ValueError(), "read_session") from None
            return raw
        except BaseException as error:
            _zeroize_mutable(raw)
            if isinstance(error, Exception):
                raise _read_failure(error, stage) from None
            raise

    def _project(self, raw: bytearray) -> JobDefinitionReadback:
        return self._project_detail(raw)[0]

    def _envelope_fields(self, raw: bytearray, *, collection: bool = False) -> dict[str, tuple[int, int]]:
        if not 0 < len(raw) <= _LIMIT:
            raise ValueError
        left = _skip_json_space(raw, 0)
        right = _json_value_end(raw, left)
        if _skip_json_space(raw, right) != len(raw):
            raise ValueError
        _validate_value(raw, left, right, depth=0)
        envelope = _object_spans(raw, left, right)
        for key, token in self._envelope.items():
            if collection and key in {"http_method", "status"}:
                token = _token("POST" if key == "http_method" else "OK")
            _require_token(raw, envelope[key], token)
        if "mkey" in envelope and not collection:
            _require_token(raw, envelope["mkey"], _token(self._name))
        if "error" in envelope:
            with memoryview(raw)[slice(*envelope["error"])] as error:
                if len(error) > 4 or error.tobytes() not in (b"0", b"null"):
                    raise ValueError
        return envelope

    def _project_detail(self, raw: bytearray, *, execution_witness: bool = False) -> tuple[JobDefinitionReadback, str | None]:
        stage = "detail_envelope"
        try:
            envelope = self._envelope_fields(raw)
            stage = "detail_shape"
            left, right = envelope["results"]
            if raw[left] == 91:
                left = _skip_json_space(raw, left + 1)
                end = _json_value_end(raw, left)
                if _skip_json_space(raw, end) != right - 1:
                    raise ValueError
                right = end
            fields = _object_spans(raw, left, right)
            stage = "detail_definition"
            for key, token in self._expected_tokens.items():
                _require_token(raw, fields[key], token)
            stage = "detail_origin"
            if "q_origin_key" in fields:
                _require_token(raw, fields["q_origin_key"], _token(self._name))
            witness = None
            if execution_witness:
                stage = "detail_control"
                _require_token(raw, fields["q_ref"], b"0")
                _require_token(raw, fields["q_static"], b"false")
                stage = "detail_result"
                _require_token(raw, fields["result-txt"], b'""')
                stage = "detail_execution"
                digest = hashlib.sha256()
                for key in _EXECUTION_FIELDS:
                    digest.update(key.encode("ascii") + b"\x00")
                    with memoryview(raw)[slice(*fields[key])] as value:
                        digest.update(value)
                    digest.update(b"\x00")
                witness = digest.hexdigest()
            return JobDefinitionReadback(True, True, True, True, True, True, True, True), witness
        except Exception as error:
            raise _read_failure(error, stage) from None
        finally:
            _zeroize_mutable(raw)

    def _project_not_started(self, raw: bytearray) -> None:
        stage = "collection_envelope"
        try:
            envelope = self._envelope_fields(raw, collection=True)
            stage = "collection_shape"
            from .ldap_server_projection import _array
            rows = _array(raw, envelope["results"])
            if len(rows) > 4096:
                raise ValueError
            selected = []
            for span in rows:
                fields = _object_spans(raw, *span)
                name_span = fields["name"]
                if raw[name_span[0]] != 34:
                    raise ValueError
                with memoryview(raw)[slice(*name_span)] as name:
                    if name == self._expected_tokens["name"]:
                        selected.append(fields)
            stage = "collection_selection"
            if len(selected) != 1:
                raise ValueError
            fields = selected[0]
            stage = "collection_definition"
            for key, token in self._expected_tokens.items():
                if key not in _SUMMARY_TRANSFORMED and key != "max-timeout":
                    _require_token(raw, fields[key], token)
            stage = "collection_execution"
            for key, value in zip(_EXECUTION_FIELDS, (0, 0, ""), strict=True):
                _require_token(raw, fields[key], _token(value))
        except Exception as error:
            raise _read_failure(error, stage) from None
        finally:
            _zeroize_mutable(raw)


def _token(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def _require_token(raw: bytearray, span: tuple[int, int], expected: bytes) -> None:
    # Compare the fixed native wire value without decoding returned script text
    # or unselected values. Native empty procedure arrays contain JSON whitespace.
    with memoryview(raw)[slice(*span)] as token:
        if token == expected:
            return
        if (expected == b"[]" and len(token) >= 2 and token[0] == 91 and token[-1] == 93
                and all(token[index] in (9, 10, 13, 32) for index in range(1, len(token) - 1))):
            return
        raise ValueError
