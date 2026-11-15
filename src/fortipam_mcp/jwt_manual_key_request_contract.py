"""I/O-free native JWT request/ACK candidate, without runtime authority.

The frozen body contract remains unchanged. This separate boundary binds the
inherited metadata query; native backend success still requires qualification.
"""
from __future__ import annotations

from collections.abc import Mapping
import hashlib

from .jwt_manual_key_contract import (
    JwtManualCreatePlan, build_jwt_manual_create_body, _Private, _fail, _digest, _require_digest,
)

REQUEST_CONTRACT = "fortipam-700-build29-manual-jwt-public-key-request-private-v1"


class JwtManualCreateRequest(_Private):
    """Fixed native request metadata and caller-owned bytes, without authority.

    This request adds the native inherited metadata query to the existing body
    contract. It performs no IO, permission check, dispatch reservation or retry.
    Its digest cannot stand in for original-wire custody or server authorization.
    """

    __slots__ = ("_body", "_closed", "_name", "plan_digest", "schema_digest", "defaults_digest", "serial_digest", "body_digest", "digest")
    _body: bytearray
    _closed: bool
    _name: str
    plan_digest: str
    schema_digest: str
    defaults_digest: str
    serial_digest: str
    body_digest: str
    digest: str

    def __init__(self, plan: JwtManualCreatePlan, defaults: Mapping[str, object], *,
                 schema_digest: str, serial_digest: str) -> None:
        body = build_jwt_manual_create_body(plan, defaults, schema_digest=schema_digest, serial_digest=serial_digest)
        try:
            values = {"_body":body, "_closed":False, "_name":plan._name, "plan_digest":plan.digest,
                "schema_digest":schema_digest, "defaults_digest":plan._default_digest, "serial_digest":serial_digest,
                "body_digest":hashlib.sha256(body).hexdigest()}
            for name, value in values.items():
                object.__setattr__(self, name, value)
            object.__setattr__(self, "digest", self._request_digest())
        except BaseException:
            body[:] = b"\x00" * len(body)
            raise

    @property
    def method(self) -> str:
        return "POST"

    @property
    def path(self) -> str:
        return "/api/v2/cmdb/secret/jwt-key"

    @property
    def query(self) -> str:
        return "with_meta=true"

    def _request_digest(self) -> str:
        return _digest({"contract":REQUEST_CONTRACT, "plan":self.plan_digest,
            "schema":self.schema_digest, "defaults":self.defaults_digest,
            "serial":self.serial_digest, "body":self.body_digest, "name":self._name,
            "method":self.method, "path":self.path, "query":self.query})

    def validate(self) -> None:
        if (self._closed or type(self._body) is not bytearray
                or hashlib.sha256(self._body).hexdigest() != self.body_digest
                or self._request_digest() != self.digest):
            self.close()
            _fail()

    def borrow_body(self) -> memoryview:
        self.validate()
        return memoryview(self._body).toreadonly()

    def close(self) -> None:
        self._body[:] = b"\x00" * len(self._body)
        object.__setattr__(self, "_closed", True)


class JwtManualCreateAck(_Private):
    """Only a response-shape observation; no original dispatch or ownership."""

    __slots__ = ("request_digest", "response_digest")
    request_digest: str
    response_digest: str

    def __init__(self, request_digest: str, response_digest: str) -> None:
        _require_digest(request_digest)
        _require_digest(response_digest)
        object.__setattr__(self, "request_digest", request_digest)
        object.__setattr__(self, "response_digest", response_digest)


def consume_jwt_manual_create_ack(raw: bytearray, request: JwtManualCreateRequest, *, http_status: int) -> JwtManualCreateAck:
    """Consume strict candidate CMDB POST/success metadata and erase all bytes.

    JWT-specific native success is still unqualified. A future trusted producer
    must capture bounded failure/unknown responses before invoking this consumer,
    and independently bind actual wire ownership, full state and recovery.
    """
    from . import secret_bulk_import_metadata as parser
    from .secret_metadata_http_transport import _skip_json_space, _json_value_end, _zeroize_mutable
    try:
        if (type(raw) is not bytearray or not 0 < len(raw) <= 524288
                or type(request) is not JwtManualCreateRequest or type(http_status) is not int or http_status != 200):
            _fail()
        request.validate()
        start = _skip_json_space(raw, 0)
        end = _json_value_end(raw, start)
        if _skip_json_space(raw, end) != len(raw):
            _fail()
        parser._validate_json(raw, start, end, depth=0, budget=[50000])
        fields = parser._object_spans(raw, start, end, frozenset({"version", "build", "serial", "http_method",
            "http_status", "status", "path", "name", "vdom", "mkey", "error", "schema_errors", "action"}))
        for name, wanted in {"version":"v7.0.0", "build":29, "http_method":"POST", "http_status":200,
                "status":"success", "path":"secret", "name":"jwt-key", "vdom":"root", "mkey":request._name}.items():
            value = parser._scalar(raw, fields[name])
            if type(value) is not type(wanted) or value != wanted:
                _fail()
        serial = parser._text(parser._scalar(raw, fields["serial"]), maximum=128)
        if hashlib.sha256(serial.encode()).hexdigest() != request.serial_digest or "schema_errors" in fields:
            _fail()
        if "error" in fields:
            value = parser._scalar(raw, fields["error"])
            if type(value) is not int or value != 0:
                _fail()
        if "action" in fields and parser._scalar(raw, fields["action"]) != "":
            _fail()
        return JwtManualCreateAck(request.digest, hashlib.sha256(raw).hexdigest())
    except Exception:
        _fail()
    finally:
        if type(raw) is bytearray:
            _zeroize_mutable(raw)


__all__ = ["REQUEST_CONTRACT", "JwtManualCreateRequest", "JwtManualCreateAck", "consume_jwt_manual_create_ack"]
