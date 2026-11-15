"""Synthetic fixed-reader checks, including the real User projection join."""
from __future__ import annotations

import json
import ssl
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from fortipam_mcp.local_user_reset_metadata_reader import (
    FortiPamLocalUserResetMetadataReader, LocalUserResetMetadataReadError,
    LocalUserResetReadFailure as Failure, _SCHEMA, _TYPES, _USAGE,
    _device_identity_digest,
)
from fortipam_mcp.secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig, SecretMetadataHttpTransportConfigurationError,
)
from test_local_user_reset_projection import NAME, _body, _case


@pytest.mark.parametrize("serial", ["SYNTHETIC01", "", None, 123, "invalid identity"])
def test_fixed_schema_device_identity_never_returns_the_serial(serial: Any) -> None:
    harness = Harness()
    schema = json.loads(harness.bodies["schema"])
    schema["serial"] = serial
    harness.bodies["schema"] = bytearray(json.dumps(schema).encode())
    if serial == "SYNTHETIC01":
        result = harness.reader.read_device_identity_digest()
        assert result == _device_identity_digest(serial.encode()) and serial not in result
    else:
        with pytest.raises(LocalUserResetMetadataReadError):
            harness.reader.read_device_identity_digest()
    assert harness.calls == [_SCHEMA]


def _monitor(route: str, results: Any, **updates: Any) -> bytearray:
    path, name = route.rsplit("/", 1)
    value = {"http_method": "GET", "path": path, "name": name, "action": "",
        "results": results, "status": "success", "serial": "synthetic", "version": "v7.0.0", "build": 29}
    if route == "system/object/usage":
        value["mkey"] = NAME
    value.update(updates)
    return bytearray(json.dumps(value, separators=(",", ":")).encode())


class Harness:
    def __init__(self) -> None:
        schema, record = _case()
        self.bodies = {"schema": bytearray(json.dumps(schema).encode()), "detail": _body(record),
            "types": _monitor("web-ui/object-urls", {"by_type": {"7": {"path": "system.admin"}}}),
            "usage": _monitor("system/object/usage", {"currently_using": []})}
        self.calls: list[str] = []
        self.buffers: list[bytearray] = []
        self.resources: list[Any] = []
        self.status = 200
        self.fail = ""
        self.reader = FortiPamLocalUserResetMetadataReader(
            SecretMetadataHttpTransportConfig("https://pam.example.test:9443", "synthetic-token", 5, None),
            username=NAME, connection_factory=self.connect,
        )

    def connect(self, host: str, port: int, **kwargs: Any) -> Any:
        assert (host, port) == ("pam.example.test", 9443)
        assert kwargs["context"].verify_mode == ssl.CERT_REQUIRED and kwargs["context"].check_hostname
        harness = self

        class Response:
            status = harness.status
            offset = 0
            closed = False
            body = bytearray()

            def getheader(self, name: str, default: str = "") -> str:
                return {"content-type": "text/html" if harness.fail == "media" else "application/json",
                    "content-encoding": "gzip" if harness.fail == "encoding" else "identity"}.get(name, default)

            def readinto(self, view: memoryview) -> int:
                harness.buffers.append(view.obj)
                if harness.fail == "read_timeout": raise TimeoutError("synthetic-timeout-detail")
                if harness.fail == "read_disconnect": raise ConnectionResetError("synthetic-connection-detail")
                if harness.fail == "count": return True  # type: ignore[return-value]
                count = min(len(view), len(self.body) - self.offset)
                view[:count] = self.body[self.offset:self.offset + count]
                self.offset += count
                return count

            def close(self) -> None:
                self.closed = True

        class Connection:
            closed = False
            response = Response()

            def request(self, method: str, path: str, *, headers: dict[str, str]) -> None:
                assert method == "GET" and headers["User-Agent"] == "fortipam-bp002-metadata-read/1"
                assert headers["Accept-Encoding"] == "identity"
                harness.calls.append(path)
                if harness.fail == "network": raise ConnectionError("synthetic-private-must-not-escape")
                key = "schema" if path == _SCHEMA else "types" if path == _TYPES else "usage" if path.startswith(_USAGE) else "detail"
                self.response.body = harness.bodies[key]

            def getresponse(self) -> Response:
                harness.resources.append(self.response)
                return self.response

            def close(self) -> None:
                self.closed = True

        result = Connection()
        self.resources.append(result)
        return result

    def disposed(self) -> None:
        assert all(not any(buffer) for buffer in self.buffers)
        assert all(resource.closed for resource in self.resources)


def test_four_fixed_gets_join_full_projection_and_reported_usage() -> None:
    h = Harness()
    result = h.reader.read_observation()
    assert result.user.username == NAME and result.usage_entry_count == 0
    assert not hasattr(result, "fixture_creation_digest")
    assert len(h.calls) == 4 and h.calls[:3] == [_SCHEMA,
        f"/api/v2/cmdb/system/admin/{NAME}?with_meta=true", _TYPES]
    query = parse_qs(urlsplit(h.calls[3]).query)
    assert query == {"mkey": [NAME], "qtypes": ["[7]"]}
    assert NAME not in repr(result) and "redacted" in repr(result)
    h.disposed()


@pytest.mark.parametrize("status,expected", [(401, Failure.AUTHORIZATION_DENIED),
    (403, Failure.AUTHORIZATION_DENIED), (404, Failure.NOT_FOUND), (302, Failure.UNQUALIFIED_RESPONSE)])
def test_http_failures_are_not_absence_or_zero(status: int, expected: Failure) -> None:
    h = Harness(); h.status = status
    with pytest.raises(LocalUserResetMetadataReadError) as error: h.reader.read_observation()
    assert error.value.reason is expected and len(h.calls) == 1
    h.disposed()


@pytest.mark.parametrize("fail,expected", [("network", Failure.TRANSPORT_UNAVAILABLE),
    ("media", Failure.UNQUALIFIED_RESPONSE), ("encoding", Failure.UNQUALIFIED_RESPONSE),
    ("count", Failure.UNQUALIFIED_RESPONSE), ("read_timeout", Failure.TIMED_OUT),
    ("read_disconnect", Failure.TRANSPORT_UNAVAILABLE)])
def test_transport_and_body_contract_failure_is_sanitized(fail: str, expected: Failure) -> None:
    h = Harness(); h.fail = fail
    with pytest.raises(LocalUserResetMetadataReadError) as error: h.reader.read_observation()
    assert error.value.reason is expected and error.value.__suppress_context__
    assert "synthetic-private" not in str(error.value)
    h.disposed()


@pytest.mark.parametrize("results", [{}, {"currently_using": None}, {"currently_using": {}},
    {"currently_using": False}, {"currently_using": [False]}, {"currently_using": ["synthetic"]}])
def test_missing_or_wrong_type_usage_never_becomes_zero(results: Any) -> None:
    h = Harness(); h.bodies["usage"] = _monitor("system/object/usage", results)
    with pytest.raises(LocalUserResetMetadataReadError): h.reader.read_observation()
    h.disposed()


@pytest.mark.parametrize("mkey", [None, "mcp-v4-user-reset-other", 7, False])
def test_usage_identity_must_match_exact_constructor_binding(mkey: Any) -> None:
    h = Harness()
    h.bodies["usage"] = _monitor("system/object/usage", {"currently_using": []}, mkey=mkey)
    with pytest.raises(LocalUserResetMetadataReadError):
        h.reader.read_observation()
    h.disposed()


def test_usage_identity_is_required_and_not_allowed_on_type_map() -> None:
    h = Harness()
    h.bodies["usage"] = h.bodies["usage"].replace(b',"mkey":' + json.dumps(NAME).encode(), b'')
    with pytest.raises(LocalUserResetMetadataReadError):
        h.reader.read_observation()
    h.disposed()
    h = Harness()
    h.bodies["types"] = _monitor("web-ui/object-urls", {"by_type": {"7": {"path": "system.admin"}}}, mkey=NAME)
    with pytest.raises(LocalUserResetMetadataReadError):
        h.reader.read_observation()
    h.disposed()


def test_usage_count_is_entry_count_not_sum_of_referring_object_counts() -> None:
    h = Harness(); h.bodies["usage"] = _monitor("system/object/usage", {
        "currently_using": [{"reference_count": 99}, {"reference_count": 300}], "other": None,
    })
    assert h.reader.read_observation().usage_entry_count == 2
    h.disposed()


@pytest.mark.parametrize("mapping", [{}, {"7": {"path": "system.other"}},
    {"7": {"path": "system.admin"}, "8": {"path": "system.admin"}}, {"07": {"path": "system.admin"}}])
def test_type_resolution_must_be_unique_and_canonical(mapping: Any) -> None:
    h = Harness(); h.bodies["types"] = _monitor("web-ui/object-urls", {"by_type": mapping})
    with pytest.raises(LocalUserResetMetadataReadError): h.reader.read_observation()
    assert len(h.calls) == 3
    h.disposed()


@pytest.mark.parametrize("key,value", [("build", 30), ("http_status", 403), ("status", "error"), ("action", "other")])
def test_monitor_firmware_route_and_business_status_are_pinned(key: str, value: Any) -> None:
    h = Harness(); h.bodies["types"] = _monitor("web-ui/object-urls", {"by_type": {}}, **{key: value})
    with pytest.raises(LocalUserResetMetadataReadError): h.reader.read_observation()
    h.disposed()


def test_detail_failure_prevents_any_usage_query() -> None:
    h = Harness(); h.bodies["detail"] = _body([])
    with pytest.raises(LocalUserResetMetadataReadError): h.reader.read_observation()
    assert len(h.calls) == 2
    h.disposed()


def test_unqualified_schema_prevents_material_bearing_user_read() -> None:
    h = Harness(); h.bodies["schema"] = bytearray(b'{"results":{}}')
    with pytest.raises(LocalUserResetMetadataReadError):
        h.reader.read_observation()
    assert h.calls == [_SCHEMA]
    h.disposed()


def test_oversized_response_is_bounded_cleared_and_never_followed() -> None:
    h = Harness(); h.bodies["schema"] = bytearray(b" " * 1_048_577)
    with pytest.raises(LocalUserResetMetadataReadError) as error:
        h.reader.read_observation()
    assert error.value.reason is Failure.UNQUALIFIED_RESPONSE
    assert len(h.calls) == 1
    h.disposed()


@pytest.mark.parametrize("fragment", [b'null', b'[{"reference_count":not_json}]', b'[{"a":0,"a":1}]', b'[{},]'])
def test_malformed_usage_fails_before_returning_a_count(fragment: bytes) -> None:
    h = Harness(); h.bodies["usage"] = _monitor("system/object/usage", {"currently_using": []}).replace(b'[]', fragment)
    with pytest.raises(LocalUserResetMetadataReadError): h.reader.read_observation()
    h.disposed()


@pytest.mark.parametrize("origin", ["https://pam.example.test:0", "http://pam.example.test", "https://user:password@pam.example.test"])
def test_invalid_origin_never_connects(origin: str) -> None:
    with pytest.raises((LocalUserResetMetadataReadError, SecretMetadataHttpTransportConfigurationError)):
        FortiPamLocalUserResetMetadataReader(SecretMetadataHttpTransportConfig(origin, "unused", 5, None), username=NAME)
