"""Fixed feature source ordering, failure stop and resource cleanup."""
from __future__ import annotations
from contextlib import contextmanager
import ssl
from typing import Any
import pytest
from fortipam_mcp import instruction_feature_http_reader as r
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from test_instruction_feature_contract import SERIAL, envelope, reverse_schema


class Response:
    def __init__(self, content: bytearray, status: int = 200):
        self.content, self.status_code = content, status
        self.headers = {"content-type":"application/json"}
        self.is_closed = False
    def iter_raw(self):
        yield bytes(self.content)


class Client:
    def __init__(self, responses: list[Response]):
        self.responses, self.calls = responses, []
        self.cookies = {"synthetic":"private-cookie"}
        self.is_closed = False
    def __enter__(self):
        return self
    def __exit__(self,*args):
        self.is_closed = True
    @contextmanager
    def stream(self,method,url,**kwargs):
        self.calls.append((method,url,kwargs))
        response = self.responses[len(self.calls)-1]
        try:
            yield response
        finally:
            response.is_closed = True


def fixture(monkeypatch: pytest.MonkeyPatch, status: int = 200):
    monkeypatch.setattr(r,"_ssl_context",lambda _:ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))
    schema = envelope({"children":{"guest-instruction":{"type":"option","options":[{"name":"enable"},{"name":"disable"}]},"future-field":{"type":"string"},"reverse-service-setting":reverse_schema()}},schema=True)
    current = envelope({"guest-instruction":"disable","future-field":"synthetic-private-value","reverse-service-setting":[]})
    client = Client([Response(schema,status),Response(current)])
    configuration = SecretMetadataHttpTransportConfig("https://synthetic.example.test","synthetic-token",30,None)
    kwargs_seen: list[dict[str,Any]] = []
    def factory(**kwargs):
        kwargs_seen.append(kwargs)
        return client
    return client,configuration,factory,kwargs_seen


def test_full_fixed_reads_close_every_resource(monkeypatch: pytest.MonkeyPatch) -> None:
    client,configuration,factory,seen = fixture(monkeypatch)
    state = r.read_instruction_feature_setting(configuration,serial_digest=SERIAL,client_factory=factory)
    assert not state.enabled and state.field_count == 3
    assert [(method,url) for method,url,_ in client.calls] == [("GET","https://synthetic.example.test"+path) for path in r._ROUTES]
    assert seen[0]["follow_redirects"] is False and seen[0]["trust_env"] is False
    assert client.is_closed and not client.cookies and all(response.is_closed for response in client.responses)


def test_failed_schema_stops_before_second_get_and_closes(monkeypatch: pytest.MonkeyPatch) -> None:
    client,configuration,factory,_ = fixture(monkeypatch,403)
    with pytest.raises(r.InstructionFeatureReadError,match="^The private Instruction feature source is unavailable.$"):
        r.read_instruction_feature_setting(configuration,serial_digest=SERIAL,client_factory=factory)
    assert len(client.calls) == 1 and client.responses[0].is_closed
    assert client.is_closed and not client.cookies


@pytest.mark.parametrize("invalid",[b'{"results":{}}',b'foreign-device'])
def test_http_200_invalid_schema_stops_at_first_get(monkeypatch: pytest.MonkeyPatch, invalid: bytes) -> None:
    client,configuration,factory,_ = fixture(monkeypatch)
    response = client.responses[0]
    if invalid == b'foreign-device':
        response.content[:] = bytes(response.content).replace(b'synthetic-device',invalid)
    else:
        response.content[:] = invalid
    with pytest.raises(r.InstructionFeatureReadError):
        r.read_instruction_feature_setting(configuration,serial_digest=SERIAL,client_factory=factory)
    assert len(client.calls) == 1 and response.is_closed
    assert client.is_closed and not client.cookies


def test_clock_rollback_stops_without_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    client,configuration,factory,_ = fixture(monkeypatch)
    values=iter([10.0,9.0])
    with pytest.raises(r.InstructionFeatureReadError):
        r.read_instruction_feature_setting(configuration,serial_digest=SERIAL,client_factory=factory,clock=lambda:next(values))
    assert not client.calls


def test_invalid_device_binding_stops_before_client_creation(monkeypatch: pytest.MonkeyPatch) -> None:
    client,configuration,factory,seen = fixture(monkeypatch)
    with pytest.raises(r.InstructionFeatureReadError):
        r.read_instruction_feature_setting(configuration,serial_digest="invalid",client_factory=factory)
    assert not seen and not client.calls


@pytest.mark.parametrize("origin",["https://synthetic-owner:synthetic-password@synthetic.example.test",
    "https://synthetic-owner@synthetic.example.test"])
def test_url_credentials_cannot_override_bearer_authentication(monkeypatch: pytest.MonkeyPatch,origin: str) -> None:
    client,_,factory,seen = fixture(monkeypatch)
    configuration = SecretMetadataHttpTransportConfig(origin,"synthetic-token",30,None)
    with pytest.raises(r.InstructionFeatureReadError):
        r.read_instruction_feature_setting(configuration,serial_digest=SERIAL,client_factory=factory)
    assert not seen and not client.calls


def test_oversized_response_stops_before_current_read_and_cleans(monkeypatch: pytest.MonkeyPatch) -> None:
    client,configuration,factory,_ = fixture(monkeypatch)
    client.responses[0].content = bytearray(b"x"*(r._LIMIT+1))
    with pytest.raises(r.InstructionFeatureReadError):
        r.read_instruction_feature_setting(configuration,serial_digest=SERIAL,client_factory=factory)
    assert len(client.calls) == 1 and client.responses[0].is_closed
    assert client.is_closed and not client.cookies


def test_invalid_utf8_schema_is_erased_before_bounded_fresh_read(monkeypatch: pytest.MonkeyPatch) -> None:
    client,configuration,factory,_ = fixture(monkeypatch)
    original_schema,current = client.responses
    bad = bytes(original_schema.content).replace(b'"string"',b'"\xff"')
    client.responses = [Response(bytearray(bad)),Response(bytearray(bad)),original_schema,current]
    erased: list[bytearray] = []
    original_zeroize = r._zeroize_mutable
    def erase(raw: bytearray) -> None:
        original_zeroize(raw)
        erased.append(raw)
    monkeypatch.setattr(r,'_zeroize_mutable',erase)
    state = r.read_instruction_feature_setting(configuration,serial_digest=SERIAL,client_factory=factory)
    assert not state.enabled and state.field_count == 3
    assert [url for _,url,_ in client.calls] == ['https://synthetic.example.test'+r._ROUTES[0]]*3+['https://synthetic.example.test'+r._ROUTES[1]]
    assert len(erased) == 4 and all(not raw for raw in erased)
    assert client.is_closed and not client.cookies and all(response.is_closed for response in client.responses)


def test_repeated_invalid_utf8_schema_stops_after_three_gets(monkeypatch: pytest.MonkeyPatch) -> None:
    client,configuration,factory,_ = fixture(monkeypatch)
    bad = bytes(client.responses[0].content).replace(b'"string"',b'"\xff"')
    client.responses = [Response(bytearray(bad)) for _ in range(3)]
    with pytest.raises(r.InstructionFeatureReadError):
        r.read_instruction_feature_setting(configuration,serial_digest=SERIAL,client_factory=factory)
    assert len(client.calls) == 3 and all(url.endswith(r._ROUTES[0]) for _,url,_ in client.calls)
    assert client.is_closed and not client.cookies and all(response.is_closed for response in client.responses)


def test_current_invalid_utf8_is_not_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    client,configuration,factory,_ = fixture(monkeypatch)
    client.responses[1].content[:] = bytes(client.responses[1].content).replace(b'synthetic-private-value',b'\xff')
    with pytest.raises(r.InstructionFeatureReadError):
        r.read_instruction_feature_setting(configuration,serial_digest=SERIAL,client_factory=factory)
    assert len(client.calls) == 2
    assert client.is_closed and not client.cookies and all(response.is_closed for response in client.responses)


def test_invalid_utf8_retry_does_not_reset_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    client,configuration,factory,_ = fixture(monkeypatch)
    client.responses[0].content[:] = bytes(client.responses[0].content).replace(b'"string"',b'"\xff"')
    expired = False
    original_zeroize = r._zeroize_mutable
    def erase(raw: bytearray) -> None:
        nonlocal expired
        original_zeroize(raw)
        expired = True
    monkeypatch.setattr(r,'_zeroize_mutable',erase)
    with pytest.raises(r.InstructionFeatureReadError):
        r.read_instruction_feature_setting(configuration,serial_digest=SERIAL,client_factory=factory,clock=lambda:31.0 if expired else 0.0)
    assert len(client.calls) == 1 and client.responses[0].is_closed
    assert client.is_closed and not client.cookies
