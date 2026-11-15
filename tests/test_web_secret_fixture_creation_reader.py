from dataclasses import replace
import math
import ssl

import pytest

from fortipam_mcp import web_secret_fixture_creation_reader as reader
from test_instruction_feature_http_reader import Client, Response
from test_web_secret_fixture_creation import _setup, _response
from test_web_secret_create_dispatch_observation import _transport, _Connection, _create


def _fixture(tmp_path, monkeypatch, mode="success"):
    bindings, connection = _setup(tmp_path, monkeypatch, mode)
    monkeypatch.setattr(reader, "_ssl_context", lambda _: ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))
    client = Client([Response(_response(bindings["create_binding"]))])
    seen = []

    def factory(**kwargs):
        seen.append(kwargs)
        return client

    config = bindings["transport"]._config
    return bindings, connection, config, client, factory, seen


def test_fixed_get_qualifies_then_joins_only_after_resource_closure(tmp_path, monkeypatch):
    bindings, connection, config, client, factory, seen = _fixture(tmp_path, monkeypatch)
    actual_join = reader.join_web_secret_fixture_creation
    buffers = []

    def join(**kwargs):
        assert client.is_closed and not client.cookies and client.responses[0].is_closed
        buffers.append(kwargs["response"])
        return actual_join(**kwargs)

    monkeypatch.setattr(reader, "join_web_secret_fixture_creation", join)
    before = bindings["execution_store"]._path.read_bytes()
    proof = reader.read_web_secret_fixture_creation(config, **bindings, client_factory=factory)
    assert proof.native_secret_id == 37 and connection.posts == 1
    assert bindings["execution_store"]._path.read_bytes() == before
    assert buffers and all(not any(buffer) for buffer in buffers)
    assert len(client.calls) == 1
    method, url, kwargs = client.calls[0]
    assert method == "GET" and url == config.base_url + reader._ROUTE
    assert kwargs["headers"]["Authorization"] == "Bearer " + config.bearer_token
    assert kwargs["headers"]["Accept-Encoding"] == "identity"
    assert seen[0]["follow_redirects"] is False and seen[0]["trust_env"] is False
    assert seen[0]["verify"].check_hostname and seen[0]["verify"].verify_mode == ssl.CERT_REQUIRED
    assert seen[0]["verify"].minimum_version >= ssl.TLSVersion.TLSv1_2


@pytest.mark.parametrize("mode", ["missing_ack", "missing_claim", "unfinished", "unknown", "post_mismatch"])
def test_original_creation_must_qualify_before_client_or_get(tmp_path, monkeypatch, mode):
    bindings, _, config, client, factory, seen = _fixture(tmp_path, monkeypatch, mode)
    before = bindings["execution_store"]._path.read_bytes()
    with pytest.raises(reader.WebSecretFixtureCreationReadError):
        reader.read_web_secret_fixture_creation(config, **bindings, client_factory=factory)
    assert not client.calls and not seen
    assert bindings["execution_store"]._path.read_bytes() == before


def test_unqualified_nonzero_request_uuid_refuses_before_client(tmp_path, monkeypatch):
    bindings, _, config, client, factory, seen = _fixture(tmp_path, monkeypatch)
    transport = _transport(monkeypatch, _Connection())
    _create(transport, bindings["create_binding"], bindings["execution_binding"].lease_request)
    bindings["transport"] = transport
    with pytest.raises(reader.WebSecretFixtureCreationReadError):
        reader.read_web_secret_fixture_creation(config, **bindings, client_factory=factory)
    assert not client.calls and not seen


@pytest.mark.parametrize("defect", ["http", "redirect", "encoding", "content_type", "oversize", "native"])
def test_invalid_response_is_not_published_and_resources_close(tmp_path, monkeypatch, defect):
    bindings, _, config, client, factory, _ = _fixture(tmp_path, monkeypatch)
    response = client.responses[0]
    if defect == "http": response.status_code = 403
    elif defect == "redirect": response.status_code = 302
    elif defect == "encoding": response.headers["content-encoding"] = "gzip"
    elif defect == "content_type": response.headers["content-type"] = "text/plain"
    elif defect == "oversize": response.content = bytearray(b"x" * (reader._LIMIT + 1))
    else: response.content = bytearray(b'{"results":[]}')
    wiped = []
    actual_wipe = reader._zeroize_mutable

    def wipe(buffer):
        actual_wipe(buffer)
        wiped.append(buffer)

    monkeypatch.setattr(reader, "_zeroize_mutable", wipe)
    with pytest.raises(reader.WebSecretFixtureCreationReadError, match="^The private Web fixture creation source is unavailable.$"):
        reader.read_web_secret_fixture_creation(config, **bindings, client_factory=factory)
    assert len(client.calls) == 1 and client.is_closed and response.is_closed and not client.cookies
    assert wiped and all(not any(buffer) for buffer in wiped)


@pytest.mark.parametrize("defect", ["origin_userinfo", "token", "serial", "store", "tls"])
def test_configuration_or_startup_binding_refuses_before_client(tmp_path, monkeypatch, defect):
    bindings, _, config, client, factory, seen = _fixture(tmp_path, monkeypatch)
    if defect == "origin_userinfo": config = replace(config, base_url="https://unit:password@fpa.example.test")
    elif defect == "token": config = replace(config, bearer_token="different-unit-token")
    elif defect == "serial": bindings["serial_digest"] = "invalid"
    elif defect == "store": bindings["expected_store_digest"] = "e" * 64
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        monkeypatch.setattr(reader, "_ssl_context", lambda _: context)
    with pytest.raises(reader.WebSecretFixtureCreationReadError):
        reader.read_web_secret_fixture_creation(config, **bindings, client_factory=factory)
    assert not seen and not client.calls


@pytest.mark.parametrize("values", [[math.nan], [math.inf], [10.0, 9.0], [10.0, 26.0]])
def test_invalid_or_expired_monotonic_clock_stops_before_get(tmp_path, monkeypatch, values):
    bindings, _, config, client, factory, seen = _fixture(tmp_path, monkeypatch)
    clock = iter(values)
    with pytest.raises(reader.WebSecretFixtureCreationReadError):
        reader.read_web_secret_fixture_creation(config, **bindings, client_factory=factory, clock=lambda: next(clock))
    assert not seen and not client.calls


def test_central_smaller_timeout_is_retained(tmp_path, monkeypatch):
    bindings, _, config, client, factory, seen = _fixture(tmp_path, monkeypatch)
    config = replace(config, timeout_seconds=2)
    bindings["transport"]._config = config
    clock = iter([10.0, 11.0, 11.0, 11.0, 13.0])
    with pytest.raises(reader.WebSecretFixtureCreationReadError):
        reader.read_web_secret_fixture_creation(config, **bindings, client_factory=factory, clock=lambda: next(clock))
    assert seen[0]["timeout"] == 1 and client.calls[0][2]["timeout"] == 1
    assert client.is_closed and client.responses[0].is_closed and not client.cookies


def test_cleanup_refusal_cannot_publish_or_call_join(tmp_path, monkeypatch):
    bindings, _, config, client, factory, _ = _fixture(tmp_path, monkeypatch)
    actual_exit = Client.__exit__

    def unclosed(self, *args):
        actual_exit(self, *args)
        self.is_closed = False

    monkeypatch.setattr(Client, "__exit__", unclosed)
    monkeypatch.setattr(reader, "join_web_secret_fixture_creation", lambda **_kwargs: pytest.fail("Cleanup must precede join."))
    with pytest.raises(reader.WebSecretFixtureCreationReadError):
        reader.read_web_secret_fixture_creation(config, **bindings, client_factory=factory)
    assert client.responses[0].is_closed and not client.cookies
