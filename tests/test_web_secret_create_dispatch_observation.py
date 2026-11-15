from dataclasses import replace

import pytest

from fortipam_mcp.secret_create_191_http_transport import FortiPam191SecretCreateHttpTransport
from fortipam_mcp.secret_create_191_private_adapter import SecretCreate191WebBinding
from test_secret_create_191_http_transport import _MetadataTransport, _config
from test_secret_create_central_lab_provider import _request
from v4_planning.secret_create_adapter import SecretCreateAdapterOutcome


def _web_binding():
    return SecretCreate191WebBinding(
        "fortipam-700-build29-web-secret-create-candidate-v1", "7.0.0", "1" * 64,
        "Public/example-folder", "example-secret", "Web Account",
        "https://app.example.test/login", True, 29,
    )


class _Response:
    def __init__(self, failure):
        self.status = 500 if failure == "status" else 200
        self.failure = failure
        self.closed = False

    def read(self, *_args):
        pytest.fail("The material-bearing response must never be read.")

    def close(self):
        self.closed = True
        if self.failure == "response_close":
            raise RuntimeError("synthetic response closure failure")


class _Connection:
    def __init__(self, failure=None):
        self.failure = failure
        self.response = _Response(failure)
        self.body = None
        self.posts = 0
        self.closed = False

    def request(self, method, path, body, headers):
        assert method == "POST" and path == "/api/v2/cmdb/secret/database"
        assert headers["Authorization"] == "Bearer unit-test-token"
        self.body = body.obj
        self.posts += 1
        if self.failure == "post":
            raise RuntimeError("synthetic dispatch uncertainty")

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True
        if self.failure == "connection_close":
            raise RuntimeError("synthetic connection closure failure")


def _transport(monkeypatch, connection, metadata=None):
    monkeypatch.setattr(
        "fortipam_mcp.secret_create_191_http_transport._ssl_context", lambda _: object(),
    )
    return FortiPam191SecretCreateHttpTransport(
        _config(), connection_factory=lambda *_args, **_kwargs: connection,
        metadata_transport=metadata or _MetadataTransport(),
    )


def _create(transport, binding=None, request=None):
    return transport._create_and_verify_with_material(
        binding or _web_binding(), request or _request(),
        memoryview(bytearray(b"unit-user")).toreadonly(),
        memoryview(bytearray(b"unit-password")).toreadonly(),
    )


def test_original_http_observation_binds_context_without_reading_material(monkeypatch):
    connection = _Connection()
    transport = _transport(monkeypatch, connection)
    binding, request = _web_binding(), _request()
    assert transport.read_web_create_dispatch_observation(binding, request) is None
    assert _create(transport, binding, request) is SecretCreateAdapterOutcome.VERIFIED_CREATED
    observation = transport.read_web_create_dispatch_observation(binding, request)
    assert observation is not None
    assert observation.binding == binding and observation.request == request
    assert observation.native_folder_id == 17
    assert observation.create_uuid == "11111111-2222-4333-8444-555555555555"
    assert observation.origin == _config().base_url
    assert str(observation) == repr(observation) == "<WebSecretCreateDispatchObservation redacted>"
    assert connection.posts == 1 and connection.closed and connection.response.closed
    assert connection.body is not None and not any(connection.body)
    for other in (replace(binding, secret_name="other-secret"),
                  replace(binding, folder_path="Public/other-folder")):
        assert transport.read_web_create_dispatch_observation(other, request) is None
    for field in ("authorization_digest", "scope_digest", "audience_digest", "policy_decision_digest"):
        assert transport.read_web_create_dispatch_observation(
            binding, replace(request, **{field: "e" * 64}),
        ) is None
    assert _transport(monkeypatch, _Connection()).read_web_create_dispatch_observation(binding, request) is None


@pytest.mark.parametrize("failure", ["status", "post", "response_close", "connection_close"])
def test_uncertain_dispatch_or_cleanup_never_publishes_observation(monkeypatch, failure):
    connection = _Connection(failure)
    transport = _transport(monkeypatch, connection)
    result = _create(transport)
    # Connection-close failure preserves the existing adapter behavior but does
    # not qualify the stricter observation required by a later fixture guard.
    expected = (SecretCreateAdapterOutcome.VERIFIED_CREATED if failure == "connection_close"
                else SecretCreateAdapterOutcome.RECONCILIATION_REQUIRED)
    assert result is expected
    assert transport.read_web_create_dispatch_observation(_web_binding(), _request()) is None
    assert connection.closed and connection.posts == 1
    assert connection.body is not None and not any(connection.body)


def test_a_later_prewrite_failure_clears_the_previous_observation(monkeypatch):
    connection = _Connection()
    transport = _transport(monkeypatch, connection)
    assert _create(transport) is SecretCreateAdapterOutcome.VERIFIED_CREATED
    assert transport.read_web_create_dispatch_observation(_web_binding(), _request()) is not None
    assert transport._create_and_verify_with_material(
        _web_binding(), _request(), memoryview(b""), memoryview(b"unit-password"),
    ) is SecretCreateAdapterOutcome.RECONCILIATION_REQUIRED
    assert transport.read_web_create_dispatch_observation(_web_binding(), _request()) is None
    assert connection.posts == 1


def test_legacy_profile_cannot_supply_a_build29_observation(monkeypatch):
    binding = replace(_web_binding(), contract_ref="fortipam-191-web-secret-create-private-v1",
                      target_product_version="1.9.1", target_product_build=None)
    transport = _transport(monkeypatch, _Connection())
    assert _create(transport, binding) is SecretCreateAdapterOutcome.VERIFIED_CREATED
    assert transport.read_web_create_dispatch_observation(binding, _request()) is None


def test_wrong_build_cannot_supply_an_observation_or_dispatch(monkeypatch):
    metadata = _MetadataTransport()
    metadata.read_product_version_and_build = lambda: ("7.0.0", 30)
    connection = _Connection()
    transport = _transport(monkeypatch, connection, metadata)
    assert _create(transport) is SecretCreateAdapterOutcome.RECONCILIATION_REQUIRED
    assert transport.read_web_create_dispatch_observation(_web_binding(), _request()) is None
    assert connection.posts == 0


def test_origin_userinfo_is_never_retained_in_the_observation(monkeypatch):
    connection = _Connection()
    transport = _transport(monkeypatch, connection)
    transport._config = replace(_config(), base_url="https://synthetic-user:synthetic-password@fpa.example.test")
    assert _create(transport) is SecretCreateAdapterOutcome.VERIFIED_CREATED
    assert transport.read_web_create_dispatch_observation(_web_binding(), _request()) is None
