from copy import deepcopy
import json

import httpx
import pytest

from fortipam_mcp.secret_event_subscription_http_transport import (
    FortiPamSecretEventSubscriptionHttpTransport, SecretEventSubscriptionHttpTransportError,
)
from fortipam_mcp.secret_event_subscription_requester_session import (
    SecretEventSubscriptionRequesterClient, SecretEventSubscriptionRequesterSessionError,
)
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from test_secret_event_subscription_contract import BINDING, PAYLOAD, PORTAL

P = "FORTIPAM_MCP_V4_LOCAL_USER_CREATE_ACTION_BP005_"


def fixture(tmp_path, case="success"):
    tmp_path.chmod(0o700)
    key = tmp_path / "key"
    key.write_bytes(b"k" * 32)
    key.chmod(0o600)
    config = SecretMetadataHttpTransportConfig("https://synthetic.invalid", "synthetic-bearer", 1, None)
    state = deepcopy(PAYLOAD)
    state["results"].update({"field": [], "credentials-history": {}, "totp-setting": {}})
    sessions, posts = [], []

    def handler(request):
        assert "authorization" not in request.headers
        assert request.headers["X-CSRFTOKEN"] == "synthetic-csrf"
        assert request.headers["X-Requested-With"] == "XMLHttpRequest"
        if request.method == "GET" and request.url.path.endswith("user-portal"):
            return httpx.Response(200, json={"results": PORTAL})
        if request.method == "GET" and request.url.path.endswith("/7"):
            return httpx.Response(200, json=state)
        assert request.method == "POST" and request.url.path == "/api/v2/internal/subscribe"
        assert json.loads(request.content) == {"secret-id": 7, "event": "cfg-chg"}
        assert (tmp_path / "subscribe.json").is_file()
        posts.append(True)
        state["results"]["subscriber"].append({"name": BINDING.owner_name, "event": "cfg-chg"})
        return httpx.Response(200, json={"version": "v7.0.0", "build": 29,
            "http_status": 200, "http_method": "POST", "status": "OK",
            "path": "internal", "name": "subscribe", "results": {}})

    class Session:
        def __init__(self):
            self._requester = "other-private-actor" if case == "wrong_actor" else BINDING.owner_name
            self._csrf = "unsafe\nprivate-token" if case == "bad_csrf" else "synthetic-csrf"
            self._client = httpx.Client(base_url=config.base_url, transport=httpx.MockTransport(handler))
            if case == "preexisting_bearer": self._client.headers["Authorization"] = "private-token"
            self.logins = self.finalizations = 0

        def inspect(self, expected):
            assert expected == BINDING.owner_name
            self.logins += 1

        def finalize(self):
            self.finalizations += 1
            self._client.close()
            return not (case == "logout_unknown" and posts)

    def builder(actual, environment):
        assert actual is config and set(environment) == {P + "USERNAME", P + "MATERIAL_DIRECTORY"}
        session = Session()
        sessions.append(session)
        return session

    client = SecretEventSubscriptionRequesterClient(config, owner_name=BINDING.owner_name,
        environment={P + "USERNAME": BINDING.owner_name, P + "MATERIAL_DIRECTORY": str(tmp_path / "material")},
        session_builder=builder)
    transport = FortiPamSecretEventSubscriptionHttpTransport(config, BINDING, operation="subscribe",
        claim_path=tmp_path / "subscribe.json", hmac_key_file=key,
        client_factory=client, execution_enabled=lambda: True, sleep=lambda _: None)
    return client, transport, sessions, posts


def test_cookie_headers_and_logout_qualify_fixed_dispatch_without_bearer(tmp_path):
    _, transport, sessions, posts = fixture(tmp_path)
    result = transport.apply_and_readback(transport.inspect())
    assert result.verified and posts == [True]
    assert len(sessions) == 2 and all(s.logins == s.finalizations == 1 for s in sessions)
    with pytest.raises(SecretEventSubscriptionHttpTransportError): transport.inspect()
    assert len(sessions) == 2


@pytest.mark.parametrize("case", ["wrong_actor", "bad_csrf", "preexisting_bearer"])
def test_unqualified_session_refuses_before_claim_and_always_finalizes(tmp_path, case):
    _, transport, sessions, posts = fixture(tmp_path, case)
    with pytest.raises(SecretEventSubscriptionHttpTransportError): transport.inspect()
    assert not posts and not (tmp_path / "subscribe.json").exists()
    assert len(sessions) == 1 and sessions[0].finalizations == 1


def test_logout_uncertainty_after_post_cannot_return_verified_success_or_replay(tmp_path):
    _, transport, sessions, posts = fixture(tmp_path, "logout_unknown")
    expected = transport.inspect()
    with pytest.raises(SecretEventSubscriptionHttpTransportError): transport.apply_and_readback(expected)
    assert posts == [True] and (tmp_path / "subscribe.json").exists()
    assert all(s.finalizations == 1 for s in sessions)
    with pytest.raises(SecretEventSubscriptionHttpTransportError): transport.apply_and_readback(expected)
    assert len(sessions) == 2 and posts == [True]


def test_wrong_origin_or_connection_policy_cannot_open_a_session(tmp_path):
    client, _, sessions, _ = fixture(tmp_path)
    for options in ({"base_url": "https://other.invalid", "trust_env": False, "follow_redirects": False},
                    {"base_url": "https://synthetic.invalid", "trust_env": True, "follow_redirects": False},
                    {"base_url": "https://synthetic.invalid", "trust_env": False, "follow_redirects": True}):
        with pytest.raises(SecretEventSubscriptionRequesterSessionError): client(**options)
    assert not sessions
