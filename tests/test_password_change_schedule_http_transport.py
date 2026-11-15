"""Regression coverage for fixed schedule preservation and non-retry behavior."""

from contextlib import contextmanager
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
import json
from types import SimpleNamespace

import pytest

import fortipam_mcp.password_change_schedule_http_transport as module
from fortipam_mcp.password_change_schedule_http_transport import (
    FortiPamPasswordChangeScheduleHttpTransport, PasswordChangeScheduleBinding,
    PasswordChangeScheduleError, PasswordChangeScheduleState,
)
from test_secret_metadata_http_transport import _config

BINDING = PasswordChangeScheduleBinding("Public/test", "test-owner", "test-secret",
    "test-policy", "test-target", "192.0.2.10", "test-account")
CURRENT = PasswordChangeScheduleState(23, 17, False, False, "month", 1, 0)


class Owner:
    logout_verified = False

    @contextmanager
    def authenticated(self):
        try:
            yield self
        finally:
            self.logout_verified = True

    def resolve_folder_id(self, _):
        return 17

    def _verify_collector_folder_acl(self, *_):
        return True

    def _request(self, *_args, **_kwargs):
        return 200, {"results": [{"id": 17, "inherit-policy": "disable", "secret-policy": BINDING.policy_name}]}


def fixture(monkeypatch, *, enabled=False, include_host=False):
    transport = FortiPamPasswordChangeScheduleHttpTransport(_config(), BINDING,
        lambda: (BINDING.owner_name, "synthetic-owner-password"),
        clock=lambda: datetime.fromtimestamp(1000, timezone.utc))
    state = replace(CURRENT, enabled=True, frequency="day", start_epoch=900) if enabled else CURRENT
    row = {"id": 23, "folder": 17, "name": BINDING.secret_name,
        "template": module._TEMPLATE, "target": BINDING.target_name,
        "inherit-permission": "enable", "ssh-service-status": "up",
        "sftp-service-status": "up", "recording": "enable",
        "password-changer": "enable" if state.enabled else "disable",
        "pwd-chg-use-policy-default": "disable", "pwd-chg-sch-frequency": state.frequency,
        "pwd-chg-sch-interval": 1, "pwd-chg-sch-start-date": state.start_epoch,
        "field": [{"name": "Username", "value": BINDING.account_name},
                  {"name": "Password", "value": "synthetic-retained-value"}]}
    if include_host:
        row["field"].append({"name": "Host", "value": BINDING.target_address})
    owner = Owner()
    observed = {"state": state}
    monkeypatch.setattr(transport, "_session", lambda: owner)
    monkeypatch.setattr(transport, "_inspect", lambda _: observed["state"])
    monkeypatch.setattr(transport, "_read", lambda *_args, **_kwargs: deepcopy(row))
    monkeypatch.setattr(transport._witness, "_request", lambda *_args, **_kwargs:
        (200, {"results": [{"name": BINDING.target_name, "address": BINDING.target_address}]}))
    return transport, owner, observed, row


@pytest.mark.parametrize("include_host", [False, True])
def test_enable_retains_fields_and_disable_accepts_backend_normalization(monkeypatch, include_host):
    transport, owner, observed, _ = fixture(monkeypatch, include_host=include_host)
    captured = []
    def put(_owner, _secret_id, body):
        captured.append(deepcopy(body))
        observed["state"] = replace(CURRENT, enabled=True, frequency="day", start_epoch=1300)
        return True
    monkeypatch.setattr(transport, "_put", put)
    result = transport.enable_and_readback(CURRENT)
    assert result.verified and result.enabled and result.logout_verified
    assert {x["name"] for x in captured[0]["field"]} == {"Username", "Password"}
    assert captured[0]["field"][1]["value"] == "synthetic-retained-value"
    with pytest.raises(PasswordChangeScheduleError):
        transport.enable_and_readback(CURRENT)
    assert len(captured) == 1

    transport, owner, observed, _ = fixture(monkeypatch, enabled=True)
    before = observed["state"]
    def disable(*_):
        observed["state"] = replace(CURRENT, uses_policy_default=True)
        return True
    monkeypatch.setattr(transport, "_put", disable)
    result = transport.disable_and_readback(before)
    assert result.verified and not result.enabled and owner.logout_verified


def test_final_protected_read_rejects_schedule_drift_before_dispatch(monkeypatch):
    transport, owner, _, row = fixture(monkeypatch)
    row["password-changer"] = "enable"
    writes = []
    monkeypatch.setattr(transport, "_put", lambda *args: writes.append(args))
    with pytest.raises(PasswordChangeScheduleError):
        transport.enable_and_readback(CURRENT)
    assert not writes and owner.logout_verified


def test_ambiguous_dispatch_is_not_repeated_and_fields_are_cleared(monkeypatch):
    transport, owner, _, _ = fixture(monkeypatch)
    attempts = []
    def ambiguous(_owner, _secret_id, body):
        attempts.append(body)
        raise TimeoutError("synthetic-retained-value")
    monkeypatch.setattr(transport, "_put", ambiguous)
    for _ in range(2):
        with pytest.raises(PasswordChangeScheduleError) as error:
            transport.enable_and_readback(CURRENT)
        assert "synthetic-retained-value" not in str(error.value)
    assert len(attempts) == 1 and attempts[0] == {} and owner.logout_verified


def test_forcing_policy_rejected_before_secret_read(monkeypatch):
    transport = FortiPamPasswordChangeScheduleHttpTransport(_config(), BINDING,
        lambda: (BINDING.owner_name, "synthetic-owner-password"))
    monkeypatch.setattr(transport._witness, "_request", lambda *_args, **_kwargs:
        (200, {"results": [{"name": BINDING.policy_name, "password-changer": "enable"}]}))
    with pytest.raises(ValueError):
        transport._inspect(Owner())


def test_owner_put_preserves_login_user_agent_and_csrf_without_bearer(monkeypatch):
    transport, _, _, _ = fixture(monkeypatch)
    captured = []
    class Response:
        status = 200
        def read(self, _): return b'{"status":"success"}'
        def close(self): pass
    class Connection:
        def request(self, method, path, *, body, headers):
            captured.append((method, path, bytes(body), headers))
        def getresponse(self): return Response()
        def close(self): pass
    monkeypatch.setattr(module, "_ssl_context", lambda _: object())
    monkeypatch.setattr(module.http.client, "HTTPSConnection", lambda *_args, **_kwargs: Connection())
    client = SimpleNamespace(headers={"User-Agent": "synthetic-login-agent"},
        build_request=lambda *_: SimpleNamespace(headers={"cookie": 'session=opaque; ccsrftoken="synthetic-csrf"'}))
    assert transport._put(SimpleNamespace(_client=client), 23, {"field": []})
    method, path, content, headers = captured[0]
    assert method == "PUT" and path.endswith("/23") and json.loads(content) == {"field": []}
    assert headers["User-Agent"] == "synthetic-login-agent"
    assert headers["X-CSRFTOKEN"] == "synthetic-csrf" and "Authorization" not in headers
