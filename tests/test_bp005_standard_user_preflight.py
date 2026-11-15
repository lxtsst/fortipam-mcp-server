from __future__ import annotations

import json
import pickle
from typing import Any

import pytest

from fortipam_mcp.bp005_standard_user_preflight import (
    FortiPamBp005StandardUserPreflightReader,
    _ACTOR,
    _DEFAULT,
    _PROFILE,
    _SCHEMA,
)
from fortipam_mcp.local_user_reset_metadata_reader import LocalUserResetMetadataReadError
from v4_planning.material_provider import MaterialAccessDenied

from test_local_user_reset_fixture_create import _defaults
from test_local_user_reset_metadata_reader import _monitor
from test_local_user_reset_name_reader import Harness as NameHarness, PRINCIPAL, _payload
from test_local_user_reset_projection import _body

NAME = "mcp-v4-user-bp005-standard-synthetic"


def _actor(**updates: Any) -> dict[str, Any]:
    return {
        "name": PRINCIPAL,
        "login_name": PRINCIPAL,
        "sponsored_group_name": "",
        "guest_admin": False,
        **updates,
    }


class Harness:
    def __init__(self) -> None:
        self.network = NameHarness()
        schema, defaults = _defaults()
        self.bodies = {
            _ACTOR: _monitor("web-ui/state", {"admin": _actor()}),
            _PROFILE: _body({"name": "pam_standard_user"}, name="accprofile"),
            _SCHEMA: bytearray(json.dumps(schema).encode()),
            _DEFAULT: _body(defaults, action="default"),
        }
        self.reader = FortiPamBp005StandardUserPreflightReader(
            self.network.reader._config,
            username=NAME,
            api_principal=PRINCIPAL,
            connection_factory=self.connect,
        )

    def connect(self, *args: Any, **kwargs: Any) -> Any:
        connection = self.network.connect(*args, **kwargs)
        original = connection.request

        def request(method: str, path: str, *, body: bytes | None = None, headers: dict[str, str]) -> None:
            if method != "GET":
                original(method, path, body=body, headers=headers)
                return
            assert body is None and path in self.bodies
            assert "X-HTTP-Method-Override" not in headers
            assert headers["Accept-Encoding"] == "identity"
            self.network.calls.append(path)
            connection.response.body = self.bodies[path]

        connection.request = request
        return connection

    def disposed(self) -> None:
        self.network.disposed()


def test_preflight_binds_absent_name_actor_standard_role_and_enabled_body() -> None:
    h = Harness()
    result = h.reader.read_preflight()
    assert h.network.calls == ["admin", "api-user", _ACTOR, _PROFILE, _SCHEMA, _DEFAULT]
    body = json.loads(result.draft._wire)
    assert body["accprofile"] == "pam_standard_user" and body["status"] == "enable"
    assert len({
        result.state_digest,
        result.name_check_digest,
        result.actor_context_digest,
        result.profile_identity_digest,
    }) == 4
    assert "password" not in body
    assert NAME not in repr(result) and PRINCIPAL not in repr(result)
    with pytest.raises(MaterialAccessDenied):
        pickle.dumps(result)
    h.disposed()


def test_local_user_or_api_user_collision_stops_before_create_defaults() -> None:
    h = Harness()
    h.network.bodies["admin"] = _payload("admin", [NAME])
    with pytest.raises(LocalUserResetMetadataReadError):
        h.reader.read_preflight()
    assert h.network.calls == ["admin", "api-user"]
    h.disposed()


def test_wrong_standard_profile_or_actor_context_fails_before_defaults() -> None:
    h = Harness()
    h.bodies[_PROFILE] = _body({"name": "Guest"}, name="accprofile")
    with pytest.raises(LocalUserResetMetadataReadError):
        h.reader.read_preflight()
    assert h.network.calls[-1] == _PROFILE
    h.disposed()

    h = Harness()
    h.bodies[_ACTOR] = _monitor("web-ui/state", {"admin": _actor(sponsored_group_name="unexpected")})
    with pytest.raises(LocalUserResetMetadataReadError):
        h.reader.read_preflight()
    assert h.network.calls[-1] == _ACTOR
    h.disposed()


def test_fixed_preflight_reader_rejects_arbitrary_routes() -> None:
    h = Harness()
    with pytest.raises(LocalUserResetMetadataReadError):
        h.reader._read("/api/v2/cmdb/system/global")
    assert h.network.calls == []
    h.disposed()


def test_bp005_preflight_rejects_reset_fixture_name_namespace() -> None:
    h = Harness()
    with pytest.raises(LocalUserResetMetadataReadError):
        FortiPamBp005StandardUserPreflightReader(
            h.reader._config,
            username="mcp-v4-user-reset-bp005-should-not-match",
            api_principal=PRINCIPAL,
            connection_factory=h.connect,
        )
    assert h.network.calls == []
    h.disposed()
