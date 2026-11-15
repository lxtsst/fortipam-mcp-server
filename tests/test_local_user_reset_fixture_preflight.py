"""Exercise the real name reader and create-body preparer in one fixed preflight."""

from __future__ import annotations

import json
import pickle
from typing import Any

import pytest

from fortipam_mcp.local_user_reset_fixture_preflight import (
    FortiPamLocalUserResetFixturePreflightReader, _ACTOR, _DEFAULT, _PROFILE, _SCHEMA,
)
from fortipam_mcp.local_user_reset_metadata_reader import LocalUserResetMetadataReadError, LocalUserResetReadFailure as Failure
from v4_planning.material_provider import MaterialAccessDenied

from test_local_user_reset_fixture_create import _defaults
from test_local_user_reset_name_reader import Harness as NameHarness, NAME, PRINCIPAL, _payload
from test_local_user_reset_metadata_reader import _monitor
from test_local_user_reset_projection import _body


def _actor(**updates: Any) -> dict[str, Any]:
    return {"name": PRINCIPAL, "login_name": PRINCIPAL, "sponsored_group_name": "",
            "guest_admin": False, **updates}


class Harness:
    def __init__(self) -> None:
        self.network = NameHarness()
        schema, record = _defaults()
        self.actor_path = _ACTOR
        self.bodies = {
            self.actor_path: _monitor("web-ui/state", {"admin": _actor()}),
            _PROFILE: _body({"name": "Guest"}, name="accprofile"),
            _SCHEMA: bytearray(json.dumps(schema).encode()),
            _DEFAULT: _body(record, action="default"),
        }
        self.get_failure: int | None = None
        self.reader = FortiPamLocalUserResetFixturePreflightReader(
            self.network.reader._config, username=NAME, api_principal=PRINCIPAL, connection_factory=self.connect,
        )

    def connect(self, *args: Any, **kwargs: Any) -> Any:
        connection = self.network.connect(*args, **kwargs)
        original = connection.request

        def request(method: str, path: str, *, body: bytes | None = None, headers: dict[str, str]) -> None:
            if method == "POST":
                original(method, path, body=body, headers=headers)
            else:
                assert method == "GET" and path in self.bodies and body is None
                assert "X-HTTP-Method-Override" not in headers
                self.network.calls.append(path)
                connection.response.body = self.bodies[path]
                if self.get_failure is not None:
                    connection.response.status = self.get_failure

        connection.request = request
        return connection

    def disposed(self) -> None:
        self.network.disposed()


def test_real_components_produce_one_bound_nonmaterial_preflight() -> None:
    h = Harness(); value = h.reader.read_preflight()
    assert h.network.calls == ["admin", "api-user", h.actor_path, _PROFILE, _SCHEMA, _DEFAULT]
    assert value.draft.username == NAME and value.draft.access_profile == "Guest"
    assert len({value.state_digest, value.name_check_digest, value.actor_context_digest, value.profile_identity_digest}) == 4
    assert "password" not in json.loads(value.draft._wire)
    assert not hasattr(value, "authorization_digest") and not hasattr(value, "fixture_creation_digest")
    assert NAME not in repr(value) and PRINCIPAL not in repr(value)
    with pytest.raises(MaterialAccessDenied): pickle.dumps(value)
    h.disposed()


def test_api_name_collision_stops_before_actor_defaults_or_material() -> None:
    h = Harness(); h.network.bodies["api-user"] = _payload("api-user", [PRINCIPAL, NAME.upper()])
    with pytest.raises(LocalUserResetMetadataReadError): h.reader.read_preflight()
    assert h.network.calls == ["admin", "api-user"]
    h.disposed()


@pytest.mark.parametrize("row", [
    {"name": PRINCIPAL}, _actor(sponsored_group_name=None),
    _actor(sponsored_group_name="synthetic-group"), _actor(sponsored_group_name={"name": ""}),
    _actor(name="different-principal"), _actor(login_name="different-principal"),
    _actor(guest_admin=True), _actor(guest_admin="false"),
])
def test_missing_or_nonempty_actor_sponsor_context_is_not_inferred(row: dict[str, Any]) -> None:
    h = Harness(); h.bodies[h.actor_path] = _monitor("web-ui/state", {"admin": row})
    with pytest.raises(LocalUserResetMetadataReadError): h.reader.read_preflight()
    assert h.network.calls == ["admin", "api-user", h.actor_path]
    h.disposed()


@pytest.mark.parametrize("body", [
    _monitor("web-ui/state", {"admin": _actor()}, build=30),
    _monitor("web-ui/state", {"admin": _actor()}, status="error"),
    _monitor("web-ui/other", {"admin": _actor()}),
    _monitor("web-ui/state", {"admin": _actor()}, http_status=403),
    _monitor("web-ui/state", _actor()),
    _body({"name": PRINCIPAL, "sponsor-group": ""}, name="api-user"),
])
def test_actor_requires_current_state_monitor_not_cmdb_identity(body: bytearray) -> None:
    h = Harness(); h.bodies[h.actor_path] = body
    with pytest.raises(LocalUserResetMetadataReadError): h.reader.read_preflight()
    assert h.network.calls[-1] == _ACTOR
    h.disposed()


@pytest.mark.parametrize("body", [
    _body({"name": "different-role"}, name="accprofile"),
    _body({"name": "Guest"}, name="accprofile", build=30),
    _body({"name": "Guest"}, name="accprofile", action="schema"),
    _body([{"name": "Guest"}, {"name": "Guest"}], name="accprofile"),
    _body({"name": "Guest", "password": "synthetic-sensitive"}, name="accprofile"),
])
def test_profile_identity_is_exact_not_full_policy_or_permission_proof(body: bytearray) -> None:
    h = Harness(); h.bodies[_PROFILE] = body
    with pytest.raises(LocalUserResetMetadataReadError): h.reader.read_preflight()
    assert h.network.calls[-1] == _PROFILE
    h.disposed()


def test_observed_profile_mkey_must_agree_with_selected_and_returned_identity() -> None:
    h = Harness(); h.bodies[_PROFILE] = _body({"name": "Guest"}, name="accprofile", mkey="Guest")
    assert h.reader.read_preflight().draft.access_profile == "Guest"
    for mkey in (None, 0, False, "", "different-role"):
        h.bodies[_PROFILE] = _body({"name": "Guest"}, name="accprofile", mkey=mkey)
        with pytest.raises(LocalUserResetMetadataReadError): h.reader.read_preflight()
    h.disposed()


@pytest.mark.parametrize("status,expected", [(401, Failure.AUTHORIZATION_DENIED), (403, Failure.AUTHORIZATION_DENIED),
    (404, Failure.NOT_FOUND), (302, Failure.UNQUALIFIED_RESPONSE)])
def test_failed_actor_get_cannot_become_empty_scope(status: int, expected: Failure) -> None:
    h = Harness(); h.get_failure = status
    with pytest.raises(LocalUserResetMetadataReadError) as error: h.reader.read_preflight()
    assert error.value.reason is expected and h.network.calls[-1] == h.actor_path
    h.disposed()


def test_value_decoder_never_sees_actor_or_role_response(monkeypatch: pytest.MonkeyPatch) -> None:
    h = Harness()
    h.bodies[h.actor_path] = _monitor("web-ui/state", {
        "admin": _actor(profile={"name": "synthetic-private-decoration", "sysgrp": "read-write"}),
        "unrelated_state": "synthetic-private-decoration",
    })
    h.bodies[_PROFILE] = _body({"name": "Guest", "q_no_edit": "synthetic-private-decoration"}, name="accprofile")
    original = json.loads
    attempts: list[bool] = []

    def decode(data: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(data, (bytes, bytearray)) and b"synthetic-private-decoration" in data:
            attempts.append(True)
        return original(data, *args, **kwargs)

    monkeypatch.setattr(json, "loads", decode)
    assert h.reader.read_preflight().draft.access_profile == "Guest"
    assert not attempts
    h.disposed()


def test_each_preflight_is_fresh_and_binds_changed_selected_defaults() -> None:
    h = Harness(); first = h.reader.read_preflight()
    second = h.reader.read_preflight()
    assert second.state_digest == first.state_digest and len(h.network.calls) == 12
    schema, record = _defaults(); record["comments"] = "changed-synthetic-comment"
    h.bodies[_DEFAULT] = _body(record, action="default")
    third = h.reader.read_preflight()
    assert third.state_digest != first.state_digest
    assert third.draft.nonmaterial_request_digest != first.draft.nonmaterial_request_digest
    h.disposed()


def test_default_parse_failure_is_categorical_and_erases_every_buffer() -> None:
    h = Harness(); h.bodies[_DEFAULT] = _body({}, action="default")
    with pytest.raises(LocalUserResetMetadataReadError) as error: h.reader.read_preflight()
    assert error.value.reason is Failure.UNQUALIFIED_RESPONSE
    h.disposed()


def test_fixed_reader_does_not_relay_an_arbitrary_path() -> None:
    h = Harness()
    with pytest.raises(LocalUserResetMetadataReadError): h.reader._read("/api/v2/cmdb/system/global")
    assert h.network.calls == []
