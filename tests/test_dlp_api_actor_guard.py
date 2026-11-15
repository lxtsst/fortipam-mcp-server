"""Synthetic identity, role drift, bounded stream and fixed-route checks."""

from __future__ import annotations

import json
import ssl
from typing import Any

import pytest

import fortipam_mcp.dlp_api_actor_guard as guard_module
from fortipam_mcp.dlp_api_actor_guard import (
    DlpApiActorGuard, DlpApiActorGuardBinding, DlpApiActorGuardError,
    _ACTOR, _ROLE_FIELDS, _SECRET_PERMISSIONS, _SYSTEM_PERMISSIONS, _digest,
)
from fortipam_mcp.dlp_sensor_delete_http_transport import DlpSensorDeleteHttpTransportConfig

ACTOR = "synthetic-api-actor"
PROFILE = "Synthetic Custom Profile"
SERIAL = "SYNTHETIC01"


def _role() -> dict[str, Any]:
    return {"name": PROFILE, "secretgrp": "custom", "sysgrp": "read-write",
            "secretgrp-permission": {key: "read-write" if key == "secret-policy" else "read"
                                     for key in _SECRET_PERMISSIONS},
            "sysgrp-permission": {key: "none" for key in _SYSTEM_PERMISSIONS}}


def _envelope(table: str, results: object, *, monitor: bool = False, **updates: Any) -> bytearray:
    payload = {"http_method": "GET", "http_status": 200, "status": "success", "version": "v7.0.0",
               "build": 29, "serial": SERIAL, "path": "web-ui" if monitor else "system",
               "name": table, "action": "", "vdom": "root", "results": results, **updates}
    return bytearray(json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("ascii"))


class Harness:
    def __init__(self, role: dict[str, Any] | None = None) -> None:
        self.config = DlpSensorDeleteHttpTransportConfig("https://pam.example.test:9443", "synthetic-token", 5, None)
        self.role = _role() if role is None else role
        self.binding = DlpApiActorGuardBinding(ACTOR, PROFILE, SERIAL, _digest(self.role))
        self.calls: list[str] = []
        self.user_agents: list[str] = []
        self.resources: list[Any] = []
        self.buffers: list[bytearray] = []
        self.status: Any = 200
        self.fail = ""
        self.guard = DlpApiActorGuard(self.config, self.binding, connection_factory=self.connect)
        self.bodies = {
            _ACTOR: _envelope("state", {"admin": {"name": ACTOR, "login_name": ACTOR,
                "guest_admin": False, "sponsored_group_name": ""}}, monitor=True),
            self.guard._user_path: _envelope("api-user", [{"name": ACTOR, "accprofile": PROFILE,
                                                          "q_origin_key": ACTOR}]),
            self.guard._role_path: _envelope("accprofile", [{**self.role, "q_origin_key": PROFILE}]),
        }

    def connect(self, host: str, port: int, **kwargs: Any) -> Any:
        assert (host, port) == ("pam.example.test", 9443)
        assert kwargs["timeout"] == 5
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
                assert isinstance(view.obj, bytearray)
                harness.buffers.append(view.obj)
                if harness.fail == "timeout":
                    raise TimeoutError("private-synthetic-transport-detail")
                if harness.fail == "count":
                    return True  # type: ignore[return-value]
                count = min(len(view), 113, len(self.body) - self.offset)
                view[:count] = self.body[self.offset:self.offset + count]
                self.offset += count
                return count

            def close(self) -> None:
                self.closed = True

        class Connection:
            closed = False

            def __init__(self) -> None:
                self.response = Response()
                harness.resources.extend([self, self.response])

            def request(self, method: str, path: str, *, headers: dict[str, str]) -> None:
                assert method == "GET" and path in harness.bodies
                assert headers["Authorization"] == "Bearer synthetic-token"
                assert headers["Accept-Encoding"] == "identity" and headers["Connection"] == "close"
                harness.user_agents.append(headers["User-Agent"])
                harness.calls.append(path)
                self.response.body = harness.bodies[path]

            def getresponse(self) -> Response:
                return self.response

            def close(self) -> None:
                self.closed = True

        return Connection()

    def disposed(self) -> None:
        assert all(resource.closed for resource in self.resources)
        assert all(not any(buffer) for buffer in self.buffers)


def test_fresh_three_routes_private_evidence_and_config_binding() -> None:
    h = Harness(); h.guard.require_same_config(h.config)
    evidence = h.guard.observe()
    assert h.calls == [_ACTOR,
        "/api/v2/cmdb/system/api-user/synthetic-api-actor?format=name%7Caccprofile",
        "/api/v2/cmdb/system/accprofile/Synthetic%20Custom%20Profile?format="
        "name%7Csecretgrp%7Csecretgrp-permission%7Csysgrp%7Csysgrp-permission"]
    assert (evidence.actor, evidence.profile, evidence.device_serial, evidence.version, evidence.build) == (
        ACTOR, PROFILE, SERIAL, "v7.0.0", 29)
    assert evidence.role_projection_digest == h.binding.expected_role_projection_digest
    assert len(evidence.evidence_digest) == 64 and not hasattr(evidence, "qualified")
    assert all(value not in repr(evidence) and value not in repr(h.binding) for value in (ACTOR, PROFILE, SERIAL))
    assert h.guard.observe() == evidence and len(h.calls) == 6
    with pytest.raises(DlpApiActorGuardError):
        h.guard.require_same_config(DlpSensorDeleteHttpTransportConfig("https://pam.example.test:9443", "synthetic-token", 5, None))
    h.disposed()


def test_all_fixed_reads_send_stable_project_user_agent() -> None:
    h = Harness(); h.guard.observe()
    assert h.user_agents == ["fortipam-bp005-dlp-api-actor/1"] * 3
    h.disposed()


@pytest.mark.parametrize("field,value", [("name", "other"), ("login_name", "other"),
    ("guest_admin", True), ("guest_admin", "false"), ("sponsored_group_name", "group"),
    ("sponsored_group_name", None)])
def test_actor_context_refusal(field: str, value: object) -> None:
    h = Harness(); body = json.loads(h.bodies[_ACTOR]); body["results"]["admin"][field] = value
    h.bodies[_ACTOR] = bytearray(json.dumps(body).encode())
    with pytest.raises(DlpApiActorGuardError): h.guard.observe()
    assert h.calls == [_ACTOR]; h.disposed()


@pytest.mark.parametrize("route", [0, 1, 2])
@pytest.mark.parametrize("field,value", [("serial", "OTHER"), ("build", 30), ("build", 29.0),
    ("version", "v1.9.1"), ("status", "error"), ("http_status", True), ("vdom", "other"),
    ("limit_reached", True), ("unknown", "extra"), ("matched_count", 2)])
def test_device_envelope_and_limits_fail_closed(route: int, field: str, value: object) -> None:
    h = Harness(); path = list(h.bodies)[route]; body = json.loads(h.bodies[path]); body[field] = value
    h.bodies[path] = bytearray(json.dumps(body).encode())
    with pytest.raises(DlpApiActorGuardError): h.guard.observe()
    h.disposed()


@pytest.mark.parametrize("case", ["profile", "profile-type", "duplicate-row", "duplicate-key", "extra-field",
    "missing-role-field", "missing-permission", "unknown-permission", "wrong-permission-type", "sys-read",
    "secret-policy-read", "role-drift", "origin-drift"])
def test_selected_identity_role_policy_and_digest_drift(case: str) -> None:
    h = Harness(); path = h.guard._user_path if case.startswith("profile") or case.startswith("duplicate") else h.guard._role_path
    body = json.loads(h.bodies[path]); row = body["results"][0]
    if case == "profile": row["accprofile"] = "different"
    elif case == "profile-type": row["accprofile"] = {"name": PROFILE}
    elif case == "duplicate-row": body["results"].append(row.copy())
    elif case == "extra-field": row["unknown"] = "read-write"
    elif case == "missing-role-field": del row["sysgrp-permission"]
    elif case == "missing-permission": del row["secretgrp-permission"]["launcher"]
    elif case == "unknown-permission": row["sysgrp-permission"]["unknown"] = "read"
    elif case == "wrong-permission-type": row["secretgrp-permission"]["secret-policy"] = True
    elif case == "sys-read": row["sysgrp"] = "read"
    elif case == "secret-policy-read": row["secretgrp-permission"]["secret-policy"] = "read"
    elif case == "role-drift": row["sysgrp-permission"]["admin"] = "read"
    elif case == "origin-drift": row["q_origin_key"] = "other"
    wire = json.dumps(body, separators=(",", ":")).encode()
    if case == "duplicate-key": wire = wire.replace(b'"accprofile":', b'"accprofile":"first","accprofile":')
    h.bodies[path] = bytearray(wire)
    with pytest.raises(DlpApiActorGuardError): h.guard.observe()
    h.disposed()


def test_top_level_read_write_role_is_bound_without_profile_label_assumption() -> None:
    role = _role(); role["secretgrp"] = "read-write"
    h = Harness(role); assert h.guard.observe().profile == PROFILE; h.disposed()


@pytest.mark.parametrize("failure", ["media", "encoding", "timeout", "count", "status", "oversize"])
def test_http_stream_refusals_are_bounded_non_disclosing_and_disposed(failure: str, monkeypatch: Any) -> None:
    h = Harness()
    if failure == "status": h.status = 302
    elif failure == "oversize": monkeypatch.setattr(guard_module, "_MAX_BYTES", 128)
    else: h.fail = failure
    with pytest.raises(DlpApiActorGuardError) as error: h.guard.observe()
    assert str(error.value) == "FortiPAM DLP API actor evidence is unavailable."
    assert error.value.__cause__ is None
    assert h.calls == [_ACTOR]; h.disposed()


@pytest.mark.parametrize("index,value", [(0, ""), (1, "bad\nprofile"), (2, "bad serial"), (3, "not-a-digest")])
def test_private_binding_rejects_invalid_values(index: int, value: str) -> None:
    values = [ACTOR, PROFILE, SERIAL, _digest(_role())]; values[index] = value
    with pytest.raises(DlpApiActorGuardError): DlpApiActorGuardBinding(*values)


def test_valid_actor_name_is_allowed_but_wrong_fresh_identity_is_rejected() -> None:
    h = Harness()
    binding = DlpApiActorGuardBinding("synthetic-other-actor", PROFILE, SERIAL, _digest(_role()))
    guard = DlpApiActorGuard(h.config, binding, connection_factory=h.connect)
    with pytest.raises(DlpApiActorGuardError): guard.observe()
    assert h.calls == [_ACTOR]
    h.disposed()


def test_guard_rejects_url_userinfo_and_unverified_tls(monkeypatch: Any) -> None:
    h = Harness()
    config = DlpSensorDeleteHttpTransportConfig("https://user@pam.example.test", "synthetic", 5, None)
    with pytest.raises(DlpApiActorGuardError): DlpApiActorGuard(config, h.binding)
    context = ssl._create_unverified_context()
    monkeypatch.setattr(guard_module, "_ssl_context", lambda config: context)
    with pytest.raises(DlpApiActorGuardError): DlpApiActorGuard(h.config, h.binding)
