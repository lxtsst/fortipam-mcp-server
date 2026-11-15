from __future__ import annotations

from array import array
from dataclasses import fields, replace
import json
from typing import Any

import pytest

from fortipam_mcp.local_user_reset_http_transport import (
    FortiPamLocalUserResetHttpTransport, LocalUserResetBaseline, LocalUserResetBinding,
    LocalUserResetHttpOutcome as Outcome, LocalUserResetHttpTransportError,
    LocalUserResetMaterialLease,
    _response_flag,
)
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig


def _baseline(**updates: Any) -> LocalUserResetBaseline:
    return replace(LocalUserResetBaseline(
        username="mcp-v4-user-reset-synthetic", status="disable", is_local=True,
        access_profile="Guest", sponsor_group="", schedule="", guest_auth="disable",
        nonmaterial_state_digest="a" * 64, fixture_creation_digest="c" * 64,
        reported_reference_count=0, usage_entry_count=0,
        product_version="7.0.0", product_build=29,
    ), **updates)


def test_policy_flag_accepts_observed_build29_envelope_without_echo() -> None:
    response = bytearray(json.dumps({
        "action": "policy-check", "build": 29, "http_method": "POST",
        "mkey": "synthetic", "name": "password-policy-conform", "path": "system",
        "serial": "synthetic", "status": "success", "vdom": [], "version": "v7.0.0",
        "results": {"valid": True, "msg": ""},
    }, separators=(",", ":")).encode())
    assert _response_flag(response, "policy_conform") is True
    response.extend(b" ")
    assert _response_flag(response, "policy_conform") is True
    echoed = bytearray(b'{"results":{"valid":true,"password":"echo"}}')
    with pytest.raises(ValueError):
        _response_flag(echoed, "policy_conform")


class Response:
    def __init__(self, content: bytes, *, status: int = 200, content_type: str = "application/json") -> None:
        self.content, self.status, self.content_type = content, status, content_type
        self.offset = 0
        self.closed = False
        self.buffers: list[bytearray] = []

    def getheader(self, name: str, default: str = "") -> str:
        assert name == "content-type"
        return self.content_type

    def readinto(self, buffer: memoryview) -> int:
        self.buffers.append(buffer.obj)
        count = min(len(buffer), len(self.content) - self.offset)
        buffer[:count] = self.content[self.offset:self.offset + count]
        self.offset += count
        return count

    def close(self) -> None:
        self.closed = True


class Connection:
    def __init__(self, owner: Harness, operation: str) -> None:
        self.owner, self.operation, self.closed = owner, operation, False
        self.response = owner.responses[operation]

    def request(self, method: str, url: str, body: memoryview, headers: dict[str, str]) -> None:
        self.owner.events.append(self.operation)
        assert method == "POST" and "Authorization" not in headers
        assert body.readonly and isinstance(body.obj, bytearray)
        self.owner.request_buffers.append(body.obj)
        self.owner.calls.append((url, json.loads(bytes(body))))
        if self.owner.fail_at == self.operation:
            raise TimeoutError("synthetic-password-echo")

    def getresponse(self) -> Response:
        if self.owner.fail_at == "response_" + self.operation:
            raise ValueError("synthetic-password-echo")
        return self.response

    def close(self) -> None:
        self.closed = True


class Harness:
    def __init__(self, *, baseline: LocalUserResetBaseline | None = None) -> None:
        self.baseline = baseline or _baseline()
        self.binding = LocalUserResetBinding(self.baseline)
        self.snapshots = [self.baseline] * 3
        self.events: list[str] = []
        self.calls: list[tuple[str, object]] = []
        self.connections: list[Connection] = []
        self.request_buffers: list[bytearray] = []
        self.responses = {
            "policy_conform": Response(b'{"results":{"valid":true}}'),
            "change_password": Response(b'{"results":{"changed":true}}'),
        }
        self.old = bytearray(b'synthetic-old-"password\\')
        self.new = bytearray(b'synthetic-new-"password\\')
        self.fail_at = ""
        self.reads = 0
        self.leases = 0
        self.lease = LocalUserResetMaterialLease(lambda: (memoryview(self.old), memoryview(self.new)))

    def read_nonmaterial_baseline(self) -> LocalUserResetBaseline:
        self.events.append("read")
        value = self.snapshots[min(self.reads, len(self.snapshots) - 1)]
        self.reads += 1
        if self.fail_at == "read":
            raise RuntimeError("synthetic-password-echo")
        return value

    def material(self) -> LocalUserResetMaterialLease:
        self.events.append("material")
        self.leases += 1
        if self.fail_at == "material":
            raise RuntimeError("synthetic-password-echo")
        return self.lease

    def local_user_reset_connection(self, host: str, port: int, **kwargs: Any) -> Connection:
        assert (host, port) == ("pam.example.test", 443)
        assert kwargs["binding"] is self.binding
        connection = Connection(self, kwargs["operation"])
        self.connections.append(connection)
        return connection

    def transport(self, *, enabled: bool = True) -> FortiPamLocalUserResetHttpTransport:
        return FortiPamLocalUserResetHttpTransport(
            SecretMetadataHttpTransportConfig("https://pam.example.test", "unused", 5, None),
            binding=self.binding, inspector=self, owner_session=self,
            material_lease_provider=self.material, enabled=enabled,
        )

    def assert_disposed(self) -> None:
        assert not any(self.old) and not any(self.new)
        assert all(not any(body) for body in self.request_buffers)
        assert all(not any(body) for response in self.responses.values() for body in response.buffers)
        assert all(connection.closed for connection in self.connections)


@pytest.mark.parametrize("guest_auth,profile,apply_to", [
    ("disable", "Guest", "admin"), ("enable", "pam_standard_user", "guest-admin"),
])
def test_fixed_order_target_guest_auth_and_zeroization(guest_auth: str, profile: str, apply_to: str) -> None:
    h = Harness(baseline=_baseline(guest_auth=guest_auth, access_profile=profile))
    new = h.new.decode()
    transport = h.transport()
    result = transport.reset()

    assert result.outcome is Outcome.BACKEND_CHANGED_METADATA_PRESERVED
    assert result.backend_changed and result.metadata_preserved and result.change_post_attempted
    assert result.login_verified is False
    assert h.events == ["read", "material", "policy_conform", "read", "change_password", "read"]
    assert h.calls == [
        ("/api/v2/monitor/system/password-policy-conform/", {
            "mkey": h.baseline.username, "apply_to": apply_to, "password": new, "old_password": "",
        }),
        ("/api/v2/monitor/system/change-password", {
            "mkey": h.baseline.username, "new_password": new, "old_password": "",
        }),
    ]
    assert h.leases == 1 and all(response.closed for response in h.responses.values())
    h.assert_disposed()
    assert transport.reset().outcome is Outcome.GATE_CLOSED
    assert len(h.calls) == 2


def test_default_closed_guard_never_reads_or_loads_material() -> None:
    h = Harness()
    transport = FortiPamLocalUserResetHttpTransport(
        SecretMetadataHttpTransportConfig("https://pam.example.test", "unused", 5, None),
        binding=h.binding, inspector=h, owner_session=h, material_lease_provider=h.material,
    )
    assert transport.reset().outcome is Outcome.GATE_CLOSED
    assert h.events == [] and h.connections == [] and h.leases == 0


@pytest.mark.parametrize("updates", [
    {"username": "mcp-v4-user-historical"}, {"status": "locked"}, {"is_local": False},
    {"access_profile": "super_admin"}, {"sponsor_group": "unrelated"}, {"schedule": "unrelated"},
    {"guest_auth": ""}, {"guest_auth": None}, {"guest_auth": True},
    {"fixture_creation_digest": ""}, {"fixture_creation_digest": None},
    {"fixture_creation_digest": "g" * 64}, {"fixture_creation_digest": "c" * 63},
    {"reported_reference_count": None}, {"reported_reference_count": "0"},
    {"reported_reference_count": 1}, {"reported_reference_count": -1},
    {"reported_reference_count": False}, {"reported_reference_count": 0.0},
    {"usage_entry_count": None}, {"usage_entry_count": "0"},
    {"usage_entry_count": 1}, {"usage_entry_count": -1},
    {"usage_entry_count": False}, {"usage_entry_count": 0.0},
    {"product_version": "1.9.1"}, {"product_build": True}, {"nonmaterial_state_digest": ""},
])
def test_private_binding_rejects_wrong_identity_relations_or_missing_target_guest_auth(updates: dict[str, object]) -> None:
    with pytest.raises(LocalUserResetHttpTransportError, match="candidate is unavailable"):
        LocalUserResetBinding(_baseline(**updates))


@pytest.mark.parametrize("missing", ["fixture_creation_digest", "reported_reference_count", "usage_entry_count"])
def test_fixture_provenance_and_reported_counts_have_no_missing_value_default(missing: str) -> None:
    baseline = _baseline()
    values = {field.name: getattr(baseline, field.name) for field in fields(baseline)}
    del values[missing]
    with pytest.raises(TypeError):
        LocalUserResetBaseline(**values)


@pytest.mark.parametrize("read_index", [0, 1])
@pytest.mark.parametrize("updates", [
    {"username": "mcp-v4-user-reset-other"}, {"sponsor_group": "unrelated"},
    {"schedule": "unrelated"}, {"guest_auth": "enable"}, {"is_local": False},
    {"nonmaterial_state_digest": "b" * 64},
    {"fixture_creation_digest": "d" * 64}, {"fixture_creation_digest": None},
    {"reported_reference_count": 1}, {"reported_reference_count": None},
    {"reported_reference_count": False}, {"reported_reference_count": 0.0},
    {"usage_entry_count": 1}, {"usage_entry_count": None},
    {"usage_entry_count": False}, {"usage_entry_count": 0.0},
])
def test_identity_and_complete_baseline_drift_never_reaches_change(read_index: int, updates: dict[str, object]) -> None:
    h = Harness()
    h.snapshots[read_index] = _baseline(**updates)
    result = h.transport().reset()
    assert result.outcome is Outcome.DRIFT_REJECTED
    assert not result.change_post_attempted and not result.backend_changed
    assert len(h.calls) == read_index
    assert h.leases == read_index
    if read_index:
        h.assert_disposed()


@pytest.mark.parametrize("policy", [
    b'{"results":{"valid":true,"reused":false}}',
    b'{"results":{"reused":false,"valid":true}}',
])
def test_explicit_false_reused_allows_change(policy: bytes) -> None:
    h = Harness()
    h.responses["policy_conform"] = Response(policy)
    assert h.transport().reset().outcome is Outcome.BACKEND_CHANGED_METADATA_PRESERVED
    h.assert_disposed()


@pytest.mark.parametrize("policy", [
    b'{"results":{"valid":false}}', b'{"results":{"valid":true,"reused":true}}',
    b'{"results":{"valid":1}}', b'{"results":{"valid":"true"}}',
    b'{"results":{"valid":true,"reused":null}}', b'{"results":{"valid":true,"reused":0}}',
    b'{"results":{"valid":true,"reused":"false"}}', b'{"results":{}}',
    b'{"results":{"valid":false,"valid":true}}', b'{"results":{"valid":true},}',
])
def test_policy_requires_exact_true_and_missing_or_exact_false_reused(policy: bytes) -> None:
    h = Harness()
    h.responses["policy_conform"] = Response(policy)
    transport = h.transport()
    result = transport.reset()
    assert result.outcome in {Outcome.POLICY_REJECTED, Outcome.RECONCILIATION_REQUIRED}
    assert not result.change_post_attempted and len(h.calls) == 1
    h.assert_disposed()
    assert transport.reset().outcome is Outcome.GATE_CLOSED


@pytest.mark.parametrize("payload", [
    b'{"results":{"changed":1}}', b'{"results":{"changed":"true"}}',
    b'{"results":{"changed":false}}', b'{"results":{"changed":null}}',
    b'{"results":{"changed":false,"changed":true}}',
    b'{"results":{"changed":true},"results":{"changed":true}}',
    b'{"results":{"changed":true,}}', b'{"results":{"changed":true}}junk',
    b'{"results":{"changed":true},"echo":"synthetic-password-echo"}',
    b'{"results":{"changed":true,"echo":"synthetic-password-echo"}}',
    b'{"results":{"changed":true', b'"synthetic-password-echo"', b'x' * 16385,
])
def test_change_and_unknown_or_echo_responses_fail_closed_without_disclosure(payload: bytes, capsys: Any, caplog: Any) -> None:
    h = Harness()
    h.responses["change_password"] = Response(payload)
    transport = h.transport()
    result = transport.reset()
    assert result.outcome is Outcome.RECONCILIATION_REQUIRED
    assert not result.backend_changed and not result.metadata_preserved and result.change_post_attempted
    assert "synthetic-password-echo" not in repr(result)
    assert capsys.readouterr().out == "" and caplog.text == ""
    h.assert_disposed()
    assert transport.reset().outcome is Outcome.GATE_CLOSED


@pytest.mark.parametrize("failure", ["policy_conform", "change_password", "response_policy_conform", "response_change_password"])
def test_error_or_timeout_never_retries_and_always_disposes(failure: str, capsys: Any, caplog: Any) -> None:
    h = Harness()
    h.fail_at = failure
    transport = h.transport()
    result = transport.reset()
    assert result.outcome is Outcome.RECONCILIATION_REQUIRED
    calls = len(h.calls)
    assert calls in {1, 2}
    assert transport.reset().outcome is Outcome.GATE_CLOSED and len(h.calls) == calls
    assert "synthetic-password-echo" not in repr(result)
    assert capsys.readouterr().out == "" and caplog.text == ""
    h.assert_disposed()


@pytest.mark.parametrize("updates", [
    {"nonmaterial_state_digest": "b" * 64}, {"fixture_creation_digest": "d" * 64},
    {"reported_reference_count": 1}, {"usage_entry_count": 1},
    {"reported_reference_count": False}, {"usage_entry_count": False},
])
def test_postwrite_complete_baseline_drift_keeps_backend_ack_separate(updates: dict[str, object]) -> None:
    h = Harness()
    h.snapshots[2] = _baseline(**updates)
    result = h.transport().reset()
    assert result.outcome is Outcome.RECONCILIATION_REQUIRED and result.backend_changed
    assert not result.metadata_preserved and not result.login_verified
    h.assert_disposed()


@pytest.mark.parametrize("kind", ["readonly", "stride", "format", "alias", "same_password"])
def test_invalid_or_aliased_material_is_rejected_and_backing_buffers_cleared(kind: str) -> None:
    h = Harness()
    backing: bytearray | array[int] = bytearray(b"other-synthetic-material")
    if kind == "readonly":
        new = memoryview(backing).toreadonly()
    elif kind == "stride":
        new = memoryview(backing)[::2]
    elif kind == "format":
        backing = array("I", [123, 456])
        new = memoryview(backing)
    elif kind == "alias":
        backing = h.old
        new = memoryview(h.old)
    else:
        backing = bytearray(h.old)
        new = memoryview(backing)
    h.lease = LocalUserResetMaterialLease(lambda: (memoryview(h.old), new))
    assert h.transport().reset().outcome is Outcome.RECONCILIATION_REQUIRED
    assert h.calls == [] and not any(h.old) and not any(backing)


def test_binding_and_lease_representations_are_redacted() -> None:
    h = Harness()
    assert h.baseline.username not in repr(h.binding)
    assert h.baseline.nonmaterial_state_digest not in repr(h.baseline)
    assert "redacted" in repr(h.lease)


@pytest.mark.parametrize("released_first", [True, False])
def test_released_material_view_cannot_skip_peer_cleanup(released_first: bool) -> None:
    h = Harness()
    released = memoryview(bytearray(b"provider-owned-released-material"))
    released.release()
    peer = bytearray(b"synthetic-peer-must-be-zeroized")
    valid = memoryview(peer)
    pair = (released, valid) if released_first else (valid, released)
    h.lease = LocalUserResetMaterialLease(lambda: pair)

    result = h.transport().reset()

    assert result.outcome is Outcome.RECONCILIATION_REQUIRED
    assert not result.change_post_attempted and h.calls == []
    assert not any(peer)
    with pytest.raises(ValueError, match="released memoryview"):
        _ = valid.obj


@pytest.mark.parametrize("origin", [
    "https://user:password@pam.example.test", "https://pam.example.test:0",
])
def test_unsafe_origin_is_rejected_without_exception_chain(origin: str) -> None:
    h = Harness()
    with pytest.raises(LocalUserResetHttpTransportError) as failure:
        FortiPamLocalUserResetHttpTransport(
            SecretMetadataHttpTransportConfig(origin, "unused", 5, None),
            binding=h.binding, inspector=h, owner_session=h, material_lease_provider=h.material,
        )
    assert failure.value.__cause__ is None and failure.value.__suppress_context__
    assert "user:password" not in str(failure.value)
    assert h.events == [] and h.connections == []
