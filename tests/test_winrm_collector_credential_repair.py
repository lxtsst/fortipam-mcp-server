from __future__ import annotations

import json
from dataclasses import replace
import threading

import pytest

from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from fortipam_mcp.winrm_collector_credential_repair import (
    CollectorCredentialRepairOutcome,
    FortiPamWinrmCollectorCredentialRepairTransport,
    WinrmCollectorCredentialRepairBinding,
    WinrmCollectorCredentialRepairGate,
    WinrmCollectorCredentialRepairMaterialLease,
    WinrmCollectorCredentialRepairWorkflow,
    WinrmCollectorUsernameForm,
)


def _binding() -> WinrmCollectorCredentialRepairBinding:
    return WinrmCollectorCredentialRepairBinding(
        23, "collector-fixture", 17, "Windows Machine", "192.0.2.10", 31, 32, 33,
    )


def _config() -> SecretMetadataHttpTransportConfig:
    return SecretMetadataHttpTransportConfig("https://pam.example.test", "not-used", 5, None)


class _Response:
    def __init__(self, status: int = 200) -> None:
        self.status = status
        self.closed = False

    def read(self, *_: object) -> bytes:
        raise AssertionError("The credential repair transport must not read a response body")

    def close(self) -> None:
        self.closed = True


class _Connection:
    def __init__(self, response: _Response) -> None:
        self.response = response
        self.calls: list[dict[str, object]] = []
        self.closed = False

    def request(self, method: str, url: str, body: memoryview, headers: dict[str, str]) -> None:
        self.calls.append({"method": method, "url": url, "body": bytes(body), "headers": headers})

    def getresponse(self) -> _Response:
        return self.response

    def close(self) -> None:
        self.closed = True


class _Inspector:
    def __init__(
        self,
        prewrite: WinrmCollectorCredentialRepairBinding,
        *,
        prewrite_material: bool = True,
        postwrite: bool = True,
    ) -> None:
        self.prewrite = prewrite
        self.prewrite_material = prewrite_material
        self.postwrite = postwrite
        self.reads = 0
        self.prewrite_material_calls: list[
            tuple[WinrmCollectorCredentialRepairBinding, bytes]
        ] = []
        self.postwrite_calls: list[
            tuple[WinrmCollectorCredentialRepairBinding, bytes, bytes]
        ] = []

    def read_prewrite(self) -> WinrmCollectorCredentialRepairBinding:
        self.reads += 1
        return self.prewrite

    def verify_prewrite_material(
        self, binding: WinrmCollectorCredentialRepairBinding, password: memoryview,
    ) -> bool:
        self.prewrite_material_calls.append((binding, bytes(password)))
        return self.prewrite_material

    def verify_postwrite(
        self,
        binding: WinrmCollectorCredentialRepairBinding,
        username: memoryview,
        password: memoryview,
    ) -> bool:
        self.postwrite_calls.append((binding, bytes(username), bytes(password)))
        return self.postwrite


class _OwnerSession:
    def __init__(self, connection: _Connection) -> None:
        self.connection = connection
        self.calls: list[tuple[str, int, int]] = []

    def collector_credential_repair_connection(
        self, host: str, port: int, *, secret_id: int,
    ) -> _Connection:
        self.calls.append((host, port, secret_id))
        return self.connection


def _workflow(
    connection: _Connection, inspector: _Inspector, gate: WinrmCollectorCredentialRepairGate,
    username: bytearray, password: bytearray,
) -> WinrmCollectorCredentialRepairWorkflow:
    transport = FortiPamWinrmCollectorCredentialRepairTransport(
        _config(), owner_session=_OwnerSession(connection),
    )
    return WinrmCollectorCredentialRepairWorkflow(
        _binding(), inspector, transport, gate,
        material_lease_provider=lambda: _lease(username, password),
    )


def _lease(username: bytearray, password: bytearray) -> WinrmCollectorCredentialRepairMaterialLease:
    return WinrmCollectorCredentialRepairMaterialLease(
        lambda: (memoryview(username), memoryview(password)),
    )


def test_one_put_uses_current_field_ids_full_array_and_categorical_readback() -> None:
    connection = _Connection(_Response())
    inspector = _Inspector(_binding())
    username = bytearray(b"MACHINE\\local_operator")
    password = bytearray(b"synthetic-password")
    gate = WinrmCollectorCredentialRepairGate(True)

    outcome = _workflow(connection, inspector, gate, username, password).repair()

    assert outcome is CollectorCredentialRepairOutcome.VERIFIED
    assert username == bytearray(len(username)) and password == bytearray(len(password))
    assert not gate.enabled
    assert connection.response.closed and connection.closed
    assert len(connection.calls) == 1
    call = connection.calls[0]
    assert call["method"] == "PUT" and call["url"] == "/api/v2/cmdb/secret/database/23"
    assert json.loads(call["body"]) == {
        "id": 23, "name": "collector-fixture", "folder": 17, "template": "Windows Machine",
        "field": [
            {"id": 31, "name": "Host", "value": "192.0.2.10"},
            {"id": 32, "name": "Username", "value": "MACHINE\\local_operator"},
            {"id": 33, "name": "Password", "value": "synthetic-password"},
        ],
    }
    assert "Authorization" not in call["headers"]
    assert inspector.prewrite_material_calls == [
        (_binding(), b"synthetic-password"),
    ]
    assert inspector.postwrite_calls == [
        (_binding(), b"MACHINE\\local_operator", b"synthetic-password"),
    ]


def test_closed_gate_does_not_read_material_or_open_a_connection() -> None:
    connection = _Connection(_Response())
    inspector = _Inspector(_binding())
    material_provider_called = False
    transport = FortiPamWinrmCollectorCredentialRepairTransport(
        _config(), owner_session=_OwnerSession(connection),
    )
    workflow = WinrmCollectorCredentialRepairWorkflow(
        _binding(), inspector, transport, WinrmCollectorCredentialRepairGate(),
        material_lease_provider=lambda: _unexpected_material(),
    )

    assert workflow.repair() is CollectorCredentialRepairOutcome.GATE_CLOSED
    assert inspector.reads == 0 and connection.calls == []
    assert material_provider_called is False


def _unexpected_material() -> WinrmCollectorCredentialRepairMaterialLease:
    raise AssertionError("The closed Gate must stop before material acquisition")


def test_prewrite_drift_rejects_before_password_acquisition_or_put() -> None:
    connection = _Connection(_Response())
    material_called = False
    transport = FortiPamWinrmCollectorCredentialRepairTransport(
        _config(), owner_session=_OwnerSession(connection),
    )
    workflow = WinrmCollectorCredentialRepairWorkflow(
        _binding(), _Inspector(replace(_binding(), username_field_id=34)), transport,
        WinrmCollectorCredentialRepairGate(True), material_lease_provider=lambda: _mark_material_provider(),
    )

    assert workflow.repair() is CollectorCredentialRepairOutcome.DRIFT_REJECTED
    assert connection.calls == [] and material_called is False


def _mark_material_provider() -> WinrmCollectorCredentialRepairMaterialLease:
    raise AssertionError("Drift must stop before material acquisition")


def test_rejected_put_is_single_shot_and_requires_reconciliation() -> None:
    connection = _Connection(_Response(500))
    inspector = _Inspector(_binding())
    username = bytearray(b"MACHINE\\local_operator")
    password = bytearray(b"synthetic-password")
    workflow = _workflow(connection, inspector, WinrmCollectorCredentialRepairGate(True), username, password)

    assert workflow.repair() is CollectorCredentialRepairOutcome.RECONCILIATION_REQUIRED
    assert workflow.repair() is CollectorCredentialRepairOutcome.GATE_CLOSED
    assert len(connection.calls) == 1
    assert inspector.postwrite_calls == []
    assert username == bytearray(len(username)) and password == bytearray(len(password))


def test_concurrent_workflows_reserve_once_before_any_c3_material_acquisition() -> None:
    connection = _Connection(_Response())
    barrier = threading.Barrier(2)
    acquisition_lock = threading.Lock()
    acquisitions = 0
    buffers: list[tuple[bytearray, bytearray]] = []

    class ConcurrentInspector(_Inspector):
        def read_prewrite(self) -> WinrmCollectorCredentialRepairBinding:
            barrier.wait(timeout=5)
            return super().read_prewrite()

    def material_lease_provider() -> WinrmCollectorCredentialRepairMaterialLease:
        nonlocal acquisitions
        username = bytearray(b"MACHINE\\local_operator")
        password = bytearray(b"synthetic-password")
        with acquisition_lock:
            acquisitions += 1
            buffers.append((username, password))
        return _lease(username, password)

    workflow = WinrmCollectorCredentialRepairWorkflow(
        _binding(), ConcurrentInspector(_binding()),
        FortiPamWinrmCollectorCredentialRepairTransport(
            _config(), owner_session=_OwnerSession(connection),
        ),
        WinrmCollectorCredentialRepairGate(True),
        material_lease_provider=material_lease_provider,
    )
    results: list[CollectorCredentialRepairOutcome] = []
    result_lock = threading.Lock()

    def run() -> None:
        outcome = workflow.repair()
        with result_lock:
            results.append(outcome)

    threads = [threading.Thread(target=run) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert all(not thread.is_alive() for thread in threads)
    assert sorted(results, key=str) == [
        CollectorCredentialRepairOutcome.GATE_CLOSED,
        CollectorCredentialRepairOutcome.VERIFIED,
    ]
    assert acquisitions == 1 and len(connection.calls) == 1
    assert all(user == bytearray(len(user)) and password == bytearray(len(password)) for user, password in buffers)


def test_owner_session_factory_is_supported_without_bearer_headers() -> None:
    connection = _Connection(_Response())
    owner_calls: list[tuple[object, ...]] = []

    class Owner:
        def collector_credential_repair_connection(self, host: str, port: int, *, secret_id: int) -> _Connection:
            owner_calls.append((host, port, secret_id))
            return connection

    transport = FortiPamWinrmCollectorCredentialRepairTransport(_config(), owner_session=Owner())
    username = bytearray(b"MACHINE\\local_operator")
    password = bytearray(b"synthetic-password")
    workflow = WinrmCollectorCredentialRepairWorkflow(
        _binding(), _Inspector(_binding()), transport, WinrmCollectorCredentialRepairGate(True),
        material_lease_provider=lambda: _lease(username, password),
    )

    assert workflow.repair() is CollectorCredentialRepairOutcome.VERIFIED
    assert owner_calls == [("pam.example.test", 443, 23)]
    assert "Authorization" not in connection.calls[0]["headers"]


def test_unqualified_local_form_requires_matching_private_binding() -> None:
    binding = replace(
        _binding(), username_form=WinrmCollectorUsernameForm.UNQUALIFIED_LOCAL,
    )
    connection = _Connection(_Response())
    username = bytearray(b"local_operator")
    password = bytearray(b"synthetic-password")
    workflow = WinrmCollectorCredentialRepairWorkflow(
        binding,
        _Inspector(binding),
        FortiPamWinrmCollectorCredentialRepairTransport(
            _config(), owner_session=_OwnerSession(connection),
        ),
        WinrmCollectorCredentialRepairGate(True),
        material_lease_provider=lambda: WinrmCollectorCredentialRepairMaterialLease(
            lambda: (memoryview(username), memoryview(password)),
            username_form=WinrmCollectorUsernameForm.UNQUALIFIED_LOCAL,
        ),
    )

    assert workflow.repair() is CollectorCredentialRepairOutcome.VERIFIED
    assert json.loads(connection.calls[0]["body"])["field"][1]["value"] == "local_operator"
    assert username == bytearray(len(username)) and password == bytearray(len(password))


def test_username_form_mismatch_rejects_before_put_and_zeroizes_material() -> None:
    binding = replace(
        _binding(), username_form=WinrmCollectorUsernameForm.UNQUALIFIED_LOCAL,
    )
    connection = _Connection(_Response())
    username = bytearray(b"MACHINE\\local_operator")
    password = bytearray(b"synthetic-password")
    gate = WinrmCollectorCredentialRepairGate(True)
    workflow = WinrmCollectorCredentialRepairWorkflow(
        binding,
        _Inspector(binding),
        FortiPamWinrmCollectorCredentialRepairTransport(
            _config(), owner_session=_OwnerSession(connection),
        ),
        gate,
        material_lease_provider=lambda: _lease(username, password),
    )

    assert workflow.repair() is CollectorCredentialRepairOutcome.DRIFT_REJECTED
    assert workflow.repair() is CollectorCredentialRepairOutcome.GATE_CLOSED
    assert not gate.enabled
    assert connection.calls == []
    assert username == bytearray(len(username)) and password == bytearray(len(password))


def test_password_drift_rejects_before_put_zeroizes_and_consumes_gate() -> None:
    connection = _Connection(_Response())
    inspector = _Inspector(_binding(), prewrite_material=False)
    username = bytearray(b"MACHINE\\local_operator")
    password = bytearray(b"synthetic-password")
    gate = WinrmCollectorCredentialRepairGate(True)
    workflow = _workflow(connection, inspector, gate, username, password)

    assert workflow.repair() is CollectorCredentialRepairOutcome.DRIFT_REJECTED
    assert workflow.repair() is CollectorCredentialRepairOutcome.GATE_CLOSED
    assert not gate.enabled
    assert connection.calls == [] and inspector.postwrite_calls == []
    assert inspector.prewrite_material_calls == [
        (_binding(), b"synthetic-password"),
    ]
    assert username == bytearray(len(username)) and password == bytearray(len(password))


@pytest.mark.parametrize(
    "username",
    ["", "operator", "operator@example.test", "MACHINE\\one\\two", "MACHINE\\bad\nname", "u" * 65 + "\\operator"],
)
def test_nonlocal_username_formats_never_dispatch(username: str) -> None:
    connection = _Connection(_Response())
    password = bytearray(b"synthetic-password")
    username_bytes = bytearray(username.encode("utf-8"))
    workflow = WinrmCollectorCredentialRepairWorkflow(
        _binding(), _Inspector(_binding()),
        FortiPamWinrmCollectorCredentialRepairTransport(
            _config(), owner_session=_OwnerSession(connection),
        ),
        WinrmCollectorCredentialRepairGate(True), material_lease_provider=lambda: _lease(username_bytes, password),
    )

    assert workflow.repair() is CollectorCredentialRepairOutcome.DRIFT_REJECTED
    assert connection.calls == [] and username_bytes == bytearray(len(username_bytes)) and password == bytearray(len(password))
