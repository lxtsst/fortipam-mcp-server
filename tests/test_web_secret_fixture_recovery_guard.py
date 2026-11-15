"""Original ACK/M4 custody plus two real producers, synthetic device only."""
from copy import copy
from dataclasses import replace
import json
import pickle
import ssl

import pytest

from fortipam_mcp import web_secret_fixture_recovery_guard as g
from fortipam_mcp import web_secret_fixture_api_preservation_reader as r
from v4_planning.material_provider import MaterialAccessDenied
from test_instruction_feature_http_reader import Client, Response
from test_secret_instruction_build29_api_preservation import _source, _raw, PASSWORD
from test_web_secret_create_ack import _record_fixture


def _fixture(tmp_path, monkeypatch):
    record, inputs, config, metadata_client, connection = _record_fixture(tmp_path, monkeypatch)
    original = record.record_creation()
    baseline = json.loads(original.baseline_json)
    row = _source("")
    row["serial"] = "unit-appliance"
    row["results"][0].update(baseline)
    password_pin = {"http_method": "POST", "http_status": 200, "status": "OK", "secret-id": 37,
                    "msg": "Synthetic Password source"}
    totp_pin = {**password_pin, "msg": "Synthetic TOTP source"}
    password = _raw({**password_pin, "results": PASSWORD})
    totp = _raw({**totp_pin, "results": ""})
    def client():
        return Client([Response(_raw(row)), Response(password), Response(totp), Response(_raw(row)),
                       Response(totp), Response(password), Response(_raw(row))])
    clients = [client(), client()]
    seen = []
    pending = iter(clients)
    def factory(**kwargs):
        seen.append(kwargs)
        return next(pending)
    now = [100]
    monkeypatch.setattr(r, "_ssl_context", lambda _: ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))
    guard = g.WebSecretFixtureRecoveryGuard(record, credential_envelope=password_pin,
        totp_envelope=totp_pin, client_factory=factory, clock=lambda: now[0])
    return guard, record, inputs, clients, seen, connection, metadata_client, now


def test_original_ack_and_complete_two_phase_observations_are_joined_privately(tmp_path, monkeypatch):
    guard, record, inputs, clients, seen, connection, metadata_client, _ = _fixture(tmp_path, monkeypatch)
    before_record = (inputs["directory"] / "creation.record").read_bytes()
    before_ack = (inputs["directory"] / "creation.ack").read_bytes()
    before_m4 = inputs["execution_store"]._path.read_bytes()
    assert guard.capture_baseline_once() is None
    result = guard.inspect_recovery_once()
    assert result.creation_digest == record.read_creation().creation_digest
    assert result.checked_at == 100 and result.expires_at == 160
    guard.check_current(result)
    assert len(seen) == 2 and all(len(client.calls) == 7 for client in clients)
    assert all(client.is_closed and not client.cookies for client in clients)
    assert all(response.is_closed for client in clients for response in client.responses)
    assert (inputs["directory"] / "api-preservation.baseline.attempt").exists()
    assert (inputs["directory"] / "api-preservation.recovery.attempt").exists()
    assert (inputs["directory"] / "creation.record").read_bytes() == before_record
    assert (inputs["directory"] / "creation.ack").read_bytes() == before_ack
    assert inputs["execution_store"]._path.read_bytes() == before_m4
    assert connection.posts == len(metadata_client.calls) == 1
    assert all(method in {"GET", "POST"} for client in clients for method, _, _ in client.calls)
    assert result.current_digest not in repr(result) and result.source_digest not in str(result)
    for value in (guard, result):
        with pytest.raises(MaterialAccessDenied): copy(value)
        with pytest.raises(MaterialAccessDenied): pickle.dumps(value)
    guard.close()
    with pytest.raises(g.WebSecretFixtureRecoveryGuardError): guard.check_current(result)


@pytest.mark.parametrize("kind", ["password", "unknown-config", "username", "permission", "totp", "instruction"])
def test_stable_within_phase_but_changed_from_original_baseline_refuses(tmp_path, monkeypatch, kind):
    guard, _, _, clients, _, _, _, _ = _fixture(tmp_path, monkeypatch)
    guard.capture_baseline_once()
    client = clients[1]
    if kind == "password":
        for index in (1, 5):
            client.responses[index].content = client.responses[index].content.replace(b"synthetic-password", b"changed-password")
    elif kind == "totp":
        for index in (2, 4):
            client.responses[index].content = client.responses[index].content.replace(b'"results":""', b'"results":"changed-key"')
    else:
        for index in (0, 3, 6):
            row = json.loads(client.responses[index].content)
            item = row["results"][0]
            if kind == "unknown-config": item["future-config"] = {"changed": True}
            elif kind == "username":
                next(field for field in item["field"] if field["name"] == "Username")["value"] = "changed-user"
            elif kind == "permission": item["future-permission"] = "changed"
            else: item["instruction-profile"] = "mcp-v4-ip-other"
            client.responses[index].content = _raw(row)
    with pytest.raises(g.WebSecretFixtureRecoveryGuardError) as caught: guard.inspect_recovery_once()
    assert str(caught.value) == g._ERROR
    expected = 3 if kind == "totp" else 1 if kind == "instruction" else 7
    assert len(client.calls) == expected and client.is_closed
    with pytest.raises(g.WebSecretFixtureRecoveryGuardError): guard.inspect_recovery_once()
    assert len(client.calls) == expected


@pytest.mark.parametrize("kind", ["missing-ack", "pending", "missing-m4", "source", "phase", "baseline-marker"])
def test_original_custody_or_source_drift_refuses_before_recovery_http(tmp_path, monkeypatch, kind):
    guard, record, inputs, clients, seen, _, _, _ = _fixture(tmp_path, monkeypatch)
    guard.capture_baseline_once()
    if kind == "missing-ack": (inputs["directory"] / "creation.ack").unlink()
    elif kind == "pending": (inputs["directory"] / "creation.pending").touch(mode=0o600)
    elif kind == "missing-m4": inputs["execution_store"]._path.unlink()
    elif kind == "source":
        record._config = replace(record._config, bearer_token="changed-unit-token")
        record._transport._config = record._config
    elif kind == "baseline-marker": (inputs["directory"] / "api-preservation.baseline.attempt").unlink()
    else: guard._recovery._phase = "applied"
    with pytest.raises(g.WebSecretFixtureRecoveryGuardError): guard.inspect_recovery_once()
    assert len(seen) == 1 and not clients[1].calls


@pytest.mark.parametrize("kind", ["foreign", "expired", "backwards", "closed", "drift", "extended", "digest", "recovery-marker"])
def test_inspection_cannot_be_imported_extended_or_used_after_custody_loss(tmp_path, monkeypatch, kind):
    guard, _, inputs, clients, _, _, _, now = _fixture(tmp_path, monkeypatch)
    guard.capture_baseline_once()
    inspection = guard.inspect_recovery_once()
    if kind == "foreign": inspection = replace(inspection)
    elif kind == "expired": now[0] = 160
    elif kind == "backwards": now[0] = 99
    elif kind == "closed": guard.close()
    elif kind == "extended": object.__setattr__(inspection, "expires_at", 200)
    elif kind == "digest": object.__setattr__(inspection, "current_digest", "0" * 64)
    elif kind == "recovery-marker": (inputs["directory"] / "api-preservation.recovery.attempt").unlink()
    else: (inputs["directory"] / "creation.ack").write_bytes(b"damaged")
    with pytest.raises(g.WebSecretFixtureRecoveryGuardError): guard.check_current(inspection)
    assert all(len(client.calls) == 7 for client in clients)


def test_fresh_guard_cannot_adopt_consumed_baseline_after_restart(tmp_path, monkeypatch):
    guard, record, _, clients, seen, _, _, _ = _fixture(tmp_path, monkeypatch)
    guard.capture_baseline_once()
    fresh = g.WebSecretFixtureRecoveryGuard(record, credential_envelope=guard._baseline._credential_envelope,
        totp_envelope=guard._baseline._totp_envelope, client_factory=guard._factory, clock=guard._clock)
    with pytest.raises(g.WebSecretFixtureRecoveryGuardError): fresh.capture_baseline_once()
    assert len(seen) == 1 and not clients[1].calls


@pytest.mark.parametrize("index", [0, 3, 6])
def test_failed_original_baseline_never_allows_recovery(tmp_path, monkeypatch, index):
    guard, _, _, clients, seen, _, _, _ = _fixture(tmp_path, monkeypatch)
    clients[0].responses[index].status_code = 403
    with pytest.raises(g.WebSecretFixtureRecoveryGuardError): guard.capture_baseline_once()
    with pytest.raises(g.WebSecretFixtureRecoveryGuardError): guard.inspect_recovery_once()
    assert len(clients[0].calls) == index + 1 and not clients[1].calls and len(seen) == 1


def test_expiry_starts_before_recovery_io_not_after_it(tmp_path, monkeypatch):
    guard, _, _, clients, _, _, _, now = _fixture(tmp_path, monkeypatch)
    guard.capture_baseline_once()
    original = clients[1].__class__.__exit__
    class SlowClient(Client):
        def __exit__(self, *args):
            original(self, *args)
            now[0] = 160
    clients[1].__class__ = SlowClient
    with pytest.raises(g.WebSecretFixtureRecoveryGuardError): guard.inspect_recovery_once()
    assert clients[1].is_closed and len(clients[1].calls) == 7


def test_missing_original_ack_cannot_construct_guard_or_read_material(tmp_path, monkeypatch):
    guard, record, inputs, clients, seen, _, _, _ = _fixture(tmp_path, monkeypatch)
    (inputs["directory"] / "creation.ack").unlink()
    with pytest.raises(g.WebSecretFixtureRecoveryGuardError):
        g.WebSecretFixtureRecoveryGuard(record, credential_envelope=guard._baseline._credential_envelope,
            totp_envelope=guard._baseline._totp_envelope, client_factory=guard._factory)
    assert not seen and all(not client.calls for client in clients)
