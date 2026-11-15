"""Policy observations reuse original custody, never Instruction source rights."""
from contextlib import contextmanager
import json
import ssl

import pytest

from fortipam_mcp import web_secret_fixture_api_preservation_reader as r
from fortipam_mcp.policy_assignment_preservation import PolicyAssignmentPreservation
from test_instruction_feature_http_reader import Client, Response
from test_secret_instruction_build29_api_preservation import _source, _raw, PASSWORD
from test_web_secret_create_ack import _record_fixture
from test_web_secret_fixture_creation_record import _fixture as unacknowledged_fixture

POLICY = "synthetic-policy-a"
OTHER = "synthetic-policy-b"


def fixture(tmp_path, monkeypatch):
    record, inputs, config, metadata_client, connection = _record_fixture(tmp_path, monkeypatch)
    evidence = record.record_creation()
    baseline = json.loads(evidence.baseline_json)
    password_pin = {"http_method": "POST", "http_status": 200, "status": "OK", "secret-id": evidence.native_secret_id,
        "msg": "Synthetic Password source"}
    totp_pin = {**password_pin, "msg": "Synthetic TOTP source"}
    monkeypatch.setattr(r, "_ssl_context", lambda _: ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))

    def make(policy=POLICY, phase="policy-baseline", observed=None, instruction=""):
        row = _source(instruction)
        row["serial"] = "unit-appliance"
        row["results"][0].update({**baseline, "instruction-profile": instruction, "policy": observed or policy or POLICY})
        password = _raw({**password_pin, "results": PASSWORD})
        totp = _raw({**totp_pin, "results": ""})
        client = Client([Response(_raw(row)), Response(password), Response(totp), Response(_raw(row)),
            Response(totp), Response(password), Response(_raw(row))])
        seen = []
        def factory(**kwargs):
            seen.append(kwargs)
            return client
        reader = r.WebSecretFixtureApiPreservationReader(record, instruction_profile_name=instruction,
            credential_envelope=password_pin, totp_envelope=totp_pin, phase=phase, policy_name=policy,
            client_factory=factory)
        return reader, client, seen
    return make, record, inputs, config, metadata_client, connection


def test_original_ack_and_seven_closed_requests_publish_only_the_policy_witness(tmp_path, monkeypatch):
    make, record, inputs, config, metadata_client, connection = fixture(tmp_path, monkeypatch)
    reader, client, seen = make()
    before = {name: (inputs["directory"] / name).read_bytes() for name in ("creation.record", "creation.ack")}
    store_before = inputs["execution_store"]._path.read_bytes()
    original = r.consume_policy_assignment_preservation
    buffers = []
    def consume(raw, **kwargs):
        assert client.is_closed and not client.cookies and all(response.is_closed for response in client.responses)
        assert kwargs["expected_policy_name"] == POLICY
        buffers.extend((raw, kwargs["witness_key"]))
        return original(raw, **kwargs)
    monkeypatch.setattr(r, "consume_policy_assignment_preservation", consume)
    result = reader.read_policy_assignment_once()
    assert type(result) is PolicyAssignmentPreservation and "redacted" in repr(result)
    assert result.summary()["source_completeness_qualified"] is False
    assert buffers and all(not any(value) for value in buffers)
    assert [method for method, _, _ in client.calls] == ["GET", "POST", "POST", "GET", "POST", "POST", "GET"]
    assert all(url == config.base_url + "/api/v2/cmdb/secret/database/37" for method, url, _ in client.calls if method == "GET")
    assert all(url == config.base_url + r._CLEAR for method, url, _ in client.calls if method == "POST")
    assert all(kwargs["headers"]["Authorization"] == "Bearer " + config.bearer_token for _, _, kwargs in client.calls)
    assert seen[0]["verify"].check_hostname and not seen[0]["trust_env"] and not seen[0]["follow_redirects"]
    assert (inputs["directory"] / "api-preservation.policy-baseline.attempt").is_file()
    assert not (inputs["directory"] / "api-preservation.baseline.attempt").exists()
    assert all((inputs["directory"] / name).read_bytes() == value for name, value in before.items())
    assert inputs["execution_store"]._path.read_bytes() == store_before
    assert record.read_acknowledged_creation().creation == record.read_creation()
    assert connection.posts == len(metadata_client.calls) == 1
    with pytest.raises(r.WebSecretFixtureApiPreservationReadError): reader.observed_envelopes()
    with pytest.raises(r.WebSecretFixtureApiPreservationReadError): reader.read_policy_assignment_once()
    assert len(client.calls) == 7


def test_policy_change_across_distinct_phases_keeps_the_complete_preservation_digest(tmp_path, monkeypatch):
    make, _, _, _, _, _ = fixture(tmp_path, monkeypatch)
    baseline, first, _ = make()
    assigned, second, _ = make(OTHER, "policy-assigned")
    restored, third, _ = make(POLICY, "policy-restored")
    second.responses[3].content = second.responses[3].content.replace(b'"shared-key":null', b'"shared-key":"ENC VOLATILE"')
    results = [reader.read_policy_assignment_once() for reader in (baseline, assigned, restored)]
    assert len({result.preservation_digest for result in results}) == 1
    assert all(client.is_closed and len(client.calls) == 7 for client in (first, second, third))


def test_wrong_projection_method_refuses_without_consuming_the_correct_phase(tmp_path, monkeypatch):
    make, _, _, _, _, _ = fixture(tmp_path, monkeypatch)
    policy, client, _ = make()
    with pytest.raises(r.WebSecretFixtureApiPreservationReadError): policy.read_once()
    with pytest.raises(r.WebSecretFixtureApiPreservationReadError): policy.read_instruction_update_once("mcp-v4-ip-unit01")
    assert not client.calls and policy.read_policy_assignment_once()
    legacy, other, _ = make(None, "baseline")
    with pytest.raises(r.WebSecretFixtureApiPreservationReadError): legacy.read_policy_assignment_once()
    assert not other.calls and legacy.read_once()


def test_policy_mismatch_stops_before_material_reads_and_cannot_retry_under_another_name(tmp_path, monkeypatch):
    make, _, _, _, _, _ = fixture(tmp_path, monkeypatch)
    wrong, client, _ = make(OTHER, observed=POLICY)
    with pytest.raises(r.WebSecretFixtureApiPreservationReadError): wrong.read_policy_assignment_once()
    assert len(client.calls) == 1 and client.calls[0][0] == "GET" and client.is_closed
    corrected, fresh, seen = make(POLICY)
    with pytest.raises(r.WebSecretFixtureApiPreservationReadError): corrected.read_policy_assignment_once()
    assert not fresh.calls and not seen


@pytest.mark.parametrize("after", [0, 2, 7])
def test_original_ack_loss_blocks_the_next_request_or_publication(tmp_path, monkeypatch, after):
    make, _, inputs, _, _, _ = fixture(tmp_path, monkeypatch)
    reader, client, _ = make()
    path = inputs["directory"] / "creation.ack"
    if after == 0:
        path.unlink()
    elif after == 7:
        class ClosingClient(Client):
            def __exit__(self, *args):
                super().__exit__(*args)
                path.unlink()
        client.__class__ = ClosingClient
    else:
        original = client.stream
        @contextmanager
        def stream(*args, **kwargs):
            with original(*args, **kwargs) as response:
                yield response
            if len(client.calls) == after:
                path.unlink()
        client.stream = stream
    erased = []
    wipe = r._zeroize_mutable
    def clear(raw):
        wipe(raw)
        erased.append(raw)
    monkeypatch.setattr(r, "_zeroize_mutable", clear)
    with pytest.raises(r.WebSecretFixtureApiPreservationReadError): reader.read_policy_assignment_once()
    assert len(client.calls) == after
    assert not client.calls or client.is_closed
    assert erased and all(not any(raw) for raw in erased)
    assert reader._source_result is None


@pytest.mark.parametrize("policy,phase,instruction", [(None, "policy-baseline", ""), (POLICY, "baseline", ""),
    (POLICY, "policy-baseline", "mcp-v4-ip-unit01"), ("", "policy-baseline", "")])
def test_profile_phase_and_reference_cannot_cross_into_legacy_contexts(tmp_path, monkeypatch, policy, phase, instruction):
    make, _, inputs, _, _, _ = fixture(tmp_path, monkeypatch)
    with pytest.raises(r.WebSecretFixtureApiPreservationReadError): make(policy, phase, instruction=instruction)
    assert not list(inputs["directory"].glob("api-preservation.*.attempt"))


def test_a_metadata_creation_record_without_original_ack_cannot_enter_policy_profile(tmp_path, monkeypatch):
    record, _, _, _, _ = unacknowledged_fixture(tmp_path, monkeypatch)
    record.record_creation()
    with pytest.raises(r.WebSecretFixtureApiPreservationReadError):
        r.WebSecretFixtureApiPreservationReader(record, instruction_profile_name="", credential_envelope=None,
            totp_envelope=None, policy_name=POLICY, phase="policy-baseline")


def test_policy_observation_between_original_source_and_m4_disposal_preserves_recovery(tmp_path, monkeypatch):
    from fortipam_mcp import web_secret_fixture_recovery_guard as guards
    from fortipam_mcp import web_secret_fixture_recovery_runtime as recovery
    from fortipam_mcp.web_secret_fixture_recovery_authority import WebSecretFixtureRecoveryAuthority
    from test_web_secret_fixture_source_observation import source_fixture
    from test_web_secret_fixture_recovery_runtime import NativeConnection

    observer, record, factory, clients, directory, store, create, creator_factory = source_fixture(tmp_path, monkeypatch)
    for client in clients:
        for index in (0, 3, 6):
            value = json.loads(client.responses[index].content)
            value["results"][0]["policy"] = POLICY
            client.responses[index].content = _raw(value)
    inserted = Client([Response(bytearray(response.content)) for response in clients[1].responses])
    clients.insert(1, inserted)
    original_files = [(directory / name).read_bytes() for name in ("creation.record", "creation.ack")]
    observer.read_once()
    pins = observer.observed_envelopes()
    source_attempt = (directory / "api-preservation.source.attempt").read_bytes()
    policy = r.WebSecretFixtureApiPreservationReader(record, instruction_profile_name="", policy_name=POLICY,
        credential_envelope=pins[0], totp_envelope=pins[1], phase="policy-baseline", client_factory=factory)
    assert type(policy.read_policy_assignment_once()) is PolicyAssignmentPreservation
    with pytest.raises(guards.WebSecretFixtureRecoveryGuardError):
        guards.WebSecretFixtureRecoveryGuard(record, credential_envelope=pins[0], totp_envelope=pins[1],
            source_observer=policy, client_factory=factory, clock=creator_factory._clock)
    guard = guards.WebSecretFixtureRecoveryGuard(record, credential_envelope=pins[0], totp_envelope=pins[1],
        source_observer=observer, client_factory=factory, clock=creator_factory._clock)
    authority = WebSecretFixtureRecoveryAuthority(guard, authority_key=b"synthetic-policy-source-recovery-key01",
        environment_ref=creator_factory._promoter._environment_ref, scope_ref=creator_factory._promoter._scope_ref,
        audience_ref="synthetic-policy-source-client", requester_digest=record._execution_binding.plan.requester_digest,
        transport_digest="a" * 64, execution_enabled=True)
    events = []
    connections = [NativeConnection("DELETE", events), NativeConnection("GET", events)]
    pending = iter(connections)
    runtime = recovery.WebSecretFixtureRecoveryRuntime(guard, authorization_verifier=authority,
        observe_delete_source=True, execution_enabled=True, connection_factory=lambda *args, **kwargs: next(pending))
    issued = authority.issue(runtime, requester_digest=record._execution_binding.plan.requester_digest,
        transport_digest="a" * 64)
    result = runtime.execute(issued.plan, issued.authorization).as_dict()
    assert result["outcome"] == "succeeded" and result["verification"] == "verified"
    assert store.claim_count == 2 and create.posts == 1
    assert all(client.is_closed and len(client.calls) == 7 for client in clients)
    assert all(connection.closed and len(connection.calls) == 1 for connection in connections)
    assert original_files == [(directory / name).read_bytes() for name in ("creation.record", "creation.ack")]
    assert (directory / "api-preservation.source.attempt").read_bytes() == source_attempt
    assert (directory / "api-preservation.policy-baseline.attempt").is_file()
    runtime.close()
