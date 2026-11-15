"""Original full-state seals require actual fresh sources and active persistent M4."""
import json

import pytest
from v4_planning import M4AdapterAmbiguous, M4ExecutionKernel, canonical_digest

from fortipam_mcp.job_definition_ack_custody import JobDefinitionAckCustodyError
from test_job_definition_ack_custody import components, ack
from test_job_definition_sources import make, CANDIDATE, SOURCE, TARGET, SERIAL
from test_v4_execution_kernel import _Verifier
import fortipam_mcp.job_namespace_ssh_reader as namespace
from test_job_namespace_ssh_reader import names_frame


def prepared(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    source, api, peers, hosts = make(tmp_path, monkeypatch)
    absent = source.observe_absence()
    (tmp_path / "custody").mkdir(mode=0o700)
    for name, value in (("execution.key", b"e" * 32), ("ack.key", b"a" * 32)):
        (tmp_path / name).write_bytes(value); (tmp_path / name).chmod(0o600)
    binding = source._candidate._bound_definition_digests()
    expected = canonical_digest({"contract": "disabled-job-pristine-state-build29/v1",
        "body_digest": binding[0], "serial_digest": binding[1], "timeout_digest": binding[2]})
    custody, store, plan, authorization, pins, _ = components(tmp_path,
        body_digest=binding[0], serial_digest=binding[1], job_name=CANDIDATE,
        expected_current_digest=absent.current_digest, expected_state_digest=expected)
    return source, api, custody, store, plan, authorization, pins


class Adapter:
    def __init__(self, source, api, custody, pins, *, fault=None):
        self.source, self.api, self.custody, self.pins, self.fault = source, api, custody, pins, fault

    def read_current(self, plan):
        self.source.check_current(self.source._current)
        return self.source._current.current_digest

    def dispatch(self, plan):
        try:
            if self.fault == "legacy-begin": self.custody.begin_original_send()
            else: self.custody.begin_original_send_from_sources(self.source)
            self.api.present = True
            if self.fault == "lost-ack": raise M4AdapterAmbiguous("Synthetic lost original ACK.")
            self.custody.capture_original_ack(ack(self.pins, serial=SERIAL), http_status=200, content_type="application/json")
            if self.fault == "readback": self.api.failure = "candidate-ref"
            self.source.observe_candidate_presence()
            self.custody.capture_original_full_state(self.source)
        except Exception:
            raise M4AdapterAmbiguous("Synthetic original dispatch unavailable.") from None

    def read_postcondition(self, plan):
        if self.fault == "postcondition": raise M4AdapterAmbiguous("Synthetic postcondition interruption.")
        assert self.custody.inspect_original_full_state().state_digest == self.source._current.state_digest
        return plan.expected_state_digest


def execute(cmp, *, fault=None):
    source, api, custody, store, plan, authorization, pins = cmp
    return M4ExecutionKernel(Adapter(source, api, custody, pins, fault=fault), _Verifier(), store,
        clock=lambda: 1000).execute(plan, authorization)


@pytest.mark.parametrize("unknown", [False, True])
def test_original_seal_remains_readable_after_expiry_and_closed_source_without_status_promotion(tmp_path, monkeypatch, unknown):
    cmp = prepared(tmp_path, monkeypatch)
    source, api, custody, store, *_ = cmp
    result = execute(cmp, fault="postcondition" if unknown else None)
    assert str(result.outcome) == ("reconciliation_required" if unknown else "succeeded")
    sealed = custody.inspect_original_full_state()
    assert sealed.state_digest == source._current.state_digest
    assert sealed.source_context_digest == source.source_context_digest
    assert sealed.original_ack.original_verification == ("unknown" if unknown else "verified")
    before = {p.name: p.read_bytes() for p in custody._directory.iterdir()}
    assert set(before) == {"send.claim.json", "create-ack.json", "source-absence.json", "created-full-state.json"}
    assert b"BP008_JOB_OK" not in b"".join(before.values()) and CANDIDATE.encode() not in b"".join(before.values())
    source.close(); custody._clock = lambda: 2000
    assert custody.inspect_original_full_state() == sealed and store.claim_count == 1
    assert before == {p.name: p.read_bytes() for p in custody._directory.iterdir()}
    with pytest.raises(JobDefinitionAckCustodyError): custody.capture_original_full_state(source)
    assert custody.inspect_original_full_state() == sealed


@pytest.mark.parametrize("fault", ["lost-ack", "readback", "legacy-begin"])
def test_missing_original_source_ack_or_complete_state_can_never_be_late_sealed(tmp_path, monkeypatch, fault):
    cmp = prepared(tmp_path, monkeypatch)
    source, api, custody, store, *_ = cmp
    result = execute(cmp, fault=fault)
    assert str(result.outcome) == "reconciliation_required" and store.claim_count == 1
    with pytest.raises(JobDefinitionAckCustodyError): custody.inspect_original_full_state()
    before = {p.name: p.read_bytes() for p in custody._directory.iterdir()}
    with pytest.raises(JobDefinitionAckCustodyError): custody.capture_original_full_state(source)
    assert before == {p.name: p.read_bytes() for p in custody._directory.iterdir()}
    source.close()


def test_namespace_delta_must_be_only_the_one_original_candidate(tmp_path, monkeypatch):
    cmp = prepared(tmp_path, monkeypatch)
    source, api, custody, store, *_ = cmp
    read = namespace._send_and_read
    async def changed(process, command, prompt, deadline):
        raw = await read(process, command, prompt, deadline)
        if api.present and command == namespace._NAME_PROJECTION:
            return names_frame((SOURCE, TARGET, CANDIDATE, "Other simultaneous Job"))
        return raw
    monkeypatch.setattr(namespace, "_send_and_read", changed)
    result = execute(cmp)
    assert str(result.outcome) == "reconciliation_required" and store.claim_count == 1
    assert custody.inspect_original_ack().original_verification == "unknown"
    with pytest.raises(JobDefinitionAckCustodyError): custody.inspect_original_full_state()
    source.close()


def test_original_full_state_record_tamper_is_not_current_state_adoption(tmp_path, monkeypatch):
    cmp = prepared(tmp_path, monkeypatch)
    source, api, custody, store, *_ = cmp
    assert str(execute(cmp).outcome) == "succeeded"
    path = custody._directory / "created-full-state.json"
    record = json.loads(path.read_bytes()); record["state_digest"] = "f" * 64
    path.write_text(json.dumps(record))
    before = len(api.calls)
    with pytest.raises(JobDefinitionAckCustodyError): custody.inspect_original_full_state()
    assert len(api.calls) == before and store.claim_count == 1
    source.close()
