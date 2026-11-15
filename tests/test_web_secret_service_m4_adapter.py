from dataclasses import replace
from types import SimpleNamespace

import pytest
from v4_planning import M4AdapterAmbiguous, M4AdapterDenied
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataProjectionInspection
from fortipam_mcp.web_secret_service_m4_adapter import (
    ACTION_ID, ACTION_VERSION, ADAPTER_REF, WebSecretServiceBinding,
    WebSecretServiceM4Adapter, parameters_digest, state_digest,
)


def _case():
    binding = WebSecretServiceBinding("web-service-ref", "Public/lab", "lab-web", 24)
    plan = SimpleNamespace(
        action_id=ACTION_ID, action_version=ACTION_VERSION, adapter_ref=ADAPTER_REF,
        target_ref=binding.object_ref, parameters_digest=parameters_digest(binding),
        expected_current_digest=state_digest(binding, enabled=False),
        expected_state_digest=state_digest(binding, enabled=True),
    )
    baseline = SecretMetadataProjectionInspection(
        True, True, True, True, True, True, True, False, recording_matches=True,
    )
    class Reader:
        value = baseline
        def inspect_web_projection(self, folder, name, template, *, expected_secret_id):
            assert (folder, name, template, expected_secret_id) == (
                "Public/lab", "lab-web", "Web Account", 24,
            )
            return self.value
    reader = Reader()
    class Writer:
        calls = 0
        def enable_http_service(self, secret_id, *, prewrite):
            assert secret_id == 24 and prewrite == baseline
            self.calls += 1
            reader.value = replace(baseline, http_service_enabled=True)
    writer = Writer()
    return WebSecretServiceM4Adapter(binding, reader, writer), plan, reader, writer


def test_one_dispatch_and_enabled_readback():
    adapter, plan, _, writer = _case()
    assert adapter.read_current(plan) == plan.expected_current_digest
    adapter.dispatch(plan)
    assert adapter.read_postcondition(plan) == plan.expected_state_digest
    with pytest.raises(M4AdapterDenied):
        adapter.dispatch(plan)
    assert writer.calls == 1


@pytest.mark.parametrize("field", ["http_service_enabled", "recording_matches", "target_matches"])
def test_last_moment_drift_rejects_write(field):
    adapter, plan, reader, writer = _case()
    adapter.read_current(plan)
    reader.value = replace(reader.value, **{field: not getattr(reader.value, field)})
    with pytest.raises((M4AdapterDenied, M4AdapterAmbiguous)):
        adapter.dispatch(plan)
    assert writer.calls == 0


def test_wrong_action_rejected_without_write():
    adapter, plan, _, writer = _case()
    plan.action_id = "secret-create"
    with pytest.raises(M4AdapterDenied):
        adapter.read_current(plan)
    assert writer.calls == 0


def test_transport_uncertainty_cannot_be_replayed():
    adapter, plan, _, writer = _case()
    def fail(*args, **kwargs):
        writer.calls += 1
        raise OSError("private device text")
    writer.enable_http_service = fail
    adapter.read_current(plan)
    with pytest.raises(M4AdapterAmbiguous) as result:
        adapter.dispatch(plan)
    assert "private" not in str(result.value)
    with pytest.raises(M4AdapterDenied):
        adapter.dispatch(plan)
    assert writer.calls == 1


@pytest.mark.parametrize("settles", [True, False])
def test_postcondition_settles_with_bounded_reads_and_no_extra_write(monkeypatch, settles):
    adapter, plan, reader, writer = _case()
    baseline = reader.value
    adapter.read_current(plan)
    adapter.dispatch(plan)
    enabled = reader.value
    values = iter([baseline, baseline, enabled if settles else baseline])
    reads = []
    sleeps = []
    def read(*args, **kwargs):
        reads.append(True)
        return next(values)
    reader.inspect_web_projection = read
    monkeypatch.setattr("fortipam_mcp.web_secret_service_m4_adapter.time.sleep", sleeps.append)
    assert adapter.read_postcondition(plan) == (
        plan.expected_state_digest if settles else plan.expected_current_digest
    )
    assert len(reads) == 3 and sleeps == [5.0, 5.0]
    assert writer.calls == 1
    with pytest.raises(M4AdapterDenied):
        adapter.dispatch(plan)
    assert writer.calls == 1


@pytest.mark.parametrize("field", ["recording_matches", "template_matches", "field_values_attached"])
def test_postcondition_drift_stops_without_polling_or_write(monkeypatch, field):
    adapter, plan, reader, writer = _case()
    adapter.read_current(plan)
    adapter.dispatch(plan)
    reader.value = replace(reader.value, **{field: not getattr(reader.value, field)})
    sleeps = []
    monkeypatch.setattr("fortipam_mcp.web_secret_service_m4_adapter.time.sleep", sleeps.append)
    with pytest.raises(M4AdapterAmbiguous):
        adapter.read_postcondition(plan)
    assert sleeps == [] and writer.calls == 1
