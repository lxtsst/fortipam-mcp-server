"""Quota transfer preserves unrelated fields and cannot recover over resources."""
import copy
import hashlib
import json
import pickle

import pytest

from fortipam_mcp import instruction_quota_contract as q
from fortipam_mcp.instruction_resource_usage import project_instruction_resource_usage
from v4_planning.material_provider import MaterialAccessDenied

SERIAL = hashlib.sha256(b"synthetic-device").hexdigest()


def envelope(values, path="secret", name="setting", schema=False):
    return bytearray(json.dumps({"version": "v7.0.0", "build": 29,
        "http_method": "GET", "http_status": 200, "status": "success", "vdom": "root",
        "serial": "synthetic-device", "path": path, "name": name,
        "action": "schema" if schema else "", "results": values}).encode())


def state(*, file=5, instruction=0, video=90, software=0, other="synthetic-private",
          missing=False, schema_type="integer", schema_extra="original"):
    children = {key: {"type": schema_type} for key in (q._FILE, q._SOFTWARE, q._INSTRUCTION)}
    children.update({"guest-instruction": {"type": "option", "options": [{"name": "enable"}, {"name": "disable"}]},
        "reverse-service-setting": {"type": "table", "children": {
            key: {"type": "string", "default": ""} for key in ("auto-gateway-id-whitelist", "client-ca")}},
        "future": {"type": "string"}})
    current = {q._FILE: file, q._INSTRUCTION: instruction, q._SOFTWARE: software,
        "guest-instruction": "disable", "reverse-service-setting": [], "future": other}
    if missing:
        del current["future"]
    raws = (envelope({"children": children, "extra": schema_extra}, schema=True),
            envelope(current), envelope({q._VIDEO: video}, path="system", name="global"))
    try:
        return q.read_instruction_quota_state(*raws, serial_digest=SERIAL)
    finally:
        assert all(not raw for raw in raws)


def usage(*, file=350, resource=0, video=1000, total=10000):
    raw = envelope({"video_disk_total_bytes": total, "video_used_bytes": video,
        "sec_file_used_bytes": file, "software_package_used_bytes": 0,
        "sec_instruction_used_bytes": resource}, path="log", name="current-disk-usage")
    return project_instruction_resource_usage(raw, serial_digest=SERIAL)


def test_fixed_transfer_and_restore_preserve_configuration_and_total():
    baseline, allocated, measured = state(), state(file=4, instruction=1), usage()
    plan = q.InstructionQuotaTransition(baseline, baseline, measured, phase="allocate", operation_nonce="a"*64)
    assert q.build_instruction_quota_body(plan, baseline, measured) == b'{"file-storage-quota":4,"secret-instruction-quota":1}'
    q.verify_instruction_quota_readback(plan, allocated, measured)
    restore = q.InstructionQuotaTransition(baseline, allocated, measured, phase="restore", operation_nonce="b"*64)
    assert q.build_instruction_quota_body(restore, allocated, measured) == b'{"secret-instruction-quota":0,"file-storage-quota":5}'
    q.verify_instruction_quota_readback(restore, baseline, measured)
    assert sum(baseline._quotas) == sum(allocated._quotas) == 95


def test_reject_config_schema_video_and_usage_drift_without_decoding_private_values(monkeypatch):
    scalar = q.m._scalar
    def selected(raw, span):
        assert b"synthetic-private" not in raw[slice(*span)]
        return scalar(raw, span)
    monkeypatch.setattr(q.m, "_scalar", selected)
    baseline, measured = state(), usage()
    plan = q.InstructionQuotaTransition(baseline, baseline, measured, phase="allocate", operation_nonce="a"*64)
    for changed in (state(other="changed"), state(video=89), state(schema_extra="changed")):
        with pytest.raises(q.InstructionQuotaContractError):
            q.build_instruction_quota_body(plan, changed, measured)
    with pytest.raises(q.InstructionQuotaContractError):
        q.build_instruction_quota_body(plan, baseline, usage(file=351))
    for item in (baseline, plan):
        assert "synthetic-private" not in repr(item)
        for clone in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(MaterialAccessDenied):
                clone(item)


def test_byte_exact_minimum_and_no_restore_while_resource_bytes_remain():
    baseline, allocated = state(), state(file=4, instruction=1)
    q.InstructionQuotaTransition(baseline, baseline, usage(file=400), phase="allocate", operation_nonce="a"*64)
    with pytest.raises(q.InstructionQuotaContractError):
        q.InstructionQuotaTransition(baseline, baseline, usage(file=401), phase="allocate", operation_nonce="a"*64)
    with pytest.raises(q.InstructionQuotaContractError):
        q.InstructionQuotaTransition(baseline, allocated, usage(resource=1), phase="restore", operation_nonce="a"*64)
    restore = q.InstructionQuotaTransition(baseline, allocated, usage(), phase="restore", operation_nonce="a"*64)
    with pytest.raises(q.InstructionQuotaContractError):
        q.verify_instruction_quota_readback(restore, baseline, usage(resource=1))


@pytest.mark.parametrize("values", [dict(file=False), dict(instruction=0.0), dict(file=0),
    dict(instruction=6), dict(software=31), dict(video=91), dict(file=6),
    dict(missing=True), dict(schema_type="string")])
def test_invalid_scalar_bounds_and_incomplete_preservation_are_rejected(values):
    with pytest.raises(q.InstructionQuotaContractError):
        state(**values)


def test_candidate_requires_zero_instruction_and_a_file_donor_above_minimum():
    for baseline in (state(file=1, video=90), state(file=4, instruction=1)):
        with pytest.raises(q.InstructionQuotaContractError):
            q.InstructionQuotaTransition(baseline, baseline, usage(file=0), phase="allocate", operation_nonce="a"*64)
