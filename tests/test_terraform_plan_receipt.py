"""Independent Ed25519 issuer, pinned reader, original window and zero raw output."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from fortipam_mcp import terraform_plan_receipt as module
from fortipam_mcp import terraform_plan_configuration as configuration_module
from test_terraform_plan_projection import MARKER, plan


class Clock:
    wall = 1000
    mono = 50.0


@pytest.fixture(params=[module.PinnedSignedTerraformPlanArtifact, configuration_module.PinnedSignedTerraformConfigurationArtifact])
def reader_class(request):
    return request.param


def setup(tmp_path, *, change=None, signer=None, domain=None, raw_payload=None,
        reader_class=module.PinnedSignedTerraformPlanArtifact, artifact_value=None):
    tmp_path.chmod(0o700)
    artifact, receipt, public = (tmp_path / name for name in ("plan.private", "receipt.private", "issuer-public.private"))
    value = plan() if artifact_value is None else artifact_value
    if artifact_value is None and reader_class is configuration_module.PinnedSignedTerraformConfigurationArtifact:
        value["configuration"]["root_module"] = {"resources": [dict(address=MARKER, name=MARKER,
            mode="managed", type="fortipam_resource_folder", provider_config_key=MARKER, schema_version=0)]}
    raw = json.dumps(value).encode(); artifact.write_bytes(raw); artifact.chmod(0o600)
    key = Ed25519PrivateKey.generate(); public_bytes = key.public_key().public_bytes_raw()
    public.write_bytes(public_bytes); public.chmod(0o600)
    pins = module.TerraformPlanProducerPins(*(hashlib.sha256(text.encode()).hexdigest()
        for text in ("producer", "terraform", "provider", "configuration", "lock")))
    bindings = dict(run_nonce="a" * 64, requester_digest="b" * 64, transport_digest="c" * 64,
        issued_at=999, expires_at=1100)
    payload = dict(contract="fortipam-synthetic-terraform-plan-receipt/v1", purpose="synthetic-plan-review-only",
        profile_digest=pins.digest(), **bindings, completed_at=1000, artifact_sha256=hashlib.sha256(raw).hexdigest(),
        artifact_bytes=len(raw), commands=["version", "init", "plan", "show"], exit_codes=[0, 0, 0, 0],
        endpoint_connection_attempts=0, device_material_loaded=False, device_contacted=False, apply_invoked=False)
    if change: change(payload)
    wire = module._canonical(payload) if raw_payload is None else raw_payload(module._canonical(payload))
    signature = (signer or key).sign((domain or module._DOMAIN) + hashlib.sha256(wire).digest()).hex()
    receipt.write_bytes(b'{"payload":' + wire + b',"signature":"' + signature.encode() + b'"}')
    receipt.chmod(0o600); clock = Clock()
    reader = reader_class(artifact_path=artifact, receipt_path=receipt,
        public_key_path=public, public_key_sha256=hashlib.sha256(public_bytes).hexdigest(), pins=pins,
        **bindings, clock=lambda: clock.wall, monotonic=lambda: clock.mono)
    return reader, clock, artifact, receipt, public


def capture_reads(monkeypatch):
    original = module._read_owned; buffers = []; paths = []
    def read(path):
        raw, identity = original(path); buffers.append(raw); paths.append(path); return raw, identity
    monkeypatch.setattr(module, "_read_owned", read)
    monkeypatch.setattr(configuration_module, "_read_owned", read)
    return buffers, paths


def test_only_public_key_consumer_authenticates_original_private_metadata_and_artifact(tmp_path, monkeypatch, reader_class):
    reader, clock, artifact, receipt, public = setup(tmp_path, reader_class=reader_class)
    buffers, paths = capture_reads(monkeypatch)
    def no_decoder(*args, **kwargs): raise AssertionError("Receipt and artifact must stay byte-only.")
    monkeypatch.setattr(json, "loads", no_decoder)
    result = reader.read_once(); summary = result.summary()
    assert summary["producer_receipt_signature_verified"] is summary["artifact_integrity_verified"] is True
    assert summary["resource_change_entries"] == 1
    assert summary["source_provenance_verified"] is summary["runtime_caller_authenticated"] is False
    assert summary["review_complete"] is summary["apply_authorized"] is summary["execution_ready"] is False
    text = json.dumps(summary)
    assert MARKER not in text and str(tmp_path) not in text and "a" * 64 not in text
    assert paths == [receipt, artifact] and all(not any(raw) for raw in buffers)
    assert "redacted" in repr(result) and "redacted" in repr(reader)
    with pytest.raises(module.TerraformPlanReceiptError): reader.read_once()
    reader.close()
    assert artifact.exists() and receipt.exists() and public.exists()


@pytest.mark.parametrize("fault", ["foreign-key", "wrong-domain", "signature", "profile", "nonce", "requester", "transport",
    "renewed-window", "future-completion", "nonzero-exit", "apply-command", "apply-effect", "material-effect",
    "device-effect", "endpoint-effect", "unknown-field", "duplicate-payload-field", "malformed-signature"])
def test_untrusted_or_expanded_receipt_refuses_before_artifact_read(tmp_path, monkeypatch, fault, reader_class):
    changes = {
        "profile": lambda p: p.update(profile_digest="d" * 64),
        "nonce": lambda p: p.update(run_nonce="d" * 64),
        "requester": lambda p: p.update(requester_digest="d" * 64),
        "transport": lambda p: p.update(transport_digest="d" * 64),
        "renewed-window": lambda p: p.update(expires_at=1101),
        "future-completion": lambda p: p.update(completed_at=1001),
        "nonzero-exit": lambda p: p.update(exit_codes=[0, 0, 1, 0]),
        "apply-command": lambda p: p.update(commands=["version", "init", "plan", "apply"]),
        "apply-effect": lambda p: p.update(apply_invoked=True),
        "material-effect": lambda p: p.update(device_material_loaded=True),
        "device-effect": lambda p: p.update(device_contacted=True),
        "endpoint-effect": lambda p: p.update(endpoint_connection_attempts=1),
        "unknown-field": lambda p: p.update(instruction=MARKER),
    }
    reader, clock, artifact, receipt, public = setup(tmp_path, change=changes.get(fault), reader_class=reader_class,
        signer=Ed25519PrivateKey.generate() if fault == "foreign-key" else None,
        domain=b"another-protocol\x00" if fault == "wrong-domain" else None,
        raw_payload=(lambda raw: raw.replace(b'"completed_at":1000', b'"completed_at":1000,"completed_at":1000'))
            if fault == "duplicate-payload-field" else None)
    if fault in ("signature", "malformed-signature"):
        wire = receipt.read_bytes(); at = wire.index(b'"signature":"') + len(b'"signature":"')
        replacement = b"g" if fault == "malformed-signature" else b"0" if wire[at] != 48 else b"1"
        receipt.write_bytes(wire[:at] + replacement + wire[at + 1:])
    buffers, paths = capture_reads(monkeypatch)
    with pytest.raises(module.TerraformPlanReceiptError) as caught: reader.read_once()
    assert str(caught.value) == "The private signed Terraform artifact is unavailable."
    assert paths == [receipt] and artifact not in paths and all(not any(raw) for raw in buffers)
    with pytest.raises(module.TerraformPlanReceiptError): reader.read_once()


@pytest.mark.parametrize("fault", ["wall-expired", "wall-rollback", "monotonic-expired", "monotonic-rollback", "closed",
    "key-mode", "same-key-new-inode", "artifact-drift", "artifact-mode", "late-expiry", "late-key-change"])
def test_original_time_and_file_bindings_fail_closed_without_renewal_or_partial_output(tmp_path, monkeypatch, fault, reader_class):
    reader, clock, artifact, receipt, public = setup(tmp_path, reader_class=reader_class)
    if fault == "wall-expired": clock.wall = 1100
    elif fault == "wall-rollback": clock.wall = 999
    elif fault == "monotonic-expired": clock.mono = 150.0
    elif fault == "monotonic-rollback": clock.mono = 49.0
    elif fault == "closed": reader.close()
    elif fault == "key-mode": public.chmod(0o644)
    elif fault == "same-key-new-inode":
        before = public.read_bytes(); public.rename(tmp_path / "old-public.private")
        public.write_bytes(before); public.chmod(0o600)
    elif fault == "artifact-drift": artifact.write_bytes(artifact.read_bytes() + b" ")
    elif fault == "artifact-mode": artifact.chmod(0o644)
    original = module._read_owned; buffers = []
    def read(path):
        raw, identity = original(path); buffers.append(raw)
        if path == artifact:
            if fault == "late-expiry": clock.wall = 1100
            elif fault == "late-key-change": public.write_bytes(b"x" * 32)
        return raw, identity
    monkeypatch.setattr(module, "_read_owned", read)
    monkeypatch.setattr(configuration_module, "_read_owned", read)
    with pytest.raises(module.TerraformPlanReceiptError): reader.read_once()
    assert all(not any(raw) for raw in buffers)
    with pytest.raises(module.TerraformPlanReceiptError): reader.read_once()


def test_interrupt_still_wipes_owned_receipt_and_artifact(tmp_path, monkeypatch, reader_class):
    reader, clock, artifact, receipt, public = setup(tmp_path, reader_class=reader_class)
    buffers, paths = capture_reads(monkeypatch)
    def interrupt(raw): raise KeyboardInterrupt
    monkeypatch.setattr(module, "project_private_terraform_plan", interrupt)
    monkeypatch.setattr(configuration_module, "project_private_terraform_configuration", interrupt)
    with pytest.raises(KeyboardInterrupt): reader.read_once()
    assert paths == [receipt, artifact] and all(not any(raw) for raw in buffers)
    with pytest.raises(module.TerraformPlanReceiptError): reader.read_once()
