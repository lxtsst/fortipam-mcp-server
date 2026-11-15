"""Synthetic parser boundary checks; these do not qualify native updates."""
from dataclasses import asdict
import json

import pytest

from fortipam_mcp import secret_approval_build29_linux_metadata as candidate
from fortipam_mcp.target_contract import DEFAULT_TEMPLATE

IDENTITY = {"id": 17, "name": "synthetic-linux", "folder": 9,
            "template": DEFAULT_TEMPLATE, "target": "synthetic-target"}


def source():
    row = {**IDENTITY, "need-approval": "disable", "need-approval-job": "disable",
           "bypass-approval": "disable", "approval-profile": "", "inherit-permission": "enable",
           "totp-setting": {"status": "disable", "shared-key": "secret-totp-marker"},
           "keyinfo": "secret-key-marker",
           "field": [{"id": i, "name": name, "type": name.lower(),
                      "value": "secret-field-marker"} for i, name in enumerate(("Host", "Username", "Password"), 1)]}
    envelope = {**candidate._NATIVE_ENVELOPE, "serial": "SYNTHETIC1", "results": [row]}
    return bytearray(json.dumps(envelope, separators=(",", ":")).encode())


def observe(raw):
    return candidate.qualify_secret_approval_build29_linux_metadata(
        raw, identity=IDENTITY, expected_serial="SYNTHETIC1")


def test_material_never_decoded_or_returned_and_input_erased(monkeypatch):
    raw = source()
    original = json.loads

    def guarded(value, **kwargs):
        encoded = value.encode() if isinstance(value, str) else value
        assert b"secret-field-marker" not in encoded
        assert b"secret-totp-marker" not in encoded
        assert b"secret-key-marker" not in encoded
        return original(value, **kwargs)

    monkeypatch.setattr(candidate.json, "loads", guarded)
    observed = observe(raw)
    assert not raw
    assert observed.approval_values == ("disable", "disable", "disable", "")
    assert observed.totp_disabled
    assert [slot.name for slot in observed.slots] == ["Host", "Username", "Password"]
    assert "secret-" not in json.dumps(asdict(observed))


@pytest.mark.parametrize("before,after", [
    (b'"id":17', b'"id":18'),
    (b'"folder":9', b'"folder":10'),
    (b'"target":"synthetic-target"', b'"target":"other"'),
    (b'"serial":"SYNTHETIC1"', b'"serial":"OTHER"'),
    (b'"build":29', b'"build":30'),
    (b'"id":17', b'"id":17,"id":17'),
    (b'"name":"Host"', b'"name":"Host","name":"Host"'),
    (b'"id":2', b'"id":1'),
    (b'"name":"Username"', b'"name":"Host"'),
    (b'"need-approval":"disable"', b'"need-approval":null'),
])
def test_drift_and_duplicate_rejected_with_erasure(before, after):
    raw = source().replace(before, after)
    with pytest.raises(candidate.SecretApprovalBuild29LinuxMetadataError, match="unavailable"):
        observe(raw)
    assert not raw


def test_template_binding_rejects_other_type_and_erases():
    raw = source()
    with pytest.raises(candidate.SecretApprovalBuild29LinuxMetadataError):
        candidate.qualify_secret_approval_build29_linux_metadata(
            raw, identity={**IDENTITY, "template": "Web Account"}, expected_serial="SYNTHETIC1")
    assert not raw
