from __future__ import annotations

import stat

import pytest

from scripts.v4_certificate_csr_mcp_oauth_acceptance import (
    CertificateCsrMcpOAuthAcceptanceError,
    _read_preview_ref,
    _validate_execution,
    _validate_preview,
    _write_preview_state,
)


def test_preview_state_is_owner_only_and_prefix_bound(tmp_path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "preview.json"
    _write_preview_state(path, "certificate-csr-preview-opaque")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert _read_preview_ref(path) == "certificate-csr-preview-opaque"
    with pytest.raises(CertificateCsrMcpOAuthAcceptanceError):
        _write_preview_state(path, "invalid")


def test_preview_requires_exact_file_based_rsa_contract() -> None:
    name = "mcp-v4-cert-b105"
    subject = "127.0.0.1"
    projection = {
        "contract": "fortipam_v4_certificate_csr_workflow_v1",
        "preview_ref": "certificate-csr-preview-opaque",
        "device_write_executed": False,
        "Current State": {
            "requested_certificate_name": name,
            "requested_subject_ipv4": subject,
            "certificate_entry_exists": False,
            "certificate_name_available": True,
            "write_transport": "rest_api",
        },
        "Proposed Changes": {
            "operation": "generate_certificate_signing_request",
            "certificate_name": name,
            "subject_type": "host_ipv4",
            "subject_ipv4": subject,
            "key_type": "rsa",
            "key_size": 2048,
            "scope": "global",
            "organization_units": [],
            "enrollment_method": "file_based",
            "private_key_password_supplied": False,
        },
        "Expected State": {
            "certificate_entry_exists": True,
            "certificate_name_matches": True,
            "csr_present": True,
            "private_key_present": True,
            "certificate_or_private_key_value_returned": False,
        },
    }
    _validate_preview(projection, name, subject, False)
    projection["Proposed Changes"]["key_size"] = 4096
    with pytest.raises(CertificateCsrMcpOAuthAcceptanceError):
        _validate_preview(projection, name, subject, False)


def test_execution_requires_categorical_verified_readback() -> None:
    result = {
        "contract": "fortipam_v4_certificate_csr_execution_v1",
        "outcome": "succeeded",
        "verification": "verified",
        "idempotent_replay": False,
        "compensation": "not_requested",
        "certificate_name_returned": False,
        "subject_value_returned": False,
        "csr_value_returned": False,
        "certificate_value_returned": False,
        "private_key_value_returned": False,
        "raw_api_response_returned": False,
    }
    _validate_execution(result, False)
    result["private_key_value_returned"] = True
    with pytest.raises(CertificateCsrMcpOAuthAcceptanceError):
        _validate_execution(result, False)
