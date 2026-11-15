"""Exact DELETE ACK candidate and non-authorizing original-response diagnostics."""
import hashlib
import json

import pytest

from fortipam_mcp.job_definition_recovery_ack import consume_disabled_job_delete_ack
from fortipam_mcp.job_definition_create_contract import _observe_disabled_job_ack_shape

NAME = "mcp-v4-bp008-job-20261022-r31"


def envelope(**changes):
    return dict(version="v7.0.0", build=29, http_method="DELETE", http_status=200, status="success",
        path="secret", name="job", vdom="root", serial="SYNTHETIC", mkey=NAME, error=0) | changes


@pytest.mark.parametrize("changes", [{}, {"http_method": "POST"}, {"status": "OK"}, {"serial": "OTHER"},
    {"mkey": NAME + "-other"}, {"error": False}, {"error": None}, {"results": []}, {"schema_errors": []}])
def test_exact_original_delete_envelope_erases_raw_on_success_and_refusal(changes):
    raw = bytearray(json.dumps(envelope(**changes)).encode())
    args = dict(job_name=NAME, serial_digest=hashlib.sha256(b"SYNTHETIC").hexdigest(), context_digest="a" * 64,
        http_status=200, content_type="application/json", witness_key=b"k" * 32)
    if not changes:
        result = consume_disabled_job_delete_ack(raw, **args)
        assert len(result) == 64
    else:
        with pytest.raises(ValueError): consume_disabled_job_delete_ack(raw, **args)
    assert not any(raw)


def test_response_diagnostics_do_not_decode_or_return_arbitrary_error_text():
    raw = bytearray(json.dumps(dict(status="SENSITIVE_ERROR_SENTINEL", error="SENSITIVE_ERROR_SENTINEL",
        message="SENSITIVE_ERROR_SENTINEL", results={"unselected": "SENSITIVE_ERROR_SENTINEL"})).encode())
    before = bytes(raw)
    result = _observe_disabled_job_ack_shape(raw, NAME)
    assert result["status_category"] == result["error_code"] == "unqualified"
    assert result["results_present"] and "SENSITIVE_ERROR_SENTINEL" not in json.dumps(result)
    assert bytes(raw) == before
