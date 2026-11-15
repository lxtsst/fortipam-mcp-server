"""Reject injected package data and unknown reference state in the native profile."""
from copy import deepcopy
import json

import pytest

from fortipam_mcp.client_integrity_http_contract import (
    ClientIntegrityHttpContractError,
    _native_metadata,
    compile_native_client_integrity_create_body,
    compile_native_client_integrity_hash_create_body,
    project_native_client_integrity_detail,
    project_native_client_integrity_hash_detail,
    validate_native_client_integrity_recovery_state,
    validate_native_client_integrity_hash_recovery_state,
)


NAME = "mcp-v4-client-integrity-rest-20261004-r2"


def envelope(row):
    return {"version": "v7.0.0", "build": 29, "http_method": "GET", "http_status": 200,
            "status": "success", "path": "secret", "name": "client-software", "vdom": "root", "results": row}


def detail():
    body = compile_native_client_integrity_create_body(envelope({"name": "", "pkg": []}), software_name=NAME)
    return envelope({"name": NAME, "q_origin_key": NAME, **_native_metadata(13), "pkg": [{
        **body["pkg"][0], "browser": "edge", "q_origin_key": "x64", "client-name": NAME, "description": "",
        "file-size": 0, "package-content": "", "state": "absent",
        "uuid": "00000000-0000-0000-0000-000000000000",
    }]})


def test_default_data_cannot_inject_fields_and_old_operations_cannot_be_rebound():
    default = envelope({"name": "", "pkg": []})
    original = deepcopy(default)
    body = compile_native_client_integrity_create_body(default, software_name=NAME)
    assert default == original and set(body) == {"name", "pkg", "$originalName"}
    assert body["pkg"][0]["browser"] == "chrome"
    assert "file" not in body["pkg"][0] and "package-content" not in body["pkg"][0]
    for row in ({"name": "", "pkg": [], "extra": "private-sentinel"},
                {"name": "", "pkg": [{"file": "private-sentinel"}]},
                {"name": "existing", "pkg": []}):
        with pytest.raises(ClientIntegrityHttpContractError, match="unavailable") as failure:
            compile_native_client_integrity_create_body(envelope(row), software_name=NAME)
        assert "private-sentinel" not in str(failure.value)
    for name in ("mcp-v4-client-integrity-mini-r1", "mcp-v4-client-integrity-b48", NAME + "/escape"):
        with pytest.raises(ClientIntegrityHttpContractError):
            compile_native_client_integrity_create_body(default, software_name=name)


def test_hash_form_is_separate_exact_and_cannot_reinterpret_certificate_records():
    default = envelope({"name": "", "pkg": []})
    before = deepcopy(default)
    hash_name = "mcp-v4-client-integrity-hash-20261006-r1"
    body = compile_native_client_integrity_hash_create_body(
        default, software_name=hash_name, executable_sha256="a" * 64,
    )
    assert default == before
    assert body == {"name": hash_name, "$originalName": "", "pkg": [{
        "name": "x64", "app-type": "native", "os": "win", "browser": "chrome",
        "integrity-check": "exe-hash", "hash-algo": "SHA-256", "hash": "a" * 64,
        "ca": "", "download-option": "external", "package-name": "",
        "external-url": "https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe",
    }]}
    for name, digest in ((NAME, "a" * 64), (hash_name + "/escape", "a" * 64),
                         (hash_name, "A" * 64), (hash_name, "a" * 63),
                         (hash_name, "private-sentinel"), (hash_name, True)):
        with pytest.raises(ClientIntegrityHttpContractError) as failure:
            compile_native_client_integrity_hash_create_body(
                default, software_name=name, executable_sha256=digest,
            )
        assert "private-sentinel" not in str(failure.value)
    injected = envelope({"name": "", "pkg": [], "ca": "private-sentinel"})
    with pytest.raises(ClientIntegrityHttpContractError):
        compile_native_client_integrity_hash_create_body(
            injected, software_name=hash_name, executable_sha256="a" * 64,
        )
    with pytest.raises(ClientIntegrityHttpContractError):
        compile_native_client_integrity_create_body(default, software_name=hash_name)
    payload = detail()
    payload["results"]["pkg"][0].update(body["pkg"][0])
    with pytest.raises(ClientIntegrityHttpContractError):
        project_native_client_integrity_detail(payload, software_name=NAME)


def test_missing_reference_count_stays_unknown_and_full_state_drift_is_rejected():
    payload = detail()
    observed = project_native_client_integrity_detail(payload, software_name=NAME)
    assert not observed.reported_reference_count_is_zero
    assert NAME not in repr(observed)
    for field, value in (('q_path','other'),('q_no_edit',True),('q_no_rename',0),('q_type',True)):
        modified = deepcopy(payload); modified['results'][field] = value
        with pytest.raises(ClientIntegrityHttpContractError):
            project_native_client_integrity_detail(modified, software_name=NAME)
    for change in ({"package-content": "private-sentinel"}, {"file-size": True},
                   {"file-size": 1}, {"state": "present"}, {"browser": "chrome"},
                   {"client-name": "putty"}, {"client-name": ""}, {"unknown": "private-sentinel"}):
        modified = deepcopy(payload); modified["results"]["pkg"][0].update(change)
        with pytest.raises(ClientIntegrityHttpContractError, match="unavailable") as failure:
            project_native_client_integrity_detail(modified, software_name=NAME)
        assert "private-sentinel" not in str(failure.value)
    payload["results"]["q_ref"] = 0
    assert project_native_client_integrity_detail(payload, software_name=NAME).reported_reference_count_is_zero
    payload["results"]["q_ref"] = False
    with pytest.raises(ClientIntegrityHttpContractError):
        project_native_client_integrity_detail(payload, software_name=NAME)


@pytest.mark.parametrize("field,value", [("build", True), ("version", "v1.9.1"), ("http_method", "POST"), ("vdom", "other")])
def test_wrong_product_or_read_envelope_is_refused(field, value):
    payload = envelope({"name": "", "pkg": []}); payload[field] = value
    with pytest.raises(ClientIntegrityHttpContractError):
        compile_native_client_integrity_create_body(payload, software_name=NAME)


def test_recovery_requires_unchanged_complete_record_and_exact_reported_empty_usage():
    payload = detail()
    sealed = project_native_client_integrity_detail(payload, software_name=NAME).configuration_digest
    usage = {"http_method": "GET", "path": "system/object", "name": "usage", "action": "",
             "status": "success", "version": "v7.0.0", "build": 29, "mkey": NAME,
             "results": {"currently_using": []}}
    validate_native_client_integrity_recovery_state(payload, bytearray(json.dumps(usage).encode()),
        software_name=NAME, expected_configuration_digest=sealed)
    for values in ({}, {"currently_using": None}, {"currently_using": False},
                   {"currently_using": [{"object": "synthetic-new-reference"}]}):
        changed = {**usage, "results": values}
        with pytest.raises(ClientIntegrityHttpContractError):
            validate_native_client_integrity_recovery_state(payload, bytearray(json.dumps(changed).encode()),
                software_name=NAME, expected_configuration_digest=sealed)
    for field, value in (("mkey", NAME + "-other"), ("build", True), ("http_method", "POST")):
        with pytest.raises(ClientIntegrityHttpContractError):
            validate_native_client_integrity_recovery_state(payload, bytearray(json.dumps({**usage, field: value}).encode()),
                software_name=NAME, expected_configuration_digest=sealed)
    changed = deepcopy(payload)
    changed["results"]["pkg"][0]["uuid"] = "11111111-1111-1111-1111-111111111111"
    with pytest.raises(ClientIntegrityHttpContractError):
        validate_native_client_integrity_recovery_state(changed, bytearray(json.dumps(usage).encode()),
            software_name=NAME, expected_configuration_digest=sealed)


def test_hash_complete_readback_and_usage_reject_hash_ca_namespace_and_metadata_drift():
    name = "mcp-v4-client-integrity-hash-20261006-r2"
    body = compile_native_client_integrity_hash_create_body(
        envelope({"name": "", "pkg": []}), software_name=name, executable_sha256="c" * 64,
    )
    row = {"name": name, "q_origin_key": name, "q_ref": 0, **_native_metadata(13), "pkg": [{
        **body["pkg"][0], "browser": "edge", "q_origin_key": "x64", "client-name": name,
        "description": "", "file-size": 0, "package-content": "", "state": "absent",
        "uuid": "00000000-0000-0000-0000-000000000000",
    }]}
    payload = envelope(row)
    current = project_native_client_integrity_hash_detail(
        payload, software_name=name, executable_sha256="c" * 64,
    )
    assert current.reported_reference_count_is_zero and name not in repr(current)
    usage = {"http_method": "GET", "path": "system/object", "name": "usage", "action": "",
             "status": "success", "version": "v7.0.0", "build": 29, "mkey": name,
             "results": {"currently_using": []}}
    validate_native_client_integrity_hash_recovery_state(
        payload, bytearray(json.dumps(usage).encode()), software_name=name,
        executable_sha256="c" * 64, expected_configuration_digest=current.configuration_digest,
    )
    for change in ({"hash": "d" * 64}, {"hash-algo": "SHA256"}, {"ca": "Fortinet_CA_SSL"},
                   {"integrity-check": "cert"}, {"browser": "chrome"},
                   {"package-content": "private-sentinel"}, {"unknown": "private-sentinel"}):
        modified = deepcopy(payload); modified["results"]["pkg"][0].update(change)
        with pytest.raises(ClientIntegrityHttpContractError) as failure:
            project_native_client_integrity_hash_detail(
                modified, software_name=name, executable_sha256="c" * 64,
            )
        assert "private-sentinel" not in str(failure.value)
    used = deepcopy(usage); used["results"]["currently_using"] = [{"object": "synthetic-reference"}]
    with pytest.raises(ClientIntegrityHttpContractError):
        validate_native_client_integrity_hash_recovery_state(
            payload, bytearray(json.dumps(used).encode()), software_name=name,
            executable_sha256="c" * 64, expected_configuration_digest=current.configuration_digest,
        )
    changed = deepcopy(payload); changed["results"]["q_type"] = 14
    with pytest.raises(ClientIntegrityHttpContractError):
        validate_native_client_integrity_hash_recovery_state(
            changed, bytearray(json.dumps(usage).encode()), software_name=name,
            executable_sha256="c" * 64, expected_configuration_digest=current.configuration_digest,
        )
