"""Private startup parsing never authorizes or dispatches an AD Source."""

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import fortipam_mcp.ad_discovery_runtime_config as config
from fortipam_mcp.domain_secret_projection_reader import PLANNING_BINDING_CONTRACT


def _write(path, payload):
    path.write_text(json.dumps(payload), encoding="utf-8")
    path.chmod(0o600)
    return path


@pytest.fixture
def files(tmp_path):
    domain = {
        "contract": PLANNING_BINDING_CONTRACT,
        "folder_path": "Public/domain-folder", "secret_name": "domain-secret",
        "target_name": "domain-target", "target_ipv4_address": "192.0.2.10",
        "domain_dns_root": "ad.example.test", "target_owner_name": "domain-owner",
        "target_classification_tag": "Other", "requester_digest": "1" * 64,
        "environment_ref": "lab-environment-ref01", "scope_ref": "lab-scope-ref01",
        "folder_object_ref": "domain-folder-object-ref01", "folder_ref": "domain-folder-ref01",
        "target_object_ref": "domain-target-object-ref01", "target_profile_ref": "domain-target-profile-ref01",
        "template_object_ref": "domain-template-object-ref01", "template_ref": "domain-template-ref01",
        "secret_object_ref": "domain-secret-object-ref01",
    }
    domain_path = _write(tmp_path / "domain.json", domain)
    payload = {
        "contract": config.AD_DISCOVERY_RUNTIME_BINDING_CONTRACT,
        "domain_binding_file": str(domain_path),
        "source_name": "bp014-discovery-ad-disabled-20261007-r1",
        "discovery_secret_id": 23, "source_object_ref": "ad-source-object-ref01",
    }
    path = _write(tmp_path / "source.json", payload)
    return path, payload, domain_path, domain


def _deny(path):
    with pytest.raises(config.AdDiscoveryRuntimeBindingConfigurationError) as caught:
        config.load_ad_discovery_runtime_binding(path)
    assert str(caught.value) == "The fixed AD Discovery runtime binding is unavailable."
    assert caught.value.__suppress_context__


def test_fixed_binding_is_restart_stable_and_protected(files):
    path, payload, _, domain_payload = files
    first = config.load_ad_discovery_runtime_binding(path)
    second = config.load_ad_discovery_runtime_binding(path)
    assert first == second
    assert first.source.parameters_digest == second.source.parameters_digest
    assert first.source.request.discovery_secret_id == 23
    assert first.source.domain_binding == first.domain.create_binding
    assert len(first.expected_objects()) == 5
    assert first.source_object_ref not in first.domain.expected_objects()
    assert first.domain.requester_digest == domain_payload["requester_digest"]
    assert first.domain.create_binding.target_product_version == "7.0.0"
    assert first.domain.create_binding.target_product_build == 29
    assert first.domain.create_binding.template_name == "Windows Domain Account"
    assert first.domain.create_binding.plan_digest == "0" * 64
    assert repr(first) == "<AdDiscoveryPlanningBinding protected>"
    for private in (str(path), payload["source_name"], domain_payload["secret_name"]):
        assert private not in repr(first)
        assert private not in repr(first.source)
        assert private not in repr(first.domain)


@pytest.mark.parametrize("field,value", [
    ("discovery_secret_id", True), ("discovery_secret_id", False),
    ("discovery_secret_id", "23"), ("discovery_secret_id", 23.0),
    ("discovery_secret_id", 0), ("discovery_secret_id", -1),
    ("discovery_secret_id", 2147483648), ("source_name", 23),
    ("source_name", "unbounded-source-name"), ("source_object_ref", True),
    ("source_object_ref", "invalid ref"), ("domain_binding_file", "relative.json"),
    ("domain_binding_file", None), ("contract", "wrong-contract"),
])
def test_exact_native_types_and_contract(files, field, value):
    path, payload, _, _ = files
    _write(path, {**payload, field: value})
    _deny(path)


@pytest.mark.parametrize("field", [
    "credential", "token", "body", "session", "private_nonce",
    "target_product_version", "target_product_build", "source_type",
    "schedule_status", "requester_digest",
])
def test_overrides_and_material_fields_rejected_before_domain_load(files, monkeypatch, field):
    path, payload, _, _ = files
    _write(path, {**payload, field: "not-allowed"})
    calls = []
    monkeypatch.setattr(config, "load_domain_secret_planning_binding", lambda path: calls.append(path))
    _deny(path)
    assert calls == []


@pytest.mark.parametrize("field", sorted(config._FIELDS))
def test_missing_field_rejected(files, field):
    path, payload, _, _ = files
    _write(path, {key: value for key, value in payload.items() if key != field})
    _deny(path)


@pytest.mark.parametrize("content", [b"", b" " * 16385, b"[]", b"null", b"{", b"\xff"])
def test_bounded_exact_json(files, content):
    path, _, _, _ = files
    path.write_bytes(content)
    _deny(path)


@pytest.mark.parametrize("which", ["source", "domain"])
def test_duplicate_keys_rejected_in_both_files(files, which):
    path, payload, domain_path, domain = files
    target, values = (path, payload) if which == "source" else (domain_path, domain)
    target.write_text(json.dumps(values)[:-1] + ', "contract": "duplicate"}')
    _deny(path)


@pytest.mark.parametrize("which,mode", [(which, mode) for which in ("source", "domain") for mode in (0o644, 0o400, 0o660)])
def test_both_inputs_require_exact_owner_only_mode(files, which, mode):
    path, _, domain_path, _ = files
    (path if which == "source" else domain_path).chmod(mode)
    _deny(path)


@pytest.mark.parametrize("which", ["source", "domain"])
def test_final_component_symlink_rejected(files, tmp_path, which):
    path, payload, domain_path, _ = files
    link = tmp_path / "link.json"
    link.symlink_to(path if which == "source" else domain_path)
    if which == "source":
        _deny(link)
    else:
        _write(path, {**payload, "domain_binding_file": str(link)})
        _deny(path)


def test_requires_absolute_path_and_regular_owned_file(files, tmp_path, monkeypatch):
    path, _, _, _ = files
    for invalid in (Path("relative.json"), str(path), tmp_path):
        _deny(invalid)
    fifo = tmp_path / "input.fifo"
    os.mkfifo(fifo, 0o600)
    _deny(fifo)
    real_fstat = config.os.fstat

    def wrong_owner(descriptor):
        info = real_fstat(descriptor)
        return SimpleNamespace(st_mode=info.st_mode, st_uid=os.getuid() + 1, st_size=info.st_size)

    monkeypatch.setattr(config.os, "fstat", wrong_owner)
    _deny(path)


@pytest.mark.parametrize("field,value", [
    ("contract", "wrong-domain-contract"), ("target_product_version", "8.0.0"),
    ("template_name", "wrong-template"), ("password", "not-allowed"),
    ("target_object_ref", "domain-secret-object-ref01"),
])
def test_domain_loader_contract_and_closed_relationships_preserved(files, field, value):
    path, _, domain_path, domain = files
    _write(domain_path, {**domain, field: value})
    _deny(path)


@pytest.mark.parametrize("field", ["folder_object_ref", "target_object_ref", "template_object_ref", "secret_object_ref"])
def test_source_reference_cannot_alias_any_domain_anchor(files, field):
    path, payload, _, domain = files
    _write(path, {**payload, "source_object_ref": domain[field]})
    _deny(path)


def test_exact_id_source_and_private_domain_changes_bind_parameters(files):
    path, payload, domain_path, domain = files
    baseline = config.load_ad_discovery_runtime_binding(path).source.parameters_digest
    for field, value in (("discovery_secret_id", 24), ("source_name", "bp014-discovery-ad-disabled-20261007-r2")):
        _write(path, {**payload, field: value})
        assert config.load_ad_discovery_runtime_binding(path).source.parameters_digest != baseline
    _write(path, payload)
    for field, value in (("target_owner_name", "different-owner"), ("domain_dns_root", "other.example.test")):
        _write(domain_path, {**domain, field: value})
        assert config.load_ad_discovery_runtime_binding(path).source.parameters_digest != baseline


def test_file_change_during_read_fails_closed_and_closes_descriptor(files, monkeypatch):
    path, _, _, _ = files
    real_read, real_close = config.os.read, config.os.close
    closed = []

    def changed_read(descriptor, size):
        content = real_read(descriptor, size)
        if content:
            path.write_text("{}")
        return content

    def close(descriptor):
        closed.append(descriptor)
        real_close(descriptor)

    monkeypatch.setattr(config.os, "read", changed_read)
    monkeypatch.setattr(config.os, "close", close)
    _deny(path)
    assert len(closed) == 1


def test_dependency_failure_has_no_path_or_raw_error(files, monkeypatch):
    path, _, _, _ = files

    def broken(_):
        raise RuntimeError("private upstream selector")

    monkeypatch.setattr(config, "load_domain_secret_planning_binding", broken)
    _deny(path)
