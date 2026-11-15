"""Synthetic protected startup sources; never credentials or device traffic."""
from dataclasses import asdict
import json
import os

import pytest

from fortipam_mcp import secret_request_approval_revoke_runtime as runtime
from fortipam_mcp.owner_collector_runtime import PREFIX as OWNER_PREFIX
from test_secret_request_approval_revoke_resolver import _setup


def _runtime_setup(tmp_path):
    args, _ = _setup(tmp_path)
    paths = {
        "continuity_file": args["continuity_path"], "invocation_witness_file": args["invocation_path"],
        "create_claim_file": args["create_claim_path"], "parent_binding_file": tmp_path / "parent.json",
        "continuity_hmac_key_file": tmp_path / "continuity.key",
        "invocation_witness_hmac_key_file": tmp_path / "invocation.key",
        "native_claim_file": tmp_path / "native.claim",
        "native_claim_hmac_key_file": tmp_path / "native.key",
        "workflow_database_file": tmp_path / "workflow.sqlite",
        "workflow_hmac_key_file": tmp_path / "workflow.key",
    }
    for name, key in (("continuity", args["continuity_key"]), ("invocation_witness", args["invocation_key"]),
                      ("native_claim", b"n" * 32), ("workflow", b"w" * 32)):
        path = paths[name + "_hmac_key_file"]
        path.write_bytes(key if name == "workflow" else key.hex().encode())
        path.chmod(0o600)
    expected = args["expected"]
    paths["parent_binding_file"].write_bytes(expected.parent_binding_json)
    paths["parent_binding_file"].chmod(0o600)
    manifest = dict(contract=runtime.CONTRACT, paths={k: str(v) for k, v in paths.items()},
        binding=asdict(expected.binding), original_parent={key: getattr(expected, key) for key in runtime._PARENT_KEYS},
        reviewer_mapping=dict(original_reviewer=expected.binding.original_reviewer,
            allowed_requester_digest="c" * 64, allowed_transport_digest="d" * 64),
        original_intent_ref=args["intent_ref"],
        transport=dict(base_url="https://synthetic.invalid", timeout_seconds=5, ca_file=None))
    path = tmp_path / "startup.json"
    path.write_text(json.dumps(manifest))
    path.chmod(0o600)
    environment = {runtime.PREFIX + "ENABLED": "true", runtime.PREFIX + "STARTUP_MANIFEST_FILE": str(path),
        OWNER_PREFIX + "SESSION_ENABLED": "true", OWNER_PREFIX + "LOGIN_ENV_FILE": str(tmp_path / "never-read.env"),
        OWNER_PREFIX + "USERNAME_VARIABLE": "TEST_USERNAME", OWNER_PREFIX + "PASSWORD_VARIABLE": "TEST_PASSWORD"}
    return environment, manifest, path, paths


def test_disabled_reads_no_file(monkeypatch):
    monkeypatch.setattr(runtime, "_read", lambda *args: pytest.fail("disabled file read"))
    assert runtime.build_secret_request_approval_revoke_candidate({}) is None


@pytest.mark.parametrize("values", [{"ENABLED": "TRUE"}, {"ENABLED": "1"}, {"EXECUTION_ENABLED": "yes"},
    {"EXECUTION_ENABLED": "true"}, {"ENABLED": True}, {"EXECUTION_ENABLED": ""}])
def test_invalid_gate_is_closed(values):
    with pytest.raises(ValueError, match="startup is unavailable"):
        runtime.build_secret_request_approval_revoke_candidate({runtime.PREFIX + k: v for k, v in values.items()})


def test_enabled_composes_without_login_and_restarts(tmp_path):
    environment, _, _, _ = _runtime_setup(tmp_path)
    first = runtime.build_secret_request_approval_revoke_candidate(environment)
    assert first is not None and not first._enabled
    assert not first._workflow._enabled and not first._workflow._transport._enabled
    assert first._workflow._allowed_requester == "c" * 64
    assert first._workflow._resolver._expected.requester_digest == "a" * 64
    assert runtime.build_secret_request_approval_revoke_candidate(environment) is not None
    environment[runtime.PREFIX + "EXECUTION_ENABLED"] = "true"
    action = runtime.build_secret_request_approval_revoke_candidate(environment)
    assert action._enabled and action._workflow._enabled and action._workflow._transport._enabled


@pytest.mark.parametrize("fault", ["extra", "duplicate", "material", "nested_material", "wrong_version",
    "manifest_mode", "parent_mode", "symlink", "hardlink", "key_reuse", "key_length", "path_collision",
    "database_sidecar", "reviewer", "scope", "parent", "claim", "invocation", "intent", "owner_disabled",
    "url_userinfo", "boolean_timeout", "relative_path"])
def test_invalid_startup_refuses_without_database_creation(tmp_path, fault):
    environment, manifest, manifest_path, paths = _runtime_setup(tmp_path)
    raw = None
    if fault == "extra": manifest["unknown"] = "denied"
    elif fault == "duplicate": raw = json.dumps(manifest)[:-1] + ',"contract":"duplicate"}'
    elif fault == "material": manifest["transport"]["password"] = "synthetic-forbidden"
    elif fault == "nested_material": manifest["transport"]["ca_file"] = {"password": "synthetic-forbidden"}
    elif fault == "wrong_version": manifest["contract"] += "-v2"
    elif fault == "manifest_mode": manifest_path.chmod(0o644)
    elif fault == "parent_mode": tmp_path.chmod(0o755)
    elif fault == "symlink":
        source = paths["parent_binding_file"]
        moved = tmp_path / "real-parent.json"
        source.rename(moved)
        source.symlink_to(moved)
    elif fault == "hardlink": os.link(paths["parent_binding_file"], tmp_path / "alias.json")
    elif fault == "key_reuse": paths["native_claim_hmac_key_file"].write_bytes(paths["continuity_hmac_key_file"].read_bytes())
    elif fault == "key_length": paths["workflow_hmac_key_file"].write_bytes(b"w" * 64)
    elif fault == "path_collision": manifest["paths"]["native_claim_file"] = str(paths["parent_binding_file"])
    elif fault == "database_sidecar": manifest["paths"]["native_claim_file"] = str(paths["workflow_database_file"]) + "-journal"
    elif fault == "reviewer": manifest["reviewer_mapping"]["original_reviewer"] = "other"
    elif fault == "scope": manifest["original_parent"]["scope_ref"] = "other"
    elif fault == "parent": paths["parent_binding_file"].write_bytes(b'{}')
    elif fault == "claim": paths["create_claim_file"].write_bytes(b'{}')
    elif fault == "invocation": paths["invocation_witness_file"].write_bytes(b'{}')
    elif fault == "intent": manifest["original_intent_ref"] = "other"
    elif fault == "owner_disabled": environment[OWNER_PREFIX + "SESSION_ENABLED"] = "false"
    elif fault == "url_userinfo": manifest["transport"]["base_url"] = "https://synthetic:forbidden@example.invalid"
    elif fault == "boolean_timeout": manifest["transport"]["timeout_seconds"] = True
    elif fault == "relative_path": manifest["paths"]["parent_binding_file"] = "relative.json"
    manifest_path.write_text(raw if raw else json.dumps(manifest))
    with pytest.raises(ValueError, match="^FortiPAM Request approval withdrawal startup is unavailable.$"):
        runtime.build_secret_request_approval_revoke_candidate(environment)
    assert not paths["workflow_database_file"].exists()


def test_unknown_material_is_rejected_before_json_decode(tmp_path, monkeypatch):
    environment, manifest, path, _ = _runtime_setup(tmp_path)
    manifest["transport"]["password"] = "synthetic-forbidden"
    path.write_text(json.dumps(manifest))
    monkeypatch.setattr(runtime, "_decode", lambda *args: pytest.fail("decoded rejected material"))
    with pytest.raises(ValueError):
        runtime.build_secret_request_approval_revoke_candidate(environment)


def test_parent_material_is_rejected_before_json_decode(tmp_path, monkeypatch):
    environment, _, _, paths = _runtime_setup(tmp_path)
    parent = json.loads(paths["parent_binding_file"].read_bytes())
    parent["password"] = "synthetic-forbidden"
    paths["parent_binding_file"].write_text(json.dumps(parent))
    original = runtime._decode
    decoded = []

    def decode(raw):
        assert b"synthetic-forbidden" not in raw
        decoded.append(raw)
        return original(raw)

    monkeypatch.setattr(runtime, "_decode", decode)
    with pytest.raises(ValueError):
        runtime.build_secret_request_approval_revoke_candidate(environment)
    assert len(decoded) == 1  # Only the safe startup manifest was decoded.
