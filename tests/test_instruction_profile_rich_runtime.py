"""Private rich startup reaches the existing M4 lifecycle without new authority."""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from fortipam_mcp import instruction_profile_http_transport as transport
from fortipam_mcp import instruction_profile_runtime as runtime
from fortipam_mcp.instruction_profile_contract import (
    RICH_CONTRACT, InstructionProfileCreatePlan,
)
from test_instruction_profile_http_transport import Fixture, fixture as fixture
from test_instruction_profile_live_workflow import IDENTITY
from test_instruction_profile_runtime import delete_manifest, setup


def rich_setup(tmp_path: Path, fixture: Fixture) -> tuple[dict[str, str], dict[str, Any], Path]:
    env, manifest, path = setup(tmp_path, fixture)
    manifest["contract"] = runtime.RICH_CONTRACT
    del manifest["binding"]["text"]
    manifest["binding"]["blocks"] = [
        {"kind": "heading", "level": 2, "children": [{"kind": "text", "text": "Synthetic heading"}]},
        {"kind": "paragraph", "children": [{"kind": "text", "text": "Synthetic private content", "marks": ["strong"],
            "link": {"href": "https://synthetic.invalid/private-reference", "title": "Private link title"}},
            {"kind": "hard_break"}]},
        {"kind": "ordered_list", "children": [{"kind": "list_item", "children": [{"kind": "paragraph"}]}]},
    ]
    peer = fixture[1]
    peer.binding = InstructionProfileCreatePlan(peer.binding._name, manifest["binding"]["nonce"],
        runtime._content(manifest), peer.defaults, schema_digest=peer.schema_digest, serial_digest=peer.serial_digest)
    path.write_text(json.dumps(manifest))
    return env, manifest, path


def test_rich_owner_startup_m4_roundtrip_and_reopen_keep_original_ack(
    tmp_path: Path, fixture: Fixture, monkeypatch: pytest.MonkeyPatch,
) -> None:
    env, manifest, path = rich_setup(tmp_path, fixture)
    env[runtime.PREFIX + "EXECUTION_ENABLED"] = "true"
    state, peer, _ = fixture
    monkeypatch.setattr(transport.http.client, "HTTPSConnection", peer.connection)
    public = []
    original = {}
    for phase in ("create", "delete"):
        if phase == "delete":
            path.write_text(json.dumps(delete_manifest(manifest, tmp_path)))
        action = runtime.build_instruction_profile_candidate(env)
        assert action is not None
        workflow = action._workflow
        preview = workflow.preview(**IDENTITY)
        assert preview["contract"] == RICH_CONTRACT
        assert preview["Proposed Changes"]["operation"] == phase + "_rich_structure_instruction_profile"
        authorization = workflow.authorize(preview["preview_ref"], **IDENTITY)
        issued = workflow._authority._issued
        assert issued is not None and issued.plan.action_version == "1.2.0"
        assert issued.plan.adapter_ref.endswith("-rich-structure-v2")
        result = workflow.execute(authorization["authorization_ref"], **IDENTITY)
        assert result["contract"] == RICH_CONTRACT
        assert result["outcome"] == "succeeded" and result["verification"] == "verified"
        assert workflow._execution_store.claim_count == 1
        reopened = runtime.build_instruction_profile_candidate(env)
        assert reopened is not None
        with pytest.raises(RuntimeError):
            reopened._workflow.preview(**IDENTITY)
        if phase == "create":
            original = {name: (state / name).read_bytes() for name in (
                "creation.plan.json", "create.claim.json", "create-ack.json", "created.json")}
        public.extend((preview, authorization, result))
    assert all((state / name).read_bytes() == raw for name, raw in original.items())
    assert peer.created is None and peer.writes == ["POST", "DELETE"]
    assert all(not any(body) for body in peer.bodies)
    rendered = json.dumps(public)
    for literal in ("Synthetic private content", "https://synthetic.invalid/private-reference", "Private link title",
                    peer.binding._name, peer.brief, "synthetic-token"):
        assert literal not in rendered


@pytest.mark.parametrize("fault", ["old_contract", "old_rich_contract", "unknown_node", "native_type", "native_attrs", "password",
    "link", "image", "unicode", "null_level", "unknown_mark", "raw_detail", "empty", "deep"])
def test_invalid_rich_owner_manifest_cannot_pin_or_create_a_ledger(
    tmp_path: Path, fixture: Fixture, fault: str,
) -> None:
    env, manifest, path = rich_setup(tmp_path, fixture)
    first = manifest["binding"]["blocks"][0]
    if fault == "old_contract": manifest["contract"] = runtime.CONTRACT
    elif fault == "old_rich_contract": manifest["contract"] = "fortipam-v4-instruction-profile-rich-structure-startup-v1"
    elif fault == "unknown_node": first["kind"] = "unknown"
    elif fault == "native_type": first["type"] = first.pop("kind")
    elif fault == "native_attrs": first["attrs"] = {"level": 2}
    elif fault == "password": first["password"] = "synthetic-forbidden"
    elif fault in {"link", "image"}: first["kind"] = fault
    elif fault == "unicode": first["children"][0]["text"] = "中文"
    elif fault == "null_level": first["level"] = None
    elif fault == "unknown_mark": first["children"][0]["marks"] = ["link"]
    elif fault == "raw_detail": manifest["binding"]["detail"] = "untrusted-base64"
    elif fault == "empty": manifest["binding"]["blocks"] = []
    else:
        for _ in range(12):
            first = {"kind": "blockquote", "children": [first]}
        manifest["binding"]["blocks"] = [first]
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="^FortiPAM Instruction Profile startup is unavailable.$"):
        runtime.build_instruction_profile_candidate(env)
    assert list(fixture[0].iterdir()) == []
    assert not Path(manifest["paths"]["execution_database_file"]).exists()
    assert fixture[1].calls == []


def test_rich_binding_cannot_rebind_plain_pins_or_change_content_after_startup(tmp_path: Path, fixture: Fixture) -> None:
    env, original, path = setup(tmp_path, fixture)
    assert runtime.build_instruction_profile_candidate(env) is not None
    original_files = {file: file.read_bytes() for file in fixture[0].iterdir()}
    changed = copy.deepcopy(original)
    changed["contract"] = runtime.RICH_CONTRACT
    text = changed["binding"].pop("text")
    changed["binding"]["blocks"] = [{"kind": "paragraph", "children": [{"kind": "text", "text": text}]}]
    path.write_text(json.dumps(changed))
    with pytest.raises(ValueError):
        runtime.build_instruction_profile_candidate(env)
    assert all(file.read_bytes() == data for file, data in original_files.items())
    assert fixture[1].calls == []


@pytest.mark.parametrize("extra_depth", [0, 1])
def test_owner_manifest_accepts_full_compiler_depth_and_refuses_one_more(
    tmp_path: Path, fixture: Fixture, extra_depth: int,
) -> None:
    env, manifest, path = rich_setup(tmp_path, fixture)
    block: dict[str, Any] = {"kind": "paragraph"}
    for _ in range(10 + extra_depth):
        block = {"kind": "blockquote", "children": [block]}
    manifest["binding"]["blocks"] = [block]
    path.write_text(json.dumps(manifest))
    if extra_depth:
        with pytest.raises(ValueError):
            runtime.build_instruction_profile_candidate(env)
        assert not Path(manifest["paths"]["execution_database_file"]).exists()
    else:
        assert runtime.build_instruction_profile_candidate(env) is not None
    assert fixture[1].calls == []


def test_nested_duplicate_rich_field_is_rejected_before_content_decode(
    tmp_path: Path, fixture: Fixture, monkeypatch: pytest.MonkeyPatch,
) -> None:
    env, manifest, path = rich_setup(tmp_path, fixture)
    raw = json.dumps(manifest).replace('"kind": "heading"', '"kind": "heading", "ki\\u006ed": "paragraph"')
    path.write_text(raw)
    monkeypatch.setattr(runtime, "_decode", lambda *args: pytest.fail("Duplicate rich field decoded"))
    with pytest.raises(ValueError):
        runtime.build_instruction_profile_candidate(env)
    assert fixture[1].calls == []


@pytest.mark.parametrize("reference", [
    None, [], "https://synthetic.invalid", {}, {"href": 1}, {"href": "https://synthetic.invalid", "title": None},
    {"href": "https://synthetic.invalid", "target": "_blank"},
    {"type": "link", "attrs": {"href": "https://synthetic.invalid"}},
    {"href": "javascript:synthetic()"}, {"href": "https://user@synthetic.invalid"},
    {"href": "https://synthetic.invalid", "title": "中文"},
])
def test_owner_link_dsl_is_strict_before_state_or_device_use(
    tmp_path: Path, fixture: Fixture, reference: Any,
) -> None:
    env, manifest, path = rich_setup(tmp_path, fixture)
    manifest["binding"]["blocks"][1]["children"][0]["link"] = reference
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="^FortiPAM Instruction Profile startup is unavailable.$"):
        runtime.build_instruction_profile_candidate(env)
    assert list(fixture[0].iterdir()) == []
    assert not Path(manifest["paths"]["execution_database_file"]).exists()
    assert fixture[1].calls == []


def test_duplicate_link_field_is_rejected_before_decode_and_link_drift_cannot_rebind(
    tmp_path: Path, fixture: Fixture, monkeypatch: pytest.MonkeyPatch,
) -> None:
    env, manifest, path = rich_setup(tmp_path, fixture)
    raw = json.dumps(manifest).replace('"href": "https://synthetic.invalid/private-reference"',
        '"href": "https://synthetic.invalid/private-reference", "h\\u0072ef": "https://other.invalid"')
    path.write_text(raw)
    with monkeypatch.context() as patch:
        patch.setattr(runtime, "_decode", lambda *args: pytest.fail("Duplicate link decoded"))
        with pytest.raises(ValueError):
            runtime.build_instruction_profile_candidate(env)
    assert fixture[1].calls == []
    path.write_text(json.dumps(manifest))
    assert runtime.build_instruction_profile_candidate(env) is not None
    original_files = {file: file.read_bytes() for file in fixture[0].iterdir()}
    manifest["binding"]["blocks"][1]["children"][0]["link"]["title"] = "Changed title"
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        runtime.build_instruction_profile_candidate(env)
    assert all(file.read_bytes() == data for file, data in original_files.items())
    assert fixture[1].calls == []
