"""Native text-document shape, byte bounds, privacy and context-drift checks."""
from __future__ import annotations

import base64
import copy
import json
import pickle

import pytest

from fortipam_mcp.instruction_profile_contract import (
    InstructionPlainText, InstructionProfileContractError, InstructionProfileCreatePlan,
    WIRE_FIELDS, build_instruction_profile_create_body,
)
from v4_planning.material_provider import MaterialAccessDenied

CONTEXT = {"schema_digest": "a" * 64, "serial_digest": "b" * 64}
DEFAULTS: dict[str, object] = {"name": "", "brief": "", "detail": ""}


def plan(content: InstructionPlainText | None = None) -> InstructionProfileCreatePlan:
    return InstructionProfileCreatePlan("mcp-v4-ip-synthetic", "c" * 64,
        content if content is not None else InstructionPlainText("Synthetic brief", "Synthetic instructions."),
        DEFAULTS, **CONTEXT)


def test_literal_markup_is_only_a_text_node_and_never_a_resource() -> None:
    text = '<script src="https://synthetic.invalid/script"></script> \\ {"type":"image"}'
    raw = build_instruction_profile_create_body(plan(InstructionPlainText("Synthetic brief", text)), DEFAULTS, **CONTEXT)
    try:
        body = json.loads(raw)
        assert set(body) == WIRE_FIELDS
        assert json.loads(base64.b64decode(body["detail"], validate=True)) == {
            "type": "doc", "content": [{"type": "paragraph", "content": [{"type": "text", "text": text}]}]}
        assert len(body["detail"]) <= 24000
        assert DEFAULTS == {"name": "", "brief": "", "detail": ""}
    finally:
        raw[:] = b"\0" * len(raw)


@pytest.mark.parametrize("text", ["", "   ", "line\nbreak", "tab\tstop", "\x00", "\x7f", "中文", "a" * 24001,
                                  '"' * 12000])
def test_nonqualified_text_and_post_escape_size_are_rejected(text: str) -> None:
    with pytest.raises(InstructionProfileContractError, match="^The private Instruction Profile contract is unavailable.$"):
        InstructionPlainText("Synthetic", text)


def test_exact_native_base64_and_brief_limits() -> None:
    # Empty text contributes 85 bytes to the fixed document structure.
    text = "a" * (18000 - 85)
    content = InstructionPlainText("b" * 1023, text)
    body = json.loads(build_instruction_profile_create_body(plan(content), DEFAULTS, **CONTEXT))
    assert len(body["detail"]) == 24000
    for brief, value in (("b" * 1024, text), ("brief", text + "a")):
        with pytest.raises(InstructionProfileContractError):
            InstructionPlainText(brief, value)


@pytest.mark.parametrize("field", ["name", "brief", "detail", "unknown"])
def test_default_drift_refuses_body(field: str) -> None:
    current = dict(DEFAULTS, **{field: "drift"})
    with pytest.raises(InstructionProfileContractError):
        build_instruction_profile_create_body(plan(), current, **CONTEXT)


@pytest.mark.parametrize("field", list(CONTEXT))
def test_schema_or_device_drift_refuses_body(field: str) -> None:
    with pytest.raises(InstructionProfileContractError):
        build_instruction_profile_create_body(plan(), DEFAULTS, **dict(CONTEXT, **{field: "d" * 64}))


def test_native_name_limit_and_opaque_immutable_carriers() -> None:
    content = InstructionPlainText("Private synthetic brief", "Private synthetic instructions.")
    name = "mcp-v4-ip-" + "a" * 13
    assert len(name) == 23
    prepared = InstructionProfileCreatePlan(name, "c" * 64, content, DEFAULTS, **CONTEXT)
    for bad in (name + "x", "shared-profile", "mcp-v4-ip-../escape"):
        with pytest.raises(InstructionProfileContractError):
            InstructionProfileCreatePlan(bad, "c" * 64, content, DEFAULTS, **CONTEXT)
    for item in (content, prepared):
        assert name not in repr(item) and "Private synthetic" not in repr(item)
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(MaterialAccessDenied):
                operation(item)
        with pytest.raises(InstructionProfileContractError):
            setattr(item, "digest", "f" * 64)
