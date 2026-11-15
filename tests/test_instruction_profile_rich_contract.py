"""Typed rich content normalization, input budgets, and private wire binding."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import pickle
import traceback
from typing import Any

import pytest

from fortipam_mcp.instruction_profile_contract import (
    CONTRACT, RICH_CONTRACT, InstructionDocument, InstructionHttpsLink, InstructionNode as Node,
    InstructionPlainText, InstructionProfileContractError, InstructionProfileCreatePlan,
    InstructionRichText, build_instruction_profile_create_body,
)
from v4_planning.material_provider import MaterialAccessDenied

DEFAULTS: dict[str, object] = {"name": "", "brief": "", "detail": ""}
CONTEXT = {"schema_digest": "a" * 64, "serial_digest": "b" * 64}


def compiled(*blocks: Node) -> dict[str, Any]:
    return json.loads(base64.b64decode(InstructionDocument(blocks)._detail, validate=True))


def test_native_normalization_marks_merging_breaks_and_empty_blocks() -> None:
    assert compiled(Node("paragraph", children=(
        Node("text", text="A", marks=("strong", "em")),
        Node("text", text="B", marks=("em", "strong")), Node("hard_break"),
        Node("text", text="<script>literal</script>", marks=("code",)),
        Node("hard_break"), Node("hard_break"))),
        Node("paragraph", children=(Node("hard_break"),)), Node("code_block")) == {
        "type": "doc", "content": [
            {"type": "paragraph", "content": [
                {"type": "text", "marks": [{"type": "em"}, {"type": "strong"}], "text": "AB"},
                {"type": "hard_break"},
                {"type": "text", "marks": [{"type": "code"}], "text": "<script>literal</script>"}]},
            {"type": "paragraph"}, {"type": "code_block"}]}


def test_nested_lists_headings_quote_code_and_rule_have_fixed_native_shape() -> None:
    paragraph = Node("paragraph", children=(Node("text", text="Synthetic"),))
    item = Node("list_item", children=(paragraph, Node("ordered_list", order=3,
        children=(Node("list_item", children=(Node("paragraph"),)),))))
    wire = compiled(*(Node("heading", level=level, children=(Node("text", text="Heading"), Node("hard_break")))
                      for level in range(1, 7)),
        Node("bullet_list", children=(item,)), Node("blockquote", children=(paragraph,)),
        Node("code_block", children=(Node("text", text="first\n"), Node("text", text="\tsecond"))),
        Node("horizontal_rule"))
    assert [row["attrs"]["level"] for row in wire["content"][:6]] == list(range(1, 7))
    assert all(len(row["content"]) == 1 for row in wire["content"][:6])
    assert wire["content"][6]["content"][0]["content"][1]["attrs"] == {"order": 3}
    assert wire["content"][8] == {"type": "code_block", "content": [{"type": "text", "text": "first\n\tsecond"}]}
    assert wire["content"][9] == {"type": "horizontal_rule"}
    assert compiled(Node("heading"))["content"][0] == {"type": "heading", "attrs": {"level": 1}}
    assert compiled(Node("ordered_list", children=(Node("list_item", children=(Node("paragraph"),)),)))["content"][0]["attrs"] == {"order": 1}


@pytest.mark.parametrize("kwargs", [
    {"kind": "doc"}, {"kind": "image"}, {"kind": "link"}, {"kind": "resource"},
    {"kind": "text", "text": ""}, {"kind": "text", "text": "中文"},
    {"kind": "text", "text": "\r"}, {"kind": "text", "text": "\x00"},
    {"kind": "text", "text": "\x7f"}, {"kind": "text", "text": "é"},
    {"kind": "text", "text": "x", "marks": ("link",)},
    {"kind": "text", "text": "x", "marks": ("em", "em")},
    {"kind": "text", "text": "x", "marks": ["em"]},
    {"kind": "text", "text": "x", "children": (Node("hard_break"),)},
    {"kind": "paragraph", "children": []},
    {"kind": "paragraph", "children": ({"type": "text", "text": "x"},)},
    {"kind": "paragraph", "text": "ignored"}, {"kind": "paragraph", "level": 1},
    {"kind": "paragraph", "marks": ("em",)},
    {"kind": "paragraph", "children": (Node("text", text="x\ny"),)},
    {"kind": "paragraph", "children": (Node("text", text="\t"),)},
    {"kind": "heading", "level": True}, {"kind": "heading", "level": 0},
    {"kind": "heading", "level": 7}, {"kind": "heading", "level": 1.0},
    {"kind": "heading", "order": 1},
    {"kind": "blockquote"}, {"kind": "bullet_list"}, {"kind": "list_item"},
    {"kind": "bullet_list", "children": (Node("paragraph"),)},
    {"kind": "list_item", "children": (Node("heading"),)},
    {"kind": "code_block", "children": (Node("hard_break"),)},
    {"kind": "code_block", "children": (Node("text", text="x", marks=("code",)),)},
    {"kind": "horizontal_rule", "children": (Node("paragraph"),)},
])
def test_malformed_or_unqualified_structure_is_value_free(kwargs: dict[str, Any]) -> None:
    with pytest.raises(InstructionProfileContractError, match="^The private Instruction Profile contract is unavailable.$"):
        Node(**kwargs)


@pytest.mark.parametrize("order", [False, 0, -1, 1.5, "1", 2147483648])
def test_order_requires_a_bounded_positive_integer(order: Any) -> None:
    with pytest.raises(InstructionProfileContractError):
        Node("ordered_list", order=order, children=(Node("list_item", children=(Node("paragraph"),)),))


def test_input_tree_budget_counts_nodes_before_normalization_and_shared_subtrees() -> None:
    paragraph = Node("paragraph")
    InstructionDocument((paragraph,) * 511)
    with pytest.raises(InstructionProfileContractError):
        InstructionDocument((paragraph,) * 512)
    breaks = (Node("hard_break"),) * 510
    assert compiled(Node("paragraph", children=breaks)) == {"type": "doc", "content": [{"type": "paragraph"}]}
    with pytest.raises(InstructionProfileContractError):
        Node("paragraph", children=breaks + (Node("hard_break"),))
    for _ in range(10):
        paragraph = Node("blockquote", children=(paragraph,))
    InstructionDocument((paragraph,))
    with pytest.raises(InstructionProfileContractError):
        Node("blockquote", children=(paragraph,))


def test_exact_encoded_limit_applies_after_escaping_and_combining_blocks() -> None:
    paragraph = Node("paragraph", children=(Node("text", text="a" * (18000 - 85)),))
    assert len(InstructionDocument((paragraph,))._detail) == 24000
    with pytest.raises(InstructionProfileContractError):
        InstructionDocument((paragraph, Node("paragraph")))
    with pytest.raises(InstructionProfileContractError):
        Node("text", text='"' * 9000)
    with pytest.raises(InstructionProfileContractError):
        Node("paragraph", children=(Node("text", text="x" * 10000),) * 2)


def test_plain_wire_and_digest_remain_stable_and_rich_cannot_reuse_plain_binding() -> None:
    plain = InstructionPlainText("Brief", "Text")
    rich = InstructionRichText("Brief", InstructionDocument((Node("paragraph", children=(Node("text", text="Text"),)),)))
    plans = [InstructionProfileCreatePlan("mcp-v4-ip-synthetic", "c" * 64, content, DEFAULTS, **CONTEXT)
             for content in (plain, rich)]
    bodies = [build_instruction_profile_create_body(item, DEFAULTS, **CONTEXT) for item in plans]
    try:
        assert bodies[0] == bodies[1]
        expected = {"contract": CONTRACT, "name": "mcp-v4-ip-synthetic", "nonce": "c" * 64,
            "content_digest": plain.digest,
            "defaults_digest": hashlib.sha256(b'{"brief":"","detail":"","name":""}').hexdigest(), **CONTEXT}
        assert plans[0].digest == hashlib.sha256(json.dumps(expected, separators=(",", ":")).encode()).hexdigest()
        assert plans[0].contract == CONTRACT and plans[1].contract == RICH_CONTRACT
        assert plans[0].digest != plans[1].digest and plain.digest != rich.digest
    finally:
        for body in bodies:
            body[:] = b"\0" * len(body)


def test_private_nodes_document_and_content_are_opaque_and_immutable() -> None:
    node = Node("paragraph", children=(Node("text", text="Private synthetic instructions"),))
    document = InstructionDocument((node,))
    content = InstructionRichText("Private synthetic brief", document)
    link = InstructionHttpsLink("https://synthetic.invalid/private", "Private synthetic title")
    for item in (node, document, content, link):
        assert "Private synthetic" not in repr(item)
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(MaterialAccessDenied):
                operation(item)
        with pytest.raises(InstructionProfileContractError):
            setattr(item, "_wire", b"replacement")
    for value in ((), (Node("text", text="inline"),), (Node("list_item", children=(Node("paragraph"),)),)):
        with pytest.raises(InstructionProfileContractError):
            InstructionDocument(value)


def test_https_link_native_order_defaults_merging_and_digest() -> None:
    href = "https://synthetic.invalid/help?section=one#start"
    first = Node("text", text="A", marks=("code", "strong", "em"), link=InstructionHttpsLink(href))
    second = Node("text", text="B", marks=("em", "code", "strong"), link=InstructionHttpsLink(href, None))
    document = InstructionDocument((Node("paragraph", children=(first, second, Node("hard_break"))),))
    expected = ('{"type":"doc","content":[{"type":"paragraph","content":[{"type":"text",'
        '"marks":[{"type":"link","attrs":{"href":"https://synthetic.invalid/help?section=one#start",'
        '"title":null}},{"type":"em"},{"type":"strong"},{"type":"code"}],"text":"AB"}]}]}')
    assert base64.b64decode(document._detail).decode() == expected
    combined = InstructionDocument((Node("paragraph", children=(Node("text", text="AB",
        marks=("strong", "em", "code"), link=InstructionHttpsLink(href)),)),))
    assert InstructionRichText("Brief", document).digest == InstructionRichText("Brief", combined).digest
    variants = compiled(Node("paragraph", children=(
        Node("text", text="A", link=InstructionHttpsLink(href)),
        Node("text", text="B", link=InstructionHttpsLink(href, "")),
        Node("text", text="C", link=InstructionHttpsLink(href, "Title")),
        Node("text", text="D", link=InstructionHttpsLink(href + "-other", "Title")),
    )))
    assert len(variants["content"][0]["content"]) == 4
    assert [node["marks"][0]["attrs"]["title"] for node in variants["content"][0]["content"]] == [None, "", "Title", "Title"]


@pytest.mark.parametrize("href", [
    "https://synthetic.invalid", "https://sub.synthetic.invalid:8443/path?x=one&y=two#part",
    "https://synthetic.invalid:443/a%20b?q=%2F%25", "https://synthetic.invalid/~user+one;item",
])
def test_https_reference_subset_preserves_accepted_bytes(href: str) -> None:
    title = 'Literal "quoted" <title> \\ content'
    link = InstructionHttpsLink(href, title)
    assert json.loads(link._wire) == {"type": "link", "attrs": {"href": href, "title": title}}


@pytest.mark.parametrize("href", [
    None, True, 1, "", "http://synthetic.invalid", "javascript:synthetic()", "data:text/plain,synthetic",
    "//synthetic.invalid/path", "/path", "HTTPS://synthetic.invalid", "https://Synthetic.invalid",
    "https://", "https:///path", "https://user@synthetic.invalid", "https://user:password@synthetic.invalid",
    "https://synthetic.invalid:", "https://synthetic.invalid:0443", "https://synthetic.invalid:0",
    "https://synthetic.invalid:65536", "https://synthetic.invalid:no", "https://127.0.0.1", "https://[::1]",
    "https://synthetic.invalid.", "https://bad..invalid", "https://-bad.invalid", "https://bad-.invalid",
    "https://bad_name.invalid", "https://syn%74hetic.invalid", "https://synthetic.invalid/a b",
    "https://synthetic.invalid/\t", "https://synthetic.invalid/\n", "https://synthetic.invalid/\r",
    "https://synthetic.invalid/\\path", "https://synthetic.invalid/中文", "https://synthetic.invalid/<tag>",
    "https://synthetic.invalid/%", "https://synthetic.invalid/%0", "https://synthetic.invalid/%GG",
    "https://synthetic.invalid/%00", "https://synthetic.invalid/%0a", "https://synthetic.invalid/%7F",
])
def test_unqualified_https_reference_is_value_free(href: Any) -> None:
    with pytest.raises(InstructionProfileContractError, match="^The private Instruction Profile contract is unavailable.$"):
        InstructionHttpsLink(href)


@pytest.mark.parametrize("title", [1, False, [], "中文", "line\nbreak", "\t", "\x00", "\x7f"])
def test_https_title_requires_printable_ascii(title: Any) -> None:
    with pytest.raises(InstructionProfileContractError, match="^The private Instruction Profile contract is unavailable.$"):
        InstructionHttpsLink("https://synthetic.invalid", title)


def test_url_parser_errors_do_not_disclose_private_values_in_tracebacks() -> None:
    private_port = "synthetic-private-port-token"
    with pytest.raises(InstructionProfileContractError) as failure:
        InstructionHttpsLink("https://synthetic.invalid:" + private_port)
    rendered = "".join(traceback.format_exception(failure.value))
    assert private_port not in rendered
    assert "Port could not be cast" not in rendered


def test_https_link_is_typed_text_only_and_counts_toward_encoded_and_input_budgets() -> None:
    link = InstructionHttpsLink("https://synthetic.invalid/path", 'Quoted "title"')
    linked = Node("text", text="x", link=link)
    for kind in ("paragraph", "heading", "hard_break", "code_block", "horizontal_rule"):
        with pytest.raises(InstructionProfileContractError):
            Node(kind, link=link)  # type: ignore[arg-type]
    with pytest.raises(InstructionProfileContractError):
        Node("text", text="x", link={"href": "https://synthetic.invalid"})  # type: ignore[arg-type]
    with pytest.raises(InstructionProfileContractError):
        Node("code_block", children=(linked,))
    overhead = len(base64.b64decode(InstructionDocument((Node("paragraph", children=(linked,)),))._detail)) - 1
    exact = Node("paragraph", children=(Node("text", text="x" * (18000 - overhead), link=link),))
    assert len(InstructionDocument((exact,))._detail) == 24000
    with pytest.raises(InstructionProfileContractError):
        InstructionDocument((Node("paragraph", children=(Node("text", text="x" * (18001 - overhead), link=link),)),))
    large_link = InstructionHttpsLink("https://synthetic.invalid/" + "x" * 9000)
    with pytest.raises(InstructionProfileContractError):
        Node("paragraph", children=(Node("text", text="x", link=large_link),) * 2)
