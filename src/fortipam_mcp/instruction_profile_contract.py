"""Private, I/O-free build-29 Instruction Profile content candidates.

This compiles bounded ASCII text or typed structure into the native format. It
confers no dispatch, ownership, resource, attachment or feature-change authority.
"""
from __future__ import annotations

import base64
from collections.abc import Mapping
import hashlib
import json
import re
from typing import Literal, NoReturn
from urllib.parse import urlsplit

from v4_planning.material_provider import C3MaterialBinding

CONTRACT = "fortipam-700-build29-instruction-profile-plain-text-private-v1"
RICH_CONTRACT = "fortipam-700-build29-instruction-profile-rich-structure-private-v2"
WIRE_FIELDS = frozenset({"name", "brief", "detail"})
_NAME = re.compile(r"mcp-v4-ip-[a-z0-9][a-z0-9-]{0,12}\Z")
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_UNAVAILABLE = "The private Instruction Profile contract is unavailable."


class InstructionProfileContractError(RuntimeError):
    """A value-free refusal that cannot disclose private profile content."""


def _fail() -> NoReturn:
    raise InstructionProfileContractError(_UNAVAILABLE) from None


def _json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def _digest(value: object) -> str:
    return hashlib.sha256(_json(value)).hexdigest()


def _require_digest(value: str) -> None:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        _fail()


def _defaults_digest(defaults: Mapping[str, object]) -> str:
    if not isinstance(defaults, Mapping) or set(defaults) != WIRE_FIELDS:
        _fail()
    if any(type(defaults[key]) is not str or defaults[key] != "" for key in WIRE_FIELDS):
        _fail()
    return _digest({key: defaults[key] for key in sorted(WIRE_FIELDS)})


def _plain_ascii(value: str, maximum: int) -> None:
    if (type(value) is not str or not 0 < len(value) <= maximum
            or not value.strip() or any(ord(char) < 32 or ord(char) > 126 for char in value)):
        _fail()


class _Private(C3MaterialBinding):
    __slots__ = ()

    def __setattr__(self, name: str, value: object) -> None:
        _fail()

    def __delattr__(self, name: str) -> None:
        _fail()


class InstructionPlainText(_Private):
    """A bounded literal paragraph, without caller-supplied JSON or rich nodes."""

    __slots__ = ("_brief", "_detail", "digest")
    _brief: str
    _detail: str
    digest: str

    def __init__(self, brief: str, text: str) -> None:
        _plain_ascii(brief, 1023)
        _plain_ascii(text, 24000)
        document = {"type": "doc", "content": [{"type": "paragraph", "content": [{"type": "text", "text": text}]}]}
        # The native editor measures Base64 length, including JSON escaping.
        detail = base64.b64encode(_json(document)).decode("ascii")
        if len(detail) > 24000:
            _fail()
        object.__setattr__(self, "_brief", brief)
        object.__setattr__(self, "_detail", detail)
        object.__setattr__(self, "digest", _digest({"brief": brief, "detail": detail}))


InstructionNodeKind = Literal["text", "paragraph", "heading", "bullet_list", "ordered_list",
    "list_item", "blockquote", "code_block", "hard_break", "horizontal_rule"]
InstructionMark = Literal["em", "strong", "code"]
_MARKS = ("em", "strong", "code")
_BLOCKS = frozenset({"paragraph", "heading", "bullet_list", "ordered_list",
                     "blockquote", "code_block", "horizontal_rule"})
_INLINE = frozenset({"text", "hard_break"})
_MAX_DEPTH, _MAX_NODES, _MAX_TEXT = 12, 512, 18000
_HTTPS_URI = re.compile(r"https://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]+\Z")
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_ESCAPE = re.compile(r"%([A-Fa-f0-9]{2})")


class InstructionHttpsLink(_Private):
    """An opaque ASCII HTTPS reference; never fetched by the MCP server.

    The private supported subset uses lowercase DNS names and canonical decimal
    ports. IP literals and escaped authorities are outside this contract.
    Percent escapes in path/query/fragment are preserved, except control octets.
    """

    __slots__ = ("_wire", "_text_size")
    _wire: bytes
    _text_size: int

    def __init__(self, href: str, title: str | None = None) -> None:
        if (type(href) is not str or not 0 < len(href) <= _MAX_TEXT
                or _HTTPS_URI.fullmatch(href) is None
                or (title is not None and (type(title) is not str or len(title) > _MAX_TEXT
                    or any(ord(char) < 32 or ord(char) > 126 for char in title)))):
            _fail()
        try:
            parsed = urlsplit(href)
            host, port = parsed.hostname, parsed.port
            if (host is None or len(host) > 253 or parsed.username is not None
                    or parsed.password is not None or "%" in parsed.netloc
                    or any(_DNS_LABEL.fullmatch(label) is None for label in host.split("."))
                    or not host.rsplit(".", 1)[-1][0].isalpha()
                    or (port is not None and not 1 <= port <= 65535)
                    or parsed.netloc != host + (":" + str(port) if port is not None else "")):
                _fail()
            for match in re.finditer("%", href):
                escape = _ESCAPE.match(href, match.start())
                if escape is None or int(escape.group(1), 16) < 32 or int(escape.group(1), 16) == 127:
                    _fail()
        except ValueError:
            _fail()
        encoded = _json({"type": "link", "attrs": {"href": href, "title": title}})
        if len(encoded) > 18000:
            _fail()
        object.__setattr__(self, "_wire", encoded)
        object.__setattr__(self, "_text_size", len(href) + (len(title) if title is not None else 0))


class InstructionNode(_Private):
    """Typed private structure; no arbitrary native attributes or resources.

    ASCII text is qualified for the native btoa editor. LF and TAB are accepted
    only inside code blocks. Unicode and resource contracts remain separate work.
    Bounds count the input tree before trailing-break removal or text merging.
    """

    __slots__ = ("_kind", "_wire", "_depth", "_count", "_text_size", "_code_text")
    _kind: InstructionNodeKind
    _wire: bytes
    _depth: int
    _count: int
    _text_size: int
    _code_text: bool

    def __init__(self, kind: InstructionNodeKind, *, children: tuple[InstructionNode, ...] = (),
                 text: str | None = None, marks: tuple[InstructionMark, ...] = (),
                 level: int | None = None, order: int | None = None,
                 link: InstructionHttpsLink | None = None) -> None:
        if (type(kind) is not str or kind not in _BLOCKS | _INLINE | {"list_item"}
                or type(children) is not tuple or len(children) > _MAX_NODES
                or any(type(child) is not InstructionNode for child in children)
                or type(marks) is not tuple or len(marks) > len(_MARKS)
                or any(type(mark) is not str or mark not in _MARKS for mark in marks)
                or len(set(marks)) != len(marks)):
            _fail()
        if ((link is not None and type(link) is not InstructionHttpsLink)
                or (kind != "text" and (text is not None or marks or link is not None))
                or (kind != "heading" and level is not None)
                or (kind != "ordered_list" and order is not None)):
            _fail()
        depth = 1 + max((child._depth for child in children), default=0)
        count = 1 + sum(child._count for child in children)
        text_size = sum(child._text_size for child in children)
        if depth > _MAX_DEPTH - 1 or count > _MAX_NODES - 1 or text_size > _MAX_TEXT:
            _fail()
        code_text = False
        wire: dict[str, object] = {"type": kind}
        if kind == "text":
            if (children or type(text) is not str or not 0 < len(text) <= _MAX_TEXT
                    or any(not (32 <= ord(char) <= 126 or char in "\n\t") for char in text)):
                _fail()
            if marks or link is not None:
                wire["marks"] = ([json.loads(link._wire)] if link is not None else []) + [
                    {"type": mark} for mark in _MARKS if mark in marks]
            wire["text"] = text
            text_size = len(text) + (link._text_size if link is not None else 0)
            code_text = "\n" in text or "\t" in text
        elif kind in {"hard_break", "horizontal_rule"}:
            if children:
                _fail()
        else:
            kinds = tuple(child._kind for child in children)
            if kind in {"paragraph", "heading"}:
                if any(child._kind not in _INLINE or child._code_text for child in children):
                    _fail()
            elif kind == "code_block":
                if any(child._kind != "text" or "marks" in json.loads(child._wire) for child in children):
                    _fail()
            elif kind in {"bullet_list", "ordered_list"}:
                if not kinds or any(item != "list_item" for item in kinds):
                    _fail()
            elif kind == "list_item":
                if not kinds or kinds[0] != "paragraph" or any(item not in _BLOCKS for item in kinds):
                    _fail()
            elif not kinds or any(item not in _BLOCKS for item in kinds):
                _fail()
            if kind == "heading":
                if level is not None and (type(level) is not int or not 1 <= level <= 6):
                    _fail()
                wire["attrs"] = {"level": 1 if level is None else level}
            if kind == "ordered_list":
                if order is not None and (type(order) is not int or not 1 <= order <= 2147483647):
                    _fail()
                wire["attrs"] = {"order": 1 if order is None else order}
            # Exact native Nt behavior: remove trailing breaks in textblocks,
            # then Fragment.from merges adjacent text with identical marks.
            end = len(children)
            if kind in {"paragraph", "heading"}:
                while end and children[end - 1]._kind == "hard_break":
                    end -= 1
            content: list[dict[str, object]] = []
            for child in children[:end]:
                value = json.loads(child._wire)
                if (child._kind == "text" and content and content[-1]["type"] == "text"
                        and content[-1].get("marks") == value.get("marks")):
                    content[-1]["text"] = str(content[-1]["text"]) + value["text"]
                else:
                    content.append(value)
            if content:
                wire["content"] = content
        encoded = _json(wire)
        if len(encoded) > 18000:
            _fail()
        for key, value in {"_kind": kind, "_wire": encoded, "_depth": depth, "_count": count,
                           "_text_size": text_size, "_code_text": code_text}.items():
            object.__setattr__(self, key, value)


class InstructionDocument(_Private):
    """Bounded normalized native document assembled only from typed blocks."""

    __slots__ = ("_detail",)
    _detail: str

    def __init__(self, blocks: tuple[InstructionNode, ...]) -> None:
        if (type(blocks) is not tuple or not 0 < len(blocks) < _MAX_NODES
                or any(type(block) is not InstructionNode or block._kind not in _BLOCKS for block in blocks)
                or 1 + sum(block._count for block in blocks) > _MAX_NODES
                or sum(block._text_size for block in blocks) > _MAX_TEXT):
            _fail()
        detail = base64.b64encode(_json({"type": "doc",
            "content": [json.loads(block._wire) for block in blocks]})).decode("ascii")
        if len(detail) > 24000:
            _fail()
        object.__setattr__(self, "_detail", detail)


class InstructionRichText(_Private):
    """Privately compiled structure, version-bound separately from plain text."""

    __slots__ = ("_brief", "_detail", "digest")
    _brief: str
    _detail: str
    digest: str

    def __init__(self, brief: str, document: InstructionDocument) -> None:
        _plain_ascii(brief, 1023)
        if type(document) is not InstructionDocument:
            _fail()
        object.__setattr__(self, "_brief", brief)
        object.__setattr__(self, "_detail", document._detail)
        object.__setattr__(self, "digest", _digest({"contract": RICH_CONTRACT,
            "brief": brief, "detail": document._detail}))


class InstructionProfileCreatePlan(_Private):
    """Bind a distinct candidate and private content to exact source context."""

    __slots__ = ("_name", "_content", "_defaults", "_schema", "_serial", "contract", "digest")
    _name: str
    _content: InstructionPlainText | InstructionRichText
    _defaults: str
    _schema: str
    _serial: str
    digest: str
    contract: str

    def __init__(self, name: str, nonce: str, content: InstructionPlainText | InstructionRichText,
                 defaults: Mapping[str, object], *, schema_digest: str, serial_digest: str) -> None:
        if type(name) is not str or len(name) > 23 or _NAME.fullmatch(name) is None:
            _fail()
        if type(content) not in {InstructionPlainText, InstructionRichText}:
            _fail()
        for value in (nonce, schema_digest, serial_digest):
            _require_digest(value)
        default_digest = _defaults_digest(defaults)
        contract = CONTRACT if type(content) is InstructionPlainText else RICH_CONTRACT
        values: dict[str, object] = {"_name": name, "_content": content, "_defaults": default_digest,
            "_schema": schema_digest, "_serial": serial_digest, "contract": contract,
            "digest": _digest({"contract": contract, "name": name, "nonce": nonce,
                "content_digest": content.digest, "defaults_digest": default_digest,
                "schema_digest": schema_digest, "serial_digest": serial_digest})}
        for key, item in values.items():
            object.__setattr__(self, key, item)


def build_instruction_profile_create_body(plan: InstructionProfileCreatePlan,
        defaults: Mapping[str, object], *, schema_digest: str, serial_digest: str) -> bytearray:
    """Return exactly three native fields; erase the private buffer after use."""
    if type(plan) is not InstructionProfileCreatePlan:
        _fail()
    _require_digest(schema_digest)
    _require_digest(serial_digest)
    if (_defaults_digest(defaults) != plan._defaults or schema_digest != plan._schema
            or serial_digest != plan._serial):
        _fail()
    return bytearray(_json({"name": plan._name, "brief": plan._content._brief, "detail": plan._content._detail}))


__all__ = ["CONTRACT", "RICH_CONTRACT", "WIRE_FIELDS", "InstructionProfileContractError", "InstructionPlainText",
           "InstructionNodeKind", "InstructionMark", "InstructionHttpsLink", "InstructionNode", "InstructionDocument", "InstructionRichText",
           "InstructionProfileCreatePlan", "build_instruction_profile_create_body"]
