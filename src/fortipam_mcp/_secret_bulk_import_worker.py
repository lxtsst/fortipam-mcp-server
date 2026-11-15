"""One-shot private parser. Only the parent may use its binary pipe protocol.

No FortiPAM client, provider registration, action dispatch, or plaintext output
file belongs here. Python/library strings live only in this short-lived child;
process exit is not a claim of physical memory or swap erasure.
"""

from __future__ import annotations

import csv
import io
import logging
import os
from pathlib import PurePosixPath
import re
import resource
import struct
import sys
from typing import Any
import zipfile

HEADERS = (
    "Secret Template", "Name", "Folder", "Target-Address", "Domain", "Username",
    "Password/Passphrase", "Private-Key", "Public-Key", "Certificate", "URL",
    "Text", "Service Type", "Port", "Association-Secret", "Description",
)
INPUT_MAGIC = b"FPBIin01"
OUTPUT_MAGIC = b"FPBIout1"
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_WORKBOOK_BYTES = 8 * 1024 * 1024
MAX_XML_BYTES = 16 * 1024 * 1024
MAX_FRAME_BYTES = 8 * 1024 * 1024
MAX_CELL_BYTES = 65536
MAX_ROWS = 256
MAX_PASSWORD_BYTES = 1024
_CELL = re.compile(r"([A-Z]{1,3})([1-9][0-9]{0,6})\Z")
_ESCAPED_TEXT = re.compile(r"_x[0-9A-Fa-f]{4}_|x005F_")
_SHEET_NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"


def _text_container(node: Any) -> None:
    children = list(node)
    if not children:
        return
    if len(children) == 1 and children[0].tag == _SHEET_NS + "t":
        if len(children[0]):
            raise ValueError
        return
    for run in children:
        if run.tag != _SHEET_NS + "r":
            raise ValueError
        tags = [child.tag for child in run]
        if (tags.count(_SHEET_NS + "t") != 1 or tags.count(_SHEET_NS + "rPr") > 1
                or any(tag not in {_SHEET_NS + "t", _SHEET_NS + "rPr"} for tag in tags)):
            raise ValueError
        if any(len(child) for child in run if child.tag == _SHEET_NS + "t"):
            raise ValueError


def _audit(event: str, args: tuple[Any, ...]) -> None:
    # Defense in depth, not a substitute for an OS sandbox. Imports may read
    # installed code. No file path is derived from an input workbook.
    if event.startswith(("socket.", "subprocess.", "os.exec", "os.spawn")):
        raise ValueError
    if event in {"os.system", "os.fork", "os.forkpty", "os.posix_spawn",
                 "os.remove", "os.rename", "os.mkdir", "os.link", "os.symlink"}:
        raise ValueError
    if event == "open":
        _, mode, flags = args
        if (isinstance(mode, str) and any(c in mode for c in "wax+")) or (
            isinstance(flags, int)
            and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)
        ):
            raise ValueError


def _harden() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (15, 15))
    if sys.platform.startswith("linux"):
        resource.setrlimit(resource.RLIMIT_AS, (384 * 1024 * 1024,) * 2)
    logging.disable(logging.CRITICAL)
    sys.dont_write_bytecode = True
    sys.addaudithook(_audit)


def _plain_workbook(raw: bytes, password: bytes) -> bytes:
    if raw.startswith(b"PK\x03\x04"):
        if password:
            raise ValueError
        return raw
    if not raw.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") or not password:
        raise ValueError
    # Harden the encryption-info XML before importing its parser.
    import defusedxml  # type: ignore[import-untyped]
    defusedxml.defuse_stdlib()
    from msoffcrypto.format.ooxml import OOXMLFile  # type: ignore[import-untyped]
    with io.BytesIO(raw) as encrypted:
        office = OOXMLFile(encrypted)
        try:
            if office.type != "agile" or not 0 < office.info["spinValue"] <= 1_000_000:
                raise ValueError
            with office.file.openstream("EncryptedPackage") as package:
                declared = struct.unpack("<Q", package.read(8))[0]
                if not 0 < declared <= MAX_WORKBOOK_BYTES:
                    raise ValueError
            office.load_key(password=password.decode("utf-8"), verify_password=True)
            with io.BytesIO() as decrypted:
                office.decrypt(decrypted, verify_integrity=True)
                if not 0 < decrypted.tell() <= MAX_WORKBOOK_BYTES:
                    raise ValueError
                return decrypted.getvalue()
        finally:
            office.file.close()


def _preflight_zip(raw: bytes) -> None:
    from defusedxml.ElementTree import fromstring  # type: ignore[import-untyped]
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        if not 0 < len(entries) <= 128:
            raise ValueError
        names = [entry.filename for entry in entries]
        if len(set(names)) != len(names) or sum(e.file_size for e in entries) > MAX_XML_BYTES:
            raise ValueError
        for entry in entries:
            path = PurePosixPath(entry.filename)
            if (path.is_absolute() or ".." in path.parts or "\\" in entry.filename
                    or entry.flag_bits & 1 or entry.file_size > MAX_WORKBOOK_BYTES
                    or entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)):
                raise ValueError
            if entry.filename.startswith(("xl/externalLinks/", "xl/embeddings/", "xl/activeX/")):
                raise ValueError
            if not entry.filename.endswith((".xml", ".rels")):
                # VBA/printer data are inert: never extracted, loaded, or run.
                continue
            root = fromstring(archive.read(entry), forbid_dtd=True, forbid_entities=True,
                              forbid_external=True)
            count = 0
            cell_refs: set[str] = set()
            row_refs: set[int] = set()
            last_row = 0
            for node in root.iter():
                count += 1
                if count > 100_000:
                    raise ValueError
                tag = node.tag.rsplit("}", 1)[-1]
                if tag in {"si", "is"}:
                    _text_container(node)
                text = ("".join(child.text or "" for child in node.iter()
                                if child.tag == _SHEET_NS + "t")
                        if tag in {"si", "is"} else node.text or "")
                if tag in {"t", "si", "is"} and _ESCAPED_TEXT.search(text):
                    # Excel escape sequences are not uniformly decoded by the
                    # library. Refuse rather than silently change credentials.
                    raise ValueError
                if (node.tag == _SHEET_NS + "f"
                        or tag in {"externalReference", "oleObject", "ddeLink"}):
                    raise ValueError
                if tag == "Relationship":
                    target = node.attrib.get("Target", "")
                    if (node.attrib.get("TargetMode", "Internal") != "Internal"
                            or ":" in target or "\\" in target):
                        raise ValueError
                if tag == "row":
                    row = int(node.attrib.get("r", "0"))
                    if not last_row < row <= MAX_ROWS + 1 or row in row_refs:
                        raise ValueError
                    row_refs.add(row)
                    last_row = row
                    previous_column = 0
                    for cell in node:
                        if cell.tag.rsplit("}", 1)[-1] != "c":
                            raise ValueError
                        address = _CELL.fullmatch(cell.attrib.get("r", ""))
                        if address is None or int(address[2]) != row:
                            raise ValueError
                        column_number = 0
                        for char in address[1]:
                            column_number = column_number * 26 + ord(char) - 64
                        if column_number <= previous_column:
                            raise ValueError
                        previous_column = column_number
                if tag == "c":
                    cell_type = node.attrib.get("t", "n")
                    if cell_type not in {"inlineStr", "s", "n"} or len(node) > 1:
                        raise ValueError
                    if len(node):
                        expected_tag = _SHEET_NS + ("is" if cell_type == "inlineStr" else "v")
                        value = node[0]
                        if value.tag != expected_tag:
                            raise ValueError
                        if cell_type != "inlineStr":
                            if len(value) or value.text is None:
                                raise ValueError
                            if cell_type == "s" and re.fullmatch(r"0|[1-9][0-9]{0,5}", value.text) is None:
                                raise ValueError
                    ref = node.attrib.get("r", "")
                    match = _CELL.fullmatch(ref)
                    if match is None or ref in cell_refs:
                        raise ValueError
                    column = 0
                    for char in match[1]:
                        column = column * 26 + ord(char) - 64
                    if column > len(HEADERS) or int(match[2]) > MAX_ROWS + 1:
                        raise ValueError
                    cell_refs.add(ref)


def _workbook_rows(raw: bytes, password: bytes) -> list[list[str]]:
    from openpyxl import load_workbook  # type: ignore[import-untyped]
    plain = _plain_workbook(raw, password)
    _preflight_zip(plain)
    book = load_workbook(io.BytesIO(plain), read_only=True, data_only=False,
                         keep_vba=False, keep_links=False)
    try:
        names = book.sheetnames
        if "data" not in names or len({name.casefold() for name in names}) != len(names):
            raise ValueError
        sheet = book["data"]
        sheet.reset_dimensions()
        result: list[list[str]] = []
        for cells in sheet.iter_rows():
            if len(result) > MAX_ROWS or len(cells) > len(HEADERS):
                raise ValueError
            row: list[str] = []
            for index, cell in enumerate(cells):
                value = cell.value
                if value is None:
                    row.append("")
                elif cell.data_type == "s" and type(value) is str:
                    row.append(value)
                elif index == 13 and type(value) is int and 1 <= value <= 65535:
                    row.append(str(value))
                else:
                    # No cached formulas, dates, booleans, or lossy conversion
                    # of numeric usernames/passwords/IDs into text.
                    raise ValueError
            row.extend([""] * (len(HEADERS) - len(row)))
            result.append(row)
        return result
    finally:
        book.close()


def _parse(raw: bytes, password: bytes, kind: int) -> bytes:
    rows: list[list[str]]
    if kind == 1:
        if password:
            raise ValueError
        csv.field_size_limit(MAX_CELL_BYTES)
        rows = []
        for row in csv.reader(io.StringIO(raw.decode("utf-8-sig"), newline=""), strict=True):
            if len(rows) > MAX_ROWS:
                raise ValueError
            rows.append(row)
    elif kind == 2:
        rows = _workbook_rows(raw, password)
    else:
        raise ValueError
    if not rows or tuple(rows[0]) != HEADERS:
        raise ValueError
    payload = bytearray(OUTPUT_MAGIC + b"\x00\x00")
    names: set[str] = set()
    count = 0
    for row in rows[1:]:
        if not row or not any(row):
            continue
        if len(row) != len(HEADERS) or any(not row[i].strip() for i in (0, 1, 2)):
            raise ValueError
        if any(row[i] != row[i].strip() for i in (0, 1, 2)):
            raise ValueError
        name = row[1].casefold()
        if name in names:
            raise ValueError
        names.add(name)
        count += 1
        if count > MAX_ROWS:
            raise ValueError
        for value in row:
            encoded = value.encode("utf-8")
            if len(encoded) > MAX_CELL_BYTES or "\x00" in value:
                raise ValueError
            payload.extend(struct.pack("!I", len(encoded)))
            payload.extend(encoded)
            if len(payload) > MAX_FRAME_BYTES:
                raise ValueError
    if not count:
        raise ValueError
    struct.pack_into("!H", payload, len(OUTPUT_MAGIC), count)
    return bytes(payload)


def main() -> int:
    try:
        _harden()
        raw = sys.stdin.buffer.read(MAX_FILE_BYTES + MAX_PASSWORD_BYTES + 16)
        if len(raw) < 15 or raw[:8] != INPUT_MAGIC:
            return 1
        kind, password_size, file_size = struct.unpack_from("!BHI", raw, 8)
        if (not 0 < file_size <= MAX_FILE_BYTES or password_size > MAX_PASSWORD_BYTES
                or len(raw) != 15 + password_size + file_size):
            return 1
        result = _parse(raw[15 + password_size:], raw[15:15 + password_size], kind)
        sys.stdout.buffer.write(result)
        sys.stdout.buffer.flush()
        return 0
    except BaseException:
        # Never include an exception type, text, parser location, or input value.
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
