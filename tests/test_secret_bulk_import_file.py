"""Synthetic-only file boundary and private worker integration regressions."""

import copy
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import pickle
import subprocess
import sys
import threading
import time
import zipfile

import pytest

from fortipam_mcp import _secret_bulk_import_worker as worker
from fortipam_mcp import secret_bulk_import_file as boundary


def row(**changes):
    values = dict.fromkeys(worker.HEADERS, "")
    values.update({"Secret Template": "Web Account", "Name": "Synthetic item",
                   "Folder": "Synthetic folder", "Username": "synthetic-user",
                   "Password/Passphrase": " synthetic-only,\r\n密码 ",
                   "URL": "https://example.invalid", "Port": "443"})
    values.update(changes)
    return [values[name] for name in worker.HEADERS]


def csv_bytes(rows=None, headers=worker.HEADERS):
    out = io.StringIO(newline="")
    writer = csv.writer(out)
    writer.writerow(headers)
    writer.writerows(rows if rows is not None else [row()])
    return out.getvalue().encode("utf-8")


def workbook_bytes(rows=None):
    pytest.importorskip("openpyxl")
    pytest.importorskip("defusedxml")
    from openpyxl import Workbook
    book = Workbook()
    book.active.title = "data"
    book.active.append(worker.HEADERS)
    for item in rows if rows is not None else [row()]:
        book.active.append(item)
    out = io.BytesIO()
    book.save(out)
    book.close()
    # stdlib ElementTree used by openpyxl's writer emits literal CR, which XML
    # normalizes. Encode it as a character reference to test an actual CR value.
    return rewrite_zip(out.getvalue(), "xl/worksheets/sheet1.xml",
                       lambda xml: xml.replace(b"\r", b"&#13;"))


def encrypted_bytes(raw):
    pytest.importorskip("msoffcrypto")
    from msoffcrypto.format.ooxml import OOXMLFile
    out = io.BytesIO()
    OOXMLFile(io.BytesIO(raw)).encrypt("synthetic-password", out)
    return out.getvalue()


def private_file(tmp_path, raw):
    tmp_path.chmod(0o700)
    path = tmp_path / "synthetic-input"
    path.write_bytes(raw)
    path.chmod(0o600)
    # macOS /var resolves through a symlink, intentionally disallowed by reader.
    return path.resolve()


def decode(tmp_path, raw, fmt="csv", password=None):
    return boundary.decode_prebound_file(
        private_file(tmp_path, raw), expected_sha256=hashlib.sha256(raw).hexdigest(),
        file_format=fmt, workbook_password=password,
    )


def test_csv_multiline_bom_credentials_are_opaque_consumed_and_zeroized(tmp_path, capfd):
    rows = decode(tmp_path, b"\xef\xbb\xbf" + csv_bytes())
    raw = rows._ProtectedBulkImportRows__raw
    assert repr(rows) == str(rows) == "<ProtectedBulkImportRows redacted>"
    for serializer in (copy.copy, copy.deepcopy, pickle.dumps, json.dumps):
        with pytest.raises((RuntimeError, TypeError)):
            serializer(rows)
    escaped = []

    def consume(values):
        assert len(values) == 1
        assert all(v.readonly for v in values[0])
        assert bytes(values[0][6]) == row()[6].encode()
        escaped.extend(values[0])
        return "consumed"

    assert rows._consume_once(consume) == "consumed"
    assert raw and not any(raw)
    with pytest.raises(ValueError):
        bytes(escaped[0])
    with pytest.raises(boundary.BulkImportFileError, match="^Protected bulk-import file unavailable\\.$"):
        rows._consume_once(lambda _: pytest.fail("Replayed"))
    assert capfd.readouterr() == ("", "")


@pytest.mark.parametrize("encrypted", [False, True])
def test_xlsm_text_preservation_and_integer_port(tmp_path, encrypted):
    values = row()
    values[13] = 443
    raw = workbook_bytes([values])
    password = bytearray(b"synthetic-password") if encrypted else None
    if encrypted:
        raw = encrypted_bytes(raw)
    with decode(tmp_path, raw, "xlsm", password) as rows:
        assert rows._consume_once(lambda decoded: [bytes(c).decode() for c in decoded[0]]) == row()
    if password is not None:
        assert not any(password)


@pytest.mark.parametrize("completion_offset", [0.0, 1.0])
def test_consumer_completion_at_or_after_expiry_is_terminal(tmp_path, monkeypatch, completion_offset):
    rows = decode(tmp_path, csv_bytes())
    raw = rows._ProtectedBulkImportRows__raw
    expiry = rows._ProtectedBulkImportRows__expires
    now = [expiry - 1.0]
    monkeypatch.setattr(boundary.time, "monotonic", lambda: now[0])
    escaped = []

    def consume(values):
        escaped.append(values[0][0])
        now[0] = expiry + completion_offset
        return "must-not-return"

    with pytest.raises(boundary.BulkImportFileError, match="Protected bulk-import file unavailable"):
        rows._consume_once(consume)
    assert raw and not any(raw)
    with pytest.raises(ValueError):
        bytes(escaped[0])
    now[0] = expiry - 1.0
    with pytest.raises(boundary.BulkImportFileError):
        rows._consume_once(lambda _: pytest.fail("Consumed rows cannot reopen"))


@pytest.mark.parametrize("raw", [
    csv_bytes(headers=tuple(reversed(worker.HEADERS))),
    csv_bytes(headers=worker.HEADERS[:-1]),
    csv_bytes(rows=[]),
    csv_bytes([row(), row(Name="synthetic ITEM")]),
    csv_bytes([row(), row(Name="other", Folder="")]),
    csv_bytes([row(Name=" leading")]),
    csv_bytes([row(Text="\x00")]),
    csv_bytes([row(Text="x" * (worker.MAX_CELL_BYTES + 1))]),
    csv_bytes([row(Name=f"item-{i}") for i in range(worker.MAX_ROWS + 1)]),
    b"\xff" + csv_bytes(),
])
def test_entire_csv_rejected_without_partial_rows(tmp_path, raw, capfd):
    with pytest.raises(boundary.BulkImportFileError) as caught:
        decode(tmp_path, raw)
    assert str(caught.value) == "Protected bulk-import file unavailable."
    assert capfd.readouterr() == ("", "")


@pytest.mark.parametrize("changes", [
    {"Username": 123}, {"Password/Passphrase": 123}, {"Text": True},
    {"Text": "=1+1"}, {"Port": 1.5}, {"Port": 65536},
])
def test_xlsm_rejects_formulas_and_lossy_cell_types(tmp_path, changes):
    with pytest.raises(boundary.BulkImportFileError):
        decode(tmp_path, workbook_bytes([row(**changes)]), "xlsm")


@pytest.mark.parametrize("password", [bytearray(b"wrong"), bytearray()])
def test_wrong_xlsm_password_denied_and_cleared(tmp_path, password, capfd):
    with pytest.raises(boundary.BulkImportFileError):
        decode(tmp_path, encrypted_bytes(workbook_bytes()), "xlsm", password)
    assert not any(password)
    assert capfd.readouterr() == ("", "")


def rewrite_zip(raw, name, mutate):
    out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(raw)) as source, zipfile.ZipFile(out, "w") as dest:
        for entry in source.infolist():
            data = source.read(entry)
            dest.writestr(entry, mutate(data) if entry.filename == name else data)
    return out.getvalue()


def with_shared_strings(raw, entries):
    out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(raw)) as source, zipfile.ZipFile(out, "w") as dest:
        for entry in source.infolist():
            data = source.read(entry)
            if entry.filename == "[Content_Types].xml":
                data = data.replace(b'</Types>', b'<Override PartName="/xl/sharedStrings.xml" '
                    b'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/></Types>')
            if entry.filename == "xl/_rels/workbook.xml.rels":
                data = data.replace(b'</Relationships>', b'<Relationship Id="syntheticShared" '
                    b'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" '
                    b'Target="sharedStrings.xml"/></Relationships>')
            dest.writestr(entry, data)
        dest.writestr("xl/sharedStrings.xml",
                      b'<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                      + entries + b'</sst>')
    return out.getvalue()


@pytest.mark.parametrize("name,mutate", [
    ("xl/worksheets/sheet1.xml", lambda x: x.replace(b'<row r="2">', b'<row r="1048576">')),
    ("xl/worksheets/sheet1.xml", lambda x: x.replace(b'r="A2"', b'r="XFD2"')),
    ("xl/worksheets/sheet1.xml", lambda x: x.replace(b'r="B2"', b'r="A2"')),
    ("xl/worksheets/sheet1.xml", lambda x: x.replace(b'r="A2"', b'r="A3"')),
    ("xl/_rels/workbook.xml.rels", lambda x: x.replace(b'Target="', b'TargetMode="External" Target="', 1)),
    ("xl/workbook.xml", lambda x: b'<!DOCTYPE workbook [<!ENTITY x "synthetic">]>' + x),
])
def test_workbook_structure_abuse_is_rejected(tmp_path, name, mutate):
    with pytest.raises(boundary.BulkImportFileError):
        decode(tmp_path, rewrite_zip(workbook_bytes(), name, mutate), "xlsm")


@pytest.mark.parametrize("mode", [0o644, 0o660, 0o400])
def test_file_permissions_fail_before_worker(tmp_path, monkeypatch, mode):
    raw = csv_bytes()
    path = private_file(tmp_path, raw)
    path.chmod(mode)
    monkeypatch.setattr(boundary, "_run_parser", lambda *a: pytest.fail("Parser ran"))
    with pytest.raises(boundary.BulkImportFileError):
        boundary.decode_prebound_file(path, expected_sha256=hashlib.sha256(raw).hexdigest(), file_format="csv")


@pytest.mark.parametrize("fault", ["digest", "symlink", "hardlink", "parent", "oversize", "changed"])
def test_file_identity_and_size_fail_closed(tmp_path, monkeypatch, fault):
    raw = csv_bytes()
    path = private_file(tmp_path, raw)
    digest = hashlib.sha256(raw).hexdigest()
    if fault == "digest":
        digest = "0" * 64
    elif fault == "symlink":
        link = path.with_name("link")
        link.symlink_to(path)
        path = link
    elif fault == "hardlink":
        os.link(path, path.with_name("link"))
    elif fault == "parent":
        path.parent.chmod(0o755)
    elif fault == "oversize":
        with path.open("r+b") as f:
            f.truncate(worker.MAX_FILE_BYTES + 1)
    else:
        original = os.readv

        def mutate(fd, views):
            n = original(fd, views)
            path.write_bytes(raw + b"x")
            return n

        monkeypatch.setattr(os, "readv", mutate)
    monkeypatch.setattr(boundary, "_run_parser", lambda *a: pytest.fail("Parser ran"))
    password = bytearray(b"synthetic-password")
    with pytest.raises(boundary.BulkImportFileError):
        boundary.decode_prebound_file(path, expected_sha256=digest, file_format="csv", workbook_password=password)
    assert not any(password)


@pytest.mark.parametrize("kind", ["csv", "xlsm", "encrypted-xlsm"])
def test_pinned_source_decodes_fresh_frames_without_retaining_material(tmp_path, kind):
    raw = csv_bytes() if kind == "csv" else workbook_bytes()
    if kind == "encrypted-xlsm":
        raw = encrypted_bytes(raw)
    path = private_file(tmp_path, raw)
    source = boundary.PinnedBulkImportFile(
        path, expected_sha256=hashlib.sha256(raw).hexdigest(),
        file_format="csv" if kind == "csv" else "xlsm",
    )
    assert repr(source) == str(source) == "<PinnedBulkImportFile redacted>"
    for serializer in (copy.copy, copy.deepcopy, pickle.dumps, json.dumps):
        with pytest.raises((RuntimeError, TypeError)):
            serializer(source)
    frames = []
    for _ in range(2):
        password = bytearray(b"synthetic-password") if kind == "encrypted-xlsm" else None
        with source.decode(workbook_password=password) as rows:
            frames.append(rows._ProtectedBulkImportRows__raw)
            assert rows._consume_once(lambda data: bytes(data[0][6])) == row()[6].encode()
        if password is not None:
            assert not any(password)
    assert frames[0] is not frames[1] and all(not any(frame) for frame in frames)
    assert path.read_bytes() == raw


@pytest.mark.parametrize("fault", ["replace", "rewrite", "mode", "hardlink", "parent", "during-read"])
def test_pinned_source_rejects_identity_drift_before_parser(tmp_path, monkeypatch, fault, capfd):
    raw = csv_bytes()
    directory = tmp_path / "owner"
    directory.mkdir()
    path = private_file(directory, raw)
    source = boundary.PinnedBulkImportFile(
        path, expected_sha256=hashlib.sha256(raw).hexdigest(), file_format="csv",
    )
    original_stat = path.stat()
    if fault == "replace":
        replacement = path.with_name("replacement")
        replacement.write_bytes(raw)
        replacement.chmod(0o600)
        os.utime(replacement, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
        replacement.replace(path)
        assert path.stat().st_ino != original_stat.st_ino
    elif fault == "rewrite":
        # Same content/inode/mtime is insufficient: change time must still match.
        path.write_bytes(raw)
        os.utime(path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
        assert path.stat().st_ctime_ns != original_stat.st_ctime_ns
    elif fault == "mode":
        path.chmod(0o644)
    elif fault == "hardlink":
        os.link(path, path.with_name("alias"))
    elif fault == "parent":
        previous = path.parent.with_name("previous")
        path.parent.rename(previous)
        path.parent.mkdir(mode=0o700)
        (previous / path.name).rename(path)
    else:
        original_read = os.readv

        def change_during_read(fd, views):
            count = original_read(fd, views)
            os.utime(path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns + 1_000_000_000))
            return count

        monkeypatch.setattr(os, "readv", change_during_read)
    monkeypatch.setattr(boundary, "_run_parser", lambda *args: pytest.fail("Parser ran after drift"))
    password = bytearray(b"synthetic-password")
    with pytest.raises(boundary.BulkImportFileError) as caught:
        source.decode(workbook_password=password)
    assert str(caught.value) == "Protected bulk-import file unavailable."
    assert not any(password) and path.exists()
    assert capfd.readouterr() == ("", "")


@pytest.mark.parametrize("valid_digest", [True, False])
def test_source_pinning_clears_read_buffer_without_parser_or_retained_descriptor(tmp_path, monkeypatch, valid_digest):
    raw = csv_bytes()
    path = private_file(tmp_path, raw)
    observed = []
    original_read = os.readv

    def capture(fd, views):
        observed.append((fd, views[0].obj))
        return original_read(fd, views)

    monkeypatch.setattr(os, "readv", capture)
    monkeypatch.setattr(boundary, "_run_parser", lambda *args: pytest.fail("Pinning decoded materials"))
    digest = hashlib.sha256(raw).hexdigest() if valid_digest else "0" * 64
    if valid_digest:
        boundary.PinnedBulkImportFile(path, expected_sha256=digest, file_format="csv")
    else:
        with pytest.raises(boundary.BulkImportFileError):
            boundary.PinnedBulkImportFile(path, expected_sha256=digest, file_format="csv")
    assert observed and all(not any(buffer) for _, buffer in observed)
    for fd, _ in observed:
        with pytest.raises(OSError):
            os.fstat(fd)
    assert path.read_bytes() == raw


@pytest.mark.parametrize("fault", ["content", "parser-contract"])
def test_pinned_source_rechecks_digest_and_parser_contract(tmp_path, monkeypatch, fault):
    raw = csv_bytes()
    path = private_file(tmp_path, raw)
    source = boundary.PinnedBulkImportFile(
        path, expected_sha256=hashlib.sha256(raw).hexdigest(), file_format="csv",
    )
    captured = []
    if fault == "content":
        original_read = boundary._read_owned

        def corrupt_content(path, expected_identity=None):
            buffer, identity = original_read(path, expected_identity)
            buffer[0] ^= 1
            captured.append(buffer)
            return buffer, identity

        monkeypatch.setattr(boundary, "_read_owned", corrupt_content)
    else:
        monkeypatch.setattr(boundary, "_PARSER_CONTRACT", "different-contract")
        monkeypatch.setattr(boundary, "_read_owned", lambda *args: pytest.fail("Read after contract drift"))
    monkeypatch.setattr(boundary, "_run_parser", lambda *args: pytest.fail("Parser ran"))
    password = bytearray(b"synthetic-password")
    with pytest.raises(boundary.BulkImportFileError):
        source.decode(workbook_password=password)
    assert not any(password) and all(not any(buffer) for buffer in captured)


@pytest.mark.parametrize("close_target", ["file", "parent"])
def test_source_read_close_failure_still_clears_buffer_and_closes_other_descriptor(tmp_path, monkeypatch, close_target):
    raw = csv_bytes()
    path = private_file(tmp_path, raw)
    captured, closed = [], []
    original_read, original_close = os.readv, os.close
    file_fd = []

    def capture(fd, views):
        file_fd[:] = [fd]
        captured.append(views[0].obj)
        return original_read(fd, views)

    def fail_close(fd):
        original_close(fd)
        if file_fd:
            closed.append(fd)
            if (fd == file_fd[0]) == (close_target == "file"):
                raise OSError("Synthetic close failure")

    monkeypatch.setattr(os, "readv", capture)
    monkeypatch.setattr(os, "close", fail_close)
    with pytest.raises(boundary.BulkImportFileError, match="Protected bulk-import file unavailable"):
        boundary.PinnedBulkImportFile(
            path, expected_sha256=hashlib.sha256(raw).hexdigest(), file_format="csv",
        )
    assert len(closed) == 2 and len(set(closed)) == 2
    assert captured and all(not any(buffer) for buffer in captured)
    for fd in closed:
        with pytest.raises(OSError):
            os.fstat(fd)


def test_consumer_error_expiry_and_clear_destroy_mutable_rows(tmp_path, monkeypatch, capfd):
    for fault in ("error", "expiry", "clear"):
        rows = decode(tmp_path, csv_bytes())
        raw = rows._ProtectedBulkImportRows__raw
        if fault == "expiry":
            rows._ProtectedBulkImportRows__expires = time.monotonic() - 1
        elif fault == "clear":
            rows.clear()

        def fail(_):
            raise ValueError("Synthetic secret must not escape")

        with pytest.raises(boundary.BulkImportFileError) as caught:
            rows._consume_once(fail)
        assert "Synthetic" not in str(caught.value)
        assert not any(raw)
    assert capfd.readouterr() == ("", "")


def test_worker_has_clean_environment_and_no_file_locator_arguments(tmp_path, monkeypatch):
    original = subprocess.Popen
    calls = []

    def capture(argv, **kw):
        assert kw["env"] == {} and kw["stderr"] is subprocess.DEVNULL
        assert str(tmp_path) not in repr(argv)
        assert argv[1:3] == ["-I", "-B"]
        calls.append(True)
        return original(argv, **kw)

    monkeypatch.setattr(subprocess, "Popen", capture)
    decode(tmp_path, csv_bytes()).clear()
    assert calls == [True]


def test_worker_timeout_is_reaped_and_inputs_cleared(tmp_path, monkeypatch):
    original = subprocess.Popen
    children = []

    def delayed(argv, **kw):
        child = original([sys.executable, "-I", "-c", "import time; time.sleep(60)"], **kw)
        children.append(child)
        return child

    monkeypatch.setattr(subprocess, "Popen", delayed)
    monkeypatch.setattr(boundary, "_TIMEOUT_SECONDS", 0.05)
    password = bytearray(b"synthetic-password")
    with pytest.raises(boundary.BulkImportFileError):
        decode(tmp_path, csv_bytes(), password=password)
    assert children[0].poll() is not None
    assert not any(password)


@pytest.mark.parametrize("close_target", ["stdin", "stdout"])
def test_worker_pipe_close_failure_clears_output_and_closes_both_pipes(
    tmp_path, monkeypatch, capfd, close_target,
):
    original_spawn, original_read = subprocess.Popen, os.readv
    children, output_buffers, original_closers = [], [], []

    def failing_close(argv, **kwargs):
        child = original_spawn(argv, **kwargs)
        children.append(child)
        original_closers.extend((child.stdin.close, child.stdout.close))
        stream = getattr(child, close_target)
        original_close = stream.close
        calls = 0

        def close():
            nonlocal calls
            calls += 1
            original_close()
            # stdin first closes when input is sent; fail during final cleanup.
            if close_target == "stdout" or calls == 2:
                raise OSError("synthetic-private-close-detail")

        monkeypatch.setattr(stream, "close", close)
        return child

    def capture_output(descriptor, views):
        if children and descriptor == children[0].stdout.fileno():
            output_buffers.append(views[0].obj)
        return original_read(descriptor, views)

    monkeypatch.setattr(subprocess, "Popen", failing_close)
    monkeypatch.setattr(os, "readv", capture_output)
    try:
        with pytest.raises(boundary.BulkImportFileError) as caught:
            decode(tmp_path, csv_bytes())
        assert str(caught.value) == "Protected bulk-import file unavailable."
        assert output_buffers
        output_cleared = all(not any(buffer) for buffer in output_buffers)
        assert output_cleared
        assert children[0].poll() is not None
        assert children[0].stdin.closed and children[0].stdout.closed
        assert capfd.readouterr() == ("", "")
    finally:
        for close in original_closers:
            close()


def test_worker_blocks_network_and_file_writes(tmp_path):
    script = (
        "import runpy,sys; w=runpy.run_path(sys.argv[1]); w['_harden'](); "
        "import socket; socket.socket()"
    )
    result = subprocess.run([sys.executable, "-I", "-B", "-c", script, worker.__file__],
                            capture_output=True, env={}, timeout=5)
    assert result.returncode != 0 and result.stdout == b""
    script = script.replace("import socket; socket.socket()", "open(sys.argv[2], 'w')")
    path = tmp_path / "not-written"
    result = subprocess.run([sys.executable, "-I", "-B", "-c", script, worker.__file__, str(path)],
                            capture_output=True, env={}, timeout=5)
    assert result.returncode != 0 and not path.exists()


def test_concurrent_consumption_is_denied_without_corrupting_owner(tmp_path):
    rows = decode(tmp_path, csv_bytes())
    entered, release = threading.Event(), threading.Event()
    result = []

    def consume(values):
        entered.set()
        assert release.wait(2)
        result.append(bytes(values[0][6]) == row()[6].encode())

    thread = threading.Thread(target=rows._consume_once, args=(consume,))
    thread.start()
    try:
        assert entered.wait(2)
        with pytest.raises(boundary.BulkImportFileError):
            rows._consume_once(lambda _: pytest.fail("Concurrent reuse"))
    finally:
        release.set()
        thread.join(2)
    assert result == [True] and not thread.is_alive()


def test_encrypted_payload_integrity_tampering_is_rejected(tmp_path):
    raw = bytearray(encrypted_bytes(workbook_bytes()))
    import olefile
    stream = io.BytesIO(raw)
    with olefile.OleFileIO(stream, write_mode=True) as ole:
        package = bytearray(ole.openstream("EncryptedPackage").read())
        package[-1] ^= 1
        ole.write_stream("EncryptedPackage", bytes(package))
    with pytest.raises(boundary.BulkImportFileError):
        decode(tmp_path, stream.getvalue(), "xlsm", bytearray(b"synthetic-password"))


@pytest.mark.parametrize("raw", [b"", worker.OUTPUT_MAGIC + b"\x00\x01", worker.OUTPUT_MAGIC + b"\x00\x00"])
def test_malformed_private_frames_cannot_escape(raw):
    mutable = bytearray(raw)
    with pytest.raises(boundary.BulkImportFileError):
        boundary.ProtectedBulkImportRows(mutable, time.monotonic() + 60)
    assert not any(mutable)


def test_partial_worker_output_is_discarded_on_nonzero_exit(tmp_path, monkeypatch):
    original = subprocess.Popen

    def fail(argv, **kw):
        return original([sys.executable, "-I", "-c",
                         "import sys; sys.stdout.buffer.write(b'FPBIout1\\x00\\x01'); sys.exit(1)"], **kw)

    monkeypatch.setattr(subprocess, "Popen", fail)
    with pytest.raises(boundary.BulkImportFileError):
        decode(tmp_path, csv_bytes())


def test_ambiguous_excel_string_escapes_fail_instead_of_mutating_password(tmp_path):
    raw = workbook_bytes([row(**{"Password/Passphrase": "synthetic_x005F_password"})])
    with pytest.raises(boundary.BulkImportFileError):
        decode(tmp_path, raw, "xlsm")


def test_inert_template_dropdown_formula_does_not_replace_cell_values(tmp_path):
    extension = (b'<extLst><ext uri="synthetic"><xm:f '
                 b'xmlns:xm="http://schemas.microsoft.com/office/excel/2006/main">'
                 b'template!$A$2:$A$35</xm:f></ext></extLst>')
    raw = rewrite_zip(workbook_bytes(), "xl/worksheets/sheet1.xml",
                      lambda x: x.replace(b'</worksheet>', extension + b'</worksheet>'))
    with decode(tmp_path, raw, "xlsm") as rows:
        assert rows._consume_once(lambda data: bytes(data[0][6])) == row()[6].encode()


def test_rich_text_split_escape_is_rejected_before_library_concatenation(tmp_path):
    import re
    shared_cell = b'<c r="G2" t="s"><v>0</v></c>'
    raw = rewrite_zip(workbook_bytes(), "xl/worksheets/sheet1.xml",
                      lambda x: re.sub(rb'<c r="G2"[^>]*>.*?</c>', shared_cell, x, flags=re.S))
    raw = with_shared_strings(raw, b'<si><r><t>syntheticx00</t></r><r><t>5F_credential</t></r></si>')
    from openpyxl import load_workbook
    book = load_workbook(io.BytesIO(raw), read_only=True)
    assert book['data']['G2'].value == "syntheticcredential"
    book.close()
    with pytest.raises(boundary.BulkImportFileError):
        decode(tmp_path, raw, "xlsm")


def test_consumer_can_clear_without_deadlock_or_success(tmp_path):
    rows = decode(tmp_path, csv_bytes())
    results = []

    def consume(_):
        rows.clear()
        return "must not succeed"

    def run():
        try:
            rows._consume_once(consume)
        except boundary.BulkImportFileError:
            results.append("denied")

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(2)
    assert not thread.is_alive() and results == ["denied"]
    assert not any(rows._ProtectedBulkImportRows__raw)


def test_recursive_consume_does_not_wipe_active_consumers_views(tmp_path):
    rows = decode(tmp_path, csv_bytes())

    def consume(values):
        with pytest.raises(boundary.BulkImportFileError):
            rows._consume_once(lambda _: pytest.fail("Recursive reuse"))
        return bytes(values[0][6])

    assert rows._consume_once(consume) == row()[6].encode()


@pytest.mark.parametrize("cell", [
    b'<c r="G2" t="s"><v>-1</v></c>',
    b'<c r="G2" t="s"><v>0</v><v>1</v></c>',
    b'<c r="G2" t="str"><v>synthetic</v></c>',
    b'<c r="G2" t="inlineStr"><is><t>synthetic</t><t>different</t></is></c>',
    b'<c r="G2" t="inlineStr"><is><t>synthetic</t></is><is><t>different</t></is></c>',
    b'<c r="G2" t="inlineStr"><is><t>synthetic</t><r><t>different</t></r></is></c>',
])
def test_ambiguous_cell_encodings_are_rejected(tmp_path, cell):
    import re
    raw = rewrite_zip(workbook_bytes(), "xl/worksheets/sheet1.xml",
                      lambda x: re.sub(rb'<c r="G2"[^>]*>.*?</c>', cell, x, flags=re.S))
    if b't="s"' in cell:
        raw = with_shared_strings(raw, b'<si><t>synthetic-first</t></si><si><t>synthetic-last</t></si>')
        from openpyxl import load_workbook
        book = load_workbook(io.BytesIO(raw), read_only=True)
        assert book['data']['G2'].value == ("synthetic-last" if b'-1' in cell else "synthetic-first")
        book.close()
    with pytest.raises(boundary.BulkImportFileError):
        decode(tmp_path, raw, "xlsm")


def test_duplicate_data_worksheets_cannot_hide_another_batch(tmp_path):
    import re
    raw = rewrite_zip(workbook_bytes(), "xl/workbook.xml",
                      lambda x: re.sub(rb'(<sheet\s[^>]+/>)', rb'\1\1', x, count=1))
    with pytest.raises(boundary.BulkImportFileError):
        decode(tmp_path, raw, "xlsm")
