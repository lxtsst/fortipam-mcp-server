"""Synthetic full native-row DTO conversion inside the original fixed handoff."""

import copy
from dataclasses import replace
import json
import pickle
import threading
import time

import pytest

from fortipam_mcp.secret_bulk_import_dependencies import (
    ImportTemplate, ImportTemplateField, ResolvedImportDependencies, dependency_catalog_digest,
)
from fortipam_mcp.secret_bulk_import_intake import BulkImportIntakeError
from fortipam_mcp.secret_bulk_import_row_adapter import _OriginalRowSecretCreateAdapter
from fortipam_mcp.secret_bulk_import_row_conversion import _Build29OriginalRowConversion
from fortipam_mcp.secret_bulk_import_row_provider import _OriginalRowMaterialRuntime
from test_secret_bulk_import_dependencies import catalog, item
from test_secret_bulk_import_row_adapter import context, execute
from test_secret_bulk_import_row_authority import configured
from test_secret_bulk_import_row_provider import execute as execute_material, material_store, original_claim
from v4_planning import M4Verification
from v4_planning.material_runtime import MaterialRuntimeOutcome, MaterialUseClaimState
from v4_planning.secret_create_adapter import SecretCreateAdapterOutcome


KINDS = ("target-address", "domain", "username", "password", "passphrase", "private-key", "public-key", "cert", "url", "text")


def fixture(tmp_path, monkeypatch, *, association="", index=0, fault=None, targetless=False, names=None):
    snapshot = replace(catalog(), templates=(ImportTemplate("Synthetic complete template",
        tuple(ImportTemplateField((names or {}).get(kind, "Synthetic " + kind), kind,
            not targetless or kind not in {"target-address", "domain", "url"}) for kind in KINDS)),))
    first = item(**{"Secret Template": snapshot.templates[0].name, "Name": "Original parent",
        "Target-Address": "192.0.2.50", "Domain": "fixture.example.test", "Username": " user\r\n秘密 ",
        "Password/Passphrase": ' password\r\n"\\秘密 ', "Private-Key": "private\r\nkey\rend",
        "Public-Key": "public\r\nkey", "Certificate": "cert\r\nvalue", "Text": "text\r\nvalue\rend",
        "URL": "https://fixture.example.test/path", "Service Type": "SSH;WEB;SAMBA", "Port": "22;443;",
        "Description": "description\r\n秘密"})
    if targetless:
        first = list(first)
        for column in (3, 4, 10):
            first[column] = ""
    second = list(first)
    second[1], second[14] = "Original child", association
    captured = {}
    loader, session, state, values, _, _, _, _, reference = configured(tmp_path, monkeypatch,
        values=[first, tuple(second)], snapshot=snapshot, index=index, capture=captured)
    class Transport:
        converter = None
        dto = None
        buffers = None
        body_view = None
        body = None
        calls = 0
        def _create_and_verify_with_original_row(self, use_context, columns, *, deadline):
            self.calls += 1
            self.buffers = [column.obj for column in columns]
            if fault == "context":
                use_context = replace(use_context, expires_at=1059)
            elif fault == "substitute":
                columns = tuple(memoryview(bytearray(column)).toreadonly() for column in columns)
            if fault == "deadline":
                deadline += 1
            elif fault == "idle":
                deadline = time.monotonic() + 0.1
            try:
                with self.converter._convert_once(use_context, columns, deadline=deadline) as view:
                    self.body_view, self.body = view, view.obj
                    assert view.readonly
                    self.dto = json.loads(bytes(view))
                    with pytest.raises(TypeError):
                        view[0] = 0
                    if fault == "consumer":
                        raise ValueError("Synthetic downstream failure")
                    if fault == "interrupt":
                        raise KeyboardInterrupt
                    if fault == "cancel":
                        session.close()
                    if fault == "idle":
                        time.sleep(0.18)
                        assert not any(self.body)
                return SecretCreateAdapterOutcome.VERIFIED_CREATED
            finally:
                if fault == "substitute":
                    for column in columns:
                        column.release()
    transport = Transport()
    bridge = _OriginalRowSecretCreateAdapter(loader, context(loader), transport)
    converter = _Build29OriginalRowConversion(bridge, captured["catalog"], captured["projected"],
        target_name=None if targetless else "Synthetic resolved target", associated_secret_id=42 if association.endswith("(ID: 42)") else 101 if association else None)
    transport.converter = converter
    return loader, session, state, reference, bridge, converter, transport, captured


@pytest.mark.parametrize("association,index", [("", 0), ("Existing parent (ID: 42)", 1), ("Original parent", 1)])
def test_all_sixteen_columns_map_in_template_order_without_changing_sensitive_line_endings(tmp_path, monkeypatch, association, index, capfd):
    loader, session, state, reference, bridge, converter, transport, _ = fixture(tmp_path, monkeypatch, association=association, index=index)
    original = session._transaction._binding.path.read_bytes()
    try:
        with reference:
            assert execute(loader, state, bridge).verification is M4Verification.VERIFIED
            assert execute(loader, state, bridge).verification is M4Verification.VERIFIED
        assert transport.calls == 1
        dto = transport.dto
        assert dto["name"] == ("Original child" if index else "Original parent")
        assert dto["folder"] == 7 and dto["target"] == "Synthetic resolved target"
        assert [field["type"] for field in dto["field"]] == list(KINDS)
        expected = ["192.0.2.50", "fixture.example.test", " user\r\n秘密 ", ' password\r\n"\\秘密 ',
            ' password\r\n"\\秘密 ', "private\nkey\rend", "public\nkey", "cert\r\nvalue",
            "https://fixture.example.test/path", "text\nvalue\rend"]
        assert [field["value"] for field in dto["field"]] == expected
        assert dto["description"] == "description\r\n秘密"
        assert dto["ssh-service-port"] == 22 and dto["http-service-port"] == 443
        assert dto["samba-service-status"] == "up" and "samba-service-port" not in dto
        assert dto["inherit-permission"] == "enable" and dto["user-permission"] == dto["group-permission"] == []
        assert dto["launch-with"] == ("associate" if association else "itself")
        if association:
            assert dto["associated-secret"] == (42 if association.endswith("(ID: 42)") else 101)
        else:
            assert "associated-secret" not in dto
        assert not any(transport.body) and all(not any(buffer) for buffer in transport.buffers)
        with pytest.raises(ValueError):
            transport.body_view.tobytes()
        assert session._transaction._binding.path.read_bytes() == original
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(RuntimeError):
                operation(converter)
        assert capfd.readouterr() == ("", "")
    finally:
        session.close()


@pytest.mark.parametrize("fault", ["context", "substitute", "deadline", "consumer", "cancel", "idle", "interrupt"])
def test_conversion_failure_clears_dto_and_row_and_never_replays_original_use(tmp_path, monkeypatch, fault):
    loader, session, state, reference, bridge, _, transport, _ = fixture(tmp_path, monkeypatch, fault=fault)
    try:
        with reference:
            if fault == "interrupt":
                with pytest.raises(KeyboardInterrupt):
                    execute(loader, state, bridge)
            else:
                assert execute(loader, state, bridge).verification is M4Verification.UNKNOWN
            assert execute(loader, state, bridge).verification is M4Verification.UNKNOWN
        assert transport.calls == 1 and all(not any(buffer) for buffer in transport.buffers)
        assert transport.body is None or not any(transport.body)
        assert not any(thread.name == "owner-row-conversion-disposal" and thread.is_alive()
                       for thread in threading.enumerate())
    finally:
        session.close()


def test_mapping_rejects_changed_original_graph_or_unresolved_association_without_material_use(tmp_path, monkeypatch):
    loader, session, _, reference, bridge, _, transport, captured = fixture(tmp_path, monkeypatch, association="Original parent", index=1)
    try:
        with reference:
            with pytest.raises(BulkImportIntakeError):
                _Build29OriginalRowConversion(bridge, captured["catalog"], captured["projected"],
                    target_name="Synthetic resolved target", associated_secret_id=None)
            changed = replace(captured["catalog"], templates=tuple(replace(template, fields=tuple(reversed(template.fields)))
                              for template in captured["catalog"].templates))
            with pytest.raises(BulkImportIntakeError):
                _Build29OriginalRowConversion(bridge, changed, captured["projected"],
                    target_name="Synthetic resolved target", associated_secret_id=101)
        assert not loader._used and transport.calls == 0
    finally:
        session.close()


@pytest.mark.parametrize("changed", ["row", "target", "order", "template"])
def test_forged_projection_with_matching_catalog_pin_cannot_replace_original_full_graph(tmp_path, monkeypatch, changed):
    loader, session, _, reference, bridge, _, transport, captured = fixture(tmp_path, monkeypatch)
    snapshot, projected = captured["catalog"], captured["projected"]
    digest = session._transaction._binding.file_sha256
    rows, targets, order = projected._inspect_private(_Build29OriginalRowConversion._graph,
        file_digest=digest, catalog_digest=dependency_catalog_digest(snapshot))
    if changed == "row":
        rows = (replace(rows[0], name="Forged original row"), *rows[1:])
    elif changed == "target":
        targets = (replace(targets[0], address="192.0.2.99"), *targets[1:])
    elif changed == "order":
        order = tuple(reversed(order))
    else:
        snapshot = replace(snapshot, templates=tuple(replace(template, fields=tuple(reversed(template.fields)))
                           for template in snapshot.templates))
    forged = ResolvedImportDependencies(rows, targets, order, file_digest=digest,
        catalog_digest=dependency_catalog_digest(snapshot), expires=snapshot.expires_at)
    try:
        with reference, pytest.raises(BulkImportIntakeError):
            _Build29OriginalRowConversion(bridge, snapshot, forged,
                target_name="Synthetic resolved target", associated_secret_id=None)
        assert not loader._used and transport.calls == 0
    finally:
        session.close()


@pytest.mark.parametrize("fault", [None, "consumer", "idle"])
def test_full_conversion_reuses_candidate_material_claim_release_and_uncertain_cleanup(tmp_path, monkeypatch, fault):
    loader, session, state, reference, bridge, _, transport, _ = fixture(tmp_path, monkeypatch, fault=fault)
    store = material_store(tmp_path)
    runtime = _OriginalRowMaterialRuntime(bridge, store)
    from fortipam_mcp.secret_bulk_import_file import PinnedBulkImportFile
    decode = PinnedBulkImportFile.decode
    def observed(self, **kwargs):
        assert original_claim(store, runtime).state is MaterialUseClaimState.IN_PROGRESS
        return decode(self, **kwargs)
    monkeypatch.setattr(PinnedBulkImportFile, "decode", observed)
    try:
        with reference:
            expected = M4Verification.VERIFIED if fault is None else M4Verification.UNKNOWN
            assert execute_material(loader, state, runtime).verification is expected
            assert execute_material(loader, state, runtime).verification is expected
        assert store.claim_count == transport.calls == 1
        assert original_claim(store, runtime).outcome is (MaterialRuntimeOutcome.VERIFIED_AND_RELEASED if fault is None
            else MaterialRuntimeOutcome.RECONCILIATION_REQUIRED)
        assert not any(transport.body) and all(not any(buffer) for buffer in transport.buffers)
    finally:
        session.close()
