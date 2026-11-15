"""Synthetic batch joins; no FortiPAM transport or authority is instantiated."""

import copy
from dataclasses import replace
import hashlib
import pickle
import threading
import time

import pytest

from fortipam_mcp import secret_bulk_import_dependencies as dep
from fortipam_mcp.secret_bulk_import_metadata import ImportMetadataField, ImportMetadataFolder, ImportMetadataTemplate
from test_secret_bulk_import_file import csv_bytes, decode, encrypted_bytes, row, workbook_bytes


def catalog():
    now = time.monotonic()
    return dep.ImportDependencyCatalog(
        scope_digest="1" * 64, source_digest="2" * 64,
        observed_at=now, expires_at=now + 50,
        coverage=frozenset({"folders", "templates", "targets", "secret_names", "association_ids"}),
        folders=(dep.ImportFolder("Synthetic folder", 7, True),),
        templates=(dep.ImportTemplate("Web Account", (
            dep.ImportTemplateField("URL", "url", True),
            dep.ImportTemplateField("Username", "username", True),
            dep.ImportTemplateField("Password", "password", True),
        )),), targets=(),
        secret_names=("Existing parent", "Denied parent"),
        secrets=(dep.ImportExistingSecret(42, "Existing parent", True),
                 dep.ImportExistingSecret(43, "Denied parent", False)),
        service_types=frozenset({"http", "ssh", "sftp", "rdp", "samba", "telnet"}),
    )


def item(**changes):
    return row(**{"Service Type": "WEB", **changes})


def resolve(tmp_path, values, snapshot=None, **overrides):
    snapshot = snapshot or catalog()
    raw = csv_bytes(values)
    rows = decode(tmp_path, raw)
    buffer = rows._ProtectedBulkImportRows__raw
    file_digest = hashlib.sha256(raw).hexdigest()
    catalog_digest = dep.dependency_catalog_digest(snapshot)
    args = dict(expected_file_digest=file_digest, expected_catalog_digest=catalog_digest,
                expected_scope_digest=snapshot.scope_digest)
    args.update(overrides)
    try:
        result = dep.resolve_import_dependencies(rows, snapshot, **args)
        return result, file_digest, catalog_digest
    finally:
        assert buffer and not any(buffer)


def inspect(result):
    value, file_digest, catalog_digest = result
    return value._inspect_private(lambda rows, targets, order: (rows, targets, order),
                                  file_digest=file_digest, catalog_digest=catalog_digest)


def test_definition_projection_keeps_only_explicitly_usable_expressible_templates():
    field = ImportMetadataField("Password", "password", True)
    supported = ImportMetadataTemplate("Supported", (field,), "create-secret")
    records = (supported, replace(supported, name="Unknown permission", permission=None),
        replace(supported, name="Denied", permission="none"), replace(supported, name="Empty", fields=()),
        replace(supported, name="Unmapped", fields=(replace(field, kind="service-address"),)),
        replace(supported, name="Duplicate kind", fields=(field, replace(field, name="Second password"))))
    projected = dep.project_importable_templates(records)
    assert len(projected) == 1 and projected[0].name == "Supported"
    assert projected[0].fields == (dep.ImportTemplateField("Password", "password", True),)
    with pytest.raises(dep.BulkImportDependencyError):
        dep.project_importable_templates((supported, replace(supported, name="SUPPORTED")))


def test_folder_projection_requires_complete_paths_and_preserves_explicit_add_permission():
    root = ImportMetadataFolder(1, "Public", 0, "public", "view")
    child = ImportMetadataFolder(2, "Child", 1, "public", "add-secret")
    unknown = ImportMetadataFolder(3, "Unknown", 2, "public", None)
    personal = ImportMetadataFolder(4, "Personal", 0, "personal", "owner")
    result = dep.project_import_folder_paths((child, root, unknown, personal, personal))
    by_id = {folder.identifier: folder for folder in result}
    assert by_id[2].path == "Public/Child" and by_id[2].can_add
    assert by_id[3].path == "Public/Child/Unknown" and not by_id[3].can_add
    assert not by_id[1].can_add and by_id[4].can_add and len(result) == 4


@pytest.mark.parametrize("fault", ["missing_parent", "cycle", "duplicate_id", "ambiguous_path", "dot", "slash"])
def test_folder_projection_never_truncates_or_picks_an_ambiguous_ancestor(fault):
    root = ImportMetadataFolder(1, "Public", 0, "public", "owner")
    child = ImportMetadataFolder(2, "Child", 1, "public", "owner")
    records = (root, child)
    if fault == "missing_parent": records = (child,)
    elif fault == "cycle": records = (replace(root, parent_identifier=2), child)
    elif fault == "duplicate_id": records = (root, child, replace(child, permission="none"))
    elif fault == "ambiguous_path": records = (root, child, replace(child, identifier=3, name="CHILD"))
    elif fault == "dot": records = (root, replace(child, name=".."))
    else: records = (root, replace(child, name="one/two"))
    with pytest.raises(dep.BulkImportDependencyError, match="^Protected bulk-import dependencies unavailable\\.$"):
        dep.project_import_folder_paths(records)


def test_complete_batch_has_shared_target_and_stable_dependency_order(tmp_path, capfd):
    result = resolve(tmp_path, [item(Name="Child", **{"Association-Secret": "Parent"}), item(Name="Parent")])
    rows, targets, order = inspect(result)
    assert order == (1, 0) and len(targets) == 1 and targets[0].effect == "create"
    assert targets[0].existing_name is None and targets[0].baseline_digest is None
    assert rows[0].association_row == 1 and rows[1].association_row is None
    assert rows[0].target_group == rows[1].target_group == 0
    assert rows[0].services == (("http", 443),)
    assert all(value.folder_id == 7 for value in rows)
    assert "synthetic-user" not in repr(result)
    assert "synthetic-only" not in repr(result)
    for value in (result[0], rows[0], targets[0]):
        for action in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(RuntimeError):
                action(value)
    assert capfd.readouterr() == ("", "")


@pytest.mark.parametrize("association", ["(ID:42)", "(ID: 42)", "Existing parent (ID: 42)"])
def test_existing_association_requires_exact_id_and_matching_label(tmp_path, association):
    rows, _, _ = inspect(resolve(tmp_path, [item(**{"Association-Secret": association})]))
    assert rows[0].association_id == 42 and rows[0].association_row is None


@pytest.mark.parametrize("name", ["Hidden existing name", "HIDDEN EXISTING NAME"])
def test_global_name_without_visible_id_still_denies_whole_batch_collision(tmp_path, name):
    snapshot = catalog()
    snapshot = replace(snapshot, secret_names=(*snapshot.secret_names, "Hidden existing name"))
    with pytest.raises(dep.BulkImportDependencyError):
        resolve(tmp_path, [item(Name="First"), item(Name=name)], snapshot)


def test_complete_name_namespace_does_not_supply_association_ids(tmp_path):
    snapshot = catalog()
    original_digest = dep.dependency_catalog_digest(snapshot)
    snapshot = replace(snapshot, secret_names=(*snapshot.secret_names, "Hidden existing name"))
    assert dep.dependency_catalog_digest(snapshot) != original_digest
    assert inspect(resolve(tmp_path, [item(**{"Association-Secret": "(ID:42)"})], snapshot))[0][0].association_id == 42
    for association in ("Hidden existing name", "Hidden existing name (ID:99)", "(ID:99)"):
        with pytest.raises(dep.BulkImportDependencyError):
            resolve(tmp_path, [item(**{"Association-Secret": association})], snapshot)


@pytest.mark.parametrize("names", [(), ["Existing parent", "Denied parent"],
    ("Different", "Denied parent"), ("Existing parent", "Denied parent", 7),
    ("Existing parent", "Denied parent", "bad\nname"),
    ("Existing parent", "Denied parent", "x" * 256),
    ("Existing parent", "Denied parent", *("extra" for _ in range(4095))),
])
def test_collision_namespace_is_typed_bounded_and_covers_visible_id_names(names):
    with pytest.raises(dep.BulkImportDependencyError):
        dep.dependency_catalog_digest(replace(catalog(), secret_names=names))


def test_namespace_multiplicity_covers_each_visible_record_without_inventing_ids(tmp_path):
    snapshot = replace(catalog(), secrets=(dep.ImportExistingSecret(42, "Existing parent", True),
        dep.ImportExistingSecret(43, "Existing parent", False)))
    with pytest.raises(dep.BulkImportDependencyError):
        dep.dependency_catalog_digest(snapshot)
    snapshot = replace(snapshot, secret_names=("Existing parent", "Existing parent"))
    rows, _, _ = inspect(resolve(tmp_path, [item(**{"Association-Secret": "(ID:42)"})], snapshot))
    assert rows[0].association_id == 42
    with pytest.raises(dep.BulkImportDependencyError):
        resolve(tmp_path, [item(**{"Association-Secret": "(ID:43)"})], snapshot)


@pytest.mark.parametrize("association", ["Unknown", "Wrong label (ID:42)", "(ID:43)",
    "(ID:99)", "(ID:0)", "(ID:2147483648)", "prefix (ID:42) suffix"])
def test_unknown_denied_or_misleading_associations_reject_whole_batch(tmp_path, association):
    with pytest.raises(dep.BulkImportDependencyError, match="^Protected bulk-import dependencies unavailable\\.$"):
        resolve(tmp_path, [item(Name="First"), item(Name="Second", **{"Association-Secret": association})])


@pytest.mark.parametrize("values", [
    [item(Name="Self", **{"Association-Secret": "Self"})],
    [item(Name="A", **{"Association-Secret": "B"}), item(Name="B", **{"Association-Secret": "A"})],
    [item(Name="(ID:42)"), item(Name="Child", **{"Association-Secret": "(ID:42)"})],
])
def test_cycles_and_cross_namespace_association_ambiguity_are_denied(tmp_path, values):
    with pytest.raises(dep.BulkImportDependencyError):
        resolve(tmp_path, values)


@pytest.mark.parametrize("changes", [
    {"Secret Template": "Missing"}, {"Folder": "Missing"}, {"Folder": "Synthetic folder/../other"},
    {"Username": ""}, {"Password/Passphrase": ""}, {"URL": ""}, {"Private-Key": "synthetic-unused"},
    {"Name": "existing PARENT"}, {"Service Type": "SSH;SFTP", "Port": "22;65536"},
    {"Service Type": "", "Port": "443"}, {"Service Type": "WEB;http"},
    {"Service Type": "UNKNOWN"}, {"Service Type": "WEB", "Port": "443;22"},
    {"Service Type": "samba", "Port": "445"}, {"Service Type": "ssh", "Port": "22.0"},
])
def test_later_invalid_row_never_produces_partial_dependencies(tmp_path, changes):
    with pytest.raises(dep.BulkImportDependencyError):
        resolve(tmp_path, [item(Name="First"), item(**{"Name": "Second", **changes})])


def test_folder_permission_and_path_canonicalization(tmp_path):
    result = resolve(tmp_path, [item(Folder="/Synthetic folder/")])
    assert inspect(result)[0][0].folder_id == 7
    snapshot = replace(catalog(), folders=(dep.ImportFolder("Synthetic folder", 7, False),))
    with pytest.raises(dep.BulkImportDependencyError):
        resolve(tmp_path, [item()], snapshot)


def test_target_reuse_preserves_unspecified_fields_and_update_is_explicit(tmp_path):
    target = dep.ImportTarget("Existing target", "Web Account", "192.0.2.1", "", "https://example.invalid", "3" * 64)
    snapshot = replace(catalog(), targets=(target,))
    _, targets, _ = inspect(resolve(tmp_path, [item()], snapshot))
    assert targets[0].effect == "reuse" and targets[0].address == "192.0.2.1"
    snapshot = replace(snapshot, targets=(replace(target, address=""),))
    _, targets, _ = inspect(resolve(tmp_path, [item(**{"Target-Address": "192.0.2.1"})], snapshot))
    assert targets[0].effect == "update" and targets[0].baseline_digest == "3" * 64
    assert targets[0].existing_name == "Existing target"


@pytest.mark.parametrize("fault", ["ambiguous", "conflict", "batch_conflict"])
def test_target_join_never_picks_a_winner_or_silently_changes_shared_target(tmp_path, fault):
    target = dep.ImportTarget("Target A", "Web Account", "192.0.2.1", "", "https://example.invalid", "3" * 64)
    snapshot = replace(catalog(), targets=(target,))
    values = [item(**{"Target-Address": "192.0.2.1"})]
    if fault == "ambiguous":
        snapshot = replace(snapshot, targets=(target, replace(target, name="Target B")))
    elif fault == "conflict":
        values = [item(**{"Target-Address": "192.0.2.2"})]
    else:
        snapshot = replace(snapshot, targets=())
        values += [item(Name="Second", **{"Target-Address": "192.0.2.2"})]
    with pytest.raises(dep.BulkImportDependencyError):
        resolve(tmp_path, values, snapshot)


@pytest.mark.parametrize("field", ["expected_file_digest", "expected_catalog_digest", "expected_scope_digest"])
def test_exact_file_catalog_and_scope_binding_cannot_be_substituted(tmp_path, field):
    with pytest.raises(dep.BulkImportDependencyError):
        resolve(tmp_path, [item()], **{field: "f" * 64})


@pytest.mark.parametrize("fault", ["expired", "future", "nan", "partial", "duplicate_folder",
                                  "duplicate_template", "unknown_field", "version"])
def test_catalog_validation_does_not_upgrade_unqualified_data(fault):
    snapshot = catalog()
    if fault == "expired":
        snapshot = replace(snapshot, expires_at=time.monotonic() - 1)
    elif fault == "future":
        snapshot = replace(snapshot, observed_at=time.monotonic() + 1)
    elif fault == "nan":
        snapshot = replace(snapshot, observed_at=float("nan"))
    elif fault == "partial":
        snapshot = replace(snapshot, coverage=snapshot.coverage - {"targets"})
    elif fault == "duplicate_folder":
        snapshot = replace(snapshot, folders=(*snapshot.folders, dep.ImportFolder("/Synthetic folder/", 8, True)))
    elif fault == "duplicate_template":
        snapshot = replace(snapshot, templates=snapshot.templates * 2)
    elif fault == "unknown_field":
        snapshot = replace(snapshot, templates=(dep.ImportTemplate("Unknown", (dep.ImportTemplateField("Other", "opaque", True),)),))
    else:
        snapshot = replace(snapshot, product_version="v1.9.1")
    with pytest.raises(dep.BulkImportDependencyError):
        dep.dependency_catalog_digest(snapshot)


def test_stale_catalog_during_resolution_clears_all_material(tmp_path, monkeypatch):
    snapshot = catalog()
    original = dep._services

    def expired(*args):
        result = original(*args)
        monkeypatch.setattr(time, "monotonic", lambda: snapshot.expires_at + 1)
        return result

    monkeypatch.setattr(dep, "_services", expired)
    with pytest.raises(dep.BulkImportDependencyError):
        resolve(tmp_path, [item()], snapshot)


def test_failed_concurrent_resolution_does_not_clear_active_consumer(tmp_path):
    raw = csv_bytes([item()])
    rows = decode(tmp_path, raw)
    entered, release = threading.Event(), threading.Event()
    results = []

    def consume(values):
        entered.set()
        assert release.wait(2)
        results.append(bool(values[0][6]))

    thread = threading.Thread(target=rows._consume_once, args=(consume,))
    thread.start()
    try:
        assert entered.wait(2)
        snapshot = catalog()
        with pytest.raises(dep.BulkImportDependencyError):
            dep.resolve_import_dependencies(rows, snapshot, expected_file_digest=hashlib.sha256(raw).hexdigest(),
                expected_catalog_digest=dep.dependency_catalog_digest(snapshot), expected_scope_digest=snapshot.scope_digest)
    finally:
        release.set()
        thread.join(2)
    assert not thread.is_alive() and results == [True]


def test_resolved_metadata_cannot_be_used_after_expiry_or_with_other_binding(tmp_path, monkeypatch):
    result, file_digest, catalog_digest = resolve(tmp_path, [item()])
    with pytest.raises(dep.BulkImportDependencyError):
        result._inspect_private(lambda *_: pytest.fail("Wrong binding"), file_digest="f" * 64,
                                catalog_digest=catalog_digest)
    monkeypatch.setattr(time, "monotonic", lambda: float("inf"))
    with pytest.raises(dep.BulkImportDependencyError):
        result._inspect_private(lambda *_: pytest.fail("Expired"), file_digest=file_digest,
                                catalog_digest=catalog_digest)


def test_invalid_catalog_still_consumes_and_clears_the_owned_rows(tmp_path):
    raw = csv_bytes([item()])
    rows = decode(tmp_path, raw)
    owned = rows._ProtectedBulkImportRows__raw
    snapshot = catalog()
    digest = dep.dependency_catalog_digest(snapshot)
    with pytest.raises(dep.BulkImportDependencyError):
        dep.resolve_import_dependencies(rows, replace(snapshot, coverage=frozenset()),
            expected_file_digest=hashlib.sha256(raw).hexdigest(), expected_catalog_digest=digest,
            expected_scope_digest=snapshot.scope_digest)
    assert not any(owned)


def test_encrypted_xlsm_to_dependency_graph_preserves_binding_and_clears_material(tmp_path):
    raw = encrypted_bytes(workbook_bytes([
        item(Name="Child", **{"Association-Secret": "Parent"}), item(Name="Parent"),
    ]))
    password = bytearray(b"synthetic-password")
    rows = decode(tmp_path, raw, "xlsm", password)
    owned = rows._ProtectedBulkImportRows__raw
    snapshot = catalog()
    file_digest = hashlib.sha256(raw).hexdigest()
    catalog_digest = dep.dependency_catalog_digest(snapshot)
    result = dep.resolve_import_dependencies(rows, snapshot, expected_file_digest=file_digest,
        expected_catalog_digest=catalog_digest, expected_scope_digest=snapshot.scope_digest)
    assert result._inspect_private(lambda rows, targets, order: (len(rows), len(targets), order),
        file_digest=file_digest, catalog_digest=catalog_digest) == (2, 1, (1, 0))
    assert not any(password) and not any(owned)
