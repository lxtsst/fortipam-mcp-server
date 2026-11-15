"""Text-profile composition over explicit source fixtures, not native qualification."""

import copy
from dataclasses import replace
import hashlib
import pickle
import ssl
import time

import pytest

from fortipam_mcp import dlp_api_actor_guard as actor
from fortipam_mcp import secret_bulk_import_dependencies as dependencies
from fortipam_mcp import secret_bulk_import_metadata as metadata
from fortipam_mcp import secret_bulk_import_namespace_source as namespace_source
from fortipam_mcp import secret_bulk_import_source_catalog as source
from test_secret_bulk_import_file import csv_bytes, decode, row


_TEXT = "synthetic-protected-text,\r\n文字"
_CREDENTIAL = "synthetic-credential-marker"
_SCOPE = "a" * 64
_OTHER = "f" * 64
_ERROR = r"^Protected bulk-import Folder source unavailable\.$"


def _text_row(name, *, template_name="Text", **changes):
    values = {"Secret Template": template_name, "Name": name, "Folder": "Text folder",
        "Username": "", "Password/Passphrase": "", "URL": "", "Port": "", "Text": _TEXT}
    values.update(changes)
    return row(**values)


def _source_fixtures(tmp_path, monkeypatch, fault, *, template_name="Text", field_name="Text"):
    """Construct fixed readers, but install explicitly synthetic observations/checks."""
    ca, known_hosts = tmp_path / "ca.pem", tmp_path / "known_hosts"
    ca.write_bytes(b"Synthetic public CA snapshot")
    known_hosts.write_bytes(b"Synthetic SSH host pin")
    known_hosts.chmod(0o600)
    trust = ssl.create_default_context()
    monkeypatch.setattr(actor, "_ssl_context", lambda _: trust)
    config = source.SecretMetadataHttpTransportConfig(
        "https://synthetic.invalid:9443", "synthetic-token", 30, str(ca))
    binding = actor.DlpApiActorGuardBinding("synthetic-owner", "super_admin", "SYNTHETIC01", "b" * 64)
    ssh = namespace_source.TargetSshTransportConfig(
        "synthetic.invalid", 22, binding.expected_actor, "synthetic-password", known_hosts, 30)
    started = time.monotonic()
    clocks = {"folder": started, "namespace": started}

    def no_transport(*args, **kwargs):
        pytest.fail("Profile composition must not read a device")

    folder_reader = source.ImportTemplateFolderSourceReader(config, binding,
        connection_factory=no_transport, client_factory=no_transport, clock=lambda: clocks["folder"])
    namespace_reader = namespace_source.ImportSecretNamespaceSourceReader(
        replace(config) if fault == "source-config" else config, ssh, binding,
        connection_factory=no_transport, client_factory=no_transport, clock=lambda: clocks["namespace"])
    serial = folder_reader._guard.serial_digest
    fields = (metadata.ImportMetadataField(field_name, "text", True),)
    if fault == "text-schema":
        fields += (metadata.ImportMetadataField("Username", "username", False),)
    other_fields = fields if fault == "ambiguous-template" else (
        metadata.ImportMetadataField("Username", "username", True),)
    templates = (metadata.ImportMetadataTemplate(template_name, fields, "create-secret"),
        metadata.ImportMetadataTemplate("Other", other_fields, "create-secret"))
    folders = (metadata.ImportMetadataFolder(7, "Text folder", 0, "public",
        "view" if fault == "folder-permission" else "add-secret"),
        metadata.ImportMetadataFolder(8, "Other folder", 0, "public", "owner"))

    def collection(table, records, *, size=None):
        return metadata.NativeImportMetadataCollection(
            table, records, len(records) if size is None else size, len(records), "fixture", serial)

    folder_metadata = source.ImportTemplateFolderObservation(collection("template", templates),
        collection("folder", folders), collection("folder", ()),
        dependencies.project_importable_templates(templates),
        dependencies.project_import_folder_paths(folders), started, started)
    folder_observation = source.ImportTemplateFolderSourceObservation(
        folder_metadata, folder_reader._source, "c" * 64, serial, started, started + 30)
    api_view = collection("database", (metadata.ImportMetadataSecret(41, "Existing A", "owner"),
        metadata.ImportMetadataSecret(42, "Existing B", "view")), size=3)
    namespace = namespace_source.ImportSecretNamespaceObservation(
        ("Existing A", "Existing B", "Hidden"), api_view, started, started + 30)
    namespace_observation = namespace_source.ImportSecretNamespaceSourceObservation(
        api_view, namespace, namespace_reader._source, "c" * 64, "d" * 64,
        namespace_reader._ssh_source, serial, started, started + 30)
    mismatches = {"source-context": "source_context_digest", "source-serial": "serial_digest",
        "source-actor": "actor_evidence_digest"}
    if fault in mismatches:
        namespace_observation = replace(namespace_observation, **{mismatches[fault]: _OTHER})
    checks = {"folder": 0, "namespace": 0}
    for name, reader, observation in (("folder", folder_reader, folder_observation),
            ("namespace", namespace_reader, namespace_observation)):
        def check_current(actual, *, name=name, reader=reader, observation=observation):
            checks[name] += 1
            if (actual is not observation or reader._closed
                    or not observation.observed_at <= clocks[name] < observation.expires_at):
                raise ValueError("Synthetic source unavailable")
            reader._guard._require_config(reader._config)

        monkeypatch.setattr(reader, "check_current", check_current)
    return (folder_reader, folder_observation, namespace_reader, namespace_observation), clocks, checks


@pytest.mark.parametrize("fault", [None, "non-text", "target", "service", "batch-association",
    "existing-association", "hidden-collision", "folder-permission", "multiple-folders",
    "text-schema", "ambiguous-template", "credential", "source-config", "source-context", "source-serial", "source-actor",
    "folder-expired", "namespace-expired", "file-before", "file-after", "scope-after",
    "catalog-after", "foreign-result", "replay"])
def test_text_profile_binds_one_file_and_folder_without_material_decoding(
        tmp_path, monkeypatch, capfd, fault):
    template_name = "Synthetic Note"
    fixtures, clocks, checks = _source_fixtures(tmp_path, monkeypatch, fault,
        template_name=template_name, field_name="Contents")
    if fault in {"source-config", "source-context", "source-serial", "source-actor"}:
        with pytest.raises(source.BulkImportSourceCatalogError, match=_ERROR):
            source._TextOnlyImportSource(*fixtures)
        return
    profile = source._TextOnlyImportSource(*fixtures)
    decoded_material = []

    class MetadataBytes(bytes):
        def decode(self, *args, **kwargs):
            if _TEXT.encode() in self or _CREDENTIAL.encode() in self:
                decoded_material.append(True)
                raise AssertionError("Protected material reached metadata decoding")
            return super().decode(*args, **kwargs)

    monkeypatch.setattr(dependencies, "bytes", MetadataBytes, raising=False)
    changes = {
        "non-text": {"Secret Template": "Text"},
        "target": {"Target-Address": "host.example.invalid"},
        "service": {"Service Type": "ssh", "Port": "22"},
        "batch-association": {"Association-Secret": "First"},
        "existing-association": {"Association-Secret": "Existing A (ID: 41)"},
        "hidden-collision": {"Name": "hidden"},
        "multiple-folders": {"Folder": "Other folder"},
        "credential": {"Password/Passphrase": _CREDENTIAL},
    }
    raw = csv_bytes([_text_row("First", template_name=template_name),
        _text_row("Second", template_name=template_name, **changes.get(fault, {}))])
    file_digest = hashlib.sha256(raw).hexdigest()
    rows = decode(tmp_path, raw)
    original_buffer = rows._ProtectedBulkImportRows__raw
    rejected = set(changes) | {"folder-permission", "text-schema", "ambiguous-template", "file-before"}
    if fault in rejected:
        with pytest.raises(source.BulkImportSourceCatalogError, match=_ERROR):
            profile.resolve_once(rows, expected_file_digest=_OTHER if fault == "file-before" else file_digest,
                scope_digest=_SCOPE)
        assert profile._current is None
    else:
        result = profile.resolve_once(rows, expected_file_digest=file_digest, scope_digest=_SCOPE)
        assert result.file_digest == file_digest and result.scope_digest == _SCOPE
        assert result.catalog.targets == result.catalog.secrets == ()
        assert result.catalog.secret_names == ("Existing A", "Existing B", "Hidden")
        assert tuple(template.name for template in result.catalog.templates) == (template_name,)
        assert result.catalog.templates[0].fields[0].name == "Contents"

        def inspect(projected_rows, targets, order):
            assert len(projected_rows) == 2 and order == (0, 1) and targets == ()
            assert {item.folder_id for item in projected_rows} == {7}
            assert all(item.template == template_name and item.target_group is None
                and item.association_row is None and item.association_id is None
                and not item.services for item in projected_rows)

        result.projected._inspect_private(inspect, file_digest=file_digest,
            catalog_digest=dependencies.dependency_catalog_digest(result.catalog))
        profile.check_current(result, file_digest=file_digest, scope_digest=_SCOPE)
        assert all(count > 1 for count in checks.values())
        assert repr(result) == "<OpaqueC3Object redacted>"
        for serializer in (copy.copy, pickle.dumps):
            with pytest.raises(RuntimeError):
                serializer(result)
        actual_result, actual_file, actual_scope = result, file_digest, _SCOPE
        if fault in {"folder-expired", "namespace-expired"}:
            clocks[fault.removesuffix("-expired")] = fixtures[1].expires_at
        elif fault == "file-after":
            object.__setattr__(result, "file_digest", _OTHER)
            actual_file = _OTHER
        elif fault == "scope-after":
            object.__setattr__(result, "scope_digest", _OTHER)
            object.__setattr__(result, "catalog", replace(result.catalog, scope_digest=_OTHER))
            actual_scope = _OTHER
        elif fault == "catalog-after":
            object.__setattr__(result, "catalog", replace(result.catalog, source_digest=_OTHER))
        elif fault == "foreign-result":
            actual_result = replace(result)
        if fault == "replay":
            replay_rows = decode(tmp_path, raw)
            replay_buffer = replay_rows._ProtectedBulkImportRows__raw
            with pytest.raises(source.BulkImportSourceCatalogError, match=_ERROR):
                profile.resolve_once(replay_rows, expected_file_digest=file_digest, scope_digest=_SCOPE)
            assert replay_buffer and not any(replay_buffer)
        elif fault is not None:
            with pytest.raises(source.BulkImportSourceCatalogError, match=_ERROR):
                profile.check_current(actual_result, file_digest=actual_file, scope_digest=actual_scope)
        else:
            # Even identical metadata from the same sources cannot substitute a different file.
            changed_raw = csv_bytes([_text_row("First", template_name=template_name, Text=_TEXT + " changed"),
                _text_row("Second", template_name=template_name)])
            changed_rows = decode(tmp_path, changed_raw)
            changed_buffer = changed_rows._ProtectedBulkImportRows__raw
            changed = source._TextOnlyImportSource(*fixtures).resolve_once(changed_rows,
                expected_file_digest=hashlib.sha256(changed_raw).hexdigest(), scope_digest=_SCOPE)
            assert changed.catalog.source_digest != result.catalog.source_digest
            assert changed_buffer and not any(changed_buffer)
    assert original_buffer and not any(original_buffer)
    assert not decoded_material
    assert capfd.readouterr() == ("", "")
