from dataclasses import replace
import os
import shutil
import ssl
import stat

import pytest

from fortipam_mcp import web_secret_fixture_creation_reader as reader
from fortipam_mcp import web_secret_fixture_creation_record as record
from test_instruction_feature_http_reader import Client, Response
from test_web_secret_create_dispatch_observation import _transport, _Connection
from test_web_secret_fixture_creation import _setup, _response


def _fixture(tmp_path, monkeypatch):
    inputs, connection = _setup(tmp_path, monkeypatch)
    directory = tmp_path / "record"
    directory.mkdir(mode=0o700)
    key_file = tmp_path / "record.key"
    key_file.write_bytes(b"unit-web-creation-record-key-0001")
    key_file.chmod(0o600)
    client = Client([Response(_response(inputs["create_binding"]))])
    monkeypatch.setattr(reader, "_ssl_context", lambda _: ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))
    actual_read = reader.read_web_secret_fixture_creation
    monkeypatch.setattr(record, "read_web_secret_fixture_creation",
                        lambda *args, **kwargs: actual_read(*args, **kwargs, client_factory=lambda **_kw: client))
    kwargs = {**inputs, "directory": directory, "key_file": key_file}
    config = inputs["transport"]._config
    controller = record.WebSecretFixtureCreationRecord(config, **kwargs)
    return controller, kwargs, config, client, connection


def test_fixed_reader_record_can_reload_after_restart_without_importing_http_ack(tmp_path, monkeypatch):
    controller, kwargs, config, client, connection = _fixture(tmp_path, monkeypatch)
    before = kwargs["execution_store"]._path.read_bytes()
    evidence = controller.record_creation()
    path = kwargs["directory"] / "creation.record"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert not (kwargs["directory"] / "creation.pending").exists()
    assert b"UNIT_PROTECTED_PASSWORD" not in path.read_bytes() and b"UNIT_PROTECTED_TOTP" not in path.read_bytes()
    fresh_connection = _Connection()
    fresh_transport = _transport(monkeypatch, fresh_connection)
    restarted = record.WebSecretFixtureCreationRecord(config, **{**kwargs, "transport": fresh_transport})
    assert restarted.read_creation() == evidence
    assert fresh_transport.read_web_create_dispatch_observation(
        kwargs["create_binding"], kwargs["execution_binding"].lease_request) is None
    assert len(client.calls) == 1 and fresh_connection.posts == 0 and connection.posts == 1
    assert kwargs["execution_store"]._path.read_bytes() == before
    assert repr(controller) == str(controller) == "<WebSecretFixtureCreationRecord redacted>"


def test_existing_record_is_never_overwritten_or_native_reader_repeated(tmp_path, monkeypatch):
    controller, kwargs, _, client, connection = _fixture(tmp_path, monkeypatch)
    controller.record_creation()
    original = (kwargs["directory"] / "creation.record").read_bytes()
    with pytest.raises(record.WebSecretFixtureCreationRecordError):
        controller.record_creation()
    assert (kwargs["directory"] / "creation.record").read_bytes() == original
    assert len(client.calls) == 1 and connection.posts == 1


def test_modified_payload_refuses_before_decoding_any_json(tmp_path, monkeypatch):
    controller, kwargs, _, _, _ = _fixture(tmp_path, monkeypatch)
    controller.record_creation()
    path = kwargs["directory"] / "creation.record"
    path.write_bytes(path.read_bytes() + b'"UNIT_PROTECTED_PASSWORD"')
    monkeypatch.setattr(record.json, "loads", lambda *_args, **_kw: pytest.fail("Seal must verify before decode."))
    with pytest.raises(record.WebSecretFixtureCreationRecordError):
        controller.read_creation()


@pytest.mark.parametrize("defect", ["key", "directory", "scope"])
def test_copied_or_wrong_startup_context_cannot_adopt_a_record(tmp_path, monkeypatch, defect):
    controller, kwargs, config, _, _ = _fixture(tmp_path, monkeypatch)
    controller.record_creation()
    if defect == "key":
        kwargs["key_file"].write_bytes(b"other-unit-web-record-key-0000001")
    elif defect == "directory":
        destination = tmp_path / "other"
        destination.mkdir(mode=0o700)
        shutil.copyfile(kwargs["directory"] / "creation.record", destination / "creation.record")
        (destination / "creation.record").chmod(0o600)
        kwargs["directory"] = destination
    else:
        execution = kwargs["execution_binding"]
        request = replace(execution.lease_request, scope_digest="e" * 64)
        kwargs["execution_binding"] = replace(execution, lease_request=request, scope_digest=request.scope_digest)
    other = record.WebSecretFixtureCreationRecord(config, **kwargs)
    with pytest.raises(record.WebSecretFixtureCreationRecordError):
        other.read_creation()


def test_missing_original_m4_cannot_be_recreated_by_record_reload(tmp_path, monkeypatch):
    controller, kwargs, _, client, connection = _fixture(tmp_path, monkeypatch)
    controller.record_creation()
    path = kwargs["execution_store"]._path
    path.unlink()
    with pytest.raises(record.WebSecretFixtureCreationRecordError):
        controller.read_creation()
    assert not path.exists() and len(client.calls) == 1 and connection.posts == 1


@pytest.mark.parametrize("defect", ["mode", "symlink", "hardlink", "partial"])
def test_unsafe_or_incomplete_record_is_not_read_or_replaced(tmp_path, monkeypatch, defect):
    controller, kwargs, _, client, connection = _fixture(tmp_path, monkeypatch)
    path = kwargs["directory"] / "creation.record"
    if defect == "partial":
        path.write_bytes(b"incomplete-record")
        path.chmod(0o600)
    else:
        controller.record_creation()
        if defect == "mode": path.chmod(0o644)
        elif defect == "symlink":
            path.rename(kwargs["directory"] / "original.record")
            path.symlink_to("original.record")
        else: os.link(path, kwargs["directory"] / "alias.record")
    before = len(client.calls)
    with pytest.raises(record.WebSecretFixtureCreationRecordError): controller.read_creation()
    with pytest.raises(record.WebSecretFixtureCreationRecordError): controller.record_creation()
    assert len(client.calls) == before and connection.posts == 1


def test_replaced_directory_refuses_without_source_io(tmp_path, monkeypatch):
    controller, kwargs, _, client, _ = _fixture(tmp_path, monkeypatch)
    kwargs["directory"].rename(tmp_path / "retained-original")
    kwargs["directory"].mkdir(mode=0o700)
    with pytest.raises(record.WebSecretFixtureCreationRecordError): controller.record_creation()
    assert not client.calls


def test_no_original_observation_cannot_write_any_record(tmp_path, monkeypatch):
    controller, kwargs, config, client, _ = _fixture(tmp_path, monkeypatch)
    transport = _transport(monkeypatch, _Connection())
    controller = record.WebSecretFixtureCreationRecord(config, **{**kwargs, "transport": transport})
    with pytest.raises(record.WebSecretFixtureCreationRecordError): controller.record_creation()
    assert not client.calls and not (kwargs["directory"] / "creation.record").exists()


@pytest.mark.parametrize("failed_sync", [1, 2, 3, 4])
def test_failed_sync_keeps_pending_and_restart_cannot_adopt_or_repeat(tmp_path, monkeypatch, failed_sync):
    controller, kwargs, config, client, connection = _fixture(tmp_path, monkeypatch)
    actual_sync = os.fsync
    calls = 0

    def fail_sync(descriptor):
        nonlocal calls
        calls += 1
        if calls == failed_sync:
            raise OSError("Synthetic storage failure")
        actual_sync(descriptor)

    with monkeypatch.context() as patch:
        patch.setattr(record.os, "fsync", fail_sync)
        with pytest.raises(record.WebSecretFixtureCreationRecordError):
            controller.record_creation()
    pending = kwargs["directory"] / "creation.pending"
    assert pending.exists() and stat.S_IMODE(pending.stat().st_mode) == 0o600
    restarted = record.WebSecretFixtureCreationRecord(config, **kwargs)
    before = len(client.calls)
    with pytest.raises(record.WebSecretFixtureCreationRecordError): restarted.read_creation()
    with pytest.raises(record.WebSecretFixtureCreationRecordError): restarted.record_creation()
    assert len(client.calls) == before and connection.posts == 1


@pytest.mark.parametrize("defect", ["source", "validation", "commit", "interruption"])
def test_precommit_failure_keeps_pending_for_explicit_reconciliation(tmp_path, monkeypatch, defect):
    controller, kwargs, config, client, connection = _fixture(tmp_path, monkeypatch)
    with monkeypatch.context() as patch:
        def refuse(*_args, **_kwargs):
            raise OSError("Synthetic precommit failure")

        if defect == "source": patch.setattr(record, "read_web_secret_fixture_creation", refuse)
        elif defect == "validation": patch.setattr(controller, "_read_creation", refuse)
        elif defect == "commit": patch.setattr(record.os, "unlink", refuse)
        else:
            def interrupt(*_args):
                raise KeyboardInterrupt
            patch.setattr(record.os, "fsync", interrupt)
        exception = KeyboardInterrupt if defect == "interruption" else record.WebSecretFixtureCreationRecordError
        with pytest.raises(exception): controller.record_creation()
    assert (kwargs["directory"] / "creation.pending").exists()
    restarted = record.WebSecretFixtureCreationRecord(config, **kwargs)
    before = len(client.calls)
    with pytest.raises(record.WebSecretFixtureCreationRecordError): restarted.read_creation()
    with pytest.raises(record.WebSecretFixtureCreationRecordError): restarted.record_creation()
    assert len(client.calls) == before and connection.posts == 1


def test_same_path_directory_copy_after_restart_cannot_adopt_record(tmp_path, monkeypatch):
    controller, kwargs, config, _, _ = _fixture(tmp_path, monkeypatch)
    controller.record_creation()
    original = tmp_path / "original-directory"
    kwargs["directory"].rename(original)
    kwargs["directory"].mkdir(mode=0o700)
    path = kwargs["directory"] / "creation.record"
    shutil.copyfile(original / "creation.record", path)
    path.chmod(0o600)
    restarted = record.WebSecretFixtureCreationRecord(config, **kwargs)
    with pytest.raises(record.WebSecretFixtureCreationRecordError): restarted.read_creation()


def test_public_read_rechecks_pending_after_validation(tmp_path, monkeypatch):
    controller, kwargs, _, _, _ = _fixture(tmp_path, monkeypatch)
    controller.record_creation()
    actual_qualify = record._qualify_web_creation_execution

    def add_pending(**values):
        result = actual_qualify(**values)
        pending = kwargs["directory"] / "creation.pending"
        pending.write_bytes(b"")
        pending.chmod(0o600)
        return result

    monkeypatch.setattr(record, "_qualify_web_creation_execution", add_pending)
    with pytest.raises(record.WebSecretFixtureCreationRecordError): controller.read_creation()


def test_commit_has_no_later_sync_or_reload_and_close_error_does_not_report_failed_write(tmp_path, monkeypatch):
    controller, kwargs, config, _, _ = _fixture(tmp_path, monkeypatch)
    actual_unlink, actual_sync, actual_close = os.unlink, os.fsync, os.close
    committed_fd = None
    close_failure_injected = False

    def unlink_pending(path, *, dir_fd):
        nonlocal committed_fd
        assert path == "creation.pending"
        actual_unlink(path, dir_fd=dir_fd)
        committed_fd = dir_fd

    def sync_before_commit(descriptor):
        assert committed_fd is None
        actual_sync(descriptor)

    def close(descriptor):
        nonlocal close_failure_injected
        actual_close(descriptor)
        if descriptor == committed_fd:
            close_failure_injected = True
            raise OSError("Synthetic postcommit close failure")

    with monkeypatch.context() as patch:
        patch.setattr(record.os, "unlink", unlink_pending)
        patch.setattr(record.os, "fsync", sync_before_commit)
        patch.setattr(record.os, "close", close)
        evidence = controller.record_creation()
    assert close_failure_injected
    restarted = record.WebSecretFixtureCreationRecord(config, **kwargs)
    assert restarted.read_creation() == evidence
