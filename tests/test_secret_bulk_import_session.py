"""Synthetic source lifetime and real decoder cancellation; no device import."""

import asyncio
import copy
from dataclasses import replace
import pickle
import subprocess
import sys
import threading
import time

import pytest

from fortipam_mcp import secret_bulk_import_file as file_boundary
from fortipam_mcp import secret_bulk_import_session as boundary
from test_secret_bulk_import_dependencies import catalog
from test_secret_bulk_import_intake import Authority, prepared


class SessionAuthority(Authority):
    def verify_source_session(self, binding, *, now_epoch):
        return self.verify(binding, now_epoch=now_epoch)

    def source_session_expires_at(self, binding, *, now_epoch):
        return getattr(self, "until", binding.expires_at)


def admitted(tmp_path, kind="encrypted"):
    binding, options, clocks = prepared(tmp_path, kind)
    options["session_authority"] = SessionAuthority(binding)
    password = bytearray(b"synthetic-password") if kind == "encrypted" else None
    session = asyncio.run(boundary.admit_prebound_owner_file_session(
        binding, workbook_password=password, **options,
    ))
    assert password is None or not any(password)
    return session, binding, options, clocks


@pytest.mark.parametrize("kind", ["csv", "xlsm", "encrypted"])
def test_session_projects_original_parser_once_retains_only_owned_unlock_and_closes(tmp_path, kind, capfd):
    session, binding, _, _ = admitted(tmp_path, kind)
    retained = session._password
    original = binding.path.read_bytes()
    try:
        for value in (session,):
            assert "synthetic" not in repr(value)
            for serialize in (copy.copy, copy.deepcopy, pickle.dumps):
                with pytest.raises(RuntimeError):
                    serialize(value)
        assert bool(any(retained)) == (kind == "encrypted")
        result = session.project_dependencies_once(catalog())
        assert repr(result) == "<ResolvedImportDependencies redacted>"
        assert bool(any(retained)) == (kind == "encrypted")
        with pytest.raises(boundary.BulkImportIntakeError):
            session.project_dependencies_once(catalog())
    finally:
        session.close()
    assert not any(retained) and not session._watchdog.is_alive()
    assert binding.path.read_bytes() == original
    assert capfd.readouterr() == ("", "")


@pytest.mark.parametrize("fault", ["wall-expiry", "mono-expiry", "wall-rollback", "mono-rollback", "bad-clock"])
def test_idle_watchdog_clears_without_a_followup_call(tmp_path, fault):
    session, _, _, clocks = admitted(tmp_path)
    retained = session._password
    try:
        if fault == "wall-expiry":
            clocks[0] = 1100
        elif fault == "mono-expiry":
            clocks[1] = 200
        elif fault == "wall-rollback":
            clocks[0] = 999
        elif fault == "mono-rollback":
            clocks[1] = 99
        else:
            clocks[0] = float("nan")
        session._watchdog.join(1)
        assert not session._watchdog.is_alive()
        assert session._transaction._closed.is_set() and not any(retained)
    finally:
        session.close()


def test_real_deadline_disposes_even_if_injected_clocks_are_frozen(tmp_path):
    binding, options, clocks = prepared(tmp_path, "encrypted")
    options["session_authority"] = SessionAuthority(binding)
    clocks[:] = [1099.8, 100]
    password = bytearray(b"synthetic-password")
    session = asyncio.run(boundary.admit_prebound_owner_file_session(binding, workbook_password=password, **options))
    try:
        session._watchdog.join(1)
        assert not session._watchdog.is_alive() and not any(session._password)
        clocks[:] = [1000, 100]
        with pytest.raises(boundary.BulkImportIntakeError):
            session.project_dependencies_once(catalog())
    finally:
        session.close()


def test_activity_or_later_decision_cannot_renew_original_session(tmp_path):
    binding, options, clocks = prepared(tmp_path, "encrypted")
    permission = SessionAuthority(binding)
    permission.until = 1030
    password = bytearray(b"synthetic-password")
    session = asyncio.run(boundary.admit_prebound_owner_file_session(
        binding, workbook_password=password, session_authority=permission, **options))
    try:
        original_deadline = session._deadline
        assert session._transaction._expires == 1030
        permission.until = 1120
        clocks[:] = [1020, 120]
        assert session.project_dependencies_once(catalog())
        assert session._deadline == original_deadline and session._transaction._expires == 1030
        clocks[:] = [1030, 130]
        session._watchdog.join(1)
        assert not session._watchdog.is_alive() and not any(session._password)
    finally:
        session.close()


@pytest.mark.parametrize("expires", [True, 1000, 1121])
def test_invalid_source_decision_horizon_denies_before_pinning(tmp_path, monkeypatch, expires):
    from fortipam_mcp import secret_bulk_import_intake as intake
    binding, options, _ = prepared(tmp_path, "encrypted")
    permission = SessionAuthority(binding)
    permission.until = expires
    password = bytearray(b"synthetic-password")
    monkeypatch.setattr(intake, "PinnedBulkImportFile", lambda *args, **kwargs: pytest.fail("Invalid session horizon read source"))
    with pytest.raises(boundary.BulkImportIntakeError):
        asyncio.run(boundary.admit_prebound_owner_file_session(
            binding, workbook_password=password, session_authority=permission, **options))
    assert not any(password)


@pytest.mark.parametrize("exit_kind", ["close", "context", "exception", "transaction-cancel"])
def test_owner_disposal_is_idempotent_and_keeps_source(tmp_path, exit_kind):
    session, binding, _, _ = admitted(tmp_path)
    original = binding.path.read_bytes()
    retained = session._password
    if exit_kind == "close":
        session.close()
    elif exit_kind == "context":
        with session:
            pass
    elif exit_kind == "exception":
        with pytest.raises(ValueError), session:
            raise ValueError("Synthetic failure")
    else:
        session._transaction.close()
        session._watchdog.join(1)
    session.close()
    assert not any(retained) and not session._watchdog.is_alive()
    assert binding.path.read_bytes() == original


@pytest.mark.parametrize("fault", ["authority", "session-authority", "missing-session", "projection-only", "expired", "csv-unlock", "oversized", "immutable", "cancelled-auth", "thread-start"])
def test_failed_admission_never_retains_unlock_and_denied_auth_never_reads(tmp_path, monkeypatch, fault):
    binding, options, clocks = prepared(tmp_path, "csv" if fault == "csv-unlock" else "encrypted")
    options["session_authority"] = SessionAuthority(binding)
    password = bytearray(b"synthetic-password")
    if fault == "authority":
        options["authority"].denied = True
    elif fault == "session-authority":
        options["session_authority"].denied = True
    elif fault == "missing-session":
        options.pop("session_authority")
    elif fault == "projection-only":
        options["session_authority"] = options["authority"]
    elif fault == "expired":
        clocks[0] = 1100
    elif fault == "oversized":
        password = bytearray(1025)
    elif fault == "immutable":
        password = b"synthetic-password"
    elif fault == "cancelled-auth":
        async def cancelled(token):
            raise asyncio.CancelledError
        options["planning_verifier"].verify_token = cancelled
    elif fault == "thread-start":
        def failed_start(thread):
            raise RuntimeError("Synthetic thread failure")
        monkeypatch.setattr(threading.Thread, "start", failed_start)
    reads = []
    original = file_boundary._read_owned
    def capture(*args, **kwargs):
        reads.append(True)
        return original(*args, **kwargs)
    monkeypatch.setattr(file_boundary, "_read_owned", capture)
    with pytest.raises(boundary.BulkImportIntakeError):
        asyncio.run(boundary.admit_prebound_owner_file_session(binding, workbook_password=password, **options))
    if type(password) is bytearray:
        assert not any(password)
    if fault != "thread-start":
        assert reads == []


@pytest.mark.parametrize("fault", ["revoked", "drift", "wrong-password", "catalog"])
def test_projection_failure_clears_retained_unlock_and_prevents_reuse(tmp_path, fault):
    session, binding, options, _ = admitted(tmp_path)
    retained = session._password
    if fault == "revoked":
        options["authority"].denied = True
    elif fault == "drift":
        binding.path.write_bytes(b"Synthetic source drift")
    elif fault == "wrong-password":
        session._password[:] = b"synthetic-invalid"
    snapshot = replace(catalog(), scope_digest="9" * 64) if fault == "catalog" else catalog()
    with pytest.raises(boundary.BulkImportIntakeError):
        session.project_dependencies_once(snapshot)
    assert not any(retained) and not session._watchdog.is_alive()
    with pytest.raises(boundary.BulkImportIntakeError):
        session.project_dependencies_once(catalog())


@pytest.mark.parametrize("fault", ["close", "expiry"])
def test_active_stalled_parser_is_killed_and_every_password_copy_clears(tmp_path, monkeypatch, fault):
    session, _, _, clocks = admitted(tmp_path)
    entered = threading.Event()
    children, copies, errors = [], [], []
    original_spawn, original_decode = subprocess.Popen, file_boundary.PinnedBulkImportFile.decode
    def stall(argv, **kwargs):
        child = original_spawn([sys.executable, "-I", "-c", "import time; time.sleep(60)"], **kwargs)
        children.append(child)
        entered.set()
        return child
    def capture(source, *, workbook_password=None, _lifetime=None):
        copies.append(workbook_password)
        return original_decode(source, workbook_password=workbook_password, _lifetime=_lifetime)
    monkeypatch.setattr(subprocess, "Popen", stall)
    monkeypatch.setattr(file_boundary.PinnedBulkImportFile, "decode", capture)
    def project():
        try:
            session.project_dependencies_once(catalog())
        except BaseException as error:
            errors.append(type(error))
    active = threading.Thread(target=project)
    active.start()
    try:
        assert entered.wait(2)
        if fault == "close":
            session.close()
        else:
            clocks[1] = 200
        active.join(2)
        assert not active.is_alive() and errors == [boundary.BulkImportIntakeError]
        assert children and all(child.poll() is not None for child in children)
        assert copies and all(not any(value) for value in copies)
        assert not any(session._password) and not session._watchdog.is_alive()
    finally:
        session.close()
        active.join(2)


def test_concurrent_projection_rejects_without_corrupting_active_copy(tmp_path, monkeypatch):
    session, _, _, _ = admitted(tmp_path)
    entered, release = threading.Event(), threading.Event()
    original = file_boundary.PinnedBulkImportFile.decode
    outcomes, copies = [], []
    def paused(source, *, workbook_password=None, _lifetime=None):
        copies.append(workbook_password)
        entered.set()
        assert release.wait(2)
        assert any(workbook_password) and any(session._password)
        return original(source, workbook_password=workbook_password, _lifetime=_lifetime)
    monkeypatch.setattr(file_boundary.PinnedBulkImportFile, "decode", paused)
    def project():
        try:
            outcomes.append(session.project_dependencies_once(catalog()))
        except BaseException as error:
            outcomes.append(type(error))
    active = threading.Thread(target=project)
    active.start()
    try:
        assert entered.wait(2)
        with pytest.raises(boundary.BulkImportIntakeError):
            session.project_dependencies_once(catalog())
        release.set()
        active.join(2)
        assert not active.is_alive() and len(outcomes) == 1
        assert isinstance(outcomes[0], boundary.ResolvedImportDependencies)
        assert all(not any(value) for value in copies) and any(session._password)
    finally:
        release.set()
        active.join(2)
        session.close()


def test_consumed_admission_cannot_be_wrapped_again_and_restart_requires_auth(tmp_path):
    session, binding, options, _ = admitted(tmp_path)
    try:
        with pytest.raises(boundary.BulkImportIntakeError):
            boundary._OwnerFileSourceSession(session._transaction, bytearray())
        assert any(session._password) and not session._transaction._closed.is_set()
    finally:
        session.close()
    password = bytearray(b"synthetic-password")
    options["planning_verifier"].result = None
    with pytest.raises(boundary.BulkImportIntakeError):
        asyncio.run(boundary.admit_prebound_owner_file_session(binding, workbook_password=password, **options))
    assert not any(password) and len(options["planning_verifier"].calls) == 2
