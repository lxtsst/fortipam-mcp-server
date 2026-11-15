"""Synthetic allocation witnesses; never inspect freed memory."""
import builtins
import json
import tracemalloc

import pytest

from fortipam_mcp import mutable_json_buffer as buffers
from fortipam_mcp.secret_create_191_http_transport import _append_material


def _allocations(monkeypatch):
    allocations = []

    def allocate(size=0):
        storage = builtins.bytearray(size)
        allocations.append(storage)
        return storage

    monkeypatch.setattr(buffers, "bytearray", allocate, raising=False)
    return allocations


def test_growth_erases_replaced_allocations_and_transfers_exact_result(monkeypatch):
    allocations = _allocations(monkeypatch)
    with buffers._MutableJSONBuffer() as target:
        for _ in range(300):
            target.append(65)
        target.extend(b'"\\\n')
        result = target.finish()
    assert type(result) is bytearray and len(result) == 303
    assert result == b"A" * 300 + b'"\\\n'
    assert len(allocations) >= 5
    assert all(not any(old) for old in allocations if old is not result)
    result[:] = b"\0" * len(result)


@pytest.mark.parametrize("phase", ["growth", "finish"])
def test_copy_interruption_erases_both_owned_allocations(monkeypatch, phase):
    allocations = _allocations(monkeypatch)
    target = buffers._MutableJSONBuffer()
    target.extend(b"synthetic-private-value")
    original = memoryview

    class InterruptAfterCopy:
        def __init__(self, value):
            self.view = original(value)

        def __enter__(self):
            return self.view

        def __exit__(self, *args):
            self.view.release()
            raise KeyboardInterrupt

    monkeypatch.setattr(buffers, "memoryview", InterruptAfterCopy, raising=False)
    with pytest.raises(KeyboardInterrupt):
        with target:
            if phase == "growth":
                for _ in range(65):
                    target.append(66)
            else:
                target.finish()
    assert all(not any(storage) for storage in allocations)


@pytest.mark.parametrize("phase", ["growth", "finish"])
def test_allocation_failure_context_erases_existing_material(monkeypatch, phase):
    allocations = _allocations(monkeypatch)
    with pytest.raises(MemoryError):
        with buffers._MutableJSONBuffer() as target:
            target.extend(b"synthetic-private-value")

            def unavailable(size=0):
                raise MemoryError

            monkeypatch.setattr(buffers, "bytearray", unavailable)
            if phase == "growth":
                target.extend(b"X" * 100)
            else:
                target.finish()
    assert all(not any(storage) for storage in allocations)


def test_context_interruption_erases_material_without_finish(monkeypatch):
    allocations = _allocations(monkeypatch)
    with pytest.raises(KeyboardInterrupt):
        with buffers._MutableJSONBuffer() as target:
            target.extend(b"synthetic-private-value")
            raise KeyboardInterrupt
    assert all(not any(storage) for storage in allocations)


def test_material_escaping_and_closed_buffer_rejection(monkeypatch):
    allocations = _allocations(monkeypatch)
    material = bytearray(bytes(range(128)) + "合成".encode())
    with memoryview(material) as view, buffers._MutableJSONBuffer() as target:
        _append_material(target, view)
        result = target.finish()
    assert json.loads(result) == material.decode()
    assert b'\\u0000' in result and b'\\u000a' in result and b'\\"' in result
    assert all(not any(old) for old in allocations if old is not result)
    for operation in (lambda: target.append(65), lambda: target.extend(b"X"), target.finish):
        with pytest.raises(ValueError):
            operation()
    result[:] = b"\0" * len(result)
    material[:] = b"\0" * len(material)


def test_material_encoder_refuses_unsafe_bare_bytearray():
    unsafe = bytearray()
    with memoryview(b"synthetic") as view, pytest.raises(ValueError):
        _append_material(unsafe, view)
    assert unsafe == b""


@pytest.mark.parametrize("phase", ["growth", "finish"])
@pytest.mark.parametrize("failure", [MemoryError, KeyboardInterrupt, SystemExit])
def test_repeated_view_and_wipe_failures_erase_storage_without_an_outer_context(monkeypatch, phase, failure):
    allocations = _allocations(monkeypatch)
    target = buffers._MutableJSONBuffer()
    target.extend(b"synthetic-private-value")
    def unavailable(*args): raise failure()
    monkeypatch.setattr(buffers, "memoryview", unavailable, raising=False)
    with pytest.raises(failure):
        if phase == "growth":
            for _ in range(65): target.append(65)
        else: target.finish()
    assert target._closed is True
    assert all(not any(storage) for storage in allocations)


@pytest.mark.parametrize("codec", ["secret", "ldap-create", "ldap-info", "winrm"])
@pytest.mark.parametrize("failure", [ValueError, KeyboardInterrupt])
def test_unreturned_private_bodies_are_erased(monkeypatch, codec, failure):
    from fortipam_mcp import ldap_server_http_transport as ldap
    from fortipam_mcp import secret_create_191_http_transport as secret
    from fortipam_mcp import winrm_collector_credential_repair as winrm
    from test_ldap_server_http_transport import binding as ldap_binding
    from test_secret_create_191_http_transport import _binding as secret_binding
    from test_winrm_collector_credential_repair import _binding as winrm_binding

    allocations = _allocations(monkeypatch)
    material = bytearray(b"synthetic-private-value")
    module = secret if codec == "secret" else winrm if codec == "winrm" else ldap
    original = module._append_material

    def interrupted(target, value):
        original(target, value)
        if value.obj is material:
            raise failure()

    monkeypatch.setattr(module, "_append_material", interrupted)
    try:
        with memoryview(material).toreadonly() as view, pytest.raises(failure):
            if codec == "secret":
                secret._secret_create_body(secret_binding(), 17,
                    "11111111-2222-4333-8444-555555555555", view, view)
            elif codec == "winrm":
                winrm._repair_body(winrm_binding(), view, view)
            else:
                function = ldap._create_body if codec == "ldap-create" else ldap._info_body
                function(ldap_binding(), view, view)
        assert allocations and all(not any(storage) for storage in allocations)
        assert material == b"synthetic-private-value"
    finally:
        material[:] = b"\0" * len(material)


@pytest.mark.parametrize("phase", ["extend", "growth", "finish"])
def test_copy_does_not_allocate_an_unowned_material_sized_temporary(phase):
    # bytearray[:] = memoryview creates an internal temporary in CPython.
    # A destination memoryview avoids that material-sized, unowned allocation.
    size = 262144
    material = bytearray(b"A" * size)
    result = bytearray()
    try:
        with buffers._MutableJSONBuffer() as target:
            if phase == "extend":
                target._reserve(size)
            else:
                target.extend(material)
            tracemalloc.start()
            try:
                tracemalloc.reset_peak()
                if phase == "extend":
                    target.extend(material)
                elif phase == "growth":
                    target.append(65)
                else:
                    result = target.finish()
                current, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
            assert peak - current < size // 4
    finally:
        for storage in (material, result):
            for index in range(len(storage)):
                storage[index] = 0
