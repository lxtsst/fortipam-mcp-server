"""Synthetic live-allocation witnesses, including isolated worker copies."""
import builtins
import ast
import ctypes
import os
from pathlib import Path
import stat
import tracemalloc
from types import ModuleType

import pytest

from fortipam_mcp import mutable_json_buffer as shared
from fortipam_mcp import radius_fixture_material_worker as primary
from fortipam_mcp import radius_pair_fixture_material_worker as paired
from fortipam_mcp.secret_approval_build29_runtime_provider import _REMOTE_USERNAME_PROGRAM


def _embedded_helpers():
    tree = ast.parse(_REMOTE_USERNAME_PROGRAM, feature_version=(3, 8))
    names = {"erase", "_erase_transfer_storage", "_take_mutable_prefix", "read_fixed"}
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names
             or isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "_BYTEARRAY_TYPE"
                                                    for target in node.targets)]
    assert len(nodes) == 5
    module = ModuleType("embedded_username_prefix_helpers")
    module.__dict__.update(os=os, stat=stat, Path=Path)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "<fixed-helper-definitions>", "exec"), module.__dict__)
    return module


embedded = _embedded_helpers()
MODULES = (shared, primary, paired, embedded)


def _wipe_name(module):
    return "erase" if module is embedded else "_wipe"


@pytest.mark.parametrize("module", MODULES)
@pytest.mark.parametrize("length", [0, 1, 31, 256, 4096])
def test_exact_mutable_prefix_transfers_after_original_allocation_is_erased(module, length, monkeypatch):
    source = bytearray(b"S" * 65536)
    address = ctypes.addressof(ctypes.c_char.from_buffer(source))
    original = getattr(module, _wipe_name(module))
    witnessed = []
    def erase(value):
        if value is source:
            assert len(value) == 65536
            assert ctypes.addressof(ctypes.c_char.from_buffer(value)) == address
            witnessed.append(True)
        original(value)
    monkeypatch.setattr(module, _wipe_name(module), erase)
    result = module._take_mutable_prefix(source, length)
    try:
        assert type(result) is bytearray and result == b"S" * length
        assert result is not source and witnessed
        assert not any(source)
    finally:
        result[:] = b"\0" * len(result)


@pytest.mark.parametrize("module", MODULES)
@pytest.mark.parametrize("length", [-1, True, None, "1", 65])
def test_invalid_length_consumes_original_without_copying_material(module, length):
    source = bytearray(b"S" * 64)
    with pytest.raises(ValueError): module._take_mutable_prefix(source, length)
    assert not any(source)


@pytest.mark.parametrize("module", MODULES)
def test_result_allocation_failure_erases_original(module, monkeypatch):
    source = bytearray(b"S" * 64)
    def unavailable(*args): raise MemoryError
    monkeypatch.setattr(module, "bytearray", unavailable, raising=False)
    with pytest.raises(MemoryError): module._take_mutable_prefix(source, 31)
    assert not any(source)


@pytest.mark.parametrize("module", MODULES)
@pytest.mark.parametrize("failure", [ValueError, MemoryError, KeyboardInterrupt, SystemExit])
def test_copy_or_context_interruption_erases_both_allocations(module, failure, monkeypatch):
    source = bytearray(b"S" * 64); allocated = []
    def allocate(size):
        value = builtins.bytearray(size); allocated.append(value); return value
    class InterruptedView:
        def __init__(self, value): self.value = memoryview(value)
        def __enter__(self): return self.value
        def __exit__(self, *args):
            self.value.release()
            raise failure()
    monkeypatch.setattr(module, "bytearray", allocate, raising=False)
    monkeypatch.setattr(module, "memoryview", InterruptedView, raising=False)
    with pytest.raises(failure): module._take_mutable_prefix(source, 31)
    assert not any(source) and allocated and all(not any(value) for value in allocated)


@pytest.mark.parametrize("module", MODULES)
@pytest.mark.parametrize("failure", [ValueError, MemoryError, KeyboardInterrupt, SystemExit])
def test_simultaneous_primary_wipe_failures_erase_both_live_allocations(module, failure, monkeypatch):
    source = bytearray(b"S" * 64); allocated = []; attempted = []
    def allocate(size):
        value = builtins.bytearray(size); allocated.append(value); return value
    def unavailable(value):
        attempted.append(id(value)); raise failure()
    monkeypatch.setattr(module, "bytearray", allocate, raising=False)
    monkeypatch.setattr(module, _wipe_name(module), unavailable)
    with pytest.raises(failure): module._take_mutable_prefix(source, 31)
    assert not any(source) and allocated and all(not any(value) for value in allocated)
    assert set(attempted) == {id(source), id(allocated[0])}


@pytest.mark.parametrize("module", MODULES)
def test_copy_avoids_an_internal_material_sized_bytearray_temporary(module, monkeypatch):
    source = bytearray(b"S" * 262144)
    result = bytearray()
    # Isolate copy allocations from the workers' known all-zero wipe buffers.
    def erase(value):
        for index in range(len(value)): value[index] = 0
    monkeypatch.setattr(module, _wipe_name(module), erase)
    tracemalloc.start()
    try:
        result = module._take_mutable_prefix(source, 131072)
        current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
        result[:] = b"\0" * len(result)
    assert peak - current < 32768
    assert not any(source)
