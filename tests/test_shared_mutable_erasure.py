"""Shared owned-buffer erasure without a payload-sized zero allocation."""
import tracemalloc

import pytest

from fortipam_mcp import mutable_json_buffer
from fortipam_mcp.secret_metadata_http_transport import _zeroize_mutable


@pytest.mark.parametrize('size', [0, 1, 4095, 4096, 4097, 2*1024*1024])
@pytest.mark.parametrize('pinned', [False, True])
def test_success_clears_storage_or_zeroes_in_place_while_a_view_is_pinned(size, pinned):
    raw = bytearray(b'X'*size)
    view = memoryview(raw).toreadonly() if pinned else None
    try:
        assert _zeroize_mutable(raw) is None
        assert not any(raw)
        if pinned:
            assert len(raw) == size and not any(view)
        else: assert raw == bytearray()
        _zeroize_mutable(raw)
        assert not any(raw)
    finally:
        if view is not None: view.release()


def test_two_megabyte_payload_does_not_allocate_a_payload_sized_zero_copy():
    raw = bytearray(b'X'*(2*1024*1024)); view = memoryview(raw).toreadonly()
    try:
        tracemalloc.start()
        try:
            _zeroize_mutable(raw)
            _, peak = tracemalloc.get_traced_memory()
        finally: tracemalloc.stop()
        assert peak < 65536
        assert not any(raw) and len(view) == 2*1024*1024
    finally: view.release()


@pytest.mark.parametrize('error_type', [MemoryError, RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('pinned', [False, True])
def test_failed_block_wipe_uses_scalar_fallback_and_propagates_without_resizing(monkeypatch, error_type, pinned):
    raw = bytearray(b'SYNTHETIC_PROTECTED_BUFFER')
    view = memoryview(raw).toreadonly() if pinned else None
    def fail(_raw): raise error_type('Synthetic block-wipe failure')
    monkeypatch.setattr(mutable_json_buffer, '_wipe', fail)
    try:
        with pytest.raises(error_type): _zeroize_mutable(raw)
        assert not any(raw) and len(raw) == len(b'SYNTHETIC_PROTECTED_BUFFER')
        if view is not None: assert not any(view)
    finally:
        if view is not None: view.release()


@pytest.mark.parametrize('error_type', [MemoryError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('clear_first', [False, True])
def test_clear_failure_occurs_only_after_erasure_and_is_not_swallowed(error_type, clear_first):
    class Storage(bytearray):
        def clear(self):
            if clear_first: super().clear()
            raise error_type('Synthetic clear failure')
    raw = Storage(b'SYNTHETIC_PROTECTED_BUFFER')
    with pytest.raises(error_type): _zeroize_mutable(raw)
    assert not any(raw)
