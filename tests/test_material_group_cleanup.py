"""Synthetic multi-buffer leases and selectors; no account/token operations."""
import pytest
from types import SimpleNamespace

from fortipam_mcp import mutable_json_buffer as buffers
from fortipam_mcp import ems_tag_account_material as ems
from fortipam_mcp import scim_client_material as scim
from fortipam_mcp import fortitoken_user_contract as token
from fortipam_mcp.secret_metadata_http_transport import _zeroize_mutable
from v4_planning.material_provider import MaterialAccessDenied
from v4_planning.material_runtime import MaterialUseOutcome

ERRORS = (MemoryError, RuntimeError, KeyboardInterrupt, SystemExit)


def test_group_owns_only_exact_mutable_buffers_and_keeps_clear_callback_semantics():
    owned = [bytearray(b'SYNTHETIC_PRIVATE') for _ in range(3)]
    calls = []
    def clear(raw): calls.append(raw); _zeroize_mutable(raw)
    assert buffers._clear_mutable_group((None, owned[0], b'SYNTHETIC_NOT_OWNED', owned[1], 'not-owned', owned[2]), clear) is None
    assert len(calls) == 3 and all(not any(raw) for raw in owned)


@pytest.mark.parametrize('index', [0, 1, 2])
@pytest.mark.parametrize('error_type', ERRORS)
def test_group_attempts_every_buffer_then_propagates_failure(index, error_type):
    owned = [bytearray(b'SYNTHETIC_PRIVATE') for _ in range(3)]
    calls = []
    def clear(raw):
        calls.append(raw); _zeroize_mutable(raw)
        if raw is owned[index]: raise error_type('Synthetic group failure')
    with pytest.raises(error_type): buffers._clear_mutable_group(owned, clear)
    assert len(calls) == 3 and all(not any(raw) for raw in owned)


def test_multiple_cleanup_failures_do_not_skip_slots_or_replace_first_failure():
    owned = [bytearray(b'SYNTHETIC_PRIVATE') for _ in range(3)]
    first = KeyboardInterrupt('Synthetic first failure'); calls = []
    def clear(raw):
        calls.append(raw); _zeroize_mutable(raw)
        raise first if len(calls) == 1 else MemoryError('Synthetic later failure')
    with pytest.raises(KeyboardInterrupt) as result: buffers._clear_mutable_group(owned, clear)
    assert result.value is first and len(calls) == 3 and all(not any(raw) for raw in owned)


@pytest.mark.parametrize('error_type', ERRORS)
def test_scim_rejected_multi_buffer_result_is_fully_erased_and_cannot_reload(monkeypatch, error_type):
    from test_scim_client_material import make
    provider, resolver, binding, request, _ = make()
    owned = [bytearray(b'SYNTHETIC_FIRST'), bytearray(b'SYNTHETIC_SECOND')]; loads = []
    def load(): loads.append(True); return owned
    resolver.load_scim_material_once = load
    calls = []
    def clear(raw):
        calls.append(raw); _zeroize_mutable(raw)
        if len(calls) == 1: raise error_type()
    monkeypatch.setattr(scim, '_zeroize_mutable', clear)
    with pytest.raises(error_type): provider.acquire_lease(binding, request)
    assert len(calls) == 2 and all(not any(raw) for raw in owned)
    assert provider._buffer is None and provider._attempted
    with pytest.raises(MaterialAccessDenied): provider.acquire_lease(binding, request)
    assert len(loads) == 1


@pytest.mark.parametrize('error_type', ERRORS)
def test_scim_consumption_cleanup_failure_releases_view_and_internal_reference(monkeypatch, error_type):
    from test_scim_client_material import make
    provider, resolver, binding, request, _ = make()
    lease = provider.acquire_lease(binding, request); views = []
    def clear(raw): _zeroize_mutable(raw); raise error_type()
    def use(view): views.append(view); return MaterialUseOutcome.VERIFIED
    monkeypatch.setattr(scim, '_zeroize_mutable', clear)
    with pytest.raises(error_type): provider.consume(binding, lease, request, use)
    assert provider._buffer is None and provider._consumed and all(not any(raw) for raw in resolver.buffers)
    with pytest.raises(ValueError): bytes(views[0])
    assert provider.consume(binding, lease, request, use) is MaterialUseOutcome.FAILED


def lease_for(source=None):
    # Cleanup-only unit fixture. Real M4 ownership remains covered by the
    # unchanged original Account material integration tests.
    source = source or SimpleNamespace(_active=lambda *_: None, _enrollment=SimpleNamespace(_draft=object()))
    return ems._EmsAccountInitialLease(source, bytearray(b'SYNTHETIC_USERNAME'),
        bytearray(b'SYNTHETIC_PASSWORD'), object(), object())


@pytest.mark.parametrize('index', [0, 1])
@pytest.mark.parametrize('error_type', ERRORS)
def test_ems_lease_close_always_attempts_both_slots_without_reopening(monkeypatch, index, error_type):
    lease = lease_for(); owned = (lease._username, lease._password); calls = []
    def clear(raw):
        calls.append(raw); _zeroize_mutable(raw)
        if raw is owned[index]: raise error_type()
    monkeypatch.setattr(ems, '_zeroize_mutable', clear)
    with pytest.raises(error_type): lease.close()
    assert lease._closed and len(calls) == 2 and all(not any(raw) for raw in owned)
    lease.close(); assert len(calls) == 2


@pytest.mark.parametrize('error_type', ERRORS)
def test_ems_encoded_body_is_erased_when_final_active_check_interrupts(monkeypatch, error_type):
    calls = []
    def active(*_):
        calls.append(True)
        if len(calls) == 2: raise error_type()
    source = SimpleNamespace(_active=active, _enrollment=SimpleNamespace(_draft=object()))
    lease = lease_for(source); body = bytearray(b'SYNTHETIC_ENCODED_CREDENTIALS')
    monkeypatch.setattr(ems, '_encode_create', lambda *_: body)
    with pytest.raises(MaterialAccessDenied if issubclass(error_type, Exception) else error_type): lease.encode_once()
    assert not any(body) and not any(lease._username) and not any(lease._password)
    assert lease._closed and lease._consumed
    with pytest.raises(MaterialAccessDenied): lease.encode_once()


@pytest.mark.parametrize('error_type', ERRORS)
def test_ems_encoded_body_is_not_abandoned_when_lease_cleanup_fails(monkeypatch, error_type):
    lease = lease_for(); body = bytearray(b'SYNTHETIC_ENCODED_CREDENTIALS'); calls = []
    def clear(raw):
        calls.append(raw); _zeroize_mutable(raw)
        if len(calls) == 1: raise error_type()
    monkeypatch.setattr(ems, '_encode_create', lambda *_: body)
    monkeypatch.setattr(ems, '_zeroize_mutable', clear)
    with pytest.raises(MaterialAccessDenied if issubclass(error_type, Exception) else error_type): lease.encode_once()
    assert not any(body) and not any(lease._username) and not any(lease._password)
    assert len(calls) == 3 and lease._closed and lease._consumed


@pytest.mark.parametrize('control_type', (KeyboardInterrupt, SystemExit))
@pytest.mark.parametrize('cleanup_type', (MemoryError, RuntimeError))
def test_ems_main_control_failure_survives_ordinary_cleanup_failures(monkeypatch, control_type, cleanup_type):
    active_calls = []
    control = control_type('Synthetic main control failure')
    def active(*_):
        active_calls.append(True)
        if len(active_calls) == 2: raise control
    source = SimpleNamespace(_active=active, _enrollment=SimpleNamespace(_draft=object()))
    lease = lease_for(source); body = bytearray(b'SYNTHETIC_ENCODED_CREDENTIALS'); cleared = []
    def clear(raw):
        cleared.append(raw); _zeroize_mutable(raw)
        raise cleanup_type('Synthetic cleanup failure')
    monkeypatch.setattr(ems, '_encode_create', lambda *_: body)
    monkeypatch.setattr(ems, '_zeroize_mutable', clear)
    with pytest.raises(control_type) as result: lease.encode_once()
    assert result.value is control
    assert len(cleared) == 3 and all(not any(raw) for raw in cleared)
    assert lease._closed and lease._consumed
    with pytest.raises(MaterialAccessDenied): lease.encode_once()
    assert len(active_calls) == 2


@pytest.mark.parametrize('error_type', (MemoryError, RuntimeError))
def test_ems_repeated_cleanup_failures_keep_fixed_material_error(monkeypatch, error_type):
    lease = lease_for(); body = bytearray(b'SYNTHETIC_ENCODED_CREDENTIALS'); cleared = []
    def clear(raw):
        cleared.append(raw); _zeroize_mutable(raw)
        raise error_type('Synthetic repeated cleanup failure')
    monkeypatch.setattr(ems, '_encode_create', lambda *_: body)
    monkeypatch.setattr(ems, '_zeroize_mutable', clear)
    with pytest.raises(MaterialAccessDenied, match=ems._ERROR): lease.encode_once()
    assert len(cleared) == 3 and all(not any(raw) for raw in cleared)
    assert lease._closed and lease._consumed


@pytest.mark.parametrize('control_type', (KeyboardInterrupt, SystemExit))
def test_ems_cleanup_control_is_not_replaced_by_later_ordinary_failures(monkeypatch, control_type):
    lease = lease_for(); body = bytearray(b'SYNTHETIC_ENCODED_CREDENTIALS'); cleared = []
    control = control_type('Synthetic first cleanup control')
    def clear(raw):
        cleared.append(raw); _zeroize_mutable(raw)
        if len(cleared) == 1: raise control
        raise MemoryError('Synthetic later cleanup failure')
    monkeypatch.setattr(ems, '_encode_create', lambda *_: body)
    monkeypatch.setattr(ems, '_zeroize_mutable', clear)
    with pytest.raises(control_type) as result: lease.encode_once()
    assert result.value is control
    assert len(cleared) == 3 and all(not any(raw) for raw in cleared)
    assert lease._closed and lease._consumed


@pytest.mark.parametrize('control_type', (KeyboardInterrupt, SystemExit))
@pytest.mark.parametrize('control_slot', (0, 1))
def test_ems_cleanup_control_takes_precedence_over_main_ordinary_failure(monkeypatch, control_type, control_slot):
    active_calls = []
    def active(*_):
        active_calls.append(True)
        if len(active_calls) == 2: raise RuntimeError('Synthetic main ordinary failure')
    source = SimpleNamespace(_active=active, _enrollment=SimpleNamespace(_draft=object()))
    lease = lease_for(source); body = bytearray(b'SYNTHETIC_ENCODED_CREDENTIALS'); cleared = []
    control = control_type('Synthetic cleanup control')
    def clear(raw):
        cleared.append(raw); _zeroize_mutable(raw)
        if len(cleared) == control_slot + 1: raise control
        raise MemoryError('Synthetic ordinary cleanup failure')
    monkeypatch.setattr(ems, '_encode_create', lambda *_: body)
    monkeypatch.setattr(ems, '_zeroize_mutable', clear)
    with pytest.raises(control_type) as result: lease.encode_once()
    assert result.value is control
    assert len(cleared) == 3 and all(not any(raw) for raw in cleared)
    assert lease._closed and lease._consumed


@pytest.mark.parametrize('error_type', ERRORS)
def test_fortitoken_raw_sanitized_and_private_selector_are_independently_erased(monkeypatch, error_type):
    import test_fortitoken_user_contract as fixture
    schema, row = fixture.fixture('revoke')
    raw = fixture._body(row, serial=fixture.SERIAL, vdom='root'); calls = []
    def clear(value):
        calls.append(value); _zeroize_mutable(value)
        if len(calls) == 1: raise error_type()
    monkeypatch.setattr(token, '_zeroize_mutable', clear)
    with pytest.raises(error_type): token.project_fortitoken_user(raw, schema, fixture.binding(), expected_serial=fixture.SERIAL)
    assert len(calls) == 3 and all(not any(value) for value in calls)
