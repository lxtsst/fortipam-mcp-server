"""Transient NEW-dispatch ownership; no extra ledger or callable surface."""

from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
import copy
import pickle

import pytest

from test_v4_execution_kernel import _Adapter, _Verifier, _authorization, _plan
from v4_planning import (
    InMemoryM4ExecutionStateStore, M4AdapterAmbiguous, M4AuthorizationDenied,
    M4AuthorizationReplay, M4ExecutionKernel,
)
from v4_planning.execution_kernel import (
    _ACTIVE_DISPATCH, _require_m4_dispatch_ownership,
    _reserve_m4_material_acquisition, _reserve_m4_product_startup,
)


def test_only_current_new_dispatch_owns_one_acquisition_and_copied_context_cannot_revive_it():
    plan = _plan()
    auth = _authorization(plan)
    state = InMemoryM4ExecutionStateStore()
    contexts = []

    class Adapter(_Adapter):
        def read_current(self, active):
            with pytest.raises(M4AuthorizationDenied):
                _require_m4_dispatch_ownership(plan, auth, state)
            return super().read_current(active)

        def dispatch(self, active):
            _require_m4_dispatch_ownership(plan, auth, state)
            scope = _ACTIVE_DISPATCH.get()
            assert "m4-plan" not in repr(scope)
            for serialize in (copy.copy, copy.deepcopy, pickle.dumps):
                with pytest.raises(RuntimeError):
                    serialize(scope)
            _reserve_m4_material_acquisition(plan, auth, state)
            with pytest.raises(M4AuthorizationReplay):
                _reserve_m4_material_acquisition(plan, auth, state)
            with pytest.raises(M4AuthorizationDenied):
                _require_m4_dispatch_ownership(plan, auth, InMemoryM4ExecutionStateStore())
            other = _plan(plan_ref="different-plan-01")
            with pytest.raises(M4AuthorizationDenied):
                _require_m4_dispatch_ownership(other, _authorization(other), state)
            contexts.append(copy_context())
            with ThreadPoolExecutor(max_workers=1) as pool:
                def cross_thread():
                    with pytest.raises(M4AuthorizationDenied):
                        copy_context_in_owner.run(_require_m4_dispatch_ownership, plan, auth, state)
                copy_context_in_owner = copy_context()
                pool.submit(cross_thread).result()
            super().dispatch(active)

        def read_postcondition(self, active):
            with pytest.raises(M4AuthorizationDenied):
                _require_m4_dispatch_ownership(plan, auth, state)
            return super().read_postcondition(active)

    adapter = Adapter()
    kernel = M4ExecutionKernel(adapter, _Verifier(), state)
    kernel.execute(plan, auth, now_epoch=1000)
    assert len(contexts) == 1
    assert contexts[0].run(_ACTIVE_DISPATCH.get).store is None
    with pytest.raises(M4AuthorizationDenied):
        contexts[0].run(_require_m4_dispatch_ownership, plan, auth, state)
    before = list(adapter.calls)
    assert kernel.execute(plan, auth, now_epoch=1000).idempotent_replay
    assert adapter.calls == before and len(contexts) == 1


@pytest.mark.parametrize("failure", [M4AdapterAmbiguous("synthetic"), RuntimeError("synthetic"), KeyboardInterrupt()])
def test_all_exception_exits_close_original_dispatch_ownership(failure):
    plan = _plan()
    auth = _authorization(plan)
    state = InMemoryM4ExecutionStateStore()
    contexts = []

    class Adapter(_Adapter):
        def dispatch(self, active):
            _require_m4_dispatch_ownership(plan, auth, state)
            contexts.append(copy_context())
            raise failure

    kernel = M4ExecutionKernel(Adapter(), _Verifier(), state)
    if isinstance(failure, M4AdapterAmbiguous):
        kernel.execute(plan, auth, now_epoch=1000)
    else:
        with pytest.raises(type(failure)):
            kernel.execute(plan, auth, now_epoch=1000)
    with pytest.raises(M4AuthorizationDenied):
        contexts[0].run(_require_m4_dispatch_ownership, plan, auth, state)
    assert kernel.execute(plan, auth, now_epoch=1000).idempotent_replay


@pytest.mark.parametrize('material_first', [False, True])
def test_product_startup_is_consumed_before_material_and_cannot_be_replayed(material_first):
    plan, state = _plan(), InMemoryM4ExecutionStateStore()
    auth = _authorization(plan)
    contexts = []

    class Adapter(_Adapter):
        def dispatch(self, active):
            contexts.append(copy_context())
            if material_first:
                _reserve_m4_material_acquisition(plan, auth, state)
            else:
                _reserve_m4_product_startup(plan, auth, state)
            with pytest.raises(M4AuthorizationReplay):
                _reserve_m4_product_startup(plan, auth, state)
            if not material_first:
                _reserve_m4_material_acquisition(plan, auth, state)
            raise M4AdapterAmbiguous('Synthetic startup interruption')

    with pytest.raises(M4AuthorizationDenied):
        _reserve_m4_product_startup(plan, auth, state)
    adapter = Adapter()
    kernel = M4ExecutionKernel(adapter, _Verifier(), state)
    kernel.execute(plan, auth, now_epoch=1000)
    with pytest.raises(M4AuthorizationDenied):
        contexts[0].run(_reserve_m4_product_startup, plan, auth, state)
    assert kernel.execute(plan, auth, now_epoch=1000).idempotent_replay
    assert len(contexts) == 1
