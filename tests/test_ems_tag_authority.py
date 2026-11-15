"""EMS-specific source/authority/custody join, with synthetic product replies."""
from dataclasses import replace
import hashlib

import pytest
from v4_planning import M4AuthorizationDenied, M4ExecutionKernel

from fortipam_mcp.ems_tag_authority import EmsTagCreateAuthority
from fortipam_mcp.ems_tag_custody import EmsTagOriginalCustody, EmsTagOriginalActorBinding
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_ems_tag_contract import full_scope
from test_ems_tag_custody import Adapter
from test_ems_tag_sources import make
from test_m4_execution_store import _ExternalM4Checkpoint, CHECKPOINT_STORE_REF

IDENTITY = dict(environment_ref="ems-disposable-lab", scope_ref="ems-disabled-tag-create",
                audience_ref="private-ems-lab-client", requester_digest="a" * 64, transport_digest="b" * 64)
CALLER = {name: IDENTITY[name] for name in ("requester_digest", "transport_digest")}


def authority(*, enabled=True):
    source, channel, now = make()
    observed = source.observe()
    auth = EmsTagCreateAuthority(source, authority_key=b"k" * 32, execution_enabled=enabled,
                                 clock=lambda: now[0], **IDENTITY)
    return auth, source, channel, now, observed


def test_default_closed_preview_does_not_issue_execution():
    source, _, _ = make()
    observed = source.observe()
    auth = EmsTagCreateAuthority(source, authority_key=b"k" * 32, clock=lambda: 1000, **IDENTITY)
    preview = auth.preview(observed, **CALLER)
    with pytest.raises(M4AuthorizationDenied): auth.issue(preview, observed, **CALLER)


@pytest.mark.parametrize("fault", ["requester", "transport", "detached", "drift", "collision", "expiry", "closed", "copied_preview"])
def test_authority_refuses_identity_stale_or_changed_sources(fault):
    auth, source, channel, now, observed = authority()
    preview = auth.preview(observed, **CALLER)
    caller = dict(CALLER)
    if fault in caller: caller[fault] = "c" * 64
    elif fault == "requester": caller["requester_digest"] = "c" * 64
    elif fault == "transport": caller["transport_digest"] = "c" * 64
    elif fault == "detached": observed = replace(observed)
    elif fault == "drift":
        channel.scope = full_scope(prior_change=True)
        observed = source.observe()
    elif fault == "collision":
        channel.scope = full_scope(add=True)
        observed = source.observe()
    elif fault == "expiry": now[0] += 60
    elif fault == "closed": source.close()
    else: preview = replace(preview)
    with pytest.raises(M4AuthorizationDenied): auth.issue(preview, observed, **caller)


def test_one_issue_cannot_rearm_by_replacing_preview_or_copying_plan():
    auth, source, _, now, observed = authority()
    preview = auth.preview(observed, **CALLER)
    issued = auth.issue(preview, source.observe(), **CALLER)
    auth.verify(issued.plan, issued.authorization, now_epoch=now[0])
    for plan, authorization in ((replace(issued.plan), issued.authorization),
                                (issued.plan, replace(issued.authorization))):
        with pytest.raises(M4AuthorizationDenied): auth.verify(plan, authorization, now_epoch=now[0])
    with pytest.raises(M4AuthorizationDenied): auth.issue(preview, source._current, **CALLER)
    with pytest.raises(M4AuthorizationDenied): auth.preview(source._current, **CALLER)
    auth.check_current(issued, source.observe())
    auth.close()
    with pytest.raises(M4AuthorizationDenied): auth.verify(issued.plan, issued.authorization, now_epoch=now[0])


def test_authority_key_cannot_reuse_source_key():
    source, _, _ = make()
    source.observe()
    with pytest.raises(M4AuthorizationDenied):
        EmsTagCreateAuthority(source, authority_key=b"s" * 32, **IDENTITY)


def test_real_m4_kernel_and_durable_custody_accept_only_fresh_independent_ems_authority(tmp_path):
    auth, source, channel, now, observed = authority()
    preview = auth.preview(observed, **CALLER)
    issued = auth.issue(preview, observed, **CALLER)
    tmp_path.chmod(0o700)
    for name, value in (("execution.key", b"e" * 32), ("custody.key", b"c" * 32)):
        (tmp_path / name).write_bytes(value)
        (tmp_path / name).chmod(0o600)
    (tmp_path / "custody").mkdir(mode=0o700)
    store = PersistentM4ExecutionStateStore(tmp_path / "execution.sqlite", tmp_path / "execution.key",
        monotonic_checkpoint=_ExternalM4Checkpoint(), checkpoint_store_ref=CHECKPOINT_STORE_REF)
    custody = EmsTagOriginalCustody(tmp_path / "custody", tmp_path / "custody.key", source._draft,
        observed.full_scope.digest, issued.plan, issued.authorization, store,
        source_context_digest=source.source_context_digest, actor_binding=EmsTagOriginalActorBinding("5"*64,CALLER["transport_digest"],hashlib.sha256(auth._key).hexdigest()), clock=lambda: now[0])

    class JoinedAdapter(Adapter):
        def read_current(self, plan):
            current = source.observe()
            auth.check_current(issued, current)
            return source.current_digest(current)

        def dispatch(self, plan):
            super().dispatch(plan)
            channel.scope = full_scope(add=True)

        def read_postcondition(self, plan):
            current = source.observe()
            original = custody.inspect_created_scope(require_verified_original=False)
            assert current.full_scope.digest == original.created_scope_digest
            return super().read_postcondition(plan)

    adapter = JoinedAdapter(custody, observed.full_scope)
    kernel = M4ExecutionKernel(adapter, auth, store, clock=lambda: now[0])
    result = kernel.execute(issued.plan, issued.authorization)
    assert result.outcome == "succeeded" and result.verification == "verified" and adapter.sends == 1
    assert custody.inspect_created_scope().created_scope_digest == channel.scope.digest
    assert store.claim_count == 1
    custody.close(); auth.close(); source.close()
