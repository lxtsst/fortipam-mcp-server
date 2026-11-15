from dataclasses import replace
import hashlib
import json
import pytest
from fortipam_mcp.isolated_folder_m4_adapter import (
    ACTION_ID, ACTION_VERSION, ADAPTER_REF, IsolatedFolderBinding, IsolatedFolderM4Adapter,
)
from test_v4_execution_kernel import _plan, _authorization, NOW
from v4_planning import M4ExecutionKernel, InMemoryM4ExecutionStateStore, M4Outcome, canonical_digest
from test_secret_onboarding_action_sequence import _AuthorizationVerifier


class Transport:
    def __init__(self, failure):
        self.failure, self.posts, self.reads = failure, 0, 0
    def read_product_version_and_build(self):
        return ("7.0.0", 30 if self.failure == "version" else 29)
    def read_parent_digest(self, folder_id):
        self.reads += 1
        return "b" * 64 if self.failure == "drift" and self.reads > 1 else "a" * 64
    def owner_is_available(self, owner):
        return self.failure != "owner"
    def find_child_ids(self, name, parent):
        return (23,) if self.posts or self.failure == "exists" else ()
    def create_isolated_child(self, **kwargs):
        before_dispatch = kwargs.get("before_dispatch")
        if before_dispatch is not None:
            before_dispatch()
        self.posts += 1
        if self.failure == "ambiguous":
            raise RuntimeError("synthetic transport failure")
        return {"http_status": 200, "mkey": 23}
    def verify_isolated_child(self, folder_id, **kwargs):
        return self.failure != "acl"


@pytest.mark.parametrize("failure", [None, "version", "owner", "exists", "drift", "ambiguous", "acl"])
def test_isolated_folder_kernel_rejects_drift_and_requires_readback_without_replay(failure):
    binding = IsolatedFolderBinding("Collector", 17, "synthetic-owner", "a" * 64)
    base = _plan()
    changes = dict(action_id=ACTION_ID, action_version=ACTION_VERSION, adapter_ref=ADAPTER_REF,
        parameters_digest=binding.parameters_digest,
        expected_current_digest=binding.state_digest(exists=False),
        expected_state_digest=binding.state_digest(exists=True))
    plan = replace(base, **changes, plan_digest=canonical_digest({**base.canonical_content(), **changes}))
    transport = Transport(failure)
    adapter = IsolatedFolderM4Adapter(plan, binding, transport, clock=lambda: NOW)
    kernel = M4ExecutionKernel(adapter, _AuthorizationVerifier(), InMemoryM4ExecutionStateStore(), clock=lambda: NOW)
    result = kernel.execute(plan, _authorization(plan))
    assert (result.outcome is M4Outcome.SUCCEEDED) is (failure is None)
    expected_posts = 0 if failure in {"version", "owner", "exists", "drift"} else 1
    assert transport.posts == expected_posts
    kernel.execute(plan, _authorization(plan))
    assert transport.posts == expected_posts


@pytest.mark.parametrize("expiry_offset", (0, 1))
@pytest.mark.parametrize("final_read_phase", ("adapter", "transport"))
def test_kernel_retains_consumed_claim_when_final_read_reaches_expiry(expiry_offset, final_read_phase):
    now = [NOW]
    binding = IsolatedFolderBinding("Collector", 17, "synthetic-owner", "a" * 64)
    base = _plan()
    changes = dict(action_id=ACTION_ID, action_version=ACTION_VERSION, adapter_ref=ADAPTER_REF,
        parameters_digest=binding.parameters_digest,
        expected_current_digest=binding.state_digest(exists=False),
        expected_state_digest=binding.state_digest(exists=True))
    plan = replace(base, **changes, plan_digest=canonical_digest({**base.canonical_content(), **changes}))

    class SlowTransport(Transport):
        lookups = 0

        def find_child_ids(self, name, parent):
            result = super().find_child_ids(name, parent)
            self.lookups += 1
            if self.lookups == 2 and final_read_phase == "adapter":
                now[0] = plan.expires_at + expiry_offset
            return result

        def create_isolated_child(self, **kwargs):
            if final_read_phase == "transport":
                now[0] = plan.expires_at + expiry_offset
            return super().create_isolated_child(**kwargs)

    transport = SlowTransport(None)
    adapter = IsolatedFolderM4Adapter(plan, binding, transport, clock=lambda: now[0])
    kernel = M4ExecutionKernel(adapter, _AuthorizationVerifier(), InMemoryM4ExecutionStateStore(),
                               clock=lambda: now[0])
    authorization = _authorization(plan)
    result = kernel.execute(plan, authorization)
    assert result.outcome is M4Outcome.DENIED
    assert transport.lookups == 2 and transport.posts == 0
    now[0] = NOW
    replay = kernel.execute(plan, authorization)
    assert replay.outcome is result.outcome and replay.idempotent_replay
    assert transport.lookups == 2 and transport.posts == 0


@pytest.mark.parametrize("flag", [None, 0, 1, "true", "false"])
def test_empty_inactive_policy_binding_is_keyword_only_and_strict_bool(flag):
    with pytest.raises(ValueError):
        IsolatedFolderBinding("Collector", 17, "synthetic-owner", "a" * 64, empty_inactive_policy=flag)
    with pytest.raises(TypeError):
        IsolatedFolderBinding("Collector", 17, "synthetic-owner", "a" * 64, True)


@pytest.mark.parametrize("enabled", [False, True])
def test_empty_inactive_policy_binding_preserves_legacy_digest_and_binds_dispatch_and_readback(enabled):
    legacy_body = {"id": 0, "name": "Collector", "parent-folder": 17, "inherit-policy": "enable",
        "inherit-folder-ztna": "enable", "inherit-permission": "disable", "group-permission": [],
        "user-permission": [{"id": 0, "user-name": [{"name": "synthetic-owner"}],
            "folder-permission": "owner", "secret-permission": "owner"}]}
    legacy = IsolatedFolderBinding("Collector", 17, "synthetic-owner", "a" * 64)
    assert legacy.parameters_digest == canonical_digest({"contract": ADAPTER_REF, "body": legacy_body,
                                                        "parent_digest": "a" * 64})
    binding = replace(legacy, empty_inactive_policy=enabled)
    expected_body = {**legacy_body, "secret-policy": ""} if enabled else legacy_body
    if enabled:
        body_digest = hashlib.sha256(json.dumps(expected_body, ensure_ascii=True, sort_keys=True,
            separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()
        assert binding.parameters_digest == canonical_digest({"contract": ADAPTER_REF, "body_digest": body_digest,
                                                             "parent_digest": "a" * 64})
    else:
        assert binding.parameters_digest == legacy.parameters_digest
    assert (binding.parameters_digest != legacy.parameters_digest) is enabled
    base = _plan()
    changes = dict(action_id=ACTION_ID, action_version=ACTION_VERSION, adapter_ref=ADAPTER_REF,
        parameters_digest=binding.parameters_digest, expected_current_digest=binding.state_digest(exists=False),
        expected_state_digest=binding.state_digest(exists=True))
    plan = replace(base, **changes, plan_digest=canonical_digest({**base.canonical_content(), **changes}))
    calls = []
    class RecordingTransport(Transport):
        def create_isolated_child(self, **kwargs):
            calls.append(("create", dict(kwargs)))
            return super().create_isolated_child(**kwargs)
        def verify_isolated_child(self, identifier, **kwargs):
            calls.append(("verify", dict(kwargs)))
            return super().verify_isolated_child(identifier, **kwargs)
    transport = RecordingTransport(None)
    adapter = IsolatedFolderM4Adapter(plan, binding, transport, clock=lambda: NOW)
    if enabled:
        from v4_planning import M4AdapterDenied
        with pytest.raises(M4AdapterDenied):
            IsolatedFolderM4Adapter(plan, legacy, transport, clock=lambda: NOW)
    adapter.dispatch(plan)
    assert adapter.read_postcondition(plan) == binding.state_digest(exists=True)
    assert [kind for kind, args in calls] == ["create", "verify"]
    for kind, args in calls:
        expected = {"name", "parent_folder_id", "owner_name"} | ({"before_dispatch"} if kind == "create" else set())
        if enabled:
            expected.add("empty_inactive_policy")
            assert args["empty_inactive_policy"] is True
        assert set(args) == expected
