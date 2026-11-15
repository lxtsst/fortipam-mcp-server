from dataclasses import replace
import sqlite3

import pytest

from fortipam_mcp.secret_event_subscription_live_workflow import (
    SecretEventSubscriptionLiveWorkflow, SecretEventSubscriptionLiveWorkflowError,
)
from test_secret_event_subscription_contract import BINDING
from test_secret_event_subscription_http_transport import fixture

REQUESTER = "a" * 64


def test_notification_preview_is_value_free_and_email_drift_invalidates_intent(tmp_path):
    make, _, portal, _, posts = fixture(tmp_path)
    address = "notification-fixture@example.invalid"
    portal["email"] = address
    transport = make(expected_email=address)
    workflow = SecretEventSubscriptionLiveWorkflow(tmp_path / "workflow.sqlite3", tmp_path / "key",
        transport, BINDING, operation="subscribe")
    preview = workflow.preview(requester_digest=REQUESTER)
    assert preview["Current State"]["bound_notification_recipient_or_recovery_pair_verified"] is True
    assert "enabling_email_unset_or_recovery_pair_verified" not in preview["Current State"]
    assert preview["Proposed Changes"]["notification_effects_enabled_for_bound_recipient"] is True
    assert preview["Expected State"]["notification_delivery_proven"] is False
    assert address not in repr(preview) and address.encode() not in (tmp_path / "workflow.sqlite3").read_bytes()
    portal["email"] = "unapproved@example.invalid"
    from fortipam_mcp.secret_event_subscription_http_transport import SecretEventSubscriptionHttpTransportError
    with pytest.raises(SecretEventSubscriptionHttpTransportError):
        workflow.confirm(preview["preview_ref"], requester_digest=REQUESTER)
    assert not posts and not (tmp_path / "subscribe.json").exists()


def candidate(tmp_path, case="success", *, expected_email=""):
    make, state, portal, calls, posts = fixture(tmp_path, case)
    clock = [1000]

    def workflow(operation="subscribe", *, binding=BINDING, network=None):
        return SecretEventSubscriptionLiveWorkflow(tmp_path / "workflow.sqlite3", tmp_path / "key",
            make(operation, binding=binding, factory_override=network, expected_email=expected_email), binding,
            operation=operation, clock=lambda: clock[0])

    return workflow, state, portal, calls, posts, clock


@pytest.mark.parametrize("case", ["success", "ambiguous", "no_effect", "metadata_changed", "response_unqualified"])
def test_persistent_cpe_and_terminal_replay_do_not_repeat_dispatch(tmp_path, case):
    make, state, _, calls, posts, _ = candidate(tmp_path, case)
    workflow = make()
    first = workflow.preview(requester_digest=REQUESTER)
    second = workflow.preview(requester_digest=REQUESTER)
    authorization = workflow.confirm(first["preview_ref"], requester_digest=REQUESTER)
    second_authorization = workflow.confirm(second["preview_ref"], requester_digest=REQUESTER)
    assert not posts and first["device_write_executed"] is False
    result = workflow.execute(authorization["authorization_ref"], requester_digest=REQUESTER)
    assert result["outcome"] == ("succeeded" if case == "success" else "reconciliation_required")
    assert len(posts) == 1 and result["permission_loss_behavior_proven"] is False
    count = len(calls)
    restarted = make(network=lambda **kw: pytest.fail("Terminal replay accessed network"))
    replay = restarted.execute(authorization["authorization_ref"], requester_digest=REQUESTER)
    assert replay["idempotent_replay"] and replay["outcome"] == result["outcome"]
    with pytest.raises(SecretEventSubscriptionLiveWorkflowError): restarted.preview(requester_digest=REQUESTER)
    with pytest.raises(SecretEventSubscriptionLiveWorkflowError):
        restarted.execute(second_authorization["authorization_ref"], requester_digest=REQUESTER)
    assert len(calls) == count and len(posts) == 1
    if case == "success":
        restore = make("restore")
        preview = restore.preview(requester_digest=REQUESTER)
        authorization = restore.confirm(preview["preview_ref"], requester_digest=REQUESTER)
        assert restore.execute(authorization["authorization_ref"], requester_digest=REQUESTER)["outcome"] == "succeeded"
        assert len(posts) == 2 and all(r["name"] != BINDING.owner_name for r in state["results"]["subscriber"])
    raw = (tmp_path / "workflow.sqlite3").read_bytes()
    for value in (BINDING.owner_name, BINDING.secret_name, "synthetic-token", "SYNTHETIC_MATERIAL_SENTINEL"):
        assert value.encode() not in raw


@pytest.mark.parametrize("stage", ["confirmation", "execution", "expiry", "foreign_requester", "record_mac"])
def test_drift_expiry_principal_and_record_integrity_refuse_without_post(tmp_path, stage):
    make, state, _, _, posts, clock = candidate(tmp_path)
    workflow = make()
    preview = workflow.preview(requester_digest=REQUESTER)
    if stage == "confirmation":
        state["results"]["recording"] = "disable"
        with pytest.raises(SecretEventSubscriptionLiveWorkflowError):
            workflow.confirm(preview["preview_ref"], requester_digest=REQUESTER)
    else:
        authorization = workflow.confirm(preview["preview_ref"], requester_digest=REQUESTER)
        ref = authorization["authorization_ref"]
        if stage == "execution":
            state["results"]["recording"] = "disable"
            result = workflow.execute(ref, requester_digest=REQUESTER)
            assert result["outcome"] == "not_executed" and result["device_write_may_have_occurred"] is False
            assert workflow.execute(ref, requester_digest=REQUESTER)["idempotent_replay"]
        else:
            requester = REQUESTER
            if stage == "expiry": clock[0] += 600
            if stage == "foreign_requester": requester = "b" * 64
            if stage == "record_mac":
                with sqlite3.connect(tmp_path / "workflow.sqlite3") as connection:
                    connection.execute("UPDATE secret_event_subscription_workflow SET current_digest=?", ("c" * 64,))
            with pytest.raises(SecretEventSubscriptionLiveWorkflowError): workflow.execute(ref, requester_digest=requester)
    assert not posts and not (tmp_path / "subscribe.json").exists()


def test_workflow_rejects_mismatched_operation_or_private_binding(tmp_path):
    make, _, _, _, _, _ = candidate(tmp_path)
    workflow = make()
    with pytest.raises(SecretEventSubscriptionLiveWorkflowError):
        SecretEventSubscriptionLiveWorkflow(tmp_path / "other.sqlite3", tmp_path / "key", workflow._transport,
            BINDING, operation="restore")
    with pytest.raises(SecretEventSubscriptionLiveWorkflowError):
        SecretEventSubscriptionLiveWorkflow(tmp_path / "other.sqlite3", tmp_path / "key", workflow._transport,
            replace(BINDING, secret_id=8), operation="subscribe")
