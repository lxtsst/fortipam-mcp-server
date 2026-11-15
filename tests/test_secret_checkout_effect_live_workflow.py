from dataclasses import replace
import sqlite3
from types import SimpleNamespace

import pytest

from fortipam_mcp.secret_checkout_association_http_transport import SecretCheckoutBinding
from fortipam_mcp.secret_checkout_effect_contract import SecretCheckoutEffectBinding
from fortipam_mcp.secret_checkout_effect_http_transport import (
    SecretCheckoutEffectHttpTransport, SecretCheckoutEffectInspection, SecretCheckoutEffectReadback,
)
from fortipam_mcp.secret_checkout_effect_live_workflow import SecretCheckoutEffectLiveWorkflow

BINDING = SecretCheckoutBinding(owner_name="synthetic-owner", folder_path="synthetic-folder",
    secret_name="mcp-v4-bp008-checkout-20261001-r20", target_name="synthetic-target",
    template_name="Unix Account (SSH Password)", execution_secret_name="mcp-v4-bp008-checkout-20261001-r6",
    checkout_script="", checkin_script="", baseline_controls=(), force_checkout_idle_time=0)
CURRENT = SecretCheckoutEffectInspection(
    SecretCheckoutEffectBinding(17,9,BINDING.secret_name,BINDING.target_name,41,BINDING.owner_name),
    "a"*64,"b"*64,"c"*64)
REQUESTER = "d"*64


@pytest.mark.parametrize("operation", ["checkout", "checkin"])
@pytest.mark.parametrize("mode", ["complete", "unqualified", "timeout", "intent_drift", "execute_drift",
                                 "wrong_caller", "expired", "tampered", "parallel_intents"])
def test_one_bound_durable_effect_and_fail_closed_replay(tmp_path,operation,mode):
    tmp_path.chmod(0o700)
    key=tmp_path/"key";key.write_bytes(b"k"*32);key.chmod(0o600)
    calls=[]; clock=[1000]

    class Transport(SecretCheckoutEffectHttpTransport):
        def __init__(self,binding=BINDING):
            self._binding=binding;self._operation=operation
            self._reader=SimpleNamespace(_retained_account=None)
            self.current=CURRENT
        def inspect(self): calls.append("read");return self.current
        def execute_and_readback(self,expected):
            calls.append("post")
            assert expected==self.current
            if mode=="timeout": raise TimeoutError("synthetic-private-message")
            return SecretCheckoutEffectReadback(True,True,True,True,True,True,mode!="unqualified")

    transport=Transport()
    def workflow(t=transport):
        return SecretCheckoutEffectLiveWorkflow(tmp_path/"ledger",key,t,t._binding,
            operation=operation,clock=lambda:clock[0])
    w=workflow();preview=w.preview(requester_digest=REQUESTER)
    assert BINDING.owner_name not in str(preview) and BINDING.secret_name not in str(preview)
    if mode=="wrong_caller":
        with pytest.raises(RuntimeError):w.confirm(preview["preview_ref"],requester_digest="e"*64)
    if mode=="intent_drift":transport.current=replace(CURRENT,metadata_digest="f"*64)
    if mode=="expired":clock[0]=preview["expires_at"]
    if mode in {"intent_drift","expired"}:
        with pytest.raises(RuntimeError):w.confirm(preview["preview_ref"],requester_digest=REQUESTER)
        assert "post" not in calls;return
    authorized=w.confirm(preview["preview_ref"],requester_digest=REQUESTER)
    if mode=="wrong_caller":
        with pytest.raises(RuntimeError):w.execute(authorized["authorization_ref"],requester_digest="e"*64)
    if mode=="tampered":
        with sqlite3.connect(tmp_path/"ledger") as db:
            db.execute("UPDATE secret_checkout_effect_workflow SET current_digest=?",("f"*64,));db.commit()
        with pytest.raises(RuntimeError):w.execute(authorized["authorization_ref"],requester_digest=REQUESTER)
        assert "post" not in calls;return
    if mode=="parallel_intents":
        second=w.preview(requester_digest=REQUESTER)
        second_auth=w.confirm(second["preview_ref"],requester_digest=REQUESTER)
    if mode=="execute_drift":transport.current=replace(CURRENT,metadata_digest="f"*64)
    result=w.execute(authorized["authorization_ref"],requester_digest=REQUESTER)
    assert result["outcome"]==("reconciliation_required" if mode in {"unqualified","timeout"}
                               else "not_executed" if mode=="execute_drift" else "succeeded")
    assert calls.count("post")==int(mode!="execute_drift")
    before=list(calls)
    replay=workflow().execute(authorized["authorization_ref"],requester_digest=REQUESTER)
    assert replay["idempotent_replay"] and replay["outcome"]==result["outcome"] and calls==before
    if mode=="parallel_intents":
        with pytest.raises(RuntimeError):w.execute(second_auth["authorization_ref"],requester_digest=REQUESTER)
        assert calls==before
    if mode!="execute_drift":
        with pytest.raises(RuntimeError):workflow().preview(requester_digest=REQUESTER)
        assert calls==before
    other=Transport(replace(BINDING,secret_name="mcp-v4-bp008-checkout-20261001-r21"))
    with pytest.raises(RuntimeError):workflow(other).execute(authorized["authorization_ref"],requester_digest=REQUESTER)
    assert calls==before
