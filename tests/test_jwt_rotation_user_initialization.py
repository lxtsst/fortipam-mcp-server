"""Native initialization material never reaches a value decoder or an artifact."""
import json

import pytest

from fortipam_mcp import jwt_rotation_user_initialization as c
from test_jwt_manual_rotation_contract import fixture,replacement
from test_jwt_manual_key_contract import synthetic_key
from test_jwt_manual_key_preflight import packet

TOKEN = "SYNTHETIC_UNUSED_INITIALIZATION_TOKEN_123456789"


@pytest.mark.parametrize("fault", [None,"action","device","mkey","error","http-bool","extra-result","too-many-results","missing-token","unknown-root","token-object","empty","escaped","large"])
def test_initialization_is_bound_and_material_is_never_decoded_or_retained(synthetic_key,replacement,monkeypatch,fault):
    binding,_ = fixture(synthetic_key,replacement)
    value = packet("api-user",{"access_token":TOKEN},http_method="POST",action="generate-key")
    if fault == "action": value["action"] = "unqualified"
    if fault == "device": value["serial"] = "FOREIGN"
    if fault == "mkey": value["mkey"] = "foreign-user"
    if fault == "error": value["error"] = -1
    if fault == "http-bool": value["http_status"] = True
    if fault == "extra-result": value["results"]["unknown"] = TOKEN
    if fault == "too-many-results": value["results"].update(unknown=TOKEN,other=TOKEN)
    if fault == "missing-token": value["results"] = {"unknown":TOKEN}
    if fault == "unknown-root": value["unknown"] = TOKEN
    if fault == "token-object": value["results"]["access_token"] = {"secret":TOKEN}
    if fault == "empty": value["results"]["access_token"] = ""
    if fault == "escaped": value["results"]["access_token"] = TOKEN+"\n"
    if fault == "large": value["results"]["access_token"] = TOKEN+"x"*4096
    raw = bytearray(json.dumps(value).encode());original = c.json.loads
    def only_nonmaterial(data,*args,**kwargs):
        if isinstance(data,(bytes,bytearray,str)):
            assert (TOKEN not in data if isinstance(data,str)else TOKEN.encode()not in data)
        return original(data,*args,**kwargs)
    monkeypatch.setattr(c.json,"loads",only_nonmaterial)
    if fault in (None,"extra-result"):
        witness = c.consume_jwt_user_initialization(raw,binding=binding,claim_digest="a"*64,witness_key=b"w"*32)
        assert len(witness) == 64 and TOKEN not in witness
    else:
        with pytest.raises(ValueError): c.consume_jwt_user_initialization(raw,binding=binding,claim_digest="a"*64,witness_key=b"w"*32)
    assert not raw


def test_supplementary_credential_result_is_opaque_even_when_nested(synthetic_key,replacement,monkeypatch):
    binding,_ = fixture(synthetic_key,replacement)
    value = packet("api-user",{"access_token":TOKEN,"opaque":{"value":TOKEN}},http_method="POST",action="generate-key")
    raw = bytearray(json.dumps(value).encode());original = c.json.loads
    def only_nonmaterial(data,*args,**kwargs):
        assert TOKEN.encode() not in data if isinstance(data,(bytes,bytearray)) else TOKEN not in data
        return original(data,*args,**kwargs)
    monkeypatch.setattr(c.json,"loads",only_nonmaterial)
    witness = c.consume_jwt_user_initialization(raw,binding=binding,claim_digest="a"*64,witness_key=b"w"*32)
    assert len(witness) == 64 and not raw
