"""Exact optional JWT User relationship; no tokens, source IO or authority."""
from copy import deepcopy
import json

import pytest

from fortipam_mcp import jwt_rotation_dependency_projection as c
from test_jwt_manual_rotation_contract import fixture,replacement
from test_jwt_manual_key_contract import synthetic_key
from test_jwt_manual_key_preflight import packet


def buffers(value): return bytearray(json.dumps(value).encode())


def collection(table,rows): return packet(table,rows,size=len(rows),matched_count=len(rows),next_idx=max(0,len(rows)-1))


def deps(b,present=False):
    keys = collection("jwt-key",[{"name":b._key_name,"type":"manually"}])
    users = [{"name":"synthetic-existing-api","type":"legacy","jwt-key":""}]
    if present: users.append({"name":b._user_name,"type":"jwt","jwt-key":b._key_name})
    return keys,collection("api-user",users)


def test_only_new_owned_relationship_changes_while_other_users_are_preserved(synthetic_key,replacement):
    b,_ = fixture(synthetic_key,replacement)
    first = c.consume_jwt_rotation_dependencies(*map(buffers,deps(b)),binding=b,user_present=False)
    second = c.consume_jwt_rotation_dependencies(*map(buffers,deps(b,True)),binding=b,user_present=True,
        expected_other_users_digest=first.other_users_digest)
    assert first.other_users_digest == second.other_users_digest and first.complete_namespace_digest != second.complete_namespace_digest
    final = c.consume_jwt_rotation_dependencies(*map(buffers,deps(b)),binding=b,user_present=False,
        expected_other_users_digest=first.other_users_digest)
    assert final == first


@pytest.mark.parametrize("fault", ["foreign-key","wrong-key-type","extra-key","wrong-user-key","wrong-user-type","other-jwt","other-key-reference","missing-user","truncated","filtered","duplicate-user","other-user-drift"])
def test_incomplete_foreign_or_changed_dependencies_never_qualify(synthetic_key,replacement,fault):
    b,_ = fixture(synthetic_key,replacement)
    baseline = c.consume_jwt_rotation_dependencies(*map(buffers,deps(b)),binding=b,user_present=False)
    key,user = deps(b,True)
    if fault == "foreign-key": key["results"][0]["name"] = "foreign"
    if fault == "wrong-key-type": key["results"][0]["type"] = "jwks"
    if fault == "extra-key": key = collection("jwt-key",key["results"]+[{"name":"foreign","type":"manually"}])
    if fault == "wrong-user-key": user["results"][1]["jwt-key"] = "foreign"
    if fault == "wrong-user-type": user["results"][1]["type"] = "legacy"
    if fault == "other-jwt": user["results"][0]["type"] = "jwt"
    if fault == "other-key-reference": user["results"][0]["jwt-key"] = b._key_name
    if fault == "missing-user": user = collection("api-user",user["results"][:1])
    if fault == "truncated": user["matched_count"] += 1
    if fault == "filtered": user["filtered_count"] = 2
    if fault == "duplicate-user": user = collection("api-user",user["results"]+[deepcopy(user["results"][1])])
    if fault == "other-user-drift": user["results"][0]["name"] = "changed"
    raw = [buffers(v)for v in(key,user)]
    with pytest.raises(c.JwtRotationDependencyError):
        c.consume_jwt_rotation_dependencies(*raw,binding=b,user_present=True,expected_other_users_digest=baseline.other_users_digest)
    assert all(not value for value in raw)


def user_row(b):
    config = b.user_config()
    config["claims"] = [{**claim,"q_origin_key":claim["name"]}for claim in config["claims"]]
    return {**config,"q_origin_key":b._user_name,"q_path":"system","q_name":"api-user",
        "q_mkey_type":"string","q_ref":0,"q_type":0,"q_static":False,"q_no_edit":False,"q_no_rename":True,"q_global_entry":False}


def observe(b,row,expected=None):
    raw = [buffers(packet("api-user",[deepcopy(row)],mkey=b._user_name))for _ in range(2)]
    try:
        return c.consume_jwt_rotation_owned_user(*raw,binding=b,witness_key=b"w"*32,expected_projection_hmac=expected)
    finally: assert all(not value for value in raw)


def test_full_native_user_projection_is_exact_and_preservable(synthetic_key,replacement):
    b,_ = fixture(synthetic_key,replacement); row = user_row(b); first = observe(b,row)
    assert observe(b,row,first.complete_projection_hmac) == first
    assert b._user_name not in repr(first)


@pytest.mark.parametrize("fault", ["material-field","extra","missing","wrong-profile","wrong-key","regex-claim","wrong-issuer","extra-claim","lease","bool-lease","trusthost","vdom","q-ref","bool-ref","foreign-origin","q-type-drift","claim-origin","claim-material","claim-no-origin","rename-metadata"])
def test_changed_or_unclassified_owned_user_cannot_become_delete_or_launch_evidence(synthetic_key,replacement,monkeypatch,fault):
    b,_ = fixture(synthetic_key,replacement); row = user_row(b); first = observe(b,row)
    if fault == "material-field": row["api-key"] = "PRIVATE_MATERIAL"
    if fault == "extra": row["unknown"] = "PRIVATE_MATERIAL"
    if fault == "missing": del row["claims"]
    if fault == "wrong-profile": row["accprofile"] = "super_admin"
    if fault == "wrong-key": row["jwt-key"] = "foreign"
    if fault == "regex-claim": row["claims"][0]["type"] = "regex"
    if fault == "wrong-issuer": row["claims"][0]["value"] += "-foreign"
    if fault == "extra-claim": row["claims"].append({"name":"custom","value":"value","type":"default"})
    if fault == "lease": row["lease-duration"] = 60
    if fault == "bool-lease": row["lease-duration"] = True
    if fault == "trusthost": row["trusthost"] = [{"id":1}]
    if fault == "vdom": row["vdom"] = []
    if fault == "q-ref": row["q_ref"] = 1
    if fault == "bool-ref": row["q_ref"] = False
    if fault == "foreign-origin": row["q_origin_key"] = "foreign"
    if fault == "q-type-drift": row["q_type"] = 1
    if fault == "claim-origin": row["claims"][0]["q_origin_key"] = "foreign"
    if fault == "claim-material": row["claims"][0]["password"] = "PRIVATE_MATERIAL"
    if fault == "claim-no-origin": del row["claims"][0]["q_origin_key"]
    if fault == "rename-metadata": row["q_no_rename"] = False
    original = c.json.loads
    def protected_only(raw,*a,**k):
        if isinstance(raw,(bytes,bytearray)): assert b"PRIVATE_MATERIAL" not in raw
        return original(raw,*a,**k)
    monkeypatch.setattr(c.json,"loads",protected_only)
    with pytest.raises(c.JwtRotationDependencyError): observe(b,row,first.complete_projection_hmac)


@pytest.mark.parametrize("fault", [None,"wrong-mkey","wrong-status","wrong-device","result-present","error","bool-status"])
def test_exact_user_absence_is_not_inferred_from_other_errors(synthetic_key,replacement,fault):
    b,_ = fixture(synthetic_key,replacement)
    value = packet("api-user",None,mkey=b._user_name,http_status=404,status="error")
    if fault == "wrong-mkey": value["mkey"] = "foreign"
    if fault == "wrong-status": value["http_status"] = 403
    if fault == "wrong-device": value["serial"] = "FOREIGN"
    if fault == "result-present": value["results"] = [{"name":b._user_name}]
    if fault == "error": value["error"] = -37
    if fault == "bool-status": value["http_status"] = True
    raw = buffers(value)
    if fault is None: assert len(c.consume_jwt_rotation_user_absence(raw,binding=b)) == 64
    else:
        with pytest.raises(c.JwtRotationDependencyError): c.consume_jwt_rotation_user_absence(raw,binding=b)
    assert not raw
