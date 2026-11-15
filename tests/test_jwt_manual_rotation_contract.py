"""Private rotation bodies and complete ordered-key/invariant enforcement."""
from copy import deepcopy
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric import rsa
import pytest

from fortipam_mcp import jwt_manual_rotation_contract as c
from fortipam_mcp.jwt_manual_key_contract import JwtManualPublicKey
from test_jwt_manual_key_contract import synthetic_key, public_pem
from test_jwt_manual_key_owned_state import request, owned_row
from test_jwt_manual_key_preflight import NAME, SERIAL, packet


@pytest.fixture(scope="module")
def replacement(): return rsa.generate_private_key(public_exponent=65537,key_size=2048)


def fixture(old,new):
    binding = c.JwtManualRotationBinding(NAME,"mcp-v4-jwt-u-"+"a"*18,"f"*64,serial_digest=SERIAL)
    keys = c.JwtManualRotationKeys(JwtManualPublicKey(public_pem(old)),JwtManualPublicKey(public_pem(new)))
    return binding,keys


@pytest.mark.parametrize("phase", ["user-create","user-initialize","overlap","cutover","restore"])
def test_native_private_wire_is_exact_and_closed_metadata_cannot_resend(synthetic_key,replacement,phase):
    b,k = fixture(synthetic_key,replacement); r = c.JwtManualRotationRequest(b,k,phase=phase)
    with r.borrow_body() as view: value = json.loads(view.tobytes())
    if phase == "user-create":
        assert r.method == "POST" and r.path == "/api/v2/cmdb/system/api-user" and len(value) == 11
        assert value["$originalName"] == "" and value["lease-duration"] == 10 and value["accprofile"] == "pam_standard_user"
        assert value["claims"] == b.user_config()["claims"] and all(v["type"] == "default" for v in value["claims"])
        assert not {"password","api-key","status","role"} & value.keys()
    elif phase == "user-initialize":
        assert r.method == "POST" and r.path == "/api/v2/monitor/system/api-user/generate-key"
        assert value == {"api-user":b._user_name}
    else:
        assert r.method == "PUT" and r.path.endswith("/secret/jwt-key/"+NAME)
        assert set(value) == {"q_origin_key","name","type","key","jwks-url","check-interval","ca","claim"}
        assert value["key"] == k.members(phase) and value["claim"] == []
        if phase == "overlap":
            assert value["key"] == [{"key-name":public_pem(replacement).decode()},{"key-name":public_pem(synthetic_key).decode()}]
    assert r.query == (""if phase == "user-initialize"else"with_meta=true") and r._metadata_digest() == r.digest
    before = r.digest; r.close()
    assert r._closed and not any(r._body) and r.digest == before
    with pytest.raises(c.JwtManualRotationContractError): r.borrow_body()
    assert NAME not in repr(r) and b._issuer not in repr(b) and "BEGIN" not in repr(k)


@pytest.mark.parametrize("bad", ["foreign-key-name","overlong-key-name","foreign-user-name","bad-nonce","bad-serial"])
def test_invalid_binding_cannot_compile_an_unbounded_identity(synthetic_key,replacement,bad):
    values = dict(key_name=NAME,user_name="mcp-v4-jwt-u-"+"a"*18,nonce="f"*64,serial_digest=SERIAL)
    if bad == "foreign-key-name": values["key_name"] = "existing-key"
    if bad == "overlong-key-name": values["key_name"] = "mcp-v4-jwt-"+"a"*25
    if bad == "foreign-user-name": values["user_name"] = "admin"
    if bad == "bad-nonce": values["nonce"] = "A"*64
    if bad == "bad-serial": values["serial_digest"] = "f"*63
    with pytest.raises(c.JwtManualRotationContractError): c.JwtManualRotationBinding(**values)


def test_duplicate_public_key_or_unknown_phase_cannot_become_rotation(synthetic_key,replacement):
    b,k = fixture(synthetic_key,replacement)
    with pytest.raises(c.JwtManualRotationContractError): c.JwtManualRotationKeys(k._old,k._old)
    for phase in ("original","rotate",True):
        with pytest.raises(c.JwtManualRotationContractError): c.JwtManualRotationRequest(b,k,phase=phase)
    r = c.JwtManualRotationRequest(b,k,phase="overlap"); r._body[0] = 0
    with pytest.raises(c.JwtManualRotationContractError): r.borrow_body()
    assert not any(r._body)


def observe(row,b,k,phase="original",refs=0,expected=None):
    inputs = [bytearray(json.dumps(packet("jwt-key",[deepcopy(row)],mkey=NAME)).encode())for _ in range(2)]
    try:
        return c.consume_jwt_rotation_key_state(*inputs,binding=b,keys=k,phase=phase,reference_count=refs,
            witness_key=b"w"*32,expected_invariant_hmac=expected)
    finally: assert all(not raw for raw in inputs)


def test_overlap_cutover_restore_preserve_all_non_key_and_reference_fields(synthetic_key,replacement):
    b,k = fixture(synthetic_key,replacement); row = owned_row(request(synthetic_key))
    first = observe(row,b,k)
    for phase,refs in (("overlap",1),("cutover",1),("restore",1),("restore",0)):
        row["key"] = k.members(phase); row["q_ref"] = refs
        state = observe(row,b,k,phase,refs,first.invariant_hmac)
        assert state.invariant_hmac == first.invariant_hmac
        assert state.complete_row_hmac != first.complete_row_hmac or phase == "restore" and refs == 0


@pytest.mark.parametrize("fault", ["extra","missing","wrong-old-key","duplicate-key","member-extra","wrong-ref","bool-ref","extra-claim","remote-type","remote-url","origin","static","q-type","time-drift","time-control"])
def test_unqualified_key_or_preservation_change_never_becomes_current_state(synthetic_key,replacement,fault):
    b,k = fixture(synthetic_key,replacement); row = owned_row(request(synthetic_key)); original = observe(row,b,k)
    row["key"] = k.members("overlap"); row["q_ref"] = 1
    if fault == "extra": row["unqualified"] = "PRIVATE_VALUE"
    if fault == "missing": del row["q_ref"]
    if fault == "wrong-old-key": row["key"][0]["key-name"] = "PRIVATE_KEY_IS_NOT_ACCEPTED"
    if fault == "duplicate-key": row["key"][1] = row["key"][0]
    if fault == "member-extra": row["key"][0]["unknown"] = "PRIVATE_VALUE"
    if fault == "wrong-ref": row["q_ref"] = 2
    if fault == "bool-ref": row["q_ref"] = True
    if fault == "extra-claim": row["claim"] = [{"claim-name":"unapproved"}]
    if fault == "remote-type": row["type"] = "jwks"
    if fault == "remote-url": row["jwks-url"] = "https://unapproved.invalid"
    if fault == "origin": row["q_origin_key"] = "foreign"
    if fault == "static": row["q_static"] = True
    if fault == "q-type": row["q_type"] = True
    if fault == "time-drift": row["last-update-time"] = "synthetic-changed"
    if fault == "time-control": row["last-update-time"] = "bad\nvalue"
    with pytest.raises(c.JwtManualRotationContractError): observe(row,b,k,"overlap",1,original.invariant_hmac)


def test_bracket_drift_and_foreign_envelope_clear_every_buffer(synthetic_key,replacement):
    b,k = fixture(synthetic_key,replacement); row = owned_row(request(synthetic_key))
    one = packet("jwt-key",[row],mkey=NAME); two = deepcopy(one); two["results"][0]["q_ref"] = 1
    for bad in (two,{**one,"serial":"FOREIGN"},{**one,"mkey":"foreign"}):
        raw = [bytearray(json.dumps(v).encode())for v in(one,bad)]
        with pytest.raises(c.JwtManualRotationContractError):
            c.consume_jwt_rotation_key_state(*raw,binding=b,keys=k,phase="original",reference_count=0,witness_key=b"w"*32)
        assert all(not b for b in raw)


def test_keyed_member_permutation_preserves_full_actual_row_witness_and_bracket_drift(synthetic_key,replacement):
    b,k = fixture(synthetic_key,replacement);row = owned_row(request(synthetic_key));baseline = observe(row,b,k)
    row["key"] = k.members("overlap");row["q_ref"] = 1
    submitted = observe(row,b,k,"overlap",1,baseline.invariant_hmac)
    before = packet("jwt-key",[deepcopy(row)],mkey=NAME)
    row["key"].reverse();native = observe(row,b,k,"overlap",1,baseline.invariant_hmac)
    assert submitted.invariant_hmac == native.invariant_hmac
    assert submitted.complete_row_hmac != native.complete_row_hmac
    after = packet("jwt-key",[row],mkey=NAME);raw = [bytearray(json.dumps(v).encode())for v in(before,after)]
    with pytest.raises(c.JwtManualRotationContractError):
        c.consume_jwt_rotation_key_state(*raw,binding=b,keys=k,phase="overlap",reference_count=1,witness_key=b"w"*32,expected_invariant_hmac=baseline.invariant_hmac)
    assert all(not v for v in raw)
