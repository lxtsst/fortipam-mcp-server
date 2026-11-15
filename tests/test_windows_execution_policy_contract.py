"""Inactive Policy evidence stays exact and cannot become ownership authority."""
from dataclasses import replace
import hashlib
import json

import pytest

from fortipam_mcp.windows_execution_policy_contract import (
    WindowsExecutionPolicyBinding, WindowsExecutionPolicyError,
    compile_windows_execution_policy, consume_windows_policy_response, consume_windows_policy_state,
    CANONICAL_PROFILE,
)

SERIAL = "FPAVUNIT000001"
BINDING = WindowsExecutionPolicyBinding("mcp-v4-secret-policy-winexec-20261022-r9",
    hashlib.sha256(SERIAL.encode()).hexdigest())


def defaults():
    return {
        "name":"", "password-changer":"not-set", "password-heartbeat":"not-set", "checkout":"not-set",
        "recording":"not-set", "need-approval":"not-set", "need-approval-job":"not-set", "av-scan":"not-set",
        "dlp-status":"not-set", "proxy":"enable", "ssh-filter":"not-set", "ssh-algorithm":"not-set",
        "winappfilter":"not-set", "rdp-remote-app":"not-set", "rdp-remote-app-profile":"",
        "rdp-remote-app-owner-exempt":"disable", "rdp-security-level":"not-set", "rdp-auto-totp":"not-set",
        "rdp-restricted-admin-mode":"not-set", "block-clipboard":"not-set", "cert-expiry-log":"not-set",
        "pwd-chg-sch-frequency":"day", "pwd-chg-sch-interval":1, "pwd-chg-sch-month-type":"first",
        "pwd-chg-sch-month-day":"", "pwd-chg-sch-week-day":"", "pwd-chg-sch-start-date":"2026-01-01 00:00:00",
        "heartbeat-interval":60, "heartbeat-start-time":"2026-01-01 00:00:00", "checkout-duration":30,
        "force-checkout-idle-time":0, "checkin-pwd-change":"not-set", "checkout-duration-renew":"not-set",
        "checkout-renew-times":1, "tunnel-encryption":"not-set", "secret-auth":"not-set", "secret-auth-server":"",
        "secret-auth-duration":60, "secret-auth-owner-exempt":"disable", "bypass-approval":"disable",
        "approval-profile":"", "ssh-filter-profile":"", "bypass-ssh-filter-for-owner":"disable",
        "winappfilter-profile":"", "dlp-sensor":"", "av-profile":"", "pwd-chg-secret-edit":"disable",
        "heartbeat-secret-edit":"disable", "rdp-event-filter":"not-set", "rdp-event-filter-profile":"",
        "credential-expire-notification":"not-set", "credential-expiry-after":90,
        "last-credential-change-date":"", "rdp-nla-kerberos":"not-set",
    }


def envelope(results, **changes):
    value = dict(version="v7.0.0", build=29, http_method="GET", http_status=200,
        status="success", serial=SERIAL, path="secret", name="policy", vdom="root", results=results)
    value.update(changes)
    return bytearray(json.dumps(value).encode())


def sources(*, native=False):
    values = defaults()
    if native:
        values['tunnel-encryption'] = 'enable'
    children = {key:dict(type="integer" if type(value) is int else
        "datetime" if key in ("pwd-chg-sch-start-date", "heartbeat-start-time", "last-credential-change-date") else
        "string" if key == "name" or key.endswith("-profile") or key in ("dlp-sensor", "secret-auth-server") else "option")
        for key, value in values.items()}
    return envelope([{"children":children}], action="schema"), envelope([values], action="default")


def compile_request():
    return compile_windows_execution_policy(*sources(), binding=BINDING)


def state(request, **changes):
    value = json.loads(request.expected_state_json)
    value.update(q_origin_key=BINDING.name, q_ref=0, q_static=False, q_no_edit=False, q_no_rename=False,
        q_global_entry=False, q_type=1, q_path="secret", q_name="policy", q_mkey_type="string")
    value.update(changes)
    return envelope([value], mkey=BINDING.name)


def test_inactive_request_preserves_other_defaults_and_binds_full_state_without_ownership():
    schema, raw = sources()
    request = compile_windows_execution_policy(schema, raw, binding=BINDING)
    assert not any(schema) and not any(raw)
    wire = json.loads(request.body_json)
    assert len(wire) == 51 and wire["$originalName"] == "" and "winrm-https" not in wire
    assert wire["proxy"] == wire["password-changer"] == wire["pwd-chg-secret-edit"] == "disable"
    assert wire["heartbeat-interval"] == 60 and wire["checkout-duration"] == 30
    assert "credential-expiry-after" not in wire
    assert json.loads(request.expected_state_json)["credential-expiry-after"] == 90
    assert wire["pwd-chg-sch-frequency"] == "unknown" and wire["pwd-chg-sch-interval"] == 0
    raw = state(request)
    fingerprint = consume_windows_policy_state(raw, request=request)
    assert len(fingerprint) == 64 and not any(raw)
    assert consume_windows_policy_state(state(request), request=request) == fingerprint
    assert not hasattr(request, "ownership")


@pytest.mark.parametrize("failure", ["ui-field", "schema-extra", "schema-missing", "readonly", "type",
    "option-type", "preserved-type", "default-extra", "default-missing", "relation", "malformed-default", "schema-error", "serial"])
def test_changed_sources_refuse_and_erase_both_buffers(failure):
    first, second = (json.loads(raw) for raw in sources())
    if failure == "ui-field":
        first["results"][0]["children"]["winrm-https"] = {"type":"option"}
    if failure == "schema-extra":first["results"][0]["children"]["new-feature"] = {"type":"option"}
    if failure == "schema-missing":del first["results"][0]["children"]["proxy"]
    if failure == "readonly":first["results"][0]["children"]["proxy"]["read_only"] = True
    if failure == "type":first["results"][0]["children"]["heartbeat-interval"]["type"] = "option"
    if failure == "option-type":first["results"][0]["children"]["proxy"]["type"] = "string"
    if failure == "preserved-type":second["results"][0]["last-credential-change-date"] = 0
    if failure == "default-extra":second["results"][0]["extra"] = ""
    if failure == "default-missing":del second["results"][0]["proxy"]
    if failure == "relation":second["results"][0]["approval-profile"] = "shared-profile"
    if failure == "malformed-default":second["results"][0]["proxy"] = True
    if failure == "schema-error":first["schema_errors"] = []
    if failure == "serial":second["serial"] = "WRONG"
    schema, raw = (bytearray(json.dumps(value).encode()) for value in (first, second))
    with pytest.raises(WindowsExecutionPolicyError):compile_windows_execution_policy(schema, raw, binding=BINDING)
    assert not any(schema) and not any(raw)


@pytest.mark.parametrize("phase", ["create", "delete", "absent"])
def test_exact_ack_and_absence_shapes_consume_bytes_and_reject_wrong_route(phase):
    status = 404 if phase == "absent" else 200
    method = {"create":"POST", "delete":"DELETE", "absent":"GET"}[phase]
    value = json.loads(envelope([], http_method=method, http_status=status,
        status="error" if phase == "absent" else "success", mkey=BINDING.name, error=0))
    if phase == "absent":
        del value["error"]
        del value["results"]
    raw = bytearray(json.dumps(value).encode())
    assert len(consume_windows_policy_response(raw, binding=BINDING, phase=phase, http_status=status)) == 64
    assert not any(raw)
    value["name"] = "target"
    raw = bytearray(json.dumps(value).encode())
    with pytest.raises(WindowsExecutionPolicyError):
        consume_windows_policy_response(raw, binding=BINDING, phase=phase, http_status=status)
    assert not any(raw)


@pytest.mark.parametrize("changes", [{"q_ref":1}, {"q_ref":False}, {"q_static":True}, {"proxy":"enable"},
    {"q_origin_key":"other"}, {"future-control":"disable"}, {"approval-profile":"shared-profile"},
    {"credential-expiry-after":91}, {"credential-expire-notification":"enable"}])
def test_current_state_needs_every_original_field_and_zero_references(changes):
    request = compile_request()
    raw = state(request, **changes)
    with pytest.raises(WindowsExecutionPolicyError):consume_windows_policy_state(raw, request=request)
    assert not any(raw)


def test_request_mutation_or_ambiguous_json_cannot_validate():
    request = compile_request()
    with pytest.raises(WindowsExecutionPolicyError):replace(request, body_json=request.body_json+" ").validate()
    body = request.body_json[:-1]+',"proxy":"disable"}'
    with pytest.raises(WindowsExecutionPolicyError):replace(request, body_json=body,
        body_digest=hashlib.sha256(body.encode()).hexdigest()).validate()


@pytest.mark.parametrize("changes", [{"schema_errors":[]}, {"error":True}, {"error":-3},
    {"serial":"OTHER"}, {"mkey":"other"}, {"build":True}, {"action":"set"}])
def test_unqualified_ack_never_produces_evidence_and_erases_bytes(changes):
    value = dict(http_method="POST", mkey=BINDING.name, error=0)
    value.update(changes)
    raw = envelope([], **value)
    with pytest.raises(WindowsExecutionPolicyError):
        consume_windows_policy_response(raw, binding=BINDING, phase="create", http_status=200)
    assert not any(raw)


def test_target_absence_shape_is_not_policy_absence():
    raw = envelope([], http_status=404, status="Not Found", error=2, mkey=BINDING.name)
    with pytest.raises(WindowsExecutionPolicyError):
        consume_windows_policy_response(raw, binding=BINDING, phase="absent", http_status=404)
    assert not any(raw)


def backend_normalized_state():
    # Independent native-model fixture: dormant values reset to backend
    # defaults, non-TLS Auto TOTP is disabled, disabled proxy delegates tunnel.
    # Never derive this row from the compiler's expected-state projection.
    value = defaults()
    value.update(dict.fromkeys(('password-changer', 'password-heartbeat', 'pwd-chg-secret-edit',
        'heartbeat-secret-edit', 'checkout', 'recording', 'need-approval', 'need-approval-job',
        'av-scan', 'dlp-status', 'proxy', 'ssh-filter', 'winappfilter', 'secret-auth',
        'rdp-event-filter', 'block-clipboard'), 'disable'))
    value.update(name=BINDING.name, **{'rdp-auto-totp':'disable', 'tunnel-encryption':'not-set'})
    value.update(q_origin_key=BINDING.name, q_ref=0, q_static=False, q_no_edit=False, q_no_rename=False,
        q_global_entry=False, q_type=1, q_path='secret', q_name='policy', q_mkey_type='string')
    return envelope([value], mkey=BINDING.name)


def test_explicit_v2_accepts_native_normalization_without_weakening_original_v1():
    original = compile_windows_execution_policy(*sources(native=True), binding=BINDING)
    canonical = compile_windows_execution_policy(*sources(native=True), binding=BINDING, profile=CANONICAL_PROFILE)
    assert original.body_json == canonical.body_json
    assert original.defaults_digest == canonical.defaults_digest
    assert original.request_digest != canonical.request_digest
    with pytest.raises(WindowsExecutionPolicyError):
        consume_windows_policy_state(backend_normalized_state(), request=original)
    assert len(consume_windows_policy_state(backend_normalized_state(), request=canonical)) == 64
    with pytest.raises(WindowsExecutionPolicyError):
        replace(original, profile=CANONICAL_PROFILE, defaults_json=canonical.defaults_json).validate()
    with pytest.raises(WindowsExecutionPolicyError):
        replace(canonical, profile='strict-wire-v1', defaults_json=None).validate()


@pytest.mark.parametrize('changes', [{'password-changer':'enable'}, {'password-heartbeat':'not-set'},
    {'checkout':'not-set'}, {'proxy':'not-set'}, {'rdp-auto-totp':'not-set'}, {'tunnel-encryption':'enable'},
    {'checkin-pwd-change':'disable'}, {'pwd-chg-sch-interval':0}, {'q_ref':1}])
def test_v2_still_requires_exact_inactive_parent_and_canonical_dormant_state(changes):
    request = compile_windows_execution_policy(*sources(native=True), binding=BINDING, profile=CANONICAL_PROFILE)
    raw = json.loads(backend_normalized_state())
    raw['results'][0].update(changes)
    with pytest.raises(WindowsExecutionPolicyError):
        consume_windows_policy_state(bytearray(json.dumps(raw).encode()), request=request)


def test_v2_cannot_accept_changed_default_projection_or_unqualified_rdp_mode():
    schema, raw = sources(native=True)
    value = json.loads(raw);value['results'][0]['rdp-security-level'] = 'tls'
    with pytest.raises(WindowsExecutionPolicyError):
        compile_windows_execution_policy(schema, bytearray(json.dumps(value).encode()), binding=BINDING,
            profile=CANONICAL_PROFILE)
    request = compile_windows_execution_policy(*sources(native=True), binding=BINDING, profile=CANONICAL_PROFILE)
    value = json.loads(request.defaults_json);value['checkout-duration'] += 1
    with pytest.raises(WindowsExecutionPolicyError):
        replace(request, defaults_json=json.dumps(value, separators=(',', ':'))).validate()
