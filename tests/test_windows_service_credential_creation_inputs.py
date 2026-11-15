"""Fixed creation-input reads with actual source objects and synthetic HTTP."""
import copy
from dataclasses import replace
import json
import logging
import pickle

import httpx
import pytest

from fortipam_mcp import windows_service_credential_creation_inputs as r
from fortipam_mcp.windows_service_credential_contract import _metadata, build_windows_service_credential_body
from test_windows_execution_secret_contract import defaults
from test_windows_service_credential_contract import binding
from test_windows_service_credential_target_sources import (
    Harness as TargetHarness, Body, envelope, payloads, NAME, ADDRESS, SERIAL, DIGEST,
)
from v4_planning.material_provider import MaterialAccessDenied


def input_payloads(*, same_template=False):
    names = set(_metadata(binding())) | set(r._REQUIRED_SCHEMA)
    for index in range(124 - len(names)):
        names.add(f"native-extra-{index:03}")
    assert len(names) == 124
    baseline = defaults();baseline["serial"] = SERIAL;baseline["action"] = "default"
    for name in names:
        baseline["results"].setdefault(name, "UNSELECTED_DEFAULT_SENTINEL")
    schema = envelope({"children": {name: {"type": "var-string", "opaque": "UNSELECTED_SCHEMA_SENTINEL"}
        for name in sorted(names)}})
    schema.update(name="database", action="schema")
    def template(name, *, builtin):
        value = envelope([dict(name=name, field=[dict(name=label, type=kind,
            mandatory="disable" if builtin and label != "Host" else "enable")
            for label, kind in r._KINDS.items()], permissions=dict(user="owner"),
            opaque="UNSELECTED_TEMPLATE_SENTINEL")], runtime=True)
        value["name"] = "template"
        return value
    builtin = template(r._BUILTIN, builtin=True)
    selected = template("Synthetic Template", builtin=False)
    actor = payloads()[0]
    actor["results"]["admin"]["profile"].update(secretgrp="custom",
        **{"secretgrp-permission": dict.fromkeys(r._ROLE_RIGHTS, "read-write")})
    values = [actor, baseline, schema, builtin, builtin, schema, baseline, actor] if same_template else [
        actor, baseline, schema, builtin, selected, selected, builtin, schema, baseline, actor]
    return [copy.deepcopy(value) for value in values]


class Harness(TargetHarness):
    def __init__(self, *, same_template=False):
        super().__init__()
        self.inputs = input_payloads(same_template=same_template)
        for index in (0, 5):
            self.values[index]["results"]["admin"]["profile"].update(secretgrp="custom",
                **{"secretgrp-permission": dict.fromkeys(r._ROLE_RIGHTS, "read-write")})
        if same_template:
            for index in (1, 4): self.values[index]["results"][0]["template"] = r._BUILTIN
            for index in (2, 3): self.values[index]["results"][0]["template"] = r._BUILTIN
    def factory(self, **options):
        client = super().factory(**options)
        if self.fault == "enter":
            client.cookies.set("synthetic-factory-cookie", "private")
            def fail_enter(self):
                raise OSError("PRIVATE_ENTER_SENTINEL")
            type(client).__enter__ = fail_enter
        return client
    def handle(self, request):
        if len(self.requests) < 6:
            return super().handle(request)
        index = len(self.requests) - 6;self.requests.append(request)
        logging.getLogger("httpcore.http11").debug("PRIVATE_INPUT_HEADER_SENTINEL")
        data = json.dumps(self.inputs[index]).encode()
        headers = {"content-type": "application/json", "set-cookie": "synthetic=private"}
        status = 200
        if index == 2:
            if self.fault == "oversize": data = b"x" * 1048577
            if self.fault == "truncated": data = data[:-1]
            if self.fault == "trailing": data += b"{}"
            if self.fault == "length": headers["content-length"] = str(len(data) + 1)
            if self.fault == "encoding": headers["content-encoding"] = "gzip"
            if self.fault == "type": headers["content-type"] = "text/html"
            if self.fault == "status": status = 403
            if self.fault == "redirect": status = 302;headers["location"] = "https://other.invalid/private"
            if self.fault == "late-headers": self.now = 40.0
        stream = Body(data, self, index);self.streams.append(stream)
        return httpx.Response(status, headers=headers, stream=stream)
    def prepare(self):
        target = self.reader();observed = target.read_once()
        source = r.WindowsServiceCredentialCreationInputs(target_sources=target, target_observation=observed)
        return target, observed, source


@pytest.mark.parametrize("same_template", [False, True])
def test_same_target_origin_lifetime_fixed_reads_and_native_size_minimum(monkeypatch, caplog, same_template):
    h = Harness(same_template=same_template);target, reference, source = h.prepare();owned = []
    receive = source._receive
    def track(*args, **kwargs):
        value = receive(*args, **kwargs);owned.append(value);return value
    monkeypatch.setattr(source, "_receive", track)
    caplog.set_level(logging.DEBUG)
    observed = source.read_once();source.check_current(observed)
    profile = replace(binding(), target_name=NAME, target_address=ADDRESS, serial_digest=DIGEST,
        target_reference_context_digest=reference.target_reference_context_digest)
    source.check_profile(observed, profile)
    assert len(observed.full_row_fields) == 126 and r._RUNTIME_FIELDS <= observed.full_row_fields
    assert observed.expires_at == reference.expires_at == 40.0
    assert observed.defaults.serial_digest == reference.configuration.serial_digest
    assert len(h.requests) == (14 if same_template else 16)
    requests = h.requests[6:]
    assert requests[0].url.path == requests[-1].url.path == r._ACTOR
    assert [str(q.url) for q in requests[:len(requests)//2]] == [str(q.url) for q in reversed(requests[len(requests)//2:])]
    names = [json.loads(q.content)["json_filter"][0]["filters"][0]["pattern"] for q in requests if q.method == "POST"]
    assert names == ([r._BUILTIN, r._BUILTIN] if same_template else [r._BUILTIN, "Synthetic Template", "Synthetic Template", r._BUILTIN])
    for request in requests:
        assert request.headers["authorization"] == "Bearer synthetic-token" and "cookie" not in request.headers
        assert request.headers["accept-encoding"] == "identity"
        if request.method == "POST": assert request.headers["x-http-method-override"] == "GET"
        else: assert not request.content
    assert all(not value for value in owned) and all(s.closed for s in h.streams)
    assert all(c.is_closed and not c.cookies for c in h.clients)
    assert h.options[0]["verify"] is h.options[1]["verify"] and not h.options[1]["trust_env"]
    assert "PRIVATE_" not in caplog.text and "synthetic-token" not in caplog.text
    for value in (source, observed):
        assert NAME not in repr(value)
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(MaterialAccessDenied): operation(value)
    username, password = bytearray(b"UNIT-WINDOWS\\labuser"), bytearray(b"synthetic-credential")
    body = build_windows_service_credential_body(profile, observed.defaults,
        create_uuid="00000000-0000-0000-0000-000000000000", username=memoryview(username).toreadonly(),
        password=memoryview(password).toreadonly())
    try:
        assert json.loads(body)["target"] == NAME
        assert json.loads(body)["target-privilege-account"] == "disable"
    finally:
        for value in (body, username, password): r._zeroize_mutable(value)
    source.close();target.check_current(reference)
    assert not target._closed
    with pytest.raises(r.WindowsServiceCredentialCreationInputError): source.check_current(observed)
    target.close()


@pytest.mark.parametrize("index", range(10))
def test_every_response_remains_bound_to_the_same_native_device(index):
    h = Harness();_, _, source = h.prepare();h.inputs[index]["serial"] = "OTHER"
    with pytest.raises(r.WindowsServiceCredentialCreationInputError): source.read_once()
    assert len(h.requests) == 7 + index


@pytest.mark.parametrize("fault", ["factory", "enter", "oversize", "truncated", "trailing", "length", "encoding", "type", "status",
    "redirect", "late-headers", "stream", "late-eof", "clock-rollback", "response-close", "client-close", "late-client-close"])
def test_incomplete_or_failed_transport_consumes_only_the_new_window_and_clears_buffers(fault, monkeypatch):
    h = Harness();_, _, source = h.prepare();h.fault = fault;owned = [];receive = source._receive
    def track(*args, **kwargs):
        value = receive(*args, **kwargs);owned.append(value);return value
    monkeypatch.setattr(source, "_receive", track)
    with pytest.raises(r.WindowsServiceCredentialCreationInputError) as error: source.read_once()
    assert str(error.value) == r._ERROR and error.value.__suppress_context__
    count = len(h.requests)
    with pytest.raises(r.WindowsServiceCredentialCreationInputError): source.read_once()
    assert len(h.requests) == count and all(not value for value in owned)
    assert all(s.closed for s in h.streams) and all(c.is_closed and not c.cookies for c in h.clients)


@pytest.mark.parametrize("fault", ["default-guard", "default-fields-drift", "schema-drift", "schema-missing",
    "builtin-mandatory", "template-kind", "template-permission", "template-name", "template-drift", "template-multiple",
    "actor-drift", "scope", "paging", "schema-errors", "schema-overflow", "wrong-action"])
def test_guard_schema_template_and_actor_drift_refuse_before_publication(fault):
    h = Harness();_, _, source = h.prepare()
    if fault == "default-guard": h.inputs[1]["results"]["password-changer"] = "enable"
    if fault == "default-fields-drift": h.inputs[8]["results"]["new_field"] = "opaque"
    if fault == "schema-drift": h.inputs[7]["results"]["children"]["name"]["type"] = "integer"
    if fault == "schema-missing": del h.inputs[2]["results"]["children"]["field"]
    if fault == "builtin-mandatory": h.inputs[3]["results"][0]["field"][1]["mandatory"] = "enable"
    if fault == "template-kind": h.inputs[4]["results"][0]["field"][0]["type"] = "domain"
    if fault == "template-permission": h.inputs[4]["results"][0]["permissions"]["user"] = "none"
    if fault == "template-name": h.inputs[4]["results"][0]["name"] = "other"
    if fault == "template-drift": h.inputs[5]["results"][0]["opaque"] = "changed"
    if fault == "template-multiple": h.inputs[4]["results"] *= 2
    if fault == "actor-drift": h.inputs[9]["results"]["admin"]["profile"]["other"] = "changed"
    if fault == "scope": h.inputs[2]["vdom"] = "other"
    if fault == "paging": h.inputs[2]["has_more"] = False
    if fault == "schema-errors": h.inputs[2]["schema_errors"] = []
    if fault == "schema-overflow":
        children = h.inputs[2]["results"]["children"]
        for index in range(512 - len(children)): children[f"overflow-extra-{index:03}"] = {"type": "var-string"}
    if fault == "wrong-action": h.inputs[2]["action"] = "default"
    with pytest.raises(r.WindowsServiceCredentialCreationInputError): source.read_once()
    assert len(h.requests) <= 16 and all(c.is_closed and not c.cookies for c in h.clients)


def test_unused_default_values_are_not_decoded_or_claimed_as_preserved(monkeypatch):
    h = Harness();target, _, source = h.prepare()
    h.inputs[8]["results"]["native-extra-000"] = {"value": "DIFFERENT_UNSELECTED_DEFAULT_SENTINEL"}
    original = r.m._scalar
    def selected(raw, span):
        assert b"SENTINEL" not in raw[slice(*span)]
        return original(raw, span)
    monkeypatch.setattr(r.m, "_scalar", selected)
    source.check_current(source.read_once());target.close()


@pytest.mark.parametrize("fault", ["copy", "tamper", "expiry", "target-close", "default-fields", "schema-fields",
    "own-config", "own-factory", "own-tls", "binding", "profile-context", "proposal-field", "default-proposal-field"])
def test_current_observation_and_profile_need_the_exact_borrowed_source(fault):
    h = Harness();target, reference, source = h.prepare();observed = source.read_once()
    profile = replace(binding(), target_name=NAME, target_address=ADDRESS, serial_digest=DIGEST,
        target_reference_context_digest=reference.target_reference_context_digest)
    if fault == "copy": observed = replace(observed)
    if fault == "tamper": object.__setattr__(observed, "schema_digest", "f" * 64)
    if fault == "expiry": h.now = 40
    if fault == "target-close": target.close()
    if fault == "default-fields": source._default_fields = source._default_fields | {"late-extra"}
    if fault == "schema-fields": source._schema_fields = source._schema_fields | {"late-extra"}
    if fault == "own-config": source._config = replace(source._config, bearer_token="other")
    if fault == "own-factory": source._factory = h.factory
    if fault == "own-tls": source._tls = None
    if fault == "binding": source._binding = "f" * 64
    if fault == "profile-context": profile = replace(profile, target_reference_context_digest="f" * 64)
    if fault in {"proposal-field", "default-proposal-field"}:
        # A fully read native schema can still omit a fixed proposal field.
        h = Harness();target, reference, source = h.prepare()
        if fault == "proposal-field":
            for index in (2, 7): del h.inputs[index]["results"]["children"]["recording"]
        else:
            for index in (1, 8): del h.inputs[index]["results"]["secret-auth-duration"]
        observed = source.read_once()
    with pytest.raises(r.WindowsServiceCredentialCreationInputError): source.check_profile(observed, profile)
    assert len(h.requests) == 16


def test_copied_target_reference_and_repeated_input_window_cannot_be_adopted():
    h = Harness();target, reference, source = h.prepare()
    with pytest.raises(r.WindowsServiceCredentialCreationInputError):
        r.WindowsServiceCredentialCreationInputs(target_sources=target, target_observation=replace(reference))
    h = Harness();_, _, source = h.prepare();source.read_once()
    with pytest.raises(r.WindowsServiceCredentialCreationInputError): source.read_once()
    assert len(h.requests) == 16


def test_interruption_closes_cookies_and_consumes_the_window():
    h = Harness();_, _, source = h.prepare();h.fault = "interrupt"
    with pytest.raises(KeyboardInterrupt): source.read_once()
    assert all(c.is_closed and not c.cookies for c in h.clients)
    with pytest.raises(r.WindowsServiceCredentialCreationInputError): source.read_once()
    assert len(h.requests) == 9


def role_projections(harness):
    return [value["results"]["admin"]["profile"] for value in
        (harness.values[0], harness.values[5], harness.inputs[0], harness.inputs[-1])]


@pytest.mark.parametrize("group", ["custom", "read-write"])
def test_active_role_uses_secret_write_and_reference_read_requirements(group):
    h = Harness()
    for profile in role_projections(h):
        profile["secretgrp"] = group
        profile["secretgrp-permission"] = (dict(r._ROLE_REQUIREMENTS) if group == "custom"
            else dict.fromkeys(r._ROLE_RIGHTS, "none"))
    target, reference, source = h.prepare()
    observed = source.read_once()
    profile = replace(binding(), target_name=NAME, target_address=ADDRESS, serial_digest=DIGEST,
        target_reference_context_digest=reference.target_reference_context_digest)
    source.check_profile(observed, profile)
    assert len(h.requests) == 16
    source.close();target.close()


@pytest.mark.parametrize("field", r._ROLE_RIGHTS)
@pytest.mark.parametrize("value", ["missing", "none"])
def test_each_unreadable_or_missing_active_role_bit_refuses_before_defaults(field, value):
    h = Harness()
    for profile in role_projections(h):
        if value == "missing": del profile["secretgrp-permission"][field]
        else: profile["secretgrp-permission"][field] = value
    _, _, source = h.prepare()
    with pytest.raises(r.WindowsServiceCredentialCreationInputError): source.read_once()
    assert len(h.requests) == 7 and h.requests[-1].url.path == r._ACTOR
    with pytest.raises(r.WindowsServiceCredentialCreationInputError): source.read_once()
    assert len(h.requests) == 7


@pytest.mark.parametrize("fault", ["group-read", "group-none", "group-unknown", "missing-group", "missing-granular",
    "boolean-bit", "unknown-bit", "secret-read"])
def test_active_role_group_precedence_and_field_types_are_explicit(fault):
    h = Harness()
    for profile in role_projections(h):
        if fault == "group-read": profile["secretgrp"] = "read"
        if fault == "group-none": profile["secretgrp"] = "none"
        if fault == "group-unknown": profile["secretgrp"] = "other"
        if fault == "missing-group": del profile["secretgrp"]
        if fault == "missing-granular": del profile["secretgrp-permission"]
        if fault == "boolean-bit": profile["secretgrp-permission"]["secret-table"] = True
        if fault == "unknown-bit": profile["secretgrp-permission"]["secret-table"] = "other"
        if fault == "secret-read": profile["secretgrp-permission"]["secret-table"] = "read"
    _, _, source = h.prepare()
    with pytest.raises(r.WindowsServiceCredentialCreationInputError): source.read_once()
    assert len(h.requests) == 7


def test_lost_active_role_write_permission_cannot_publish_the_completed_metadata_window():
    h = Harness();_, _, source = h.prepare()
    h.inputs[-1]["results"]["admin"]["profile"]["secretgrp-permission"]["secret-table"] = "read"
    with pytest.raises(r.WindowsServiceCredentialCreationInputError): source.read_once()
    assert len(h.requests) == 16 and all(client.is_closed and not client.cookies for client in h.clients)
