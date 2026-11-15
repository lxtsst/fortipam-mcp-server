"""The fixed usage reader preserves unknown capacity and protected values."""
import copy
import hashlib
import json
import pickle
import ssl

import httpx
import pytest

from fortipam_mcp import instruction_resource_usage as r
from v4_planning.material_provider import MaterialAccessDenied

SERIAL = hashlib.sha256(b"synthetic-device").hexdigest()


def body() -> dict:
    return {"version": "v7.0.0", "build": 29, "path": "log", "name": "current-disk-usage",
        "http_method": "GET", "http_status": 200, "status": "success", "serial": "synthetic-device",
        "results": dict(zip(r._FIELDS, (10000, 1200, 10, 0, 0))) | {
            "private": {"value": "unselected-private"}}}


def test_usage_is_opaque_and_only_selected_scalars_are_decoded(monkeypatch) -> None:
    original = r.m._scalar

    def selected(raw, span):
        assert b"unselected-private" not in raw[slice(*span)]
        return original(raw, span)

    monkeypatch.setattr(r.m, "_scalar", selected)
    raw = bytearray(json.dumps(body()).encode())
    state = r.project_instruction_resource_usage(raw, serial_digest=SERIAL)
    assert not raw and state.instruction_usage_zero
    assert state._bytes == (10000, 1200, 10, 0, 0)
    assert "10000" not in repr(state) and "synthetic-device" not in repr(state)
    for clone in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(MaterialAccessDenied):
            clone(state)
    with pytest.raises(r.InstructionResourceUsageError):
        r.InstructionResourceUsage()


@pytest.mark.parametrize("change", ["missing-serial", "foreign", "build", "missing-usage",
    "boolean", "negative", "float", "zero-total", "over-total", "sum-over-total", "duplicate", "utf8"])
def test_malformed_or_unknown_capacity_is_never_projected_as_zero(change) -> None:
    value = body()
    if change == "missing-serial":
        del value["serial"]
    if change == "foreign":
        value["serial"] = "foreign"
    if change == "build":
        value["build"] = 30
    fields = value["results"]
    if change == "missing-usage":
        del fields[r._FIELDS[4]]
    if change in {"boolean", "negative", "float"}:
        fields[r._FIELDS[4]] = {"boolean": False, "negative": -1, "float": 1.5}[change]
    if change == "zero-total":
        fields[r._FIELDS[0]] = 0
    if change == "over-total":
        fields[r._FIELDS[4]] = 10001
    if change == "sum-over-total":
        fields[r._FIELDS[4]] = 9500
    raw = bytearray(json.dumps(value).encode())
    if change == "duplicate":
        raw = raw.replace(b'"sec_instruction_used_bytes": 0',
                          b'"sec_instruction_used_bytes": 0,"sec_instruction_used_bytes": 1')
    if change == "utf8":
        raw = raw.replace(b"unselected-private", b"\xff")
    with pytest.raises(r.InstructionResourceUsageError, match="^The private Instruction resource usage source is unavailable.$"):
        r.project_instruction_resource_usage(raw, serial_digest=SERIAL)
    assert not raw


@pytest.mark.parametrize("failure", [None, "status", "oversize", "identity", "deadline"])
def test_one_fixed_get_and_cleanup_on_success_or_failure(monkeypatch, failure) -> None:
    calls, clients, responses = [], [], []
    monkeypatch.setattr(r, "_ssl_context", lambda _: ssl.create_default_context())
    clock_value = 1

    def send(request):
        nonlocal clock_value
        calls.append(request)
        assert request.method == "GET" and request.content == b""
        assert str(request.url) == "https://synthetic.invalid" + r._PATH
        assert "cookie" not in request.headers
        payload = body()
        if failure == "identity":
            payload["serial"] = "foreign"
        raw = json.dumps(payload).encode() if failure != "oversize" else b" " * (r._LIMIT + 1)
        if failure == "deadline":
            clock_value = 40
        response = httpx.Response(403 if failure == "status" else 200,
            headers={"content-type": "application/json", "set-cookie": "synthetic=value"},
            stream=httpx.ByteStream(raw))
        responses.append(response)
        return response

    def factory(**options):
        assert not options["follow_redirects"] and not options["trust_env"]
        assert options["verify"].check_hostname and options["verify"].verify_mode == ssl.CERT_REQUIRED
        client = httpx.Client(transport=httpx.MockTransport(send), **options)
        clients.append(client)
        return client

    config = r.SecretMetadataHttpTransportConfig("https://synthetic.invalid", "synthetic-token", 30, None)
    if failure:
        with pytest.raises(r.InstructionResourceUsageError):
            r.read_instruction_resource_usage(config, serial_digest=SERIAL,
                client_factory=factory, clock=lambda: clock_value)
    else:
        assert r.read_instruction_resource_usage(config, serial_digest=SERIAL,
            client_factory=factory, clock=lambda: clock_value).instruction_usage_zero
    assert len(calls) == 1
    assert all(client.is_closed and not client.cookies for client in clients)
    assert all(response.is_closed for response in responses)
