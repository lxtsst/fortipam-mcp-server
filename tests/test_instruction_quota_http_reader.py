"""Fixed quota-context reads share one deadline and reject partial observations."""
import json
import ssl

import httpx
import pytest

from fortipam_mcp import instruction_quota_http_reader as r
from fortipam_mcp import instruction_quota_contract as q
from test_instruction_quota_contract import SERIAL, envelope, state


def buffers(monkeypatch):
    captured = []
    original = q.read_instruction_quota_state
    def capture(*raw, **kwargs):
        captured.extend(bytes(item) for item in raw)
        return original(*raw, **kwargs)
    monkeypatch.setattr(q, "read_instruction_quota_state", capture)
    state()
    captured.append(bytes(envelope({"video_disk_total_bytes": 10000, "video_used_bytes": 1000,
        "sec_file_used_bytes": 350, "software_package_used_bytes": 0,
        "sec_instruction_used_bytes": 0}, path="log", name="current-disk-usage")))
    return captured


@pytest.mark.parametrize("failure", [None, "schema-type", "utf8-once", "utf8-exhausted",
    "foreign-usage", "status", "deadline"])
def test_fixed_context_cleanup_retry_and_failure_boundaries(monkeypatch, failure):
    payloads = buffers(monkeypatch)
    bad_schema = payloads[0].replace(b'"default": ""', b'"default": "\xff"', 1)
    if failure == "schema-type":
        payloads[0] = payloads[0].replace(b'"type": "integer"', b'"type": "string"', 1)
    if failure == "utf8-once":
        payloads.insert(0, bad_schema)
    if failure == "utf8-exhausted":
        payloads[:0] = [bad_schema] * 3
    if failure == "foreign-usage":
        payloads[-1] = payloads[-1].replace(b"synthetic-device", b"foreign-device")
    monkeypatch.setattr(r, "_ssl_context", lambda _: ssl.create_default_context())
    calls, clients, responses, cleared = [], [], [], []
    clock_value = 1
    original_clear = r._zeroize_mutable
    def clear(raw):
        original_clear(raw)
        cleared.append(raw)
    monkeypatch.setattr(r, "_zeroize_mutable", clear)

    def factory(**options):
        assert options["verify"].verify_mode == ssl.CERT_REQUIRED and options["verify"].check_hostname
        assert not options["trust_env"] and not options["follow_redirects"]
        def send(request):
            nonlocal clock_value
            index = len(calls)
            calls.append(request)
            assert request.method == "GET" and request.content == b"" and "cookie" not in request.headers
            if failure == "deadline":
                clock_value = 40
            response = httpx.Response(403 if failure == "status" else 200,
                headers={"content-type": "application/json", "set-cookie": "synthetic=value"},
                stream=httpx.ByteStream(payloads[index]))
            responses.append(response)
            return response
        client = httpx.Client(transport=httpx.MockTransport(send), **options)
        clients.append(client)
        return client

    config = r.SecretMetadataHttpTransportConfig("https://synthetic.invalid", "synthetic", 30, None)
    if failure in (None, "utf8-once"):
        current, usage = r.read_instruction_quota_context(config, serial_digest=SERIAL,
            client_factory=factory, clock=lambda: clock_value)
        assert current._quotas == (90, 5, 0, 0) and usage.instruction_usage_zero
        q.InstructionQuotaTransition(current, current, usage, phase="allocate", operation_nonce="a"*64)
        expected_routes = ([r._ROUTES[0]] if failure else []) + list(r._ROUTES)
        assert [str(call.url) for call in calls] == [config.base_url + route for route in expected_routes]
    else:
        with pytest.raises(r.InstructionQuotaReadError) as refused:
            r.read_instruction_quota_context(config, serial_digest=SERIAL,
                client_factory=factory, clock=lambda: clock_value)
        assert refused.value.category == ("invalid_utf8" if failure == "utf8-exhausted" else "invalid_source")
        assert refused.value.stage == {
            "schema-type": "schema_validation", "utf8-exhausted": "schema_validation",
            "foreign-usage": "usage_validation", "status": "schema_http", "deadline": "schema_http"}[failure]
        assert str(refused.value) == r._ERROR
        expected_count = {"schema-type": 1, "utf8-exhausted": 3,
            "foreign-usage": 4, "status": 1, "deadline": 1}[failure]
        assert len(calls) == expected_count
    assert all(client.is_closed and not client.cookies for client in clients)
    assert all(response.is_closed for response in responses)
    assert cleared and all(not raw for raw in cleared)
