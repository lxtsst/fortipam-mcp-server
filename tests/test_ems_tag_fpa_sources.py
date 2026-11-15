"""Actual fixed source/Owner lifecycle with synthetic HTTP product peers."""
from copy import deepcopy
from dataclasses import replace
import json
import ssl
from urllib.parse import parse_qs

import httpx
import pytest

from fortipam_mcp.ems_tag_contract import DisabledLinuxProcessTag
from fortipam_mcp.ems_tag_fpa_sources import EmsTagFpaSources
from fortipam_mcp.ems_timeout_transport import _FIELDS, COLLECTION, STATUS
from fortipam_mcp.owner_session_metadata import OwnerSessionMetadataTransport
from fortipam_mcp.secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig, FortiPamSecretMetadataHttpTransport, SYSTEM_STATUS_PATH)
from test_ems_tag_fpa_mapping import row, SERIAL as EMS_SERIAL
from test_ems_tag_http_transport import make as ems_transport

OWNER, FPA_SERIAL = "synthetic-fpa-owner", "FPA_UNIT_SOURCE"
DRAFT = DisabledLinuxProcessTag("a" * 32)


class Peer:
    def __init__(self, config, hostname, *, fault=None):
        self.config, self.hostname, self.fault = config, hostname, fault
        self.rows = [row()]
        self.calls = []; self.sessions = []; self.metadata = []
        self.active = False
        self.mapping_gets = self.actor_gets = self.status_gets = 0
        self.connector_references = 0
        self.connector_timeout = 30

    def frame(self, result, path, name, **extra):
        return dict(http_method="GET", status="success", http_status=200, version="v7.0.0", build=29,
            serial=FPA_SERIAL, vdom="root", path=path, name=name, results=deepcopy(result), **extra)

    def handle(self, request):
        self.calls.append((request.method, request.url.path))
        assert "authorization" not in request.headers
        path, method = request.url.path, request.method
        if path == "/remote/login": return httpx.Response(200, text='<form action="/XX/YY/ZZ/AUTH">')
        if path == "/XX/YY/ZZ/AUTH":
            assert method == "POST"
            assert parse_qs(request.content.decode())["username"] == [OWNER]
            self.active = True
            return httpx.Response(303, headers={"location": "/", "set-cookie": "testsession=synthetic; Secure; HttpOnly; Path=/"})
        assert method == "GET"
        if path == "/": return httpx.Response(200)
        if path == "/logout":
            self.active = self.fault == "logout"
            return httpx.Response(200)
        if not self.active: return httpx.Response(401)
        if path == SYSTEM_STATUS_PATH: return httpx.Response(200, json={"version": "v7.0.0", "build": 29, "serial": FPA_SERIAL})
        self.metadata.append(path)
        if path == "/api/v2/monitor/web-ui/state":
            self.actor_gets += 1
            name = "other-owner" if self.fault == "actor_after" and self.actor_gets % 2 == 0 else OWNER
            value = self.frame({"admin": dict(name=name, login_name=name, sponsored_group_name="", guest_admin=False)}, "web-ui", "state")
        elif path == COLLECTION:
            data = {key: (30 if key == "call-timeout" else 443) if kind == "integer" else "synthetic" for key, kind in _FIELDS.items()}
            data.update(name="selected", server="other.example.test" if self.fault == "connector" else self.hostname,
                q_ref=self.connector_references,
                **{"certificate-fingerprint": "synthetic-fingerprint", "pull-tags": "enable", "call-timeout": self.connector_timeout})
            value = self.frame([data], "endpoint-control", "fctems", limit_reached=False, matched_count=1)
        elif path == STATUS:
            assert parse_qs(request.url.query.decode()) == {"ems_name": ["selected"]}
            self.status_gets += 1
            serial = "OTHER" if self.fault == "status_after" and self.status_gets % 2 == 0 else EMS_SERIAL
            result = {"ems_status": "success", "ems_serial": serial}
            if self.fault == "missing_serial": result.pop("ems_serial")
            value = self.frame(result, "endpoint-control", "ems")
        elif path == "/api/v2/cmdb/firewall/address":
            assert parse_qs(request.url.query.decode()) == {"format": ["name|type|sub-type|obj-tag|obj-type|tag-type|tag-detection-level"], "with_meta": ["true"]}
            self.mapping_gets += 1
            result = deepcopy(self.rows)
            if self.fault == "mapping_after" and self.mapping_gets % 2 == 0: result[0]["tag-detection-level"] = "changed"
            value = self.frame(result, "firewall", "address", matched_count=len(result) + int(self.fault == "count_mismatch"), limit_reached=self.fault == "partial")
        elif path == "/api/v2/monitor/web-ui/object-urls":
            value = self.frame({"by_type": {"17": {"path": "firewall.address"}}}, "web-ui", "object-urls")
        elif path == "/api/v2/monitor/system/object/usage":
            query = parse_qs(request.url.query.decode())
            assert query["qtypes"] == ["[17]"] and query["mkey"][0] in {item["name"] for item in self.rows[1:]}
            value = self.frame({"currently_using": [{}] if self.fault == "usage" else []}, "system", "object", mkey=query["mkey"][0])
        else: raise AssertionError("Unexpected fixed source route")
        if self.fault == "framing":
            raw = json.dumps(value).encode()
            return httpx.Response(200, content=raw, headers={"Content-Type": "application/json",
                "Content-Length": str(len(raw)), "Transfer-Encoding": "chunked"})
        return httpx.Response(200, json=value)

    def owner(self):
        placeholder = "synthetic-metadata-no-object-lookup"
        owner = OwnerSessionMetadataTransport(self.config, owner_name=OWNER,
            credentials=lambda: (OWNER, "synthetic-owner-password"), folder_path=placeholder,
            secret_name=placeholder, target_name=placeholder,
            witness=FortiPamSecretMetadataHttpTransport(self.config, bound_secret_name=placeholder),
            client_factory=lambda **kwargs: httpx.Client(**kwargs, transport=httpx.MockTransport(self.handle)))
        self.sessions.append(owner)
        return owner


def make(tmp_path, monkeypatch, *, fault=None):
    real_ssl = ssl.create_default_context
    try: transport, _, _, _, _, _ = ems_transport(tmp_path, monkeypatch)
    finally: monkeypatch.setattr(ssl, "create_default_context", real_ssl)
    monkeypatch.setattr("fortipam_mcp.owner_session_metadata._ssl_context", lambda config: ssl.create_default_context())
    transport.authenticate()
    sources = transport.make_sources(DRAFT, source_key=b"s" * 32); sources.observe()
    config = SecretMetadataHttpTransportConfig("https://pam.example.test", "unused-bearer", 5, str(transport._config.ca_file))
    peer = Peer(config, transport._config.hostname, fault=fault)
    now = [int(__import__("time").time())]
    source = EmsTagFpaSources(transport=transport, sources=sources, owner_factory=peer.owner, config=config,
        owner_name=OWNER, expected_serial=FPA_SERIAL, source_key=b"f" * 32, clock=lambda: now[0])
    return source, peer, now, transport, sources


def test_fresh_absence_and_original_scope_bracket_every_candidate_usage_and_close_each_session(tmp_path, monkeypatch):
    source, peer, _, transport, ems_source = make(tmp_path, monkeypatch)
    try:
        first = source.observe(); binding = source.bind_original_absence(first)
        assert source.metadata_get_count == 9 and first.mapping.candidate_absent
        peer.rows += [row(DRAFT._name), row(DRAFT._name, mac=True)]
        next_read = source.observe(); source.require_original_scope(next_read, binding, absent=False)
        assert source.metadata_get_count == 11 and not next_read.mapping.candidate_absent
        assert len([p for p in peer.metadata if p.endswith("/object/usage")]) == 2
        assert all(owner.logout_verified and owner._client is None for owner in peer.sessions)
        with pytest.raises(ValueError): source.check_current(first)
        with pytest.raises(ValueError): source.bind_original_absence(next_read)
        with pytest.raises(ValueError): source.require_original_scope(next_read, binding, absent=True)
        assert EMS_SERIAL not in repr(source) + repr(binding) + repr(first)
        peer.rows = [row()]
        source.require_original_scope(source.observe(), binding, absent=True)
    finally:
        source.close(); assert transport.close().next_session_check_401; ems_source.close()


def test_connector_reference_counter_is_observed_but_configuration_and_tag_references_stay_bound(tmp_path, monkeypatch):
    source, peer, _, transport, ems_source = make(tmp_path, monkeypatch)
    binding = source.bind_original_absence(source.observe())
    peer.connector_references = 1
    peer.rows.append(row(DRAFT._name))
    source.require_original_scope(source.observe(), binding, absent=False)
    peer.connector_timeout = 31
    with pytest.raises(ValueError): source.observe()
    assert source._closed
    assert transport.close().next_session_check_401; ems_source.close()


@pytest.mark.parametrize("fault", ["connector", "missing_serial", "actor_after", "mapping_after", "partial", "status_after", "usage", "references", "logout", "global_controls", "framing", "count_mismatch"])
def test_failed_source_is_closed_never_replayed_and_never_emits_a_lease(tmp_path, monkeypatch, fault):
    source, peer, _, transport, ems_source = make(tmp_path, monkeypatch, fault=fault)
    if fault in ("usage", "references"):
        peer.rows.append(row(DRAFT._name))
        if fault == "references": peer.rows[-1]["q_ref"] = 1
    if fault == "global_controls": peer.rows[0]["q_global_entry"] = True
    with pytest.raises(ValueError): source.observe()
    assert source.failure_stage is not None and not source._key
    if fault == "count_mismatch":
        assert source.last_http_status == 200 and source.last_read_stage == "complete"
        assert source.mapping_diagnostic == {"rows": 1, "matched_count": 2, "limit_reached": False,
            "selected_label_rows": 0, "selected_metadata_valid": True}
    if fault == "framing":
        assert source.last_http_status == 200 and source.last_read_stage == "headers"
        assert source.mapping_diagnostic is None
    count = len(peer.calls)
    with pytest.raises(ValueError): source.observe()
    assert len(peer.calls) == count and all(owner._client is None for owner in peer.sessions)
    assert not any(method not in ("GET", "POST") or method == "POST" and path != "/XX/YY/ZZ/AUTH" for method, path in peer.calls)
    assert transport.close().next_session_check_401; ems_source.close()


@pytest.mark.parametrize("fault", ["clone", "tamper", "expiry", "clock", "ca", "key", "binding"])
def test_observation_and_original_binding_cannot_be_detached_or_relabelled(tmp_path, monkeypatch, fault):
    source, peer, now, transport, ems_source = make(tmp_path, monkeypatch)
    observed = source.observe(); binding = source.bind_original_absence(observed)
    if fault == "clone": observed = replace(observed)
    elif fault == "tamper": object.__setattr__(observed, "expires_at", observed.expires_at + 1)
    elif fault == "expiry": now[0] += 60
    elif fault == "clock": now[0] -= 1
    elif fault == "ca": transport._config.ca_file.write_bytes(b"changed-ca")
    elif fault == "key": source._key[0] ^= 1
    else: binding = replace(binding, baseline_digest="0" * 64)
    count = len(peer.calls)
    with pytest.raises(ValueError): source.require_original_scope(observed, binding, absent=True)
    if fault == "clock":
        now[0] += 1
        with pytest.raises(ValueError): source.check_current(observed)
        assert source._closed and not source._key
    assert len(peer.calls) == count
    source.close()
    if fault != "ca": assert transport.close().next_session_check_401
    ems_source.close()
