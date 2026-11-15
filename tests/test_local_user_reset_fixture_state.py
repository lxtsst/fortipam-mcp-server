"""Real fixed readers join submitted and complete state without material decode."""
from dataclasses import replace
import hashlib
import json

import pytest

from fortipam_mcp.local_user_reset_fixture_create import prepare_local_user_reset_fixture_create
from fortipam_mcp.local_user_reset_fixture_preflight import _ACTOR, _DEFAULT, _SCHEMA, _actor_context
from fortipam_mcp.local_user_reset_fixture_state import LocalResetFixtureStateReader
from fortipam_mcp.local_user_reset_metadata_reader import _TYPES, _USAGE
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from test_local_user_reset_fixture_create import _defaults
from test_local_user_reset_fixture_preflight import Harness as Preflight
from test_local_user_reset_metadata_reader import _monitor
from test_local_user_reset_projection import _body, _case
from test_local_user_reset_fixture_custody import NAME, SERIAL
from test_local_user_reset_fixture_custody import Harness as CustodyHarness, response


class Harness:
    def __init__(self, root, *, fault=None):
        self.now = 1000.0
        self.fault = fault
        self.calls, self.resources, self.buffers = [], [], []
        self.complete_reads = self.actor_reads = self.default_reads = 0
        self.material_directory = root / "material"; self.material_directory.mkdir(mode=0o700)
        self.config = SecretMetadataHttpTransportConfig("https://pam.example.test:9443", "synthetic-token", 5, None)
        schema, defaults = _defaults(); schema.update(serial=SERIAL, vdom="root")
        self.schema = bytearray(json.dumps(schema).encode())
        self.defaults = _body(defaults, action="default", serial=SERIAL, vdom="root")
        self.draft = prepare_local_user_reset_fixture_create(bytearray(self.defaults), schema, username=NAME, access_profile="Guest")
        preflight = Preflight()
        self.actor = preflight.bodies[_ACTOR]
        self.principal = preflight.reader._principal
        actor_digest = _actor_context(self.actor, expected_name=self.principal)
        self.selected = json.loads(self.draft._wire); self.selected.update(id=17, q_ref=0, q_static=False)
        self.selected["vdom"] = [{"name": "root", "q_origin_key": "root"}]
        self.record = {**defaults, **self.selected}
        self.record["webauthn"] = _case()[1]["webauthn"]
        self.record.update(q_origin_key=NAME, q_global_entry=False)
        self.source = LocalResetFixtureStateReader(self.config, draft=self.draft, api_principal=self.principal,
            serial_digest=hashlib.sha256(SERIAL.encode()).hexdigest(), actor_context_digest=actor_digest,
            material_directory=self.material_directory, connection_factory=self.connect, clock=lambda:self.now)

    def connect(self, *args, **kwargs):
        h = self
        class Response:
            status = 200
            closed = False
            def __init__(self): self.raw = bytearray(); self.offset = 0
            def getheader(self, name, default=""):
                return {"content-type":"application/json", "content-encoding":"identity"}.get(name.lower(), default)
            def readinto(self, view):
                h.buffers.append(view.obj)
                count = min(len(view), len(self.raw)-self.offset)
                view[:count] = self.raw[self.offset:self.offset+count]; self.offset += count
                return count
            def close(self): self.closed = True
        class Connection:
            closed = False
            def __init__(self): self.response = Response(); h.resources.extend((self,self.response))
            def request(self, method, path, *, headers):
                assert method == "GET"
                h.calls.append(path)
                if path == _ACTOR:
                    h.actor_reads += 1; self.response.raw = h.actor
                    if h.fault == "actor" and h.actor_reads == 2:
                        value = json.loads(h.actor); value["results"]["admin"]["sponsored_group_name"] = "foreign"
                        self.response.raw = bytearray(json.dumps(value).encode())
                elif path == _SCHEMA:
                    self.response.raw = h.schema
                    if h.fault == "serial":
                        value = json.loads(h.schema); value["serial"] = "FOREIGN01"
                        self.response.raw = bytearray(json.dumps(value).encode())
                elif path == _DEFAULT:
                    h.default_reads += 1; self.response.raw = h.defaults
                    if h.fault == "defaults" and h.default_reads == 2:
                        value = json.loads(h.defaults); value["results"]["comments"] = "changed"
                        self.response.raw = bytearray(json.dumps(value).encode())
                elif path == _TYPES:
                    self.response.raw = _monitor("web-ui/object-urls", {"by_type":{"7":{"path":"system.admin"}}})
                elif path.startswith(_USAGE):
                    self.response.raw = _monitor("system/object/usage", {"currently_using":[{}] if h.fault == "usage" else []}, mkey=NAME)
                elif "format=" in path:
                    value = dict(h.selected)
                    if h.fault == "static": value["q_static"] = True
                    if h.fault == "definition": value["comments"] = "changed"
                    self.response.raw = _body(value, mkey=NAME, serial=SERIAL, vdom="root")
                else:
                    assert path.startswith('/api/v2/cmdb/system/admin/' + NAME + '?')
                    h.complete_reads += 1; value = dict(h.record)
                    if h.fault == "refs": value["q_ref"] = 1
                    if h.fault == "drift" and h.complete_reads == 2: value["comments"] = "changed"
                    self.response.raw = _body(value, mkey=NAME, serial=SERIAL, vdom="root")
                if h.fault == "expiry" and len(h.calls) >= 15: h.now = 1060
            def getresponse(self): return self.response
            def close(self): self.closed = True
        return Connection()


def test_real_complete_state_join_matches_both_projections_and_closes_resources(tmp_path, monkeypatch):
    h = Harness(tmp_path)
    original = json.loads
    def safe_loads(value, *args, **kwargs):
        if isinstance(value, (bytes, bytearray)):
            assert b"synthetic-password" not in value and b"synthetic-history" not in value and b"synthetic-nested" not in value
        return original(value, *args, **kwargs)
    monkeypatch.setattr(json, "loads", safe_loads)
    observed = h.source.read_created(); h.source.check_current(observed)
    assert observed.user_id == 17 and len(h.calls) == 15 and h.complete_reads == 2
    assert all(resource.closed for resource in h.resources) and all(not any(raw) for raw in h.buffers)
    assert not hasattr(observed, "fixture_creation_digest") and NAME not in repr(observed)
    with pytest.raises(ValueError): h.source.check_current(replace(observed))
    assert h.source._failed


@pytest.mark.parametrize("fault", ["serial", "actor", "defaults", "refs", "usage", "static", "definition", "drift", "expiry"])
def test_changed_identity_definition_usage_full_state_or_freshness_cannot_qualify(tmp_path, fault):
    h = Harness(tmp_path, fault=fault)
    with pytest.raises(ValueError): h.source.read_created()
    assert h.source._failed and h.source._current is None and h.source._last_failure_stage
    expected = {"serial":"defaults_before", "actor":"actor_after", "defaults":"defaults_after",
        "refs":"complete_state_before", "usage":"complete_state_before", "static":"submitted_definition",
        "definition":"submitted_definition", "drift":"complete_state_after", "expiry":"verification_window"}
    assert h.source._last_failure_stage == expected[fault]
    assert all(resource.closed for resource in h.resources) and all(not any(raw) for raw in h.buffers)
    calls = len(h.calls)
    with pytest.raises(ValueError): h.source.read_created()
    assert len(h.calls) == calls


def compose(root, *, unknown=False, fault=None, capture=True):
    source = Harness(root, fault=fault)
    custody = CustodyHarness(root, request_digest=source.draft.nonmaterial_request_digest,
        actor_context_digest=source.source._actor)
    original_dispatch = custody.dispatch
    def dispatch(plan):
        from v4_planning import M4AdapterAmbiguous
        try:
            original_dispatch(plan)
            if capture: custody.custody.capture_original_full_state(source.source)
        except ValueError:
            raise M4AdapterAmbiguous("Synthetic original full-state failure.") from None
    custody.dispatch = dispatch
    result = custody.execute(unknown=unknown)
    return source, custody, result


@pytest.mark.parametrize("unknown", [False, True])
def test_original_m4_alone_seals_complete_state_and_preserves_unknown(tmp_path, unknown):
    source, h, result = compose(tmp_path, unknown=unknown)
    assert str(result.outcome) == ("reconciliation_required" if unknown else "succeeded")
    original = h.custody.inspect_original_full_state()
    assert original.user_id == 17 and original.state_digest == source.source._current.state_digest
    assert original.original_ack.original_verification == ("unknown" if unknown else "verified")
    before = {p.name:p.read_bytes() for p in (tmp_path / "state").iterdir()}
    h.now = 5000
    assert h.reopen().inspect_original_full_state() == original
    assert {p.name:p.read_bytes() for p in (tmp_path / "state").iterdir()} == before
    calls = len(source.calls)
    with pytest.raises(ValueError): h.custody.capture_original_full_state(source.source)
    assert len(source.calls) == calls and h.store.claim_count == 1


@pytest.mark.parametrize("fault", ["drift", "refs", "usage", "definition"])
def test_failed_original_full_read_retains_only_ack_and_cannot_be_backfilled(tmp_path, fault):
    source, h, result = compose(tmp_path, fault=fault)
    assert str(result.verification) == "unknown" and h.custody.inspect_original_ack().original_verification == "unknown"
    with pytest.raises(ValueError): h.custody.inspect_original_full_state()
    assert not (tmp_path / "state/original-full-state.json").exists()
    calls = len(source.calls)
    with pytest.raises(ValueError): h.custody.capture_original_full_state(source.source)
    assert len(source.calls) == calls


def test_terminal_ack_only_cannot_acquire_a_late_complete_seal(tmp_path):
    source, h, result = compose(tmp_path, capture=False)
    assert str(result.outcome) == "succeeded" and not source.calls
    with pytest.raises(ValueError): h.custody.capture_original_full_state(source.source)
    assert not source.calls and not (tmp_path / "state/original-full-state.json").exists()


def test_child_route_drift_is_rejected_before_any_product_read(tmp_path):
    h = Harness(tmp_path)
    h.source._metadata._detail += "&unqualified=1"
    with pytest.raises(ValueError): h.source.read_created()
    assert not h.calls and h.source._last_failure_stage == "source_binding"


def test_full_response_cannot_disagree_with_the_formatted_creation_projection(tmp_path):
    h = Harness(tmp_path)
    h.record['comments'] = 'changed-only-in-complete-response'
    with pytest.raises(ValueError): h.source.read_created()
    assert h.source._last_failure_stage == 'complete_state_before'


@pytest.mark.parametrize("effect", ["audit-only", "configuration", "gui-configuration", "unknown-audit-field", "audit-origin", "audit-type"])
def test_post_login_audit_row_preserves_only_the_existing_configuration_boundary(tmp_path, effect):
    h = Harness(tmp_path)
    schema = json.loads(h.schema)
    schema["results"]["children"]["login-time"] = {"children": {
        "last-failed-login": {"type": "datetime"}, "last-login": {"type": "datetime"},
        "last-login-ip": {"type": "string"}, "usr-name": {"type": "string"}}}
    h.schema = bytearray(json.dumps(schema).encode())
    h.record["login-time"] = []
    before = h.source.read_created()
    row = {"last-failed-login": "", "last-login": "2026-10-22 12:00:00",
        "last-login-ip": "192.0.2.10", "usr-name": NAME, "q_origin_key": NAME}
    h.record["login-time"] = [row]
    if effect == "configuration": h.record["comments"] = "configuration-change"
    elif effect == "gui-configuration": h.record["gui-custom-conf"] = "enable"
    elif effect == "unknown-audit-field": row["unclassified"] = "unexpected"
    elif effect == "audit-origin": row["q_origin_key"] = "different-user"
    elif effect == "audit-type": row["last-login"] = {"unexpected": "object"}
    if effect in {"configuration", "unknown-audit-field", "audit-origin", "audit-type"}:
        with pytest.raises(ValueError): h.source.read_created()
        assert h.source._failed and h.source._last_failure_stage == "complete_state_before"
    else:
        after = h.source.read_created()
        assert after.definition_digest == before.definition_digest
        assert (after.state_digest == before.state_digest) is (effect == "audit-only")
        assert (after.nonmaterial_state_digest == before.nonmaterial_state_digest) is (effect == "audit-only")
    assert all(resource.closed for resource in h.resources) and all(not any(raw) for raw in h.buffers)
