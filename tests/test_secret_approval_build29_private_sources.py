"""Fixed source composition over synthetic peers only; no network or device."""
from contextlib import asynccontextmanager
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import fortipam_mcp.secret_approval_build29_private_sources as module
from fortipam_mcp.owner_session_metadata import OwnerSessionMetadataTransport
from fortipam_mcp.secret_approval_build29_contract import qualify_secret_approval_build29_schema
from fortipam_mcp.secret_metadata_http_transport import FortiPamSecretMetadataHttpTransport, SecretMetadataHttpTransportConfig
from fortipam_mcp.target_ssh_transport import TargetSshTransportConfig
from test_secret_approval_build29_contract import _schema
from test_secret_approval_build29_native_preservation import _BASE, _APPLIED, _KEY, _NAME, _frame

SERIAL = "FPAVUNIT0001"
FOLDER = "Public/mcp-v4-private-source-unit"
WEB_URL = "https://unit-web.example.test/login"
ROOT = b"FPA-UNIT #"
SENTINEL = "synthetic-private-upstream-sentinel"


def detail(approval=_BASE):
    return {**module._NATIVE_ENVELOPE, "serial": SERIAL, "results": [{
        "id": 24, "name": _NAME, "folder": 17, "template": "Web Account", "target": "",
        **dict(zip(module._FIELD_ORDER, approval)),
        "field": [{"value": SENTINEL, "keyinfo": SENTINEL}],
        "totp-setting": {"status": "disable", "shared-key": SENTINEL}}]}


def totp(material=""):
    return {"http_method": "POST", "http_status": 200, "msg": "Successfully fetched clear_text",
            "status": "OK", "secret-id": 24, "results": material}


def wire(command, lines):
    return command.encode() + b"\r\r\n" + b"\r\n".join(lines) + b"\r\n" + ROOT


class Response:
    def __init__(self, value):
        self.value = value
        self.status_code = 200
        self.headers = {"content-type": "application/json; charset=utf-8"}
        self.raw_override = None
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def iter_bytes(self):
        raw = self.raw_override if self.raw_override is not None else json.dumps(self.value).encode()
        for index in range(0, len(raw), 29): yield raw[index:index + 29]


class Client:
    def __init__(self, events):
        self.events = events
        self.detail = Response(detail())
        self.before, self.after = Response(totp()), Response(totp())
        self.schema = Response({"version": "v7.0.0", "build": 29,
            "results": {"children": {**_schema()["selected_schema"], "field": {"value": SENTINEL}}}})
        self.cookie = "ccsrftoken=synthetic-csrf-unit"
        self.calls = []
        self.totp_calls = 0
        self.on_stream = None
    def build_request(self, method, path):
        assert method == "GET" and path == module._TOTP_PATH
        return SimpleNamespace(headers={"cookie": self.cookie})
    def stream(self, method, path, **kwargs):
        self.events.append(("http", method, path))
        self.calls.append((method, path, kwargs))
        if self.on_stream is not None: self.on_stream(method, path)
        if method == "POST":
            assert path == module._TOTP_PATH
            assert kwargs == {"json": {"secret-id": 24, "totp-share-key": 1},
                "headers": {"Accept": "application/json", "X-Requested-With": "XMLHttpRequest",
                            "X-CSRFTOKEN": "synthetic-csrf-unit"}}
            self.totp_calls += 1
            return self.before if self.totp_calls % 2 else self.after
        assert kwargs == {"headers": {"Accept": "application/json", "Cache-Control": "no-cache, no-store"}}
        assert path in {module.COLLECTION_PATH + "/24", module._SCHEMA_PATH}
        return self.schema if path == module._SCHEMA_PATH else self.detail


class Owner(OwnerSessionMetadataTransport):
    def __init__(self, events):
        config = SecretMetadataHttpTransportConfig("https://fpa.example.test", "unit-token", 15, None)
        super().__init__(config, owner_name="unit-owner", credentials=lambda: pytest.fail("no credentials requested"),
            folder_path=FOLDER, secret_name=_NAME, target_name="unit-target",
            witness=FortiPamSecretMetadataHttpTransport(config),
            client_factory=lambda **kwargs: pytest.fail("no login/client creation"), clock=lambda: self.now)
        self.now = 1.0
        self.client = Client(events)
    def activate(self):
        self._client = self.client
        self._expires_at = 300.0


class Peer:
    def __init__(self, owner, events):
        self.owner, self.events = owner, events
        self.connected = self.closed = self.connection_closed = 0
        self.prompt = ROOT
        self.serial = wire(module._SERIAL_COMMAND, [b"Serial-Number: " + SERIAL.encode()])
        self.version = wire(module._VERSION_COMMAND, [b"Version: FortiPAM-VM v7.0.0,build0029, synthetic"])
        self.native = wire("show full-configuration secret database 24", _frame().split(b"\n"))
        self.fail = None
        self.expire_at = None
    @asynccontextmanager
    async def connection(self):
        self.connected += 1
        self.events.append(("ssh", "connect"))
        try: yield self
        finally: self.connection_closed += 1
    async def create_process(self, **kwargs):
        assert kwargs == {"term_type": "vt100", "term_size": (1024, 1024), "encoding": None}
        return self
    @property
    def stdout(self): return self
    @property
    def stdin(self): return self
    async def login(self, stdout, stdin, deadline, maximum, *, accept_pre_login_banner):
        assert stdout is stdin is self and maximum == module._MAX_OUTPUT_BYTES and not accept_pre_login_banner
        if self.fail == "login": raise RuntimeError(SENTINEL)
        return self.prompt
    async def read(self, process, command, prompt, deadline):
        assert process is self and prompt == ROOT
        self.events.append(("ssh", command))
        if self.fail == command: raise RuntimeError(SENTINEL)
        if self.expire_at == command: self.owner.now = 300.0
        if command == module._SERIAL_COMMAND: return self.serial
        if command == module._VERSION_COMMAND: return self.version
        assert command == "show full-configuration secret database 24"
        return self.native
    async def close(self, process):
        assert process is self
        self.closed += 1
        if self.fail == "close": raise RuntimeError(SENTINEL)


@pytest.fixture
def setup(tmp_path, monkeypatch):
    events = []
    owner = Owner(events)
    hosts = tmp_path / "unit_known_hosts"
    hosts.write_text("synthetic pinned peer\n"); hosts.chmod(0o600)
    config = TargetSshTransportConfig("fpa.example.test", 22, "unit-owner", "synthetic-password", hosts, 15)
    options = dict(expected_serial=SERIAL, expected_secret_id=24, expected_secret_name=_NAME,
        folder_path=FOLDER, expected_folder_id=17, web_url=WEB_URL, witness_key=_KEY)
    source = module.SecretApprovalBuild29PrivateSources(owner, config, **options)
    peer = Peer(owner, events)
    monkeypatch.setattr(source._ssh, "_connection", peer.connection)
    monkeypatch.setattr(module, "_complete_pre_login", peer.login)
    monkeypatch.setattr(module, "_send_and_read", peer.read)
    monkeypatch.setattr(module, "_close_cli", peer.close)
    return source, owner, peer, events, config, options


def test_constructor_is_inert_and_bound_sources_preserve_semantics_without_login(setup):
    source, owner, peer, events, _, _ = setup
    assert events == [] and owner._client is None
    owner.activate()
    first = source.native_preservation_digest(_BASE)
    owner.client.detail.value = detail(_APPLIED)
    peer.native = wire("show full-configuration secret database 24", _frame(_APPLIED, enc=b"CHANGEDUNITENC02").split(b"\n"))
    second = source.native_preservation_digest(_APPLIED)
    assert first == second and len(first) == 64
    expected = [("http", "GET", module.COLLECTION_PATH + "/24"), ("http", "POST", module._TOTP_PATH),
        ("ssh", "connect"), ("ssh", module._SERIAL_COMMAND), ("ssh", module._VERSION_COMMAND),
        ("ssh", "show full-configuration secret database 24"), ("http", "POST", module._TOTP_PATH)]
    assert events == expected * 2
    assert peer.connected == peer.closed == peer.connection_closed == 2
    assert owner._client is owner.client and first not in repr(source)


@pytest.mark.parametrize("changes", [
    {"expected_secret_id": True}, {"expected_folder_id": 0}, {"expected_serial": "unsafe_serial"},
    {"expected_secret_name": "other-secret"}, {"folder_path": "Public/Other"}, {"web_url": "https://user@web.test"},
    {"witness_key": b"short"},
])
def test_constructor_denies_foreign_or_invalid_binding_without_io(setup, changes):
    _, owner, peer, events, config, options = setup
    with pytest.raises(module.SecretApprovalBuild29PrivateSourcesError):
        module.SecretApprovalBuild29PrivateSources(owner, config, **{**options, **changes})
    assert not events and peer.connected == 0


@pytest.mark.parametrize("attribute,value", [("host", "other.example.test"), ("username", "other-owner")])
def test_constructor_requires_same_http_ssh_host_and_owner(setup, attribute, value):
    _, owner, _, events, config, options = setup
    from dataclasses import replace
    with pytest.raises(module.SecretApprovalBuild29PrivateSourcesError):
        module.SecretApprovalBuild29PrivateSources(owner, replace(config, **{attribute: value}), **options)
    assert not events


@pytest.mark.parametrize("stage", ["native", "schema"])
@pytest.mark.parametrize("failure", ["inactive", "expired", "closed", "owner", "host"])
def test_inactive_expired_closed_or_changed_identity_denies_before_reads(setup, stage, failure):
    source, owner, peer, events, _, _ = setup
    if failure != "inactive": owner.activate()
    if failure == "expired": owner.now = 300.0
    if failure == "closed": source.close()
    if failure == "owner": owner._owner_name = "other-owner"
    if failure == "host": source._ssh._config = SimpleNamespace(host="other.example.test", username="unit-owner")
    with pytest.raises(module.SecretApprovalBuild29PrivateSourcesError):
        source.native_preservation_digest(_BASE) if stage == "native" else source.approval_schema()
    assert not events and peer.connected == 0


@pytest.mark.parametrize("changes", [{"version": "v7.0.1"}, {"build": True}, {"serial": "OTHERUNIT"},
    {"id": 25}, {"name": "other-secret"}, {"folder": 18}, {"template": "Other"}, {"target": "target"},
    {"need-approval": "enable"}, {"totp-setting": {"status": "enable", "shared-key": SENTINEL}}])
def test_sealed_http_metadata_refuses_foreign_subject_or_approval_before_totp(setup, changes):
    source, owner, peer, _, _, _ = setup
    owner.activate()
    for key, value in changes.items():
        (owner.client.detail.value if key in {"version", "build", "serial"} else owner.client.detail.value["results"][0])[key] = value
    with pytest.raises(module.SecretApprovalBuild29PrivateSourcesError): source.native_preservation_digest(_BASE)
    assert owner.client.totp_calls == peer.connected == 0


@pytest.mark.parametrize("phase", ["before", "after"])
@pytest.mark.parametrize("changes", [{"results": "MFRGGZDF"}, {"status": "success"}, {"secret-id": 25},
    {"msg": "Other status"}, {"version": "v7.0.0"}, {"results": None}])
def test_totp_exact_observed_markers_and_explicit_empty_bracket_are_required(setup, phase, changes):
    source, owner, peer, _, _, _ = setup
    owner.activate()
    getattr(owner.client, phase).value.update(changes)
    with pytest.raises(module.SecretApprovalBuild29PrivateSourcesError) as error:
        source.native_preservation_digest(_BASE)
    assert str(error.value) == module._UNAVAILABLE and error.value.__suppress_context__
    assert peer.connected == (phase == "after")
    assert peer.closed == peer.connection_closed == peer.connected


@pytest.mark.parametrize("kind", ["serial", "version", "prompt", "truncated", "echo", "name", "approval", "login", "close"])
def test_native_complete_frame_version_identity_and_cleanup_fail_closed(setup, kind):
    source, owner, peer, _, _, _ = setup
    owner.activate()
    if kind == "serial": peer.serial = wire(module._SERIAL_COMMAND, [b"Serial-Number: OTHERUNIT"])
    if kind == "version": peer.version = wire(module._VERSION_COMMAND, [b"Version: FortiPAM v7.0.0,build0030"])
    if kind == "prompt": peer.prompt = b"FPA-UNIT (database) #"
    if kind == "truncated": peer.native = peer.native[:-len(ROOT)]
    if kind == "echo": peer.native = b"foreign command\r\n" + peer.native
    if kind == "name": peer.native = peer.native.replace(_NAME.encode(), b"other-secret")
    if kind == "approval": peer.native = peer.native.replace(b"set bypass-approval enable", b"set bypass-approval disable")
    if kind in {"login", "close"}: peer.fail = kind
    with pytest.raises(module.SecretApprovalBuild29PrivateSourcesError) as error:
        source.native_preservation_digest(_BASE)
    assert SENTINEL not in str(error.value)
    assert peer.closed == peer.connection_closed == 1


@pytest.mark.parametrize("boundary", [module._SERIAL_COMMAND, module._VERSION_COMMAND, "show full-configuration secret database 24"])
def test_owner_ttl_is_rechecked_around_native_reads(setup, boundary):
    source, owner, peer, _, _, _ = setup
    owner.activate()
    peer.expire_at = boundary
    with pytest.raises(module.SecretApprovalBuild29PrivateSourcesError): source.native_preservation_digest(_BASE)
    assert owner.client.totp_calls == 1 and peer.closed == peer.connection_closed == 1


@pytest.mark.parametrize("cookie", ["", "ccsrftoken=\"unsafe token\"", "ccsrftoken=" + "a" * 4097])
def test_totp_csrf_refusal_precedes_post_and_ssh(setup, cookie):
    source, owner, peer, _, _, _ = setup
    owner.activate()
    owner.client.cookie = cookie
    with pytest.raises(module.SecretApprovalBuild29PrivateSourcesError): source.native_preservation_digest(_BASE)
    assert owner.client.totp_calls == peer.connected == 0


def test_schema_returns_only_qualified_four_fields_and_does_not_decode_material(setup, monkeypatch):
    source, owner, peer, _, _, _ = setup
    owner.activate()
    original = module.json.loads
    seen = []
    def loads(raw, **kwargs):
        if type(raw) is bytearray:
            assert SENTINEL.encode() not in raw
            if raw.startswith(b"{"):
                seen.append(raw)
        return original(raw, **kwargs)
    monkeypatch.setattr(module.json, "loads", loads)
    schema = source.approval_schema()
    qualify_secret_approval_build29_schema(schema)
    assert schema == _schema() and seen and all(not raw for raw in seen)
    assert owner.client.calls[0][:2] == ("GET", module._SCHEMA_PATH)
    assert peer.connected == 0 and SENTINEL not in json.dumps(schema)


@pytest.mark.parametrize("fault", ["build", "version", "missing", "shape", "member", "duplicate", "status", "content", "oversize"])
def test_schema_qualification_and_http_boundaries_are_closed(setup, fault, monkeypatch):
    source, owner, _, _, _, _ = setup
    owner.activate()
    response = owner.client.schema
    if fault == "build": response.value["build"] = True
    if fault == "version": response.value["version"] = "v7.0.1"
    if fault == "missing": response.value["results"]["children"].pop("need-approval")
    if fault == "shape": response.value["results"] = []
    if fault == "member": response.value["results"]["children"]["need-approval"]["default"] = "enable"
    if fault == "duplicate": response.raw_override = b'{"version":"v7.0.0","version":"v7.0.0","build":29,"results":{}}'
    if fault == "status": response.status_code = True
    if fault == "content": response.headers["content-type"] = "text/plain"
    if fault == "oversize": monkeypatch.setattr(module, "MAX_RESPONSE_BYTES", 10)
    with pytest.raises(module.SecretApprovalBuild29PrivateSourcesError): source.approval_schema()


def test_native_mutable_frame_lines_and_backing_buffers_are_erased_even_on_failure(setup, monkeypatch):
    source, owner, peer, _, _, _ = setup
    owner.activate()
    captured = []
    original = module._zeroize_mutable
    def wipe(raw):
        captured.append(raw)
        original(raw)
    monkeypatch.setattr(module, "_zeroize_mutable", wipe)
    peer.native = peer.native.replace(b"set bypass-approval enable", b"set bypass-approval disable")
    with pytest.raises(module.SecretApprovalBuild29PrivateSourcesError): source.native_preservation_digest(_BASE)
    assert captured and all(type(raw) is bytearray and not raw for raw in captured)
    key = source._key
    source.close()
    assert not key and _KEY


def test_private_get_helper_cannot_expand_compiled_routes(setup):
    source, owner, _, events, _, _ = setup
    owner.activate()
    with pytest.raises(ValueError): source._get("/api/v2/cmdb/system/admin", owner.client)
    assert not events


def linux_detail(approval=_BASE):
    payload = detail(approval)
    row = payload["results"][0]
    row.update(template=module.DEFAULT_TEMPLATE, target="unit-target", field=[
        {"id": index, "name": name, "type": kind, "value": SENTINEL}
        for index, (name, kind) in enumerate(
            (("Host", "target-address"), ("Username", "username"), ("Password", "password")), 1)])
    return payload


@pytest.fixture
def linux_setup(setup, monkeypatch):
    _, owner, peer, events, config, options = setup
    source = module.SecretApprovalBuild29PrivateSources(owner, config,
        **{**options, "web_url": None, "linux_target_name": "unit-target"})
    monkeypatch.setattr(source._ssh, "_connection", peer.connection)
    owner.client.detail.value = linux_detail()
    owner.activate()
    peer.native = wire("show full-configuration secret database 24", _frame().replace(
        b'        set description', b'        set template "Unix Account (SSH Password)"\n'
        b'        set target "unit-target"\n        set description').split(b"\n"))
    return source, owner, peer, events


def test_explicit_linux_native_kernel_preserves_template_and_target_bytes(linux_setup):
    source, owner, peer, _ = linux_setup
    baseline = source.native_preservation_digest(_BASE)
    assert len(baseline) == 64 and owner.client.totp_calls == 2
    peer.native = peer.native.replace(b'        set target "unit-target"', b'        set target "other-target"')
    assert source.native_preservation_digest(_BASE) != baseline
    assert peer.connected == peer.closed == peer.connection_closed == 2


def test_web_default_does_not_accept_linux_metadata(setup):
    source, owner, peer, _, _, _ = setup
    owner.activate()
    owner.client.detail.value = linux_detail()
    with pytest.raises(module.SecretApprovalBuild29PrivateSourcesError):
        source.native_preservation_digest(_BASE)
    assert owner.client.totp_calls == peer.connected == 0


@pytest.mark.parametrize("changes", [
    {"linux_target_name": "unit-target"}, {"web_url": None},
    {"web_url": None, "linux_target_name": "other-target"},
    {"web_url": None, "linux_target_name": ""},
    {"web_url": None, "linux_target_name": True},
    {"web_url": None, "linux_target_name": {"name": "unit-target"}},
])
def test_linux_binding_is_explicit_mutually_exclusive_and_owner_bound(setup, changes):
    _, owner, peer, events, config, options = setup
    with pytest.raises(module.SecretApprovalBuild29PrivateSourcesError):
        module.SecretApprovalBuild29PrivateSources(owner, config, **{**options, **changes})
    assert not events and peer.connected == 0


@pytest.mark.parametrize("key,value", [
    ("target", "other-target"), ("target", {"name": "unit-target"}),
    ("template", "Web Account"), ("template", {"name": module.DEFAULT_TEMPLATE}),
    ("need-approval", "enable"), ("approval-profile", "other-profile"),
    ("totp-setting", {"status": "enable"}), ("id", True), ("folder", 18),
])
def test_linux_metadata_refusals_precede_totp_and_ssh(linux_setup, key, value):
    source, owner, peer, _ = linux_setup
    owner.client.detail.value["results"][0][key] = value
    with pytest.raises(module.SecretApprovalBuild29PrivateSourcesError):
        source.native_preservation_digest(_BASE)
    assert owner.client.totp_calls == peer.connected == 0


@pytest.mark.parametrize("material", [None, "MFRGGZDF"])
def test_linux_nonempty_or_unproven_totp_refuses_before_ssh(linux_setup, material):
    source, owner, peer, _ = linux_setup
    owner.client.before.value["results"] = material
    with pytest.raises(module.SecretApprovalBuild29PrivateSourcesError):
        source.native_preservation_digest(_BASE)
    assert owner.client.totp_calls == 1 and peer.connected == 0


def test_linux_target_binding_drift_refuses_before_io(linux_setup):
    source, owner, peer, events = linux_setup
    owner._allowed_paths.remove("/api/v2/cmdb/secret/target/unit-target")
    with pytest.raises(module.SecretApprovalBuild29PrivateSourcesError):
        source.native_preservation_digest(_BASE)
    assert not events and peer.connected == 0


@pytest.mark.parametrize("linux,alias", [(False, "fpa.example.test"), (True, None),
    (True, "wrong.example.test"), (True, True)])
def test_ssh_alias_requires_explicit_linux_exact_host_binding(setup, linux, alias):
    from dataclasses import replace
    _, owner, peer, events, config, options = setup
    if linux:
        options = {**options, "web_url": None, "linux_target_name": "unit-target"}
        config = replace(config, host="ssh.example.test")
    with pytest.raises(module.SecretApprovalBuild29PrivateSourcesError):
        module.SecretApprovalBuild29PrivateSources(owner, config,
            **options, expected_ssh_host=alias)
    assert not events and peer.connected == 0


@pytest.fixture
def alias_setup(setup, monkeypatch):
    from dataclasses import replace
    _, owner, peer, events, config, options = setup
    source = module.SecretApprovalBuild29PrivateSources(owner,
        replace(config, host="ssh.example.test"), **{**options, "web_url": None,
        "linux_target_name": "unit-target", "expected_ssh_host": "ssh.example.test"})
    monkeypatch.setattr(source._ssh, "_connection", peer.connection)
    owner.client.detail.value = linux_detail()
    owner.activate()
    return source, owner, peer, events


def test_explicit_linux_alias_accepts_bound_sources(alias_setup):
    source, owner, peer, events = alias_setup
    assert not events
    assert len(source.native_preservation_digest(_BASE)) == 64
    commands = [event[1] for event in events if event[0] == "ssh"]
    assert commands == ["connect", module._SERIAL_COMMAND, module._VERSION_COMMAND,
                        "show full-configuration secret database 24"]
    assert peer.closed == peer.connection_closed == 1


@pytest.mark.parametrize("drift", ["alias", "ssh-host", "ssh-port", "http-host", "http-port"])
def test_linux_alias_endpoint_drift_refuses_before_io(alias_setup, drift):
    from dataclasses import replace
    source, owner, peer, events = alias_setup
    if drift == "alias": source._expected_ssh_host = "other.example.test"
    if drift == "ssh-host": source._ssh._config = replace(source._ssh._config, host="other.example.test")
    if drift == "ssh-port": source._ssh._config = replace(source._ssh._config, port=2222)
    if drift == "http-host": owner._config = replace(owner._config, base_url="https://other.example.test")
    if drift == "http-port": owner._config = replace(owner._config, base_url="https://fpa.example.test:8443")
    with pytest.raises(module.SecretApprovalBuild29PrivateSourcesError):
        source.native_preservation_digest(_BASE)
    assert not events and peer.connected == 0


@pytest.mark.parametrize("failure", ["serial", "version"])
def test_linux_alias_serial_version_failure_precedes_secret_cli(alias_setup, failure):
    source, owner, peer, events = alias_setup
    if failure == "serial": peer.serial = wire(module._SERIAL_COMMAND, [b"Serial-Number: OTHERUNIT"])
    if failure == "version": peer.version = wire(module._VERSION_COMMAND, [b"Version: FortiPAM v7.0.0,build0030"])
    with pytest.raises(module.SecretApprovalBuild29PrivateSourcesError):
        source.native_preservation_digest(_BASE)
    assert ("ssh", "show full-configuration secret database 24") not in events
    assert owner.client.totp_calls == 1 and peer.closed == peer.connection_closed == 1
