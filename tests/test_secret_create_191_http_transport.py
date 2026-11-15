from __future__ import annotations

import json
import pytest
from dataclasses import replace

from fortipam_mcp.secret_create_191_http_transport import (
    FortiPam191SecretCreateHttpTransport,
    _secret_create_body,
)
from fortipam_mcp.secret_create_191_private_adapter import (
    SecretCreate191TargetBinding,
    SecretCreate191WebBinding,
)
from fortipam_mcp.secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig,
)
from test_secret_create_central_lab_provider import _request
from v4_planning.secret_create_adapter import SecretCreateAdapterOutcome


class _Response:
    def __init__(self, status: int) -> None:
        self.status = status
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _Connection:
    def __init__(
        self,
        *args,
        response_status: int = 200,
        expected_event_filter: str | None = None,
        **kwargs,
    ) -> None:
        self.args = args
        self.kwargs = kwargs
        self.response = _Response(response_status)
        self.body: bytearray | None = None
        self.method = ""
        self.url = ""
        self.headers: dict[str, str] = {}
        self.body_valid = False
        self.closed = False
        self.expected_event_filter = expected_event_filter

    def request(self, method, url, body, headers) -> None:
        self.method = method
        self.url = url
        self.body = body.obj
        self.headers = headers
        parsed = json.loads(bytes(body))
        self.body_valid = parsed == {
            "id": 0,
            "name": "example-secret",
            "target": "example-target",
            "inherit-permission": "enable",
            "folder": 17,
            "template": "Unix Account (SSH Password)",
            "approval-profile": "",
            "av-profile": "",
            "av-scan": "disable",
            "bypass-ssh-filter-for-owner": "disable",
            "dlp-sensor": "",
            "dlp-status": "disable",
            "need-approval": "disable",
            "need-approval-job": "disable",
            "pwd-chg-sch-frequency": "month",
            "pwd-chg-sch-interval": 1,
            "pwd-chg-sch-month-day": "1",
            "pwd-chg-sch-month-type": "specific",
            "pwd-chg-sch-week-day": "",
            "rdp-event-filter": (
                "enable" if self.expected_event_filter is not None else "disable"
            ),
            "rdp-event-filter-profile": self.expected_event_filter or "",
            "secret-auth": "disable",
            "secret-auth-duration": 60,
            "secret-auth-server": "",
            "server-info": "Inherit",
            "ssh-filter": "disable",
            "ssh-filter-profile": "",
            "winappfilter": "disable",
            "winappfilter-profile": "",
            "target-privilege-account": "disable",
            "uuid": "11111111-2222-4333-8444-555555555555",
            "field": [
                {"id": 0, "name": "Host", "value": "192.0.2.10"},
                {"id": 0, "name": "Username", "value": "example-user"},
                {"id": 0, "name": "Password", "value": "example-password"},
            ],
        }

    def getresponse(self) -> _Response:
        return self.response

    def close(self) -> None:
        self.closed = True


class _MetadataTransport:
    def __init__(self) -> None:
        self.paths: list[str] = []

    def read_product_version(self) -> str:
        return "1.9.1"

    def read_product_version_and_build(self) -> tuple[str, int]:
        return "7.0.0", 29

    def resolve_folder_id(self, folder_path: str) -> int:
        self.paths.append(folder_path)
        return 17

    def resolve_secret_create_uuid(self) -> str:
        return "11111111-2222-4333-8444-555555555555"


def _binding() -> SecretCreate191TargetBinding:
    return SecretCreate191TargetBinding(
        "fortipam-191-secret-create-private-v1",
        "1.9.1",
        "1" * 64,
        "Public/example-folder",
        "example-secret",
        "Unix Account (SSH Password)",
        "example-target",
        "192.0.2.10",
    )


def _config() -> SecretMetadataHttpTransportConfig:
    return SecretMetadataHttpTransportConfig(
        base_url="https://fpa.example.test",
        bearer_token="unit-test-token",
        timeout_seconds=15,
        ca_file=None,
    )


def test_fixed_transport_posts_exact_body_without_reading_response(monkeypatch) -> None:
    connection = _Connection()
    monkeypatch.setattr(
        "fortipam_mcp.secret_create_191_http_transport._ssl_context",
        lambda _: object(),
    )
    transport = FortiPam191SecretCreateHttpTransport(
        _config(),
        connection_factory=lambda *args, **kwargs: connection,
        metadata_transport=_MetadataTransport(),
    )
    username = bytearray(b"example-user")
    password = bytearray(b"example-password")

    outcome = transport._create_and_verify_with_material(
        _binding(),
        _request(),
        memoryview(username).toreadonly(),
        memoryview(password).toreadonly(),
    )

    assert outcome is SecretCreateAdapterOutcome.VERIFIED_CREATED
    assert connection.method == "POST"
    assert connection.url == "/api/v2/cmdb/secret/database"
    assert connection.headers["Content-Type"] == "application/json"
    assert connection.headers["Connection"] == "close"
    assert connection.headers["User-Agent"] == "fortipam-mcp-v4-secret-create/1"
    assert connection.body_valid is True
    assert connection.response.closed is True
    assert connection.closed is True
    assert transport.last_failure_stage is None
    assert transport.last_http_status is None
    assert connection.body is not None
    assert not any(connection.body)


def test_rdp_service_activation_is_explicit_and_independent_of_event_filter() -> None:
    for enabled in (False, True):
        body = _secret_create_body(
            replace(_binding(), rdp_service_enabled=enabled),
            17,
            "00000000-0000-4000-8000-000000000001",
            memoryview(b"example-user"),
            memoryview(b"example-password"),
        )
        try:
            parsed = json.loads(body)
            assert parsed.get("rdp-service-status") == ("up" if enabled else None)
            assert parsed["rdp-event-filter"] == "disable"
        finally:
            body[:] = b"\x00" * len(body)


def test_build29_linux_ssh_candidate_pins_version_and_enables_ssh_service(monkeypatch) -> None:
    class LinuxConnection(_Connection):
        def request(self, method, url, body, headers) -> None:
            super().request(method, url, body, headers)
            parsed = json.loads(bytes(body))
            self.body_valid = (
                parsed.get("ssh-service-status") == "up"
                and parsed.get("rdp-service-status") is None
                and parsed.get("template") == "Unix Account (SSH Password)"
            )

    connection = LinuxConnection()
    monkeypatch.setattr(
        "fortipam_mcp.secret_create_191_http_transport._ssl_context",
        lambda _: object(),
    )
    transport = FortiPam191SecretCreateHttpTransport(
        _config(), connection_factory=lambda *args, **kwargs: connection,
        metadata_transport=_MetadataTransport(),
    )
    candidate = replace(
        _binding(),
        contract_ref="fortipam-700-build29-linux-ssh-create-candidate-v1",
        target_product_version="7.0.0",
        target_product_build=29,
    )
    result = transport._create_and_verify_with_material(
        candidate, _request(), memoryview(b"example-user"), memoryview(b"example-password"),
    )
    assert result is SecretCreateAdapterOutcome.VERIFIED_CREATED
    assert connection.body_valid
    assert connection.body is not None and not any(connection.body)


def test_build29_linux_v2_body_enables_ssh_sftp_and_recording_only() -> None:
    binding = replace(
        _binding(),
        contract_ref="fortipam-700-build29-linux-ssh-sftp-recording-create-candidate-v2",
        target_product_version="7.0.0",
        target_product_build=29,
    )
    body = _secret_create_body(
        binding,
        17,
        "11111111-2222-4333-8444-555555555555",
        memoryview(b"example-user"),
        memoryview(b"example-password"),
    )
    try:
        parsed = json.loads(body)
        assert parsed["ssh-service-status"] == "up"
        assert parsed["sftp-service-status"] == "up"
        assert parsed["recording"] == "enable"
        assert "rdp-service-status" not in parsed
        assert "http-service-status" not in parsed
    finally:
        body[:] = b"\x00" * len(body)


def test_build29_rdp_body_enables_only_the_declared_rdp_controls() -> None:
    binding = replace(
        _binding(),
        contract_ref="fortipam-700-build29-windows-rdp-create-candidate-v1",
        target_product_version="7.0.0", target_product_build=29,
        template_name="Windows Machine", rdp_service_enabled=True,
    )
    body = _secret_create_body(binding, 17, "11111111-2222-4333-8444-555555555555",
                               memoryview(b"example-user"), memoryview(b"example-password"))
    try:
        parsed = json.loads(body)
        assert parsed["rdp-service-status"] == "up"
        assert parsed["recording"] == parsed["block-clipboard"] == parsed["proxy"] == "enable"
        assert parsed["rdp-tcp-forward"] == "disable"
        assert "ssh-service-status" not in parsed
        assert "sftp-service-status" not in parsed
        assert "http-service-status" not in parsed
        assert parsed["target-privilege-account"] == "disable"
    finally:
        body[:] = b"\x00" * len(body)


def test_fixed_transport_binds_selected_rdp_event_filter(monkeypatch) -> None:
    connection = _Connection(
        expected_event_filter="mcp-v4-rdp-event-filter-existing"
    )
    monkeypatch.setattr(
        "fortipam_mcp.secret_create_191_http_transport._ssl_context",
        lambda _: object(),
    )
    transport = FortiPam191SecretCreateHttpTransport(
        _config(),
        connection_factory=lambda *args, **kwargs: connection,
        metadata_transport=_MetadataTransport(),
    )

    outcome = transport._create_and_verify_with_material(
        replace(
            _binding(),
            rdp_event_filter_profile_name="mcp-v4-rdp-event-filter-existing",
        ),
        _request(),
        memoryview(bytearray(b"example-user")).toreadonly(),
        memoryview(bytearray(b"example-password")).toreadonly(),
    )

    assert outcome is SecretCreateAdapterOutcome.VERIFIED_CREATED
    assert connection.body_valid is True


@pytest.mark.parametrize("candidate", [False, True])
def test_fixed_transport_posts_non_target_web_account_with_recording(monkeypatch, candidate) -> None:
    connection = _Connection()

    def validate_web_body(method, url, body, headers) -> None:
        connection.method = method
        connection.url = url
        connection.body = body.obj
        connection.headers = headers
        parsed = json.loads(bytes(body))
        connection.body_valid = (
            "target" not in parsed
            and parsed["template"] == "Web Account"
            and parsed["recording"] == "enable"
            and parsed["http-service-status"] == "up"
            and parsed["field"]
            == [
                {"id": 0, "name": "URL", "value": "https://app.example.test/login"},
                {"id": 0, "name": "Username", "value": "example-user"},
                {"id": 0, "name": "Password", "value": "example-password"},
            ]
        )

    connection.request = validate_web_body  # type: ignore[method-assign]
    monkeypatch.setattr(
        "fortipam_mcp.secret_create_191_http_transport._ssl_context",
        lambda _: object(),
    )
    transport = FortiPam191SecretCreateHttpTransport(
        _config(),
        connection_factory=lambda *args, **kwargs: connection,
        metadata_transport=_MetadataTransport(),
    )
    binding = SecretCreate191WebBinding(
        "fortipam-191-web-secret-create-private-v1",
        "1.9.1",
        "1" * 64,
        "Public/example-folder",
        "example-secret",
        "Web Account",
        "https://app.example.test/login",
        True,
    )

    if candidate:
        binding = replace(binding, contract_ref="fortipam-700-build29-web-secret-create-candidate-v1",
                          target_product_version="7.0.0", target_product_build=29)
    outcome = transport._create_and_verify_with_material(
        binding,
        _request(),
        memoryview(bytearray(b"example-user")).toreadonly(),
        memoryview(bytearray(b"example-password")).toreadonly(),
    )

    assert outcome is SecretCreateAdapterOutcome.VERIFIED_CREATED
    assert connection.body_valid is True
    assert connection.body is not None
    assert not any(connection.body)


def test_non_200_or_invalid_material_requires_reconciliation(monkeypatch) -> None:
    monkeypatch.setattr(
        "fortipam_mcp.secret_create_191_http_transport._ssl_context",
        lambda _: object(),
    )
    for status in (201, 400, 500):
        connection = _Connection(response_status=status)
        transport = FortiPam191SecretCreateHttpTransport(
            _config(),
            connection_factory=lambda *args, **kwargs: connection,
            metadata_transport=_MetadataTransport(),
        )
        assert transport._create_and_verify_with_material(
            _binding(),
            _request(),
            memoryview(bytearray(b"example-user")).toreadonly(),
            memoryview(bytearray(b"example-password")).toreadonly(),
        ) is SecretCreateAdapterOutcome.RECONCILIATION_REQUIRED
        assert transport.last_failure_stage == "secret_create_post"
        assert transport.last_http_status == status

    transport = FortiPam191SecretCreateHttpTransport(
        _config(), metadata_transport=_MetadataTransport()
    )
    assert transport._create_and_verify_with_material(
        _binding(),
        _request(),
        memoryview(bytearray()),
        memoryview(bytearray(b"example-password")),
    ) is SecretCreateAdapterOutcome.RECONCILIATION_REQUIRED
    assert transport.last_failure_stage == "secret_create_prewrite"
    assert transport.last_http_status is None


@pytest.mark.parametrize("version", ["7.0.0", None])
def test_version_mismatch_or_unavailable_stops_before_body_and_post(monkeypatch, version):
    calls = []
    class Metadata:
        def read_product_version(self):
            calls.append("version")
            if version is None:
                raise RuntimeError("private status response")
            return version
        def resolve_folder_id(self, folder_path):
            calls.append("folder")
            raise AssertionError
        def resolve_secret_create_uuid(self):
            calls.append("uuid")
            raise AssertionError
    def forbidden(*args, **kwargs):
        calls.append("body_or_connection")
        raise AssertionError
    monkeypatch.setattr("fortipam_mcp.secret_create_191_http_transport._secret_create_body", forbidden)
    transport = FortiPam191SecretCreateHttpTransport(
        _config(), metadata_transport=Metadata(), connection_factory=forbidden,
    )
    outcome = transport._create_and_verify_with_material(
        _binding(), _request(), memoryview(bytearray(b"user")), memoryview(bytearray(b"password")),
    )
    assert outcome is SecretCreateAdapterOutcome.RECONCILIATION_REQUIRED
    assert calls == ["version"]
    assert transport.last_failure_stage == "secret_create_version"
    assert transport.last_http_status is None


@pytest.mark.parametrize("identity", [("7.0.0", 30), ("1.9.1", 29), None])
def test_web_candidate_rejects_wrong_or_unavailable_build_before_body(monkeypatch, identity):
    calls = []
    class Metadata(_MetadataTransport):
        def read_product_version_and_build(self):
            calls.append("identity")
            if identity is None:
                raise ValueError
            return identity
        def resolve_folder_id(self, folder_path):
            calls.append("folder")
            raise AssertionError
    def forbidden(*args, **kwargs):
        calls.append("body_or_connection")
        raise AssertionError
    monkeypatch.setattr("fortipam_mcp.secret_create_191_http_transport._secret_create_body", forbidden)
    binding = SecretCreate191WebBinding(
        "fortipam-700-build29-web-secret-create-candidate-v1", "7.0.0", "1" * 64,
        "Public/example-folder", "example-secret", "Web Account", "https://app.example.test/login", True, 29,
    )
    transport = FortiPam191SecretCreateHttpTransport(_config(), metadata_transport=Metadata(), connection_factory=forbidden)
    outcome = transport._create_and_verify_with_material(binding, _request(), memoryview(b"user"), memoryview(b"password"))
    assert outcome is SecretCreateAdapterOutcome.RECONCILIATION_REQUIRED
    assert calls == ["identity"] and transport.last_failure_stage == "secret_create_version"


def test_unqualified_create_defaults_stop_before_material_body_and_post(monkeypatch):
    calls = []

    class Metadata(_MetadataTransport):
        def resolve_secret_create_uuid(self):
            calls.append("defaults_rejected")
            raise RuntimeError("Unqualified privilege-role default")

    def forbidden(*args, **kwargs):
        calls.append("body_or_connection")
        raise AssertionError

    monkeypatch.setattr(
        "fortipam_mcp.secret_create_191_http_transport._secret_create_body", forbidden
    )
    transport = FortiPam191SecretCreateHttpTransport(
        _config(), metadata_transport=Metadata(), connection_factory=forbidden,
    )
    outcome = transport._create_and_verify_with_material(
        _binding(), _request(), memoryview(b"example-user"), memoryview(b"example-password"),
    )
    assert outcome is SecretCreateAdapterOutcome.RECONCILIATION_REQUIRED
    assert calls == ["defaults_rejected"]
    assert transport.last_failure_stage == "secret_create_prewrite"
    assert transport.last_http_status is None


def _winrm_binding():
    from fortipam_mcp.secret_create_191_private_adapter import SecretCreate700WinrmBinding
    return SecretCreate700WinrmBinding(
        "fortipam-700-build29-winrm-collector-create-candidate-v2", "7.0.0",
        "1" * 64, "Public/example-folder", "example-secret", "Windows Machine",
        "example-target", "192.0.2.10", "example-owner",
        "Public/witness-folder", "existing-witness", "mcp-v4-rdp-event-filter-example",
    )


@pytest.mark.parametrize("defect", [None, "missing_target", "domain_drift", "owner_drift", "class_drift", "template_drift", "template_type_drift"])
@pytest.mark.parametrize("target", ("mcp-v4-target-domain-20261002-r2", "192.0.2.10_auto_1700000000"))
@pytest.mark.parametrize("classification_tag", ("Other", "Existing Domain Tag"))
def test_domain_candidate_requires_exact_dependencies_and_zeroizes_native_fields(monkeypatch, defect, target, classification_tag):
    from fortipam_mcp.secret_create_191_private_adapter import SecretCreate700DomainBinding
    from fortipam_mcp.secret_metadata_http_transport import FortiPamSecretMetadataHttpTransport
    from fortipam_mcp.target_contract import DomainTargetCreateInput

    if not target.startswith("mcp-v4-target-domain-"):
        with pytest.raises(ValueError):
            DomainTargetCreateInput(target, "192.0.2.10", "ad.example.test")
    binding = SecretCreate700DomainBinding(
        "fortipam-700-build29-domain-account-create-candidate-v1", "7.0.0", "1"*64,
        "Public/example-folder", "example-secret", "Windows Domain Account",
        target, "192.0.2.10", "ad.example.test", "example-owner")
    if classification_tag != "Other":
        binding = replace(binding, target_classification_tag=classification_tag)
    record = {"name":target, "class":classification_tag, "address":"192.0.2.10", "domain":"ad.example.test",
        "template":"Windows Domain Account", "ldaps-port":636,
        "user-naming-attribute":"sAMAccountName", "user-base":"", "access":"customized",
        "web-proxy-status":"disable", "user-permission":[{"permission":"owner", "user-name":[{"name":"example-owner"}]}]}
    if defect == "class_drift": record["class"] = "Unexpected Tag"
    if defect == "domain_drift": record["domain"] = "other.example.test"
    if defect == "owner_drift": record["user-permission"] = []
    fields = [{"name":name, "type":kind} for name,kind in (
        ("Domain-Controller", "target-address"), ("Domain", "domain"),
        ("Username", "username"), ("Password", "password"))]
    if defect == "template_drift": fields[0]["name"] = "Host"
    if defect == "template_type_drift": fields[3]["type"] = "text"
    calls = []

    class Metadata(_MetadataTransport):
        verify_domain_account_preflight = FortiPamSecretMetadataHttpTransport.verify_domain_account_preflight

        def _request(self, method, path, body, *, query=None):
            calls.append((method,path,body,query))
            assert method == "GET" and body is None and "database" not in path
            name = "target" if "/target/" in path else "template"
            assert path in {"/api/v2/cmdb/secret/target/"+target, "/api/v2/cmdb/secret/template/Windows%20Domain%20Account"}
            code = 404 if defect == "missing_target" and name == "target" else 200
            rows = [record] if name == "target" else [{"name":"Windows Domain Account","field":fields}]
            return code, {"version":"v7.0.0","build":29,"status":"Not Found" if code==404 else "success",
                "http_method":"GET","http_status":code,"path":"secret","name":name,"vdom":"root",
                "results":[] if code==404 else rows}

    class DomainConnection(_Connection):
        def request(self, method, url, body, headers):
            self.method, self.url, self.body = method, url, body.obj
            data = json.loads(bytes(body))
            assert data["target"] == target and data["template"] == "Windows Domain Account"
            assert data["target-privilege-account"] == "disable"
            assert all(data[key] == "down" for key in ("rdp-service-status","ssh-service-status","sftp-service-status",
                "http-service-status","samba-service-status","telnet-service-status"))
            assert data["field"] == [{"id":0,"name":name,"value":value} for name,value in (
                ("Password","example-password"),("Username","example-user"))]

    connection = DomainConnection()
    monkeypatch.setattr("fortipam_mcp.secret_create_191_http_transport._ssl_context",lambda _:object())
    transport = FortiPam191SecretCreateHttpTransport(_config(),metadata_transport=Metadata(),
        connection_factory=lambda *args,**kwargs:connection)
    outcome = transport._create_and_verify_with_material(binding,_request(),
        memoryview(b"example-user"),memoryview(b"example-password"))
    assert target not in repr(binding) and "ad.example.test" not in repr(binding)
    if defect is None:
        assert outcome is SecretCreateAdapterOutcome.VERIFIED_CREATED
        assert len(calls)==2 and connection.method=="POST" and connection.closed
        assert connection.body is not None and not any(connection.body)
    else:
        assert outcome is SecretCreateAdapterOutcome.RECONCILIATION_REQUIRED
        assert connection.method=="" and connection.body is None
        assert transport.last_failure_stage=="secret_create_prewrite"


@pytest.mark.parametrize("preflight", [True, False, None])
def test_collector_fixed_body_and_predispatch_denial(monkeypatch, preflight) -> None:
    class Metadata(_MetadataTransport):
        def verify_winrm_collector_preflight(self, *args):
            assert args == ("Public/example-folder", "example-secret", "example-owner",
                            "Public/witness-folder", "existing-witness", "example-target", "192.0.2.10")
            return preflight

    class CollectorConnection(_Connection):
        def request(self, method, url, body, headers):
            self.method, self.url, self.body = method, url, body.obj
            data = json.loads(bytes(body))
            assert data["target-privilege-account"] == "enable"
            assert data["target"] == "example-target"
            assert data["template"] == "Windows Machine"
            assert data["recording"] == "enable"
            assert data["rdp-event-filter"] == "enable"
            assert data["rdp-event-filter-profile"] == "mcp-v4-rdp-event-filter-example"
            assert data["rdp-service-status"] == "up"
            assert all(data[key] == "down" for key in (
                "ssh-service-status", "http-service-status",
                "samba-service-status", "telnet-service-status",
            ))
            assert data["field"] == [
                {"id": 0, "name": "Host", "value": "192.0.2.10"},
                {"id": 0, "name": "Username", "value": "example-user"},
                {"id": 0, "name": "Password", "value": "example-password"},
            ]

    connection = CollectorConnection()
    monkeypatch.setattr("fortipam_mcp.secret_create_191_http_transport._ssl_context", lambda _: object())
    transport = FortiPam191SecretCreateHttpTransport(
        _config(), connection_factory=lambda *args, **kwargs: connection,
        metadata_transport=Metadata(),
    )
    outcome = transport._create_and_verify_with_material(
        _winrm_binding(), _request(),
        memoryview(b"example-user"), memoryview(b"example-password"),
    )
    if preflight is True:
        assert outcome is SecretCreateAdapterOutcome.VERIFIED_CREATED
        assert connection.method == "POST" and connection.closed
        assert connection.body is not None and not any(connection.body)
    else:
        assert outcome is SecretCreateAdapterOutcome.RECONCILIATION_REQUIRED
        assert connection.method == "" and connection.body is None
        assert transport.last_failure_stage == "secret_create_prewrite"


@pytest.mark.parametrize("changes", [
    {"target_product_version": "1.9.1"}, {"target_product_build": 30},
    {"template_name": "Web Account"},
    {"rdp_event_filter_profile_name": "not-an-event-profile"},
    {"witness_folder_path": "Public/example-folder", "witness_secret_name": "example-secret"},
])
def test_collector_binding_rejects_other_profile_or_self_witness(changes) -> None:
    from v4_planning.secret_create_adapter import SecretCreateAdapterDenied
    with pytest.raises(SecretCreateAdapterDenied):
        replace(_winrm_binding(), **changes)


def test_transport_failure_logs_only_stage_and_http_status(monkeypatch, caplog):
    monkeypatch.setattr(
        "fortipam_mcp.secret_create_191_http_transport._ssl_context", lambda _: object()
    )
    connection = _Connection(response_status=403)
    transport = FortiPam191SecretCreateHttpTransport(
        _config(), metadata_transport=_MetadataTransport(),
        connection_factory=lambda *args, **kwargs: connection,
    )
    assert transport._create_and_verify_with_material(
        _binding(), _request(), memoryview(b"private-user"), memoryview(b"private-password")
    ) is SecretCreateAdapterOutcome.RECONCILIATION_REQUIRED
    assert "stage=secret_create_post http_status=403" in caplog.text
    assert all(value not in caplog.text for value in ("private-user", "private-password", "example-secret", "unit-test-token"))
    caplog.clear()

    def fail(*args, **kwargs):
        raise RuntimeError("private-user private-password private-response")

    transport = FortiPam191SecretCreateHttpTransport(
        _config(), metadata_transport=_MetadataTransport(), connection_factory=fail,
    )
    assert transport._create_and_verify_with_material(
        _binding(), _request(), memoryview(b"private-user"), memoryview(b"private-password")
    ) is SecretCreateAdapterOutcome.RECONCILIATION_REQUIRED
    assert "stage=secret_create_prewrite" in caplog.text
    assert "private-" not in caplog.text
    assert "example-secret" not in caplog.text
    assert "unit-test-token" not in caplog.text
    assert "Traceback" not in caplog.text


@pytest.mark.parametrize("defect", [None, "missing_reader", "existing_secret", "missing_folder", "material_attached", "wrong_build", "dependency_drift"])
def test_target_bound_web_create_uses_private_dependency_and_no_url_field(monkeypatch, defect) -> None:
    from fortipam_mcp.secret_create_191_private_adapter import SecretCreate700WebTargetBinding
    from fortipam_mcp.secret_metadata_http_transport import SecretMetadataProjectionInspection
    from fortipam_mcp.target_contract import WebTargetCreateInput
    target = WebTargetCreateInput("mcp-v4-target-web-20261003-r1", "https://app.example.test")
    binding = SecretCreate700WebTargetBinding(
        "fortipam-700-build29-target-bound-web-create-candidate-v1", "7.0.0", "1" * 64,
        "Public/example-folder", "example-secret", "Web Account", target, True)
    class Metadata(_MetadataTransport):
        def read_product_version_and_build(self):
            return ("7.0.0", 30 if defect == "wrong_build" else 29)
        def inspect_target_bound_web_projection(self, folder, name, *, target):
            assert folder == binding.folder_path and name == binding.secret_name and target == binding.target
            if defect == "dependency_drift": raise ValueError("private dependency mismatch")
            return SecretMetadataProjectionInspection(defect == "existing_secret", defect != "missing_folder",
                True, False, False, False, False, defect == "material_attached")
    class WebConnection(_Connection):
        def request(self, method, url, body, headers):
            self.method, self.url, self.body = method, url, body.obj
            parsed = json.loads(bytes(body))
            assert parsed["target"] == target.target_name and parsed["template"] == "Web Account"
            assert parsed["recording"] == "enable" and parsed["http-service-status"] == "up"
            assert parsed["proxy"] == "enable" and parsed["inherit-permission"] == "enable"
            assert parsed["field"] == [{"id": 0, "name": "Password", "value": "example-password"},
                                        {"id": 0, "name": "Username", "value": "example-user"}]
            assert target.web_url.encode() not in bytes(body)
    metadata = _MetadataTransport() if defect == "missing_reader" else Metadata()
    connection = WebConnection()
    monkeypatch.setattr("fortipam_mcp.secret_create_191_http_transport._ssl_context", lambda _: object())
    transport = FortiPam191SecretCreateHttpTransport(_config(), metadata_transport=metadata,
        connection_factory=lambda *a, **k: connection)
    result = transport._create_and_verify_with_material(binding, _request(),
        memoryview(b"example-user"), memoryview(b"example-password"))
    assert target.target_name not in repr(binding) and target.web_url not in repr(binding)
    if defect is None:
        assert result is SecretCreateAdapterOutcome.VERIFIED_CREATED and connection.method == "POST"
        assert connection.closed and connection.body is not None and not any(connection.body)
    else:
        assert result is SecretCreateAdapterOutcome.RECONCILIATION_REQUIRED
        assert connection.body is None
