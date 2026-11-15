from __future__ import annotations

from dataclasses import replace
import inspect
import os
from typing import Any, cast

import pytest

from fortipam_mcp.secret_create_central_lab_binding import (
    OwnerOnlyCentralLabSecretCreateBindingResolver,
)
from fortipam_mcp.secret_create_191_private_adapter import (
    FortiPam191SecretCreatePrivateAdapter,
    SecretCreate191TargetBinding,
)
from fortipam_mcp.secret_create_central_lab_provider import (
    CentralLabInventorySecretCreateProvider,
    CentralLabSecretCreate191LeaseTransport,
    OwnerOnlyCentralLabSecretCreateEnvFileLoader,
)
from v4_planning.material_provider import (
    C3MaterialBinding,
    MaterialAccessDenied,
    MaterialBindingStatus,
    MaterialLeaseCompletion,
    MaterialLeaseRequest,
    MaterialProviderClass,
    MaterialPurpose,
    MaterialRevocationReason,
)
from v4_planning.material_runtime import (
    InMemoryMaterialUseStateStore,
    MaterialRuntimeOutcome,
)
from v4_planning.secret_create_adapter import SecretCreateAdapterOutcome
from v4_planning.secret_create_runtime import SecretCreateMaterialRuntime


NOW = 1_000
USERNAME_VARIABLE = "LAB_SECRET_USERNAME"
PASSWORD_VARIABLE = "LAB_SECRET_PASSWORD"


def _request() -> MaterialLeaseRequest:
    return MaterialLeaseRequest(
        action_id="secret-create-from-reference",
        action_version="1.0.0",
        plan_digest="1" * 64,
        policy_decision_digest="2" * 64,
        authorization_digest="3" * 64,
        scope_digest="4" * 64,
        audience_digest="5" * 64,
        provider_class=MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE,
        purpose=MaterialPurpose.INITIAL_ONBOARDING,
        requested_at=NOW,
        expires_at=NOW + 60,
    )


def _target_binding() -> SecretCreate191TargetBinding:
    return SecretCreate191TargetBinding(
        "fortipam-191-secret-create-private-v1",
        "1.9.1",
        "1" * 64,
        "Lab/example-folder",
        "example-secret",
        "Unix Account (SSH Password)",
        "example-target",
        "192.0.2.10",
    )


class _PreboundLoader:
    def __init__(
        self,
        *,
        status: MaterialBindingStatus = MaterialBindingStatus.AVAILABLE,
        fail_validation: bool = False,
    ) -> None:
        self.status = status
        self.fail_validation = fail_validation
        self.validate_calls = 0
        self.load_calls = 0
        self.username = bytearray([65] * 8)
        self.password = bytearray([66] * 8)

    def validate_prebound(self) -> MaterialBindingStatus:
        self.validate_calls += 1
        if self.fail_validation:
            raise RuntimeError("private resolver detail")
        return self.status

    def load_secret_create_material_once(self) -> tuple[bytearray, bytearray]:
        self.load_calls += 1
        return self.username, self.password


class _MaterialTransport:
    def __init__(self) -> None:
        self.calls = 0
        self.lengths: tuple[int, int] | None = None
        self.views: tuple[memoryview, memoryview] | None = None

    def _create_and_verify_with_material(
        self,
        binding: SecretCreate191TargetBinding,
        request: MaterialLeaseRequest,
        username: memoryview,
        password: memoryview,
    ) -> SecretCreateAdapterOutcome:
        assert binding is not None
        assert request == _request()
        assert username.readonly is True
        assert password.readonly is True
        self.calls += 1
        self.lengths = (username.nbytes, password.nbytes)
        self.views = (username, password)
        return SecretCreateAdapterOutcome.VERIFIED_CREATED


class _LiteralPunctuationTransport(_MaterialTransport):
    def _create_and_verify_with_material(
        self,
        binding: SecretCreate191TargetBinding,
        request: MaterialLeaseRequest,
        username: memoryview,
        password: memoryview,
    ) -> SecretCreateAdapterOutcome:
        assert username.nbytes == 5
        assert password.nbytes == 5
        assert username[0] == 65
        assert username[1] == 36
        assert username[2] == 96
        assert username[3] == 39
        assert username[4] == 66
        assert password[0] == 67
        assert password[1] == 36
        assert password[2] == 96
        assert password[3] == 39
        assert password[4] == 68
        return super()._create_and_verify_with_material(
            binding,
            request,
            username,
            password,
        )


def _provider(
    loader: _PreboundLoader,
    binding: C3MaterialBinding,
    request: MaterialLeaseRequest,
) -> CentralLabInventorySecretCreateProvider:
    return CentralLabInventorySecretCreateProvider(
        loader,
        binding=binding,
        request=request,
        clock=lambda: NOW + 1,
    )


def _write_secret_env(path: Any, content: bytes, *, mode: int = 0o600) -> None:
    path.write_bytes(content)
    path.chmod(mode)


def _concrete_loader(path: Any) -> OwnerOnlyCentralLabSecretCreateEnvFileLoader:
    return OwnerOnlyCentralLabSecretCreateEnvFileLoader(
        secret_env_path=path,
        username_variable_name=USERNAME_VARIABLE,
        password_variable_name=PASSWORD_VARIABLE,
    )


def _valid_secret_env() -> bytes:
    return (
        USERNAME_VARIABLE.encode("ascii")
        + b"="
        + bytes([65]) * 8
        + b"\n"
        + PASSWORD_VARIABLE.encode("ascii")
        + b"='"
        + bytes([66]) * 8
        + b"'\n"
    )


def _write_credential_bindings(path: Any) -> None:
    path.write_text(
        "schema_version: credential-bindings-v1\n"
        "bindings:\n"
        "  - id: fixed-secret-create\n"
        "    provider: env-file\n"
        "    variables:\n"
        f"      username: {USERNAME_VARIABLE}\n"
        f"      password: {PASSWORD_VARIABLE}\n",
        encoding="utf-8",
    )
    path.chmod(0o600)


def test_owner_only_8022_binding_resolver_pins_metadata_and_loads_directly(
    tmp_path,
) -> None:
    binding_path = tmp_path / "credential-bindings.local.yaml"
    secret_env = tmp_path / "fortinet-lab.local.env"
    _write_credential_bindings(binding_path)
    _write_secret_env(secret_env, _valid_secret_env())
    request = _request()
    resolver = OwnerOnlyCentralLabSecretCreateBindingResolver(
        credential_bindings_path=binding_path,
        secret_env_path=secret_env,
        binding_ref="private-material-binding-ref01",
        credential_binding_id="fixed-secret-create",
        request=request,
    )

    binding = resolver.resolve("private-material-binding-ref01", request)
    assert isinstance(binding, C3MaterialBinding)
    assert resolver.validate_prebound() is MaterialBindingStatus.AVAILABLE
    provider = CentralLabInventorySecretCreateProvider(
        resolver,
        binding=binding,
        request=request,
        clock=lambda: NOW + 1,
    )
    assert provider.validate_binding(binding, request) is MaterialBindingStatus.AVAILABLE
    username, password = resolver.load_secret_create_material_once()
    assert (len(username), len(password)) == (8, 8)
    username.clear()
    password.clear()
    assert repr(resolver).endswith(" redacted>")

    _write_credential_bindings(binding_path)
    with binding_path.open("a", encoding="utf-8") as stream:
        stream.write("# drift\n")
    assert resolver.validate_prebound() is MaterialBindingStatus.UNAVAILABLE
    with pytest.raises(MaterialAccessDenied, match="unavailable"):
        resolver.resolve("private-material-binding-ref01", request)


def test_owner_only_8022_binding_resolver_rejects_unsafe_metadata(tmp_path) -> None:
    binding_path = tmp_path / "credential-bindings.local.yaml"
    secret_env = tmp_path / "fortinet-lab.local.env"
    _write_credential_bindings(binding_path)
    _write_secret_env(secret_env, _valid_secret_env())
    binding_path.chmod(0o640)

    with pytest.raises(MaterialAccessDenied, match="unavailable"):
        OwnerOnlyCentralLabSecretCreateBindingResolver(
            credential_bindings_path=binding_path,
            secret_env_path=secret_env,
            binding_ref="private-material-binding-ref01",
            credential_binding_id="fixed-secret-create",
            request=_request(),
        )

    binding_path.write_text(
        "schema_version: credential-bindings-v1\n"
        "bindings:\n"
        "  - id: fixed-secret-create\n"
        "    provider: env-file\n"
        "    variables:\n"
        f"      username: {USERNAME_VARIABLE}\n"
        f"      password: {PASSWORD_VARIABLE}\n"
        "  - id: unrelated-invalid\n"
        "    provider: env-file\n"
        "    variables:\n"
        "      password: not-an-environment-name\n",
        encoding="utf-8",
    )
    binding_path.chmod(0o600)
    with pytest.raises(MaterialAccessDenied, match="unavailable"):
        OwnerOnlyCentralLabSecretCreateBindingResolver(
            credential_bindings_path=binding_path,
            secret_env_path=secret_env,
            binding_ref="private-material-binding-ref01",
            credential_binding_id="fixed-secret-create",
            request=_request(),
        )


@pytest.mark.parametrize(
    "variant",
    ("unrelated_ssh", "selected_ssh", "unknown_role", "extra_selected_role"),
)
def test_secret_binding_in_mixed_registry_keeps_exact_material_roles(
    tmp_path, variant: str,
) -> None:
    binding_path = tmp_path / "credential-bindings.local.yaml"
    secret_env = tmp_path / "fortinet-lab.local.env"
    _write_credential_bindings(binding_path)
    _write_secret_env(secret_env, _valid_secret_env())
    with binding_path.open("a", encoding="utf-8") as stream:
        if variant == "extra_selected_role":
            stream.write("      ssh_username: UNUSED_EXTRA_USERNAME\n")
        stream.write(
            "  - id: unrelated-ssh\n"
            "    provider: env-file\n"
            "    variables:\n"
            "      identity_file: UNUSED_SSH_IDENTITY\n"
            "      known_hosts_file: UNUSED_SSH_HOST_KEYS\n"
            "      ssh_username: UNUSED_SSH_USERNAME\n"
            "      ssh_password: UNUSED_SSH_PASSWORD\n"
        )
        if variant == "unknown_role":
            stream.write("      arbitrary_path: UNUSED_ARBITRARY_PATH\n")

    def resolve():
        return OwnerOnlyCentralLabSecretCreateBindingResolver(
            credential_bindings_path=binding_path,
            secret_env_path=secret_env,
            binding_ref="private-material-binding-ref01",
            credential_binding_id=(
                "unrelated-ssh" if variant == "selected_ssh" else "fixed-secret-create"
            ),
            request=_request(),
        )

    if variant != "unrelated_ssh":
        with pytest.raises(MaterialAccessDenied, match="unavailable"):
            resolve()
        return

    # Unrelated SSH variables are deliberately absent from the material source.
    resolver = resolve()
    assert resolver.validate_prebound() is MaterialBindingStatus.AVAILABLE
    username, password = resolver.load_secret_create_material_once()
    try:
        assert len(username) == len(password) == 8
    finally:
        username.clear()
        password.clear()


def test_exact_request_loads_once_and_material_only_reaches_private_transport() -> None:
    binding = C3MaterialBinding()
    request = _request()
    loader = _PreboundLoader()
    provider = _provider(loader, binding, request)
    assert loader.load_calls == 0
    material_transport = _MaterialTransport()
    adapter = FortiPam191SecretCreatePrivateAdapter(
        _target_binding(),
        CentralLabSecretCreate191LeaseTransport(provider, material_transport),
    )
    runtime = SecretCreateMaterialRuntime(
        provider,
        InMemoryMaterialUseStateStore(),
        adapter,
    )

    outcome = runtime.execute_once(binding, request, now_epoch=NOW + 1)

    assert outcome is MaterialRuntimeOutcome.VERIFIED_AND_RELEASED
    assert loader.load_calls == 1
    assert material_transport.calls == 1
    assert material_transport.lengths == (8, 8)
    assert loader.username == bytearray()
    assert loader.password == bytearray()
    assert material_transport.views is not None
    with pytest.raises(ValueError):
        _ = material_transport.views[0].nbytes


def test_owner_only_env_loader_material_is_cleared_by_provider(tmp_path) -> None:
    secret_env = tmp_path / "secret.env"
    _write_secret_env(
        secret_env,
        b"UNRELATED=${OTHER} $(id) `unterminated\n"
        + USERNAME_VARIABLE.encode("ascii")
        + b"=A$`'B\n"
        + PASSWORD_VARIABLE.encode("ascii")
        + b'=\"C$`\'D\"\n',
    )
    loader = _concrete_loader(secret_env)
    binding = C3MaterialBinding()
    request = _request()
    provider = CentralLabInventorySecretCreateProvider(
        loader,
        binding=binding,
        request=request,
        clock=lambda: NOW + 1,
    )
    transport = _LiteralPunctuationTransport()

    assert loader.validate_prebound() is MaterialBindingStatus.AVAILABLE
    lease = provider.acquire_lease(binding, request)
    assert (
        CentralLabSecretCreate191LeaseTransport(provider, transport).create_and_verify(
            _target_binding(),
            lease,
            request,
        )
        is SecretCreateAdapterOutcome.VERIFIED_CREATED
    )
    assert transport.lengths == (5, 5)
    assert transport.views is not None
    with pytest.raises(ValueError):
        _ = transport.views[0].nbytes
    assert provider.release_lease(lease) is MaterialLeaseCompletion.RELEASED


def test_owner_only_env_loader_rejects_non_0600_file(tmp_path) -> None:
    secret_env = tmp_path / "secret.env"
    _write_secret_env(secret_env, _valid_secret_env(), mode=0o640)
    loader = _concrete_loader(secret_env)

    assert loader.validate_prebound() is MaterialBindingStatus.UNAVAILABLE
    with pytest.raises(
        MaterialAccessDenied,
        match="^The central lab Secret-create material provider is unavailable\\.$",
    ):
        loader.load_secret_create_material_once()


@pytest.mark.parametrize(
    "case",
    (
        "duplicate",
        "missing",
        "export",
        "multiline",
        "encoding",
    ),
)
def test_owner_only_env_loader_rejects_nonliteral_or_incomplete_dotenv(
    tmp_path,
    case: str,
) -> None:
    username = USERNAME_VARIABLE.encode("ascii")
    password = PASSWORD_VARIABLE.encode("ascii")
    value = bytes([65]) * 8
    valid_username = username + b"=" + value + b"\n"
    valid_password = password + b"=" + bytes([66]) * 8 + b"\n"
    payloads = {
        "duplicate": valid_username + valid_username + valid_password,
        "missing": valid_username,
        "export": b"export " + valid_username + valid_password,
        "multiline": valid_username + password + b"='first\nsecond'\n",
        "encoding": valid_username + password + b"=" + bytes([0xFF]) + b"\n",
    }
    secret_env = tmp_path / "secret.env"
    _write_secret_env(secret_env, payloads[case])
    loader = _concrete_loader(secret_env)

    assert loader.validate_prebound() is MaterialBindingStatus.UNAVAILABLE
    with pytest.raises(
        MaterialAccessDenied,
        match="^The central lab Secret-create material provider is unavailable\\.$",
    ):
        loader.load_secret_create_material_once()


@pytest.mark.parametrize(
    "changed",
    (
        {"action_id": "different-secret-create"},
        {"action_version": "2.0.0"},
        {"plan_digest": "9" * 64},
        {"policy_decision_digest": "9" * 64},
        {"authorization_digest": "9" * 64},
        {"scope_digest": "9" * 64},
        {"audience_digest": "9" * 64},
        {"provider_class": MaterialProviderClass.EXTERNAL_VAULT_LEASE},
        {"purpose": MaterialPurpose.CREDENTIAL_ROTATION},
        {"expires_at": NOW + 59},
    ),
)
def test_every_control_drift_is_incompatible_before_material_load(
    changed: dict[str, object],
) -> None:
    binding = C3MaterialBinding()
    request = _request()
    loader = _PreboundLoader()
    provider = _provider(loader, binding, request)
    drifted = replace(request, **cast(Any, changed))

    assert provider.validate_binding(binding, drifted) is MaterialBindingStatus.INCOMPATIBLE
    with pytest.raises(MaterialAccessDenied, match="unavailable"):
        provider.acquire_lease(binding, drifted)
    assert loader.validate_calls == 0
    assert loader.load_calls == 0


@pytest.mark.parametrize("terminal", ("release", "revoke"))
def test_terminal_operation_zeroizes_and_all_replay_is_denied(terminal: str) -> None:
    binding = C3MaterialBinding()
    request = _request()
    loader = _PreboundLoader()
    provider = _provider(loader, binding, request)
    lease = provider.acquire_lease(binding, request)

    if terminal == "release":
        assert provider.release_lease(lease) is MaterialLeaseCompletion.RELEASED
    else:
        assert provider.revoke_lease(
            lease,
            reason=MaterialRevocationReason.CANCELLED,
        ) is MaterialLeaseCompletion.REVOKED
    assert loader.username == bytearray()
    assert loader.password == bytearray()
    for replay in (
        lambda: provider.release_lease(lease),
        lambda: provider.revoke_lease(
            lease,
            reason=MaterialRevocationReason.CANCELLED,
        ),
        lambda: provider.acquire_lease(binding, request),
    ):
        with pytest.raises(MaterialAccessDenied, match="unavailable"):
            replay()
    assert loader.load_calls == 1


def test_validation_is_closed_and_lease_has_no_material_accessor_surface() -> None:
    binding = C3MaterialBinding()
    request = _request()
    loader = _PreboundLoader(fail_validation=True)
    provider = _provider(loader, binding, request)

    assert provider.validate_binding(binding, request) is MaterialBindingStatus.UNAVAILABLE
    assert (
        provider.validate_binding(C3MaterialBinding(), request)
        is MaterialBindingStatus.INCOMPATIBLE
    )
    assert loader.load_calls == 0
    constructor_parameters = inspect.signature(
        CentralLabInventorySecretCreateProvider
    ).parameters
    assert tuple(constructor_parameters) == (
        "resolver_loader",
        "binding",
        "request",
        "clock",
    )
    for name in ("list", "search", "read", "value", "bytes", "string"):
        assert not hasattr(provider, name)

    expired_provider = CentralLabInventorySecretCreateProvider(
        _PreboundLoader(),
        binding=binding,
        request=request,
        clock=lambda: request.expires_at,
    )
    assert (
        expired_provider.validate_binding(binding, request)
        is MaterialBindingStatus.EXPIRED
    )

    available_loader = _PreboundLoader()
    available_provider = _provider(available_loader, binding, request)
    lease = available_provider.acquire_lease(binding, request)
    for name in ("read", "value", "property", "bytes", "string"):
        assert not hasattr(lease, name)
    assert repr(lease) == "<MaterialLease redacted>"
    assert str(lease) == "<MaterialLease redacted>"
    available_provider.revoke_lease(
        lease,
        reason=MaterialRevocationReason.CANCELLED,
    )


@pytest.mark.parametrize("failure", [None, "dependency", "lost_ack"])
def test_target_bound_web_lease_reuses_provider_and_clears_material(
    monkeypatch, failure,
) -> None:
    import json

    from fortipam_mcp.secret_create_191_http_transport import (
        FortiPam191SecretCreateHttpTransport,
    )
    from fortipam_mcp.secret_create_191_private_adapter import (
        SecretCreate700WebTargetBinding,
    )
    from fortipam_mcp.secret_metadata_http_transport import (
        SecretMetadataProjectionInspection,
    )
    from fortipam_mcp.target_contract import WebTargetCreateInput
    from test_secret_create_191_http_transport import (
        _MetadataTransport, _Connection, _config,
    )
    from v4_planning.material_runtime import MaterialRuntimeError

    loader = _PreboundLoader()
    request = _request()
    opaque = C3MaterialBinding()
    provider = _provider(loader, opaque, request)
    target = WebTargetCreateInput(
        "mcp-v4-target-web-20261003-r1", "https://app.example.test",
    )
    binding = SecretCreate700WebTargetBinding(
        "fortipam-700-build29-target-bound-web-create-candidate-v1",
        "7.0.0", request.plan_digest, "Lab/example-folder", "example-secret",
        "Web Account", target, True,
    )
    observed_dependencies = []
    observed_bodies = []

    class Metadata(_MetadataTransport):
        def inspect_target_bound_web_projection(self, folder, name, *, target):
            observed_dependencies.append((folder, name, target))
            if failure == "dependency":
                raise RuntimeError("private dependency drift")
            return SecretMetadataProjectionInspection(
                False, True, True, False, False, False, False, False,
            )

    class Connection(_Connection):
        calls = 0

        def request(self, method, path, body, headers):
            self.calls += 1
            self.body = body.obj
            # Record synthetic data; assert outside the transport's error handler.
            observed_bodies.append(json.loads(bytes(body)))
            if failure == "lost_ack":
                raise TimeoutError("private upstream details")

    connection = Connection()
    monkeypatch.setattr(
        "fortipam_mcp.secret_create_191_http_transport._ssl_context",
        lambda _: object(),
    )
    http = FortiPam191SecretCreateHttpTransport(
        _config(), metadata_transport=Metadata(),
        connection_factory=lambda *a, **k: connection,
    )
    runtime = SecretCreateMaterialRuntime(
        provider, InMemoryMaterialUseStateStore(),
        FortiPam191SecretCreatePrivateAdapter(
            binding, CentralLabSecretCreate191LeaseTransport(provider, http),
        ),
    )
    outcome = runtime.execute_once(opaque, request, now_epoch=NOW + 1)
    expected = (
        MaterialRuntimeOutcome.VERIFIED_AND_RELEASED if failure is None
        else MaterialRuntimeOutcome.RECONCILIATION_REQUIRED
    )
    assert outcome is expected
    assert observed_dependencies == [
        (binding.folder_path, binding.secret_name, binding.target),
    ]
    assert loader.load_calls == 1
    assert not loader.username and not loader.password
    expected_calls = 0 if failure == "dependency" else 1
    assert connection.calls == expected_calls
    assert len(observed_bodies) == expected_calls
    if expected_calls:
        parsed = observed_bodies[0]
        assert parsed["target"] == target.target_name
        assert parsed["template"] == "Web Account"
        assert parsed["field"] == [
            {"id": 0, "name": "Password", "value": "B" * 8},
            {"id": 0, "name": "Username", "value": "A" * 8},
        ]
        assert target.web_url not in json.dumps(parsed)
        assert connection.body is not None
        assert not any(connection.body)
        assert connection.closed
    else:
        assert connection.body is None
    with pytest.raises(MaterialRuntimeError):
        runtime.execute_once(opaque, request, now_epoch=NOW + 2)
    assert loader.load_calls == 1
    assert connection.calls == expected_calls


@pytest.mark.parametrize('stage',['read','close'])
@pytest.mark.parametrize('failure',[OSError,KeyboardInterrupt,SystemExit])
def test_private_env_reader_failure_clears_its_internal_buffer(tmp_path,monkeypatch,stage,failure):
    from fortipam_mcp.secret_create_central_lab_provider import _read_owner_only_secret_env_file
    path=tmp_path/'synthetic.env'; material=b'SYNTHETIC_KEY=SYNTHETIC_VALUE_NEVER_EXPOSE\n'
    path.write_bytes(material); path.chmod(0o600)
    readv,close=os.readv,os.close; buffers=[]; descriptors=[]; closed=[]
    def tracked_readv(descriptor,views):
        count=readv(descriptor,views); buffers.append(views[0].obj); descriptors.append(descriptor)
        if stage=='read': raise failure()
        return count
    def tracked_close(descriptor):
        closed.append(descriptor); close(descriptor)
        if stage=='close': raise failure()
    monkeypatch.setattr(os,'readv',tracked_readv); monkeypatch.setattr(os,'close',tracked_close)
    with pytest.raises(MaterialAccessDenied if failure is OSError else failure) as error:
        _read_owner_only_secret_env_file(path)
    assert buffers and all(not any(raw) for raw in buffers) and set(closed)==set(descriptors)
    assert str(path) not in str(error.value) and 'SYNTHETIC_VALUE_NEVER_EXPOSE' not in str(error.value)
    for descriptor in closed:
        with pytest.raises(OSError): os.fstat(descriptor)
