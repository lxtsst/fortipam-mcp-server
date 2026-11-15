from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

import pytest
from v4_planning import M4AdapterDenied

import fortipam_mcp.secret_approval_build29_runtime_provider as module
from fortipam_mcp.secret_approval_build29_runtime_provider import (
    OwnerOnlySecretApprovalBuild29QualificationVerifier,
    OwnerOnlySecretApprovalBuild29UsernameSource,
    SecretApprovalBuild29RuntimeProviderError,
)


_KEY = b"qualification-unit-authority-key-01"
_BINDING = "a" * 64
_PLAN = "b" * 64
_EVIDENCE = "c" * 64


def _body() -> dict[str, Any]:
    return {"contract": module.QUALIFICATION_CONTRACT, "authority_ref": "unit-qualification-authority",
            "evidence_digest": _EVIDENCE, "binding_digest": _BINDING, "plan_digest": _PLAN,
            "product_version": "7.0.0", "product_build": 29,
            "scope": module.QUALIFICATION_SCOPE, "issued_at": 100, "expires_at": 400}


def _write(path: Path, body: dict[str, Any], *, key: bytes = _KEY) -> None:
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    signature = hmac.new(key, module._QUALIFICATION_DOMAIN + canonical, hashlib.sha256).hexdigest()
    path.write_text(json.dumps({"body": body, "signature": signature}))
    path.chmod(0o600)


def _verifier(path: Path) -> OwnerOnlySecretApprovalBuild29QualificationVerifier:
    return OwnerOnlySecretApprovalBuild29QualificationVerifier(
        path, authority_ref="unit-qualification-authority", authority_key=_KEY,
        expected_evidence_digest=_EVIDENCE,
    )


def test_constructor_does_not_read_and_exact_receipt_is_required(tmp_path: Path) -> None:
    path = tmp_path / "qualification.json"
    verifier = _verifier(path)
    with pytest.raises(M4AdapterDenied):
        verifier.verify(binding_digest=_BINDING, plan_digest=_PLAN, now_epoch=200)
    _write(path, _body())
    verifier.verify(binding_digest=_BINDING, plan_digest=_PLAN, now_epoch=200)
    assert "qualification.json" not in repr(verifier)


@pytest.mark.parametrize(("name", "value"), [
    ("contract", "other-contract-v1"), ("authority_ref", "other-qualification-authority"),
    ("evidence_digest", "d" * 64), ("binding_digest", "d" * 64), ("plan_digest", "d" * 64),
    ("product_version", "1.9.1"), ("product_build", True), ("scope", "known-nonempty-totp"),
    ("issued_at", True), ("issued_at", 201), ("expires_at", 200), ("expires_at", 401),
    ("caller_controlled_qualification", True),
])
def test_even_signed_foreign_or_expired_receipt_is_denied(tmp_path: Path, name: str, value: Any) -> None:
    path = tmp_path / "qualification.json"
    body = _body()
    body[name] = value
    _write(path, body)
    with pytest.raises(M4AdapterDenied, match="Protected build-29 approval sources are unavailable"):
        _verifier(path).verify(binding_digest=_BINDING, plan_digest=_PLAN, now_epoch=200)


def test_foreign_key_or_modified_file_cannot_qualify(tmp_path: Path) -> None:
    path = tmp_path / "qualification.json"
    _write(path, _body(), key=b"foreign-unit-qualification-key-01")
    with pytest.raises(M4AdapterDenied):
        _verifier(path).verify(binding_digest=_BINDING, plan_digest=_PLAN, now_epoch=200)
    _write(path, _body())
    text = path.read_text().replace('"issued_at": 100', '"issued_at": 99')
    path.write_text(text)
    with pytest.raises(M4AdapterDenied):
        _verifier(path).verify(binding_digest=_BINDING, plan_digest=_PLAN, now_epoch=200)


def test_receipt_is_reread_not_cached(tmp_path: Path) -> None:
    path = tmp_path / "qualification.json"
    _write(path, _body())
    verifier = _verifier(path)
    verifier.verify(binding_digest=_BINDING, plan_digest=_PLAN, now_epoch=200)
    path.unlink()
    with pytest.raises(M4AdapterDenied):
        verifier.verify(binding_digest=_BINDING, plan_digest=_PLAN, now_epoch=200)


@pytest.mark.parametrize("kind", ["leaf_symlink", "parent_symlink", "permissions", "duplicate", "nan"])
def test_unsafe_receipt_file_is_denied(tmp_path: Path, kind: str) -> None:
    parent = tmp_path / "private"
    parent.mkdir()
    path = parent / "qualification.json"
    _write(path, _body())
    selected = path
    if kind == "leaf_symlink":
        selected = parent / "link.json"
        selected.symlink_to(path)
    elif kind == "parent_symlink":
        link = tmp_path / "linked-directory"
        link.symlink_to(parent, target_is_directory=True)
        selected = link / path.name
    elif kind == "permissions":
        path.chmod(0o644)
    elif kind == "duplicate":
        path.write_text(path.read_text().replace('"product_build": 29', '"product_build": 29, "product_build": 29'))
    else:
        path.write_text(path.read_text().replace('"issued_at": 100', '"issued_at": NaN'))
    with pytest.raises(M4AdapterDenied):
        _verifier(selected).verify(binding_digest=_BINDING, plan_digest=_PLAN, now_epoch=200)


def test_username_is_fresh_writable_backing_without_decoding(tmp_path: Path) -> None:
    path = tmp_path / "username.bin"
    source = OwnerOnlySecretApprovalBuild29UsernameSource(path)
    path.write_bytes(b"unit-account")
    path.chmod(0o600)
    first = source.read_span()
    second = source.read_span()
    assert first.obj is not second.obj
    assert first.readonly is False
    assert first == b"unit-account"
    module._zeroize_mutable(first.obj)
    assert first == b"\x00" * 12
    assert second == b"unit-account"
    module._zeroize_mutable(second.obj)
    first.release()
    second.release()
    assert str(path) not in repr(source)


@pytest.mark.parametrize("content", [b"unit-account\n", b"unit-account\x00", b"x" * 257])
def test_username_rejects_bad_source_without_disclosing_value(tmp_path: Path, content: bytes) -> None:
    path = tmp_path / "username.bin"
    path.write_bytes(content)
    path.chmod(0o600)
    with pytest.raises(SecretApprovalBuild29RuntimeProviderError, match="Protected build-29 approval sources are unavailable"):
        OwnerOnlySecretApprovalBuild29UsernameSource(path).read_span()



def test_linux_qualification_has_independent_scope_and_signature_domain(tmp_path: Path) -> None:
    path = tmp_path / "linux-qualification.json"
    verifier = module.OwnerOnlySecretApprovalBuild29LinuxQualificationVerifier(
        path, authority_ref="unit-qualification-authority", authority_key=_KEY,
        expected_evidence_digest=_EVIDENCE,
    )
    _write(path, _body())
    with pytest.raises(M4AdapterDenied):
        verifier.verify(binding_digest=_BINDING, plan_digest=_PLAN, now_epoch=200)
    body = _body()
    body.update(contract=module.LINUX_QUALIFICATION_CONTRACT, scope=module.LINUX_QUALIFICATION_SCOPE)
    _write(path, body)
    with pytest.raises(M4AdapterDenied):
        verifier.verify(binding_digest=_BINDING, plan_digest=_PLAN, now_epoch=200)
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    signature = hmac.new(_KEY, module._LINUX_QUALIFICATION_DOMAIN + canonical, hashlib.sha256).hexdigest()
    path.write_text(json.dumps({"body": body, "signature": signature}))
    verifier.verify(binding_digest=_BINDING, plan_digest=_PLAN, now_epoch=200)
    with pytest.raises(M4AdapterDenied):
        _verifier(path).verify(binding_digest=_BINDING, plan_digest=_PLAN, now_epoch=200)


def test_env_username_reads_only_fixed_variable_and_erases_original_buffer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "original.env"
    source = module.OwnerOnlySecretApprovalBuild29EnvUsernameSource(path, username_variable="LINUX_USERNAME")
    path.write_bytes(b"# retained source\nLINUX_PASSWORD=never-extract\nLINUX_USERNAME='unit-user'\nOTHER=value\n")
    path.chmod(0o600)
    buffers: list[bytearray] = []
    original = module._read_private_buffer
    def capture(path: Path, limit: int) -> bytearray:
        raw = original(path, limit)
        buffers.append(raw)
        return raw
    monkeypatch.setattr(module, "_read_private_buffer", capture)
    first, second = source.read_span(), source.read_span()
    assert first == second == b"unit-user" and not first.readonly and first.obj is not second.obj
    assert buffers and all(not any(raw) for raw in buffers)
    assert "LINUX_USERNAME" not in repr(source) and str(path) not in repr(source)
    module._zeroize_mutable(first.obj)
    module._zeroize_mutable(second.obj)
    first.release()
    second.release()


@pytest.mark.parametrize("content", [
    b"OTHER=unit-user\n", b"LINUX_USERNAME=\n", b"LINUX_USERNAME=x\nLINUX_USERNAME=y\n",
    b"LINUX_USERNAME=x\x00\n", b"LINUX_USERNAME=x\r\n", b"LINUX_USERNAME='broken\n",
    b"export LINUX_USERNAME=x\n", b"LINUX_USERNAME=" + b"x" * 257,
    b"LINUX_USERNAME=x\nOTHER=a\nOTHER=b\n",
])
def test_env_username_rejects_malformed_ambiguous_or_missing_source(tmp_path: Path, content: bytes) -> None:
    path = tmp_path / "original.env"
    path.write_bytes(content)
    path.chmod(0o600)
    source = module.OwnerOnlySecretApprovalBuild29EnvUsernameSource(path, username_variable="LINUX_USERNAME")
    with pytest.raises(SecretApprovalBuild29RuntimeProviderError) as failure:
        source.read_span()
    assert str(failure.value) == module._UNAVAILABLE and failure.value.__cause__ is None


@pytest.mark.parametrize("unsafe", ["permissions", "symlink", "parent_symlink"])
def test_env_username_reuses_owner600_nofollow_boundary(tmp_path: Path, unsafe: str) -> None:
    parent = tmp_path / "private"
    parent.mkdir()
    path = parent / "original.env"
    path.write_bytes(b"LINUX_USERNAME=unit-user\n")
    path.chmod(0o600)
    if unsafe == "permissions":
        path.chmod(0o644)
    elif unsafe == "symlink":
        alias = parent / "alias.env"
        alias.symlink_to(path)
        path = alias
    else:
        alias = tmp_path / "alias"
        alias.symlink_to(parent, target_is_directory=True)
        path = alias / "original.env"
    with pytest.raises(SecretApprovalBuild29RuntimeProviderError):
        module.OwnerOnlySecretApprovalBuild29EnvUsernameSource(path, username_variable="LINUX_USERNAME").read_span()


def _remote_reference(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    import os
    env = tmp_path / "original.env"
    env.write_bytes(b"OTHER_PASSWORD=never-extract\nUNIT_USERNAME='unit-user'\n")
    env.chmod(0o600)
    bindings = tmp_path / "bindings.yaml"
    bindings.write_bytes(b"unit-metadata-only\n")
    bindings.chmod(0o600)
    pin = tmp_path / "known_hosts"
    pin.write_bytes(b"unit-pinned-host-public-key\n")
    pin.chmod(0o644)
    identity_directory = tmp_path / "original-key-location"
    identity_directory.mkdir()
    identity = identity_directory / "id_ed25519"
    identity.write_bytes(b"synthetic-private-key-placeholder")
    identity.chmod(0o600)
    value = {
        "contract": module.REMOTE_USERNAME_REFERENCE_CONTRACT,
        "ssh_identity_file": str(identity),
        "ssh_host": "unit.example.test", "ssh_port": 2222, "ssh_username": "unit",
        "known_hosts_file": str(pin), "known_hosts_digest": hashlib.sha256(pin.read_bytes()).hexdigest(),
        "bindings_path": str(bindings), "bindings_owner": os.getuid(),
        "bindings_digest": hashlib.sha256(bindings.read_bytes()).hexdigest(),
        "env_path": str(env), "env_owner": os.getuid(), "username_variable": "UNIT_USERNAME",
    }
    path = tmp_path / "reference.json"
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    return path, value


def _local_remote_process(monkeypatch: pytest.MonkeyPatch, *, program: str | None = None) -> list[Any]:
    """Run the compiled remote program locally against synthetic test inputs."""
    import sys
    original = module.subprocess.Popen
    processes: list[Any] = []
    def spawn(argv: list[str], **kwargs: Any) -> Any:
        assert argv[0] == "/usr/bin/ssh"
        assert argv[1:4] == ["-F", "/dev/null", "-T"]
        assert "StrictHostKeyChecking=yes" in argv and "GlobalKnownHostsFile=/dev/null" in argv
        assert "IdentitiesOnly=yes" in argv
        identity = Path(argv[argv.index("-i") + 1])
        assert identity.name == "id_ed25519" and identity.parent.name == "original-key-location"
        assert kwargs["stderr"] == module.subprocess.DEVNULL
        assert not kwargs.get("shell")
        process = original([sys.executable, "-c", program or module._REMOTE_USERNAME_PROGRAM], **kwargs)
        processes.append(process)
        return process
    monkeypatch.setattr(module.subprocess, "Popen", spawn)
    return processes


def test_remote_source_runs_fixed_program_locally_and_returns_only_mutable_username(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    path, value = _remote_reference(tmp_path)
    source = module.OwnerOnlySecretApprovalBuild29RemoteUsernameSource(path)
    processes = _local_remote_process(monkeypatch)
    first, second = source.read_span(), source.read_span()
    assert first == second == b"unit-user" and first.obj is not second.obj and not first.readonly
    assert len(processes) == 2 and all(p.poll() == 0 and p.stdout.closed and p.stdin.closed for p in processes)
    assert "unit.example.test" not in repr(source) and str(path) not in repr(source)
    module._zeroize_mutable(first.obj)
    module._zeroize_mutable(second.obj)
    first.release()
    second.release()
    assert b"OTHER_PASSWORD=never-extract" in Path(value["env_path"]).read_bytes()


@pytest.mark.parametrize("change", ["pin_drift", "pin_writable", "pin_symlink", "reference_mode", "unknown",
                                     "bad_host", "bad_user", "bool_owner", "bad_variable", "duplicate_key"])
def test_remote_source_refuses_unqualified_reference_before_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str,
) -> None:
    path, value = _remote_reference(tmp_path)
    if change == "pin_drift":
        Path(value["known_hosts_file"]).write_bytes(b"changed-pin\n")
    elif change == "pin_writable":
        Path(value["known_hosts_file"]).chmod(0o666)
    elif change == "pin_symlink":
        alias = tmp_path / "alias"
        alias.symlink_to(value["known_hosts_file"])
        value["known_hosts_file"] = str(alias)
    elif change == "reference_mode":
        path.chmod(0o644)
    else:
        key, item = {"unknown": ("command", "echo arbitrary"), "bad_host": ("ssh_host", "-oProxyCommand=bad"),
                     "bad_user": ("ssh_username", "unit;id"), "bool_owner": ("env_owner", True),
                     "bad_variable": ("username_variable", "VAR;VALUE"), "duplicate_key": ("contract", value["contract"])}[change]
        value[key] = item
    path.write_text(json.dumps(value))
    if change == "duplicate_key":
        path.write_text('{"ssh_port":22,' + path.read_text()[1:])
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("Unqualified source must not launch a process")
    monkeypatch.setattr(module.subprocess, "Popen", forbidden)
    with pytest.raises(SecretApprovalBuild29RuntimeProviderError) as failure:
        module.OwnerOnlySecretApprovalBuild29RemoteUsernameSource(path).read_span()
    assert str(failure.value) == module._UNAVAILABLE


@pytest.mark.parametrize("change", ["binding_drift", "env_permissions", "env_symlink", "missing_variable", "duplicate_variable"])
def test_compiled_remote_program_rejects_original_source_drift_without_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str,
) -> None:
    path, value = _remote_reference(tmp_path)
    if change == "binding_drift":
        Path(value["bindings_path"]).write_bytes(b"changed-metadata\n")
    elif change == "env_permissions":
        Path(value["env_path"]).chmod(0o644)
    elif change == "env_symlink":
        original = Path(value["env_path"])
        renamed = tmp_path / "renamed.env"
        original.rename(renamed)
        original.symlink_to(renamed)
    elif change == "missing_variable":
        Path(value["env_path"]).write_bytes(b"OTHER_PASSWORD=never-extract\n")
    else:
        Path(value["env_path"]).write_bytes(b"UNIT_USERNAME=unit-user\nUNIT_USERNAME=second-user\n")
    processes = _local_remote_process(monkeypatch)
    with pytest.raises(SecretApprovalBuild29RuntimeProviderError):
        module.OwnerOnlySecretApprovalBuild29RemoteUsernameSource(path).read_span()
    assert len(processes) == 1 and processes[0].poll() == 1


@pytest.mark.parametrize("program", [
    "import sys;sys.stdin.buffer.read();sys.stdout.buffer.write(b'x'*257)",
    "import sys;sys.stdin.buffer.read();sys.stdout.buffer.write(b'unit-user\\n')",
    "import sys;sys.stdin.buffer.read();sys.stdout.buffer.write(b'unit-user');sys.exit(1)",
    "import sys;sys.stdin.buffer.read()",
    "import time;time.sleep(5)",
])
def test_remote_output_is_bounded_fail_closed_erased_and_process_reaped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, program: str,
) -> None:
    path, _ = _remote_reference(tmp_path)
    processes = _local_remote_process(monkeypatch, program=program)
    monkeypatch.setattr(module, "_REMOTE_USERNAME_TIMEOUT_SECONDS", 0.25)
    erased: list[bytearray] = []
    original = module._zeroize_mutable
    def capture(raw: bytearray) -> None:
        original(raw)
        erased.append(raw)
    monkeypatch.setattr(module, "_zeroize_mutable", capture)
    with pytest.raises(SecretApprovalBuild29RuntimeProviderError) as failure:
        module.OwnerOnlySecretApprovalBuild29RemoteUsernameSource(path).read_span()
    assert str(failure.value) == module._UNAVAILABLE and failure.value.__cause__ is None
    assert len(processes) == 1 and processes[0].poll() is not None
    assert processes[0].stdout.closed and processes[0].stdin.closed
    assert erased and all(not any(raw) for raw in erased)


@pytest.mark.parametrize("change", ["missing_key", "permissions", "leaf_symlink", "parent_symlink", "relative",
                                     "interpolation", "newline", "tab", "delete_character",
                                     "nonbreaking_space", "line_separator"])
def test_remote_identity_is_explicit_owner600_nofollow_before_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str,
) -> None:
    path, value = _remote_reference(tmp_path)
    identity = Path(value["ssh_identity_file"])
    if change == "missing_key":
        del value["ssh_identity_file"]
    elif change == "permissions":
        identity.chmod(0o644)
    elif change == "leaf_symlink":
        alias = identity.parent / "alias"
        alias.symlink_to(identity)
        value["ssh_identity_file"] = str(alias)
    elif change == "parent_symlink":
        alias = tmp_path / "alias-dir"
        alias.symlink_to(identity.parent, target_is_directory=True)
        value["ssh_identity_file"] = str(alias / identity.name)
    elif change == "relative":
        value["ssh_identity_file"] = "relative/id_ed25519"
    elif change == "interpolation":
        value["ssh_identity_file"] = "/original/%h/id_ed25519"
    else:
        control = {"newline": "\n", "tab": "\t", "delete_character": "\x7f",
                   "nonbreaking_space": "\u00a0", "line_separator": "\u2028"}[change]
        value["ssh_identity_file"] = str(identity.parent / ("key" + control + "name"))
    path.write_text(json.dumps(value))
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("Unqualified identity must not start SSH")
    monkeypatch.setattr(module.subprocess, "Popen", forbidden)
    with pytest.raises(SecretApprovalBuild29RuntimeProviderError):
        module.OwnerOnlySecretApprovalBuild29RemoteUsernameSource(path).read_span()


def test_remote_identity_path_with_spaces_remains_one_literal_ssh_argument(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sys
    path, value = _remote_reference(tmp_path)
    identity = Path(value["ssh_identity_file"])
    directory = tmp_path / "protected key location"
    identity.parent.rename(directory)
    value["ssh_identity_file"] = str(directory / identity.name)
    path.write_text(json.dumps(value))
    original = module.subprocess.Popen
    calls: list[list[str]] = []

    def spawn(argv: list[str], **kwargs: Any) -> Any:
        assert argv[argv.index("-i") + 1] == value["ssh_identity_file"]
        assert not kwargs.get("shell")
        calls.append(argv)
        return original([sys.executable, "-c", module._REMOTE_USERNAME_PROGRAM], **kwargs)

    monkeypatch.setattr(module.subprocess, "Popen", spawn)
    source = module.OwnerOnlySecretApprovalBuild29RemoteUsernameSource(path)
    assert source._reference()["ssh_identity_file"] == value["ssh_identity_file"]
    span = source.read_span()
    try:
        assert span == b"unit-user" and len(calls) == 1
    finally:
        module._zeroize_mutable(span.obj)
        span.release()


def test_remote_identity_validation_does_not_open_private_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    path, value = _remote_reference(tmp_path)
    original = module.os.open
    opened: list[str] = []
    def capture(selected: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        opened.append(str(selected))
        assert str(selected) not in {value["ssh_identity_file"], "id_ed25519"}
        return original(selected, flags, *args, **kwargs)
    monkeypatch.setattr(module.os, "open", capture)
    reference = module.OwnerOnlySecretApprovalBuild29RemoteUsernameSource(path)._reference()
    assert reference["ssh_identity_file"] == value["ssh_identity_file"]
    assert opened


def _linux_folder_acl() -> dict[str, Any]:
    def relation(index: int, principal: str, name: str, permission: str) -> dict[str, Any]:
        return {"id": index, principal: [{"name": name}],
                "folder-permission": permission, "secret-permission": permission}
    return {"id": 17, "inherit-permission": "disable", "user-permission": [
        relation(1, "user-name", "mcp-v4-owner-unit01", "owner"),
        relation(2, "user-name", "unit-requester", "view"),
        relation(3, "user-name", "unit-other", "edit"),
    ], "group-permission": [relation(1, "group-name", "unit-group", "view")]}


def _linux_acl_digest(row: dict[str, Any]) -> str:
    return module.qualify_secret_approval_build29_linux_folder_acl(
        row, folder_id=17, owner_name="mcp-v4-owner-unit01",
    )


def test_linux_acl_pins_all_relations_and_is_order_independent() -> None:
    row = _linux_folder_acl()
    baseline = _linux_acl_digest(row)
    row["user-permission"].reverse()
    assert _linux_acl_digest(row) == baseline
    row["group-permission"][0]["folder-permission"] = "edit"
    assert _linux_acl_digest(row) != baseline
    row["user-permission"][0]["id"] = 18
    assert _linux_acl_digest(row) != baseline


@pytest.mark.parametrize("change", ["owner_missing", "owner_view", "owner_shared", "inherited", "wrong_folder",
                                     "zero_id", "bool_id", "duplicate_id", "duplicate_name", "unknown_relation_field",
                                     "unknown_permission", "duplicate_group", "missing_groups"])
def test_linux_acl_refuses_ambiguous_or_unqualified_relations(change: str) -> None:
    import copy
    row = _linux_folder_acl()
    users = row["user-permission"]
    if change == "owner_missing":
        users.pop(0)
    elif change == "owner_view":
        users[0]["secret-permission"] = "view"
    elif change == "owner_shared":
        users[0]["user-name"].append({"name": "unit-shared"})
    elif change == "inherited":
        row["inherit-permission"] = "enable"
    elif change == "wrong_folder":
        row["id"] = 18
    elif change == "zero_id":
        users[0]["id"] = 0
    elif change == "bool_id":
        users[0]["id"] = True
    elif change == "duplicate_id":
        users[1]["id"] = users[0]["id"]
    elif change == "duplicate_name":
        users[1]["user-name"] = users[0]["user-name"]
    elif change == "unknown_relation_field":
        users[0]["unrecognized-permission"] = "owner"
    elif change == "unknown_permission":
        users[1]["folder-permission"] = "future-owner"
    elif change == "duplicate_group":
        row["group-permission"].append(copy.deepcopy(row["group-permission"][0]))
    else:
        del row["group-permission"]
    with pytest.raises(SecretApprovalBuild29RuntimeProviderError):
        _linux_acl_digest(row)
