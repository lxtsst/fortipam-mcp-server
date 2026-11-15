from contextlib import asynccontextmanager

import pytest

import fortipam_mcp.folder_archive_reference_ssh_transport as module


@pytest.mark.parametrize("parent,child,expected,serial,hierarchy", (
    (b"entry used by secret.database:folder", b"", True, b"FPA-SYNTHETIC", (0, 7)),
    (b"entry used by secret.database:folder", b"entry used by secret.database:folder", False, b"FPA-SYNTHETIC", (0, 7)),
    (b"", b"", False, b"FPA-SYNTHETIC", (0, 7)),
    (b"entry used by secret.folder:parent-folder", b"", False, b"FPA-SYNTHETIC", (0, 7)),
    (b"Permission denied", b"", None, b"FPA-SYNTHETIC", (0, 7)),
    (b"entry used by secret.database:folder", b"unexpected output", None, b"FPA-SYNTHETIC", (0, 7)),
    (b"entry used by secret.database:folder", b"", False, b"FPA-OTHER", (0, 7)),
    (b"entry used by secret.database:folder", b"", False, b"FPA-SYNTHETIC\nVersion: unexpected", (0, 7)),
    (b"entry used by secret.database:folder", b"", False, b"FPA-SYNTHETIC\nSerial-Number: FPA-SYNTHETIC", (0, 7)),
    (b"entry used by secret.database:folder", b"", False, b"FPA-SYNTHETIC", (0, 7, 42)),
    (b"entry used by secret.database:folder", b"", False, b"FPA-SYNTHETIC", (0, 99)),
))
def test_fixed_reference_reads_require_positive_secret_witness_and_zero_child_references(
    monkeypatch: pytest.MonkeyPatch, parent: bytes, child: bytes, expected: bool | None, serial: bytes, hierarchy: tuple[int, ...],
) -> None:
    commands = []
    closed = []

    class FakeSsh:
        def __init__(self, config):
            pass

        @asynccontextmanager
        async def _connection(self):
            yield object()

        async def _open_cli(self, connection):
            return object(), b"FPA-VM #", 100

    async def dynamic(process, command, prompt, deadline):
        assert command in {"config secret folder", "end"}
        return b"FPA-VM (folder) #" if command == "config secret folder" else b"FPA-VM #"

    async def read(process, command, prompt, deadline):
        commands.append(command)
        if command == module._SERIAL_PROJECTION:
            return command.encode() + b"\nSerial-Number: " + serial + b"\n" + prompt
        if command == module._PARENT_PROJECTION:
            return command.encode() + b"\n" + b"".join(f"    set parent-folder {parent}\n".encode() for parent in hierarchy) + prompt
        row = parent if command.endswith(" 7") else child
        return command.encode() + b"\n" + (row + b"\n" if row else b"") + prompt

    async def close(process):
        closed.append(True)

    monkeypatch.setattr(module, "FortiPamTargetReferenceSshTransport", FakeSsh)
    monkeypatch.setattr(module, "_send_and_read", read)
    monkeypatch.setattr(module, "_send_and_read_dynamic_prompt", dynamic)
    monkeypatch.setattr(module, "_close_cli", close)
    transport = module.FortiPamFolderArchiveReferenceSshTransport(None)
    if expected is None:
        with pytest.raises(RuntimeError, match="reference evidence is unavailable"):
            transport.verify_no_references(42, 7, "FPA-SYNTHETIC")
    else:
        assert transport.verify_no_references(42, 7, "FPA-SYNTHETIC") is expected
    assert commands[0] == 'get system status | grep "Serial-Number"'
    if serial != b"FPA-SYNTHETIC":
        assert len(commands) == 1
    else:
        assert commands[1] == module._PARENT_PROJECTION
        if 7 in hierarchy and 42 not in hierarchy:
            assert commands[2] == "diagnose sys cmdb refcnt show secret.folder.id 7"
        else:
            assert len(commands) == 2
    if len(commands) == 4:
        assert commands[3] == "diagnose sys cmdb refcnt show secret.folder.id 42"
    assert closed == [True]


@pytest.mark.parametrize("body", (b"", b"Permission denied\n", b"    set parent-folder -1\n",
                                  b"    set parent-folder 2147483648\n", b"    set parent-folder 7\n--More--\n"))
def test_parent_projection_rejects_empty_malformed_and_paginated_evidence(body: bytes) -> None:
    prompt = b"FPA-VM (folder) #"
    output = module._PARENT_PROJECTION.encode() + b"\n" + body + prompt
    with pytest.raises(ValueError):
        module._folder_parent_ids(output, prompt)


def test_parent_projection_preserves_repeated_parent_rows_and_requires_final_prompt() -> None:
    prompt = b"FPA-VM (folder) #"
    output = module._PARENT_PROJECTION.encode() + b"\n    set parent-folder 0\n    set parent-folder 7\n    set parent-folder 7\n" + prompt
    assert module._folder_parent_ids(output, prompt) == (0, 7, 7)
    with pytest.raises(ValueError):
        module._folder_parent_ids(output.removesuffix(prompt), prompt)


def test_explicit_owner_reference_reuses_lazy_provider_and_calibrated_reader(
    tmp_path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("synthetic pinned host")
    known_hosts.chmod(0o600)
    environment = {module.ENV_PREFIX + "ENABLED": "true",
        module.ENV_PREFIX + "OWNER_LOGIN_ENABLED": "true",
        module.ENV_PREFIX + "SSH_HOST": "synthetic.invalid",
        module.ENV_PREFIX + "SSH_KNOWN_HOSTS_FILE": str(known_hosts)}
    acquired = []
    forwarded = []

    def credentials():
        acquired.append(True)
        return "synthetic-owner", "synthetic"

    class Reader:
        def __init__(self, config):
            assert config.username == "synthetic-owner"
            assert config.known_hosts_file == known_hosts
        def verify_no_references(self, folder_id, parent_folder_id, serial):
            forwarded.append((folder_id, parent_folder_id, serial))
            return True

    monkeypatch.setattr(module, "FortiPamFolderArchiveReferenceSshTransport", Reader)
    reader = module.OwnerFolderArchiveReferenceSshTransport(environment,
        owner_name="synthetic-owner", credentials=credentials)
    assert not acquired
    with pytest.raises(RuntimeError):
        reader.verify_no_references(True, 7, "FPA-SYNTHETIC")
    assert not acquired and not forwarded
    assert reader.verify_no_references(42, 7, "FPA-SYNTHETIC") is True
    assert len(acquired) == 1 and forwarded == [(42, 7, "FPA-SYNTHETIC")]
    assert not list(tmp_path.glob("*password*"))
    wrong_owner = module.OwnerFolderArchiveReferenceSshTransport(environment,
        owner_name="another-owner", credentials=credentials)
    with pytest.raises(RuntimeError):
        wrong_owner.verify_no_references(42, 7, "FPA-SYNTHETIC")
    assert len(forwarded) == 1
    for flag in (None, "false", "TRUE"):
        changed = dict(environment)
        if flag is None:
            del changed[module.ENV_PREFIX + "OWNER_LOGIN_ENABLED"]
        else:
            changed[module.ENV_PREFIX + "OWNER_LOGIN_ENABLED"] = flag
        with pytest.raises(ValueError):
            module.OwnerFolderArchiveReferenceSshTransport(changed,
                owner_name="synthetic-owner", credentials=credentials)
    assert len(acquired) == 2
