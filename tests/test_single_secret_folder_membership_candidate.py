"""Synthetic Owner lifecycle, subset calibration and pinned native capture."""

from __future__ import annotations

from contextlib import asynccontextmanager
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import ssl
from typing import Any

import httpx
import pytest

from fortipam_mcp import single_secret_folder_membership_candidate as candidate
from fortipam_mcp import single_secret_folder_membership_ssh_reader as native
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig, SYSTEM_STATUS_PATH
from fortipam_mcp.single_secret_folder_membership_source import SingleSecretFolderMembershipColumns
from fortipam_mcp.target_ssh_transport import TargetSshTransportConfig
from test_single_secret_folder_membership_source import (
    DATABASE, FOLDER, FOLDER_NAME, ROOT, SECRET_NAME, SERIAL, binding, columns, frame, metadata,
)

OWNER = "synthetic-owner"
MARKER = "SYNTHETIC_PRIVATE_FIELD_DENIAL_MARKER"


def envelope(table: str, results: object, path: str = "secret") -> dict[str, Any]:
    return {"version": "v7.0.0", "build": 29, "serial": SERIAL, "http_method": "GET", "http_status": 200,
            "path": path, "name": table, "action": "", "vdom": "root", "status": "OK", "results": results}


def global_columns() -> SingleSecretFolderMembershipColumns:
    value = columns(parents=(0, 7, 7), folders=(42, 7, 8))
    return replace(value,
        folder_names=frame(native._FOLDER_NAMES,
            [b'    set name "' + name.encode() + b'"' for name in
             (FOLDER_NAME, "Synthetic Folder Witness", "CLI-only Folder")], FOLDER),
        secret_names=frame(native._SECRET_NAMES,
            [b'        set name "' + name.encode() + b'"' for name in
             (SECRET_NAME, "Synthetic Secret Witness", "CLI-only Secret")], DATABASE),
    )


class Peer:
    def __init__(self) -> None:
        self.active = False
        self.credential_calls = 0
        self.logins = 0
        self.logouts = 0
        self.ssh_configs: list[TargetSshTransportConfig] = []
        self.calls: list[str] = []
        self.role = envelope("admin", {"name": OWNER, "accprofile": "super_admin", "status": "enable",
            "remote-auth": "disable", "wildcard": "disable", "q_origin_key": OWNER}, "system")
        self.folder_rows = [{"id": 42, "name": FOLDER_NAME}, {"id": 7, "name": "Synthetic Folder Witness"}]
        self.secret_rows = [{"id": 17, "name": SECRET_NAME, "folder": 42},
                            {"id": 18, "name": "Synthetic Secret Witness", "folder": 7}]
        self.folders = envelope("folder", self.folder_rows)
        self.secrets = envelope("database", self.secret_rows)
        for collection in (self.folders, self.secrets):
            collection.update(size=2, matched_count=2, limit_reached=False)
        self.detail = metadata()
        self.detail["results"].update(field=[{"id": 1, "name": "Password", "value": MARKER}],
                                      description="Synthetic unrelated metadata")
        self.snapshots = [global_columns(), global_columns()]
        self.actor_name = OWNER
        self.logout_fault = False
        self.raw_detail: bytes | None = None
        self.raw_other: dict[str, bytes] = {}

    def credentials(self) -> tuple[str, str]:
        self.credential_calls += 1
        return OWNER, "synthetic-password-" + str(self.credential_calls)

    def client(self, **kwargs: Any) -> httpx.Client:
        assert isinstance(kwargs["verify"], ssl.SSLContext)
        assert kwargs["follow_redirects"] is False and kwargs["trust_env"] is False
        return httpx.Client(**kwargs, transport=httpx.MockTransport(self.respond))

    def respond(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.calls.append(path)
        assert "authorization" not in request.headers
        if path == "/remote/login": return httpx.Response(200, text='<form action="/XX/YY/ZZ/AUTH">')
        if path == "/XX/YY/ZZ/AUTH":
            assert request.method == "POST" and f"synthetic-password-{self.credential_calls}" in request.content.decode()
            self.logins += 1; self.active = True
            return httpx.Response(303, headers={"location": "/", "set-cookie": "session=synthetic; Secure; Path=/"})
        assert request.method == "GET"
        if path == "/logout":
            self.logouts += 1; self.active = self.logout_fault
            return httpx.Response(200)
        if not self.active: return httpx.Response(401, json={})
        if path in self.raw_other:
            return httpx.Response(200, content=self.raw_other[path], headers={"content-type": "application/json"})
        if path == "/": return httpx.Response(200)
        if path == SYSTEM_STATUS_PATH: return httpx.Response(200, json={"version": "v7.0.0", "build": 29})
        if path == candidate._ACTOR:
            return httpx.Response(200, json={"version": "v7.0.0", "build": 29, "status": "success",
                "http_method": "GET", "http_status": 200, "path": "web-ui", "name": "state",
                "results": {"admin": {"name": self.actor_name, "login_name": OWNER,
                                      "sponsored_group_name": "", "guest_admin": False}}})
        if path.startswith("/api/v2/cmdb/system/admin/"):
            assert request.url.params["format"] == candidate._ROLE_FIELDS
            return httpx.Response(200, json=self.role)
        if path == "/api/v2/cmdb/secret/folder":
            assert request.url.params == httpx.QueryParams("format=id%7Cname&count=512&start=0")
            return httpx.Response(200, json=self.folders)
        if path == "/api/v2/cmdb/secret/database":
            assert request.url.params == httpx.QueryParams("format=id%7Cname%7Cfolder&count=512&start=0")
            return httpx.Response(200, json=self.secrets)
        assert path == "/api/v2/cmdb/secret/database/17"
        if self.raw_detail is not None:
            return httpx.Response(200, content=self.raw_detail, headers={"content-type": "application/json"})
        return httpx.Response(200, json=self.detail)

    def reader(self, config: TargetSshTransportConfig, *, expected_serial: str) -> Any:
        assert expected_serial == SERIAL
        self.ssh_configs.append(config)
        return self

    def read_columns(self) -> SingleSecretFolderMembershipColumns:
        assert self.active
        self.calls.append("SSH columns")
        return self.snapshots.pop(0)


@pytest.fixture
def setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Peer, SecretMetadataHttpTransportConfig, dict[str, Any]]:
    peer = Peer()
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("synthetic pinned peer\n"); known_hosts.chmod(0o600)
    config = SecretMetadataHttpTransportConfig("https://fortipam.example.test", "synthetic-token", 5, None)
    args = dict(binding=binding(), owner_name=OWNER, folder_path="Public/" + FOLDER_NAME,
                credentials=peer.credentials, ssh_host="synthetic.invalid", ssh_port=22,
                ssh_known_hosts_file=known_hosts, client_factory=peer.client)
    monkeypatch.setattr(candidate, "SingleSecretFolderMembershipSshReader", peer.reader)
    return peer, config, args


def test_builder_is_lazy_single_snapshot_single_owner_session_and_accepts_strict_api_subsets(setup: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    peer, config, args = setup
    original_loads = json.loads

    def checked_loads(value: Any, *positional: Any, **keywords: Any) -> Any:
        assert MARKER not in (value if isinstance(value, str) else bytes(value).decode())
        return original_loads(value, *positional, **keywords)

    monkeypatch.setattr(candidate.json, "loads", checked_loads)
    observe = candidate.build_single_secret_folder_membership_observer(config, **args)
    assert peer.calls == [] and peer.credential_calls == 0
    for expected in (1, 2):
        peer.snapshots = [global_columns(), global_columns()]
        start = len(peer.calls)
        result = observe()
        assert result.observations_stable and result.exactly_one_secret
        assert peer.credential_calls == peer.logins == peer.logouts == expected
        assert not peer.active
        ssh = peer.ssh_configs[-1]
        assert ssh.username == OWNER and ssh.password == f"synthetic-password-{expected}"
        interleaved = [event for event in peer.calls[start:] if event in {"SSH columns", "/api/v2/cmdb/secret/database/17"}]
        assert interleaved == ["SSH columns", "/api/v2/cmdb/secret/database/17"] * 2
        for private in (OWNER, SERIAL, FOLDER_NAME, SECRET_NAME, MARKER, ssh.password):
            assert private not in str(result.as_dict())
    with pytest.raises(TypeError): observe(folder_id=42)  # type: ignore[call-arg]


@pytest.mark.parametrize("present,action,accepted", (
    (False, None, True), (True, "", True), (True, "schema", False),
    (True, None, False), (True, False, False), (True, 0, False), (True, [], False),
))
def test_fixed_role_get_accepts_native_absent_action_only_without_synthesizing_header(
    setup: Any, present: bool, action: object, accepted: bool,
) -> None:
    peer, config, args = setup
    if present:
        peer.role["action"] = action
    else:
        del peer.role["action"]
    original = deepcopy(peer.role)
    observe = candidate.build_single_secret_folder_membership_observer(config, **args)
    if accepted:
        assert observe().observations_stable
        assert "SSH columns" in peer.calls
    else:
        with pytest.raises(ValueError, match=candidate._UNAVAILABLE): observe()
        assert "/api/v2/cmdb/secret/folder" not in peer.calls
        assert "SSH columns" not in peer.calls
    assert peer.role == original
    assert peer.logouts == 1 and not peer.active


def test_qualified_fixed_gets_preserve_native_action_absence_in_detail_projection(
    setup: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer, config, args = setup
    for envelope_name in ("role", "folders", "secrets", "detail"):
        del getattr(peer, envelope_name)["action"]
    original = candidate.SingleSecretFolderMembershipSource._metadata
    projections: list[dict[str, object]] = []

    def checked_metadata(source: Any, payload: Any) -> dict[str, object]:
        assert "action" not in payload
        result = original(source, payload)
        assert "action" not in result
        projections.append(result)
        return result

    monkeypatch.setattr(candidate.SingleSecretFolderMembershipSource, "_metadata", checked_metadata)
    observe = candidate.build_single_secret_folder_membership_observer(config, **args)
    assert observe().observations_stable
    assert len(projections) == 2
    for envelope_name in ("role", "folders", "secrets", "detail"):
        assert "action" not in getattr(peer, envelope_name)
    assert peer.logouts == 1 and not peer.active


@pytest.mark.parametrize("envelope_name", ("folders", "secrets", "detail"))
@pytest.mark.parametrize("action", ("schema", None, False, 0, []))
def test_qualified_fixed_gets_reject_invalid_present_action(setup: Any, envelope_name: str, action: object) -> None:
    peer, config, args = setup
    getattr(peer, envelope_name)["action"] = action
    observe = candidate.build_single_secret_folder_membership_observer(config, **args)
    with pytest.raises(ValueError, match=candidate._UNAVAILABLE): observe()
    assert peer.logouts == 1 and not peer.active


@pytest.mark.parametrize("size,accepted", (
    (2, True), (3, True), (512, True), (1, False), (513, False),
    (True, False), ("3", False), (3.0, False),
))
@pytest.mark.parametrize("envelope_name", ("folders", "secrets"))
def test_visible_collection_size_is_a_bounded_integer_without_global_scope_claim(
    setup: Any, envelope_name: str, size: object, accepted: bool,
) -> None:
    peer, config, args = setup
    collection = getattr(peer, envelope_name)
    collection["size"] = size
    assert collection["matched_count"] == len(collection["results"]) == 2
    observe = candidate.build_single_secret_folder_membership_observer(config, **args)
    if accepted:
        assert observe().observations_stable
        assert peer.calls.count("SSH columns") == 2
    else:
        with pytest.raises(ValueError, match=candidate._UNAVAILABLE): observe()
        assert "SSH columns" not in peer.calls
    assert peer.logouts == 1 and not peer.active


def duplicate_detail(peer: Peer, value: str = "enable") -> bytes:
    peer.detail["results"]["block-clipboard"] = value
    raw = json.dumps(peer.detail, separators=(",", ":")).encode()
    token = b'"block-clipboard":"' + value.encode() + b'"'
    return raw.replace(token, token + b"," + token, 1)


def duplicate_secret_collection(peer: Peer) -> bytes:
    for row, value in zip(peer.secret_rows, ("enable", "disable"), strict=True):
        row.update({"block-clipboard": value, "field": [{"value": MARKER}]})
    raw = json.dumps(peer.secrets, separators=(",", ":")).encode()
    for value in ("enable", "disable"):
        token = b'"block-clipboard":"' + value.encode() + b'"'
        raw = raw.replace(token, token + b"," + token)
    return raw


@pytest.mark.parametrize("absent_action", (False, True))
def test_fixed_secret_collection_qualifies_all_rows_before_native_duplicate_normalization(
    setup: Any, monkeypatch: pytest.MonkeyPatch, absent_action: bool,
) -> None:
    peer, config, args = setup
    raw = duplicate_secret_collection(peer)
    if absent_action:
        raw = raw.replace(b'"action":"",', b"")
    path = "/api/v2/cmdb/secret/database"
    peer.raw_other[path] = raw
    original_loads = json.loads
    original_bytes = candidate._SessionProvider._bytes
    captured: list[bytearray] = []

    def checked_loads(content: Any, *positional: Any, **keywords: Any) -> Any:
        assert MARKER not in (content if isinstance(content, str) else bytes(content).decode())
        return original_loads(content, *positional, **keywords)

    def capture_bytes(provider: Any, route: str) -> bytearray:
        content = original_bytes(provider, route)
        if route == candidate._SECRETS:
            captured.append(content)
        return content

    monkeypatch.setattr(candidate.json, "loads", checked_loads)
    monkeypatch.setattr(candidate._SessionProvider, "_bytes", capture_bytes)
    assert candidate.build_single_secret_folder_membership_observer(config, **args)().observations_stable
    assert peer.raw_other[path] == raw
    assert len(captured) == 1 and not captured[0]
    assert peer.logouts == 1 and not peer.active


@pytest.mark.parametrize("fault,before_kernel", (
    ("header_duplicate", True), ("action_duplicate", True), ("wrong_build", True), ("wrong_serial", True),
    ("wrong_action", True), ("null_action", True), ("next_idx", True), ("next_index", True),
    ("limit", True), ("total", True), ("size_under", True), ("size_over", True), ("size_bool", True),
    ("matched", True), ("matched_bool", True), ("one_row", True), ("too_many_rows", True),
    ("row_not_object", True), ("duplicate_ids", True), ("duplicate_names", True), ("id_bool", True),
    ("folder_bool", True), ("id_string", True), ("folder_string", True), ("name_object", True),
    ("unsafe_name", True), ("wrong_selected_id", True), ("wrong_selected_name", True),
    ("wrong_selected_folder", True), ("missing_witness", True), ("id_duplicate", True),
    ("name_duplicate", True), ("folder_duplicate", True), ("lookalike_row", True),
    ("three_clipboard", False), ("different_clipboard", False), ("invalid_clipboard", False),
    ("nested_clipboard", False), ("nested_lookalike", False), ("other_duplicate", False),
))
def test_secret_collection_byte_qualification_denies_invalid_rows_headers_pages_and_duplicate_shapes(
    setup: Any, monkeypatch: pytest.MonkeyPatch, fault: str, before_kernel: bool,
) -> None:
    peer, config, args = setup
    raw = duplicate_secret_collection(peer)
    token = b'"block-clipboard":"enable"'
    changes = {
        "header_duplicate": (b'"build":29', b'"build":29,"build":29'),
        "action_duplicate": (b'"action":""', b'"action":"","action":""'),
        "wrong_build": (b'"build":29', b'"build":30'),
        "wrong_serial": (json.dumps(SERIAL).encode(), b'"OTHER"'),
        "wrong_action": (b'"action":""', b'"action":"schema"'),
        "null_action": (b'"action":""', b'"action":null'),
        "limit": (b'"limit_reached":false', b'"limit_reached":true'),
        "size_under": (b'"size":2', b'"size":1'), "size_over": (b'"size":2', b'"size":513'),
        "size_bool": (b'"size":2', b'"size":true'),
        "matched": (b'"matched_count":2', b'"matched_count":3'),
        "matched_bool": (b'"matched_count":2', b'"matched_count":true'),
        "duplicate_ids": (b'"id":18', b'"id":17'),
        "duplicate_names": (b'"Synthetic Secret Witness"', json.dumps(SECRET_NAME).encode()),
        "id_bool": (b'"id":18', b'"id":true'), "folder_bool": (b'"folder":7', b'"folder":true'),
        "id_string": (b'"id":18', b'"id":"18"'), "folder_string": (b'"folder":7', b'"folder":"7"'),
        "name_object": (b'"Synthetic Secret Witness"', b'{"name":"Synthetic Secret Witness"}'),
        "unsafe_name": (b'"Synthetic Secret Witness"', b'"Unsafe\\nName"'),
        "wrong_selected_id": (b'"id":17', b'"id":19'),
        "wrong_selected_name": (json.dumps(SECRET_NAME).encode(), b'"Other"'),
        "wrong_selected_folder": (b'"folder":42', b'"folder":7'),
        "missing_witness": (b'"Synthetic Secret Witness"', b'"Other Witness"'),
        "id_duplicate": (b'"id":18', b'"id":18,"id":18'),
        "name_duplicate": (b'"Synthetic Secret Witness"', b'"Synthetic Secret Witness","name":"Synthetic Secret Witness"'),
        "folder_duplicate": (b'"folder":7', b'"folder":7,"folder":7'),
        "three_clipboard": (token + b"," + token, b",".join((token,) * 3)),
        "different_clipboard": (token + b"," + token, token + b',"block-clipboard":"disable"'),
        "invalid_clipboard": (token + b"," + token, b'"block-clipboard":true,"block-clipboard":true'),
        "nested_clipboard": (token + b"," + token, token + b',"nested":{' + token + b"," + token + b"}"),
        "nested_lookalike": (token + b"," + token, token + b',"nested":{"id":17,"name":'
            + json.dumps(SECRET_NAME).encode() + b',"folder":42,' + token + b"," + token + b"}"),
        "other_duplicate": (token + b"," + token, token + b',"access":"x","access":"x"'),
    }
    if fault in changes:
        raw = raw.replace(*changes[fault], 1)
    elif fault in {"next_idx", "next_index", "total"}:
        raw = raw[:-1] + b',"' + fault.encode() + b'":1}'
    elif fault in {"one_row", "too_many_rows", "row_not_object", "lookalike_row"}:
        rows: object = peer.secret_rows[:1]
        if fault == "too_many_rows":
            rows = [*peer.secret_rows, *({"id": index + 100, "name": f"Synthetic {index}", "folder": 7}
                                        for index in range(510))]
        elif fault == "row_not_object": rows = [peer.secret_rows[0], 1]
        elif fault == "lookalike_row": rows = [peer.secret_rows[0], {"nested": peer.secret_rows[1]}]
        replacement = deepcopy(peer.secrets)
        replacement["results"] = rows
        replacement.update(matched_count=len(rows), size=len(rows))  # type: ignore[arg-type]
        raw = json.dumps(replacement, separators=(",", ":")).encode()
    peer.raw_other["/api/v2/cmdb/secret/database"] = raw
    original = candidate._normalize_build29_clipboard_duplicate
    calls: list[bool] = []
    captured: list[bytearray] = []
    original_bytes = candidate._SessionProvider._bytes

    def checked_kernel(content: bytearray, span: tuple[int, int]) -> None:
        calls.append(True)
        original(content, span)

    def capture_bytes(provider: Any, route: str) -> bytearray:
        content = original_bytes(provider, route)
        if route == candidate._SECRETS:
            captured.append(content)
        return content

    monkeypatch.setattr(candidate, "_normalize_build29_clipboard_duplicate", checked_kernel)
    monkeypatch.setattr(candidate._SessionProvider, "_bytes", capture_bytes)
    with pytest.raises(ValueError, match=candidate._UNAVAILABLE):
        candidate.build_single_secret_folder_membership_observer(config, **args)()
    assert bool(calls) is not before_kernel
    assert len(captured) == 1 and not captured[0]
    assert "SSH columns" not in peer.calls
    assert peer.logouts == 1 and not peer.active


@pytest.mark.parametrize("value", ("enable", "disable"))
@pytest.mark.parametrize("list_row", (False, True))
@pytest.mark.parametrize("absent_action", (False, True))
def test_fixed_detail_normalizes_only_qualified_native_identical_clipboard_row_duplicate(
    setup: Any, monkeypatch: pytest.MonkeyPatch, value: str, list_row: bool, absent_action: bool,
) -> None:
    peer, config, args = setup
    raw = duplicate_detail(peer, value)
    if list_row:
        raw = raw.replace(b'"results":{', b'"results":[{').replace(b'},"size":', b'}],"size":')
    if absent_action:
        raw = raw.replace(b'"action":"",', b"")
    peer.raw_detail = raw
    original_loads = json.loads

    def checked_loads(content: Any, *positional: Any, **keywords: Any) -> Any:
        assert MARKER not in (content if isinstance(content, str) else bytes(content).decode())
        return original_loads(content, *positional, **keywords)

    monkeypatch.setattr(candidate.json, "loads", checked_loads)
    assert candidate.build_single_secret_folder_membership_observer(config, **args)().observations_stable
    assert peer.raw_detail == raw
    assert peer.logouts == 1 and not peer.active


@pytest.mark.parametrize("fault,before_kernel", (
    ("header_duplicate", True), ("header_action_duplicate", True), ("id_duplicate", True),
    ("name_duplicate", True), ("folder_duplicate", True), ("wrong_id", True), ("wrong_name", True),
    ("wrong_folder", True), ("wrong_serial", True), ("wrong_build", True), ("wrong_action", True),
    ("null_action", True), ("two_rows", True), ("lookalike_row", True),
    ("three_clipboard", False), ("different_clipboard", False), ("invalid_clipboard", False),
    ("nested_clipboard", False), ("nested_lookalike", False), ("other_duplicate", False),
))
def test_fixed_detail_duplicate_exception_keeps_exact_byte_qualification_and_recursive_denials(
    setup: Any, monkeypatch: pytest.MonkeyPatch, fault: str, before_kernel: bool,
) -> None:
    peer, config, args = setup
    raw = duplicate_detail(peer)
    token = b'"block-clipboard":"enable"'
    changes = {
        "header_duplicate": (b'"build":29', b'"build":29,"build":29'),
        "header_action_duplicate": (b'"action":""', b'"action":"","action":""'),
        "id_duplicate": (b'"id":17', b'"id":17,"id":17'),
        "name_duplicate": (json.dumps(SECRET_NAME).encode(), json.dumps(SECRET_NAME).encode() + b',"name":' + json.dumps(SECRET_NAME).encode()),
        "folder_duplicate": (b'"folder":42', b'"folder":42,"folder":42'),
        "wrong_id": (b'"id":17', b'"id":18'),
        "wrong_name": (json.dumps(SECRET_NAME).encode(), b'"Other Secret"'),
        "wrong_folder": (b'"folder":42', b'"folder":7'),
        "wrong_serial": (json.dumps(SERIAL).encode(), b'"OTHER"'),
        "wrong_build": (b'"build":29', b'"build":30'),
        "wrong_action": (b'"action":""', b'"action":"schema"'),
        "null_action": (b'"action":""', b'"action":null'),
        "three_clipboard": (token + b"," + token, b",".join((token,) * 3)),
        "different_clipboard": (token + b"," + token, token + b',"block-clipboard":"disable"'),
        "invalid_clipboard": (token + b"," + token, b'"block-clipboard":true,"block-clipboard":true'),
        "nested_clipboard": (token + b"," + token, token + b',"nested":{' + token + b"," + token + b"}"),
        "nested_lookalike": (token + b"," + token,
            token + b',"nested":{' + b'"id":17,"name":' + json.dumps(SECRET_NAME).encode()
            + b',"folder":42,' + token + b"," + token + b"}"),
        "other_duplicate": (token + b"," + token, token + b',"access":"x","access":"x"'),
    }
    if fault in changes:
        old, new = changes[fault]
        raw = raw.replace(old, new, 1)
    elif fault == "two_rows":
        raw = raw.replace(b'"results":{', b'"results":[{').replace(b'},"size":', b'},{"id":18}],"size":')
    elif fault == "lookalike_row":
        raw = raw.replace(b'"results":{', b'"results":{"nested":{').replace(b'},"size":', b'}},"size":')
    peer.raw_detail = raw
    original = candidate._normalize_build29_clipboard_duplicate
    calls: list[bool] = []

    def checked_kernel(content: bytearray, span: tuple[int, int]) -> None:
        calls.append(True)
        original(content, span)

    monkeypatch.setattr(candidate, "_normalize_build29_clipboard_duplicate", checked_kernel)
    with pytest.raises(ValueError, match=candidate._UNAVAILABLE):
        candidate.build_single_secret_folder_membership_observer(config, **args)()
    # The two qualified visible collection rows precede the fixed detail.
    assert len(calls) >= 2
    assert bool(calls[2:]) is not before_kernel
    assert peer.logouts == 1 and not peer.active


@pytest.mark.parametrize("accepted", (True, False))
def test_fixed_detail_private_raw_buffer_is_zeroized_after_duplicate_handling(
    setup: Any, monkeypatch: pytest.MonkeyPatch, accepted: bool,
) -> None:
    peer, config, args = setup
    peer.raw_detail = duplicate_detail(peer)
    if not accepted:
        peer.raw_detail = peer.raw_detail.replace(b'"folder":42', b'"folder":7', 1)
    original = candidate._SessionProvider._bytes
    captured: list[bytearray] = []

    def capture_bytes(provider: Any, path: str) -> bytearray:
        raw = original(provider, path)
        if path == provider._detail:
            captured.append(raw)
        return raw

    monkeypatch.setattr(candidate._SessionProvider, "_bytes", capture_bytes)
    observe = candidate.build_single_secret_folder_membership_observer(config, **args)
    if accepted:
        assert observe().observations_stable
    else:
        with pytest.raises(ValueError, match=candidate._UNAVAILABLE): observe()
    assert len(captured) == (2 if accepted else 1)
    assert all(not raw for raw in captured)


@pytest.mark.parametrize("envelope_name,path", (
    ("role", "/api/v2/cmdb/system/admin/" + OWNER),
    ("folders", "/api/v2/cmdb/secret/folder"), ("secrets", "/api/v2/cmdb/secret/database"),
))
def test_other_compiled_paths_never_receive_duplicate_normalization(
    setup: Any, monkeypatch: pytest.MonkeyPatch, envelope_name: str, path: str,
) -> None:
    peer, config, args = setup
    raw = json.dumps(getattr(peer, envelope_name), separators=(",", ":")).encode()
    peer.raw_other[path] = raw.replace(b'"action":""', b'"action":"","action":""', 1)

    def forbidden_kernel(content: bytearray, span: tuple[int, int]) -> None:
        pytest.fail("The native duplicate kernel must never run on another compiled path.")

    monkeypatch.setattr(candidate, "_normalize_build29_clipboard_duplicate", forbidden_kernel)
    with pytest.raises(ValueError, match=candidate._UNAVAILABLE):
        candidate.build_single_secret_folder_membership_observer(config, **args)()
    assert peer.logouts == 1 and not peer.active


@pytest.mark.parametrize("fault", (
    "actor", "role_owner", "role_disabled", "role_remote", "role_wildcard", "role_profile", "role_serial",
    "role_build", "collection_duplicate_id", "collection_duplicate_name", "collection_page", "collection_next",
    "collection_size", "collection_serial", "collection_witness", "collection_bound_id", "collection_bound_folder",
    "api_not_cli_subset", "cli_drift", "cli_sibling", "detail_id", "detail_folder", "detail_action", "detail_serial",
    "detail_page", "detail_next", "detail_mkey", "detail_duplicate", "logout",
))
def test_candidate_refuses_identity_scope_or_shutdown_faults_without_mutation_or_private_failure(setup: Any, fault: str) -> None:
    peer, config, args = setup
    if fault == "actor": peer.actor_name = "other"
    elif fault.startswith("role_"):
        key, value = {"role_owner": ("name", "other"), "role_disabled": ("status", "disable"),
            "role_remote": ("remote-auth", "enable"), "role_wildcard": ("wildcard", "enable"),
            "role_profile": ("accprofile", "read_only"), "role_serial": ("serial", "OTHER"),
            "role_build": ("build", 30)}[fault]
        (peer.role if key in {"serial", "build"} else peer.role["results"])[key] = value
    elif fault == "collection_duplicate_id": peer.folder_rows[1]["id"] = 42
    elif fault == "collection_duplicate_name": peer.folder_rows[1]["name"] = FOLDER_NAME
    elif fault == "collection_page": peer.secrets["limit_reached"] = True
    elif fault == "collection_next": peer.secrets["next_idx"] = 1
    elif fault == "collection_size": peer.folders["size"] = 1
    elif fault == "collection_serial": peer.folders["serial"] = "OTHER"
    elif fault == "collection_witness": peer.secret_rows[1]["name"] = "Missing witness"
    elif fault == "collection_bound_id": peer.folder_rows[0]["id"] = 43
    elif fault == "collection_bound_folder": peer.secret_rows[0]["folder"] = 7
    elif fault == "api_not_cli_subset":
        peer.secret_rows.append({"id": 19, "name": "API-only Secret", "folder": 7})
        peer.secrets.update(size=3, matched_count=3)
    elif fault == "cli_drift": peer.snapshots[1] = columns()
    elif fault == "cli_sibling": peer.snapshots = [columns(folders=(42, 42))] * 2
    elif fault == "detail_id": peer.detail["results"]["id"] = 18
    elif fault == "detail_folder": peer.detail["results"]["folder"] = 7
    elif fault == "detail_action": peer.detail["action"] = "schema"
    elif fault == "detail_serial": peer.detail["serial"] = "OTHER"
    elif fault == "detail_page": peer.detail["results"] = [peer.detail["results"], deepcopy(peer.detail["results"])]
    elif fault == "detail_next": peer.detail["next_idx"] = 1
    elif fault == "detail_mkey": peer.detail["mkey"] = 18
    elif fault == "detail_duplicate":
        peer.raw_detail = json.dumps(peer.detail).replace('"folder": 42', '"folder": 7, "folder": 42').encode()
    elif fault == "logout": peer.logout_fault = True
    observe = candidate.build_single_secret_folder_membership_observer(config, **args)
    with pytest.raises(ValueError) as error: observe()
    assert str(error.value) == candidate._UNAVAILABLE
    assert peer.logouts == 1 and peer.credential_calls == 1
    assert MARKER not in str(error.value) and SERIAL not in str(error.value)
    assert peer.calls[-2:] == ["/logout", SYSTEM_STATUS_PATH]


def test_known_hosts_and_local_binding_are_checked_before_credentials(setup: Any) -> None:
    peer, config, args = setup
    for changes in ({"ssh_port": True}, {"ssh_host": "bad host"}, {"folder_path": "Public/Wrong"},
                    {"owner_name": "bad/owner"}):
        with pytest.raises(ValueError): candidate.build_single_secret_folder_membership_observer(config, **{**args, **changes})
    observe = candidate.build_single_secret_folder_membership_observer(config, **args)
    args["ssh_known_hosts_file"].chmod(0o644)
    with pytest.raises(ValueError): observe()
    assert peer.credential_calls == 0 and peer.calls == []


class NativePeer:
    def __init__(self, fault: str | None = None) -> None:
        self.snapshot: SingleSecretFolderMembershipColumns = global_columns()
        self.fault = fault
        self.closed = self.connection_closed = 0
        self.commands: list[str] = []
        self.name_reads = {FOLDER: 0, DATABASE: 0}

    @asynccontextmanager
    async def _connection(self) -> Any:
        try: yield self
        finally: self.connection_closed += 1

    async def _open_cli(self, connection: Any) -> tuple[Any, bytes, float]:
        return self, ROOT, 12345

    async def dynamic(self, process: Any, command: str, prompt: bytes, deadline: float) -> bytes:
        assert process is self and deadline == 12345
        self.commands.append(command)
        if command == "config secret folder": return FOLDER
        if command == "config secret database": return DATABASE
        assert command == "end"
        return b"OTHER #" if self.fault == "exit" else ROOT

    async def read(self, process: Any, command: str, prompt: bytes, deadline: float) -> bytes:
        snapshot: SingleSecretFolderMembershipColumns = self.snapshot
        assert process is self and deadline == 12345
        self.commands.append(command)
        if command == native._SERIAL_COMMAND:
            return frame(command, [b"Serial-Number: OTHER"]) if self.fault == "serial" else snapshot.serial_output
        if command == native._VERSION_COMMAND:
            return frame(command, [b"Version: FortiPAM v7.0.0,build30"]) if self.fault == "build" else snapshot.version_output
        if command in {native._FOLDER_NAMES, native._SECRET_NAMES}:
            self.name_reads[prompt] += 1
            value = snapshot.folder_names if prompt == FOLDER else snapshot.secret_names
            if self.name_reads[prompt] == 2 and self.fault == ("folder_drift" if prompt == FOLDER else "secret_drift"):
                return value.replace(b"CLI-only", b"Changed")
            return value
        if command == native._PARENT_PROJECTION: return snapshot.folder_parents
        assert command == native._FOLDER_PROJECTION
        return snapshot.secret_folders

    async def close(self, process: Any) -> None:
        self.closed += 1


@pytest.mark.parametrize("fault", (None, "serial", "build", "folder_drift", "secret_drift", "exit"))
def test_native_reader_brackets_both_columns_and_closes_pinned_connection(setup: Any, monkeypatch: pytest.MonkeyPatch, fault: str | None) -> None:
    _, _, args = setup
    peer = NativePeer(fault)
    monkeypatch.setattr(native, "FortiPamTargetReferenceSshTransport", lambda config: peer)
    monkeypatch.setattr(native, "_send_and_read", peer.read)
    monkeypatch.setattr(native, "_send_and_read_dynamic_prompt", peer.dynamic)
    monkeypatch.setattr(native, "_close_cli", peer.close)
    config = TargetSshTransportConfig("synthetic.invalid", 22, OWNER, "synthetic-password", args["ssh_known_hosts_file"], 5)
    reader = native.SingleSecretFolderMembershipSshReader(config, expected_serial=SERIAL)
    if fault is None:
        assert reader.read_columns() == peer.snapshot
        assert peer.name_reads == {FOLDER: 2, DATABASE: 2}
        assert peer.commands == [native._SERIAL_COMMAND, native._VERSION_COMMAND, "config secret folder",
            native._FOLDER_NAMES, native._PARENT_PROJECTION, native._FOLDER_NAMES, "end", "config secret database",
            native._SECRET_NAMES, native._FOLDER_PROJECTION, native._SECRET_NAMES, "end"]
    else:
        with pytest.raises(ValueError, match="native columns are unavailable"): reader.read_columns()
    assert peer.closed == peer.connection_closed == 1
