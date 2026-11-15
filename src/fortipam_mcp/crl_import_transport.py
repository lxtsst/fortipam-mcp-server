"""Private native build29 file import and original-owned CRL recovery.

No selector, artifact, credential, HTTP client or authority crosses MCP. The
caller must reserve its real M4 dispatch before the fixed mutation callback.
"""
from __future__ import annotations

import base64
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
from http.cookies import SimpleCookie
import json
import re
import time
from typing import Any
from urllib.parse import quote, urlencode

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from v4_planning import M4ExecutionAuthorization, M4ExecutionPlan
from v4_planning.execution_kernel import _require_m4_dispatch_ownership

from .crl_import_artifact import CrlImportArtifact, prepare_build29_crl_artifact
from .ldap_server_projection import _array, _members, _validate
from .local_user_reset_fixture_preflight import _actor_context
from .owner_session_metadata import OwnerSessionMetadataTransport
from .m4_execution_store import PersistentM4ExecutionStateStore
from .target_api_dependency_reader import _private_http_logs

CONTRACT = "fortipam-700-build29-native-owned-crl-v1"
COLLECTION = "/api/v2/cmdb/vpn.certificate/crl"
IMPORT = "/api/v2/monitor/vpn-certificate/crl/import"
SELECTOR = "/api/v2/monitor/system/available-certificates?with_ca=1&with_crl=1&with_remote=1"
_ERROR = "The fixed CRL lifecycle is unavailable."
_LIMIT = 1048576
_TYPES = {"name": "string", "crl": "user", "range": "option", "source": "option",
    "update-vdom": "string", "ldap-server": "string", "ldap-username": "string",
    "ldap-password": "password", "http-url": "string", "scep-url": "string",
    "scep-cert": "string", "update-interval": "integer", "source-ip": "ipv4-address"}
_Q_FIELDS = {"q_origin_key", "q_ref", "q_static", "q_global_entry", "q_mkey_type", "q_name",
    "q_no_edit", "q_no_rename", "q_path", "q_type"}
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,34}\Z")


def _fingerprint(value: object) -> str:
    if type(value) is not str or re.fullmatch(r"(?:[A-Fa-f0-9]{64}|(?:[A-Fa-f0-9]{2}:){31}[A-Fa-f0-9]{2})", value) is None:
        raise ValueError(_ERROR)
    return value.replace(":", "").lower()


def digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def _token(raw: bytearray, span: tuple[int, int]) -> Any:
    return json.loads(raw[slice(*span)])


def _frame(raw: bytearray, serial: str, *, method: str, path: str, name: str,
           password_records: bool = False) -> dict[str, Any]:
    top = _members(raw, (0, len(raw)))
    for key, wanted in {"http_method": method, "status": "success", "version": "v7.0.0",
        "build": 29, "serial": serial, "path": path, "name": name, "vdom": "root"}.items():
        actual = _token(raw, top[key])
        if type(actual) is not type(wanted) or actual != wanted:
            raise ValueError
    if "http_status" in top and _token(raw, top["http_status"]) != 200:
        raise ValueError
    if password_records:
        result = top["results"]
        records = _array(raw, result) if raw[result[0]] == 91 else [result]
        for record in records:
            fields = _members(raw, record)
            if "ldap-password" in fields and raw[slice(*fields["ldap-password"])] != b'""':
                raise ValueError
    _validate(raw, (0, len(raw)))
    parsed = json.loads(raw)
    if type(parsed) is not dict:
        raise ValueError
    return parsed


def _metadata(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # Reference counters describe this new object's outgoing default relationship;
    # certificate identity, trust and configuration must themselves stay exact.
    return sorted(({key: value for key, value in row.items() if key != "q_ref"}
                   for row in entries if row.get("type") != "crl"), key=lambda row: row["name"])


@dataclass(frozen=True, slots=True, repr=False)
class CrlBaseline:
    schema_digest: str
    defaults: dict[str, Any]
    certificates: list[dict[str, Any]]
    current_digest: str


class NativeCrlTransport:
    """One bound public artifact, empty initial CRL table and fixed native routes."""

    def __init__(self, *, owner_factory: Callable[[], OwnerSessionMetadataTransport],
                 owner_name: str, serial: str, crl_pem: bytes, issuer_pem: bytes,
                 nonce: str, clock: Callable[[], int] = lambda: int(time.time())) -> None:
        if (not callable(owner_factory) or not callable(clock) or type(owner_name) is not str
                or not owner_name or type(serial) is not str or not serial
                or type(nonce) is not str or re.fullmatch(r"[a-f0-9]{16}", nonce) is None
                or type(crl_pem) is not bytes or type(issuer_pem) is not bytes):
            raise ValueError(_ERROR)
        self._factory, self._owner, self._serial = owner_factory, owner_name, serial
        self._crl, self._issuer, self._nonce, self._clock = crl_pem, issuer_pem, nonce, clock
        self._artifact = self._material()
        self.parameters_digest = digest({"contract": CONTRACT, "scope": "vdom", "nonce": nonce,
            "serial": self._serial, "owner_digest": hashlib.sha256(owner_name.encode()).hexdigest(),
            "crl": self._artifact.sha256, "issuer": self._artifact.issuer_sha256})
        self._baseline: CrlBaseline | None = None
        self._created: dict[str, Any] | None = None
        self._ack_digest: str | None = None
        self._qtype: int | None = None
        self._attempted = {"import": False, "recover": False}

    def _material(self) -> CrlImportArtifact:
        artifact = prepare_build29_crl_artifact(self._crl, self._issuer,
            now=self._clock(), minimum_sequence=1)
        issuer = x509.load_pem_x509_certificate(self._issuer)
        # This exact laboratory profile imports an empty list for a new,
        # uninstalled issuer. It cannot revoke an existing peer certificate.
        if (artifact.sequence != 1 or artifact.revoked_count != 0
                or artifact.next_update - self._clock() < 300
                or issuer.subject != issuer.issuer
                or self._nonce not in issuer.subject.rfc4514_string()):
            raise ValueError(_ERROR)
        issuer.verify_directly_issued_by(issuer)
        if hasattr(self, "_artifact") and artifact != self._artifact:
            raise ValueError(_ERROR)
        for extension in x509.load_pem_x509_crl(self._crl).extensions:
            if isinstance(extension.value, (x509.FreshestCRL, x509.CRLDistributionPoints,
                                            x509.AuthorityInformationAccess)):
                raise ValueError(_ERROR)
        return artifact

    @contextmanager
    def _session(self) -> Iterator[Any]:
        owner = self._factory()
        try:
            with _private_http_logs(), owner.authenticated():
                raw = self._request(owner._client, "GET", "/api/v2/monitor/web-ui/state")
                try:
                    top = _members(raw, (0, len(raw)))
                    if _token(raw, top["serial"]) != self._serial:
                        raise ValueError
                    _actor_context(raw, expected_name=self._owner)
                finally:
                    raw[:] = bytes(len(raw))
                yield owner._client
            if not owner.logout_verified:
                raise ValueError
        except Exception:
            raise ValueError(_ERROR) from None

    def _request(self, client: Any, method: str, path: str, *,
                 body: bytes | None = None, guard: Callable[[], None] | None = None) -> bytearray:
        allowed_gets = {"/api/v2/monitor/web-ui/state", COLLECTION + "?action=schema&with_meta=true",
            COLLECTION + "?action=default&with_meta=true", COLLECTION + "?with_meta=true", SELECTOR,
            "/api/v2/monitor/web-ui/object-urls"}
        owned = self._created and self._created["name"]
        download = "/api/v2/monitor/system/certificate/download/" + quote(str(owned), safe="") + "?scope=vdom&type=crl"
        usage = "/api/v2/monitor/system/object/usage?" + urlencode({"mkey": str(owned),
            "qtypes": json.dumps([self._qtype], separators=(",", ":"))})
        if method == "GET":
            if path not in allowed_gets and not (owned and (path == download or self._qtype is not None and path == usage)):
                raise ValueError(_ERROR)
        elif not (method == "POST" and path == IMPORT and body is not None
                  or method == "DELETE" and owned and path == COLLECTION + "/" + quote(owned, safe="") and body is None):
            raise ValueError(_ERROR)
        headers = {"Accept-Encoding": "identity", "Cache-Control": "no-cache, no-store"}
        if method != "GET":
            if guard is None:
                raise ValueError(_ERROR)
            cookies = SimpleCookie()
            cookies.load(client.build_request("GET", path).headers.get("cookie", ""))
            csrf = cookies.get("ccsrftoken")
            if csrf is None or not csrf.value or len(csrf.value) > 4096 or any(ord(c) < 33 or ord(c) > 126 for c in csrf.value):
                raise ValueError(_ERROR)
            headers.update({"X-CSRFTOKEN": csrf.value, "Content-Type": "application/json"})
            guard()
        raw = bytearray()
        try:
            with client.stream(method, path, content=body, headers=headers) as response:
                if response.status_code != 200:
                    raise ValueError
                if response.headers.get("content-encoding", "identity") != "identity":
                    raise ValueError
                for chunk in response.iter_bytes():
                    if len(raw) + len(chunk) > _LIMIT:
                        raise ValueError
                    raw.extend(chunk)
            return raw
        except Exception:
            raw[:] = bytes(len(raw))
            raise ValueError(_ERROR) from None

    def _json(self, client: Any, path: str, *, schema: bool = False,
              monitor: bool = False) -> dict[str, Any]:
        raw = self._request(client, "GET", path)
        try:
            return _frame(raw, self._serial, method="GET",
                path="system" if monitor else "vpn.certificate",
                name="available-certificates" if monitor else "crl", password_records=not (schema or monitor))
        finally:
            raw[:] = bytes(len(raw))

    def _observe(self, client: Any) -> tuple[CrlBaseline, list[dict[str, Any]]]:
        schema = self._json(client, COLLECTION + "?action=schema&with_meta=true", schema=True)
        children = schema["results"]["children"]
        if ({key: value["type"] for key, value in children.items()} != _TYPES
                or children["name"].get("required") is not True or children["name"].get("size") != 35):
            raise ValueError
        schema_digest = digest(children)
        defaults = self._json(client, COLLECTION + "?action=default&with_meta=true")["results"]
        if (set(defaults) - _Q_FIELDS != set(_TYPES) | {"last-updated"}
                or any(defaults[key] != "" for key in ("name", "crl", "ldap-server", "ldap-username",
                    "ldap-password", "http-url", "scep-url"))
                or defaults["source"] != "user" or defaults["range"] != "vdom"
                or type(defaults["update-interval"]) is not int or defaults["update-interval"] != 0
                or defaults["update-vdom"] != "root" or defaults["source-ip"] != "0.0.0.0"
                or type(defaults["last-updated"]) is not int or defaults["last-updated"] != 0):
            raise ValueError
        table = self._json(client, COLLECTION + "?with_meta=true")
        rows = table["results"]
        if (type(rows) is not list or len(rows) > 1 or table.get("limit_reached", False) is not False
                or table.get("matched_count", len(rows)) != len(rows)):
            raise ValueError
        entries = self._json(client, SELECTOR, monitor=True)["results"]
        if (type(entries) is not list or len(entries) >= 200
                or len({entry["name"] for entry in entries}) != len(entries)
                or any(self._nonce in json.dumps(entry) for entry in entries if entry.get("type") != "crl")):
            raise ValueError
        for entry in entries:
            if entry.get("type") not in {"crl", "local-csr"} and _fingerprint(entry.get("fingerprint")) == self._artifact.issuer_sha256:
                raise ValueError
        crl_names = [entry["name"] for entry in entries if entry.get("type") == "crl"]
        if crl_names != [row["name"] for row in rows]:
            raise ValueError
        certificates = _metadata(entries)
        normalized = {key: value for key, value in defaults.items() if key in set(_TYPES) | {"last-updated"}}
        current = digest({"contract": CONTRACT, "serial": self._serial, "schema": schema_digest,
            "defaults": normalized, "certificates": certificates, "empty_crl_table": True})
        return CrlBaseline(schema_digest, normalized, certificates, current), rows

    def inspect(self, phase: str) -> tuple[str, str]:
        self._material()
        with self._session() as client:
            observed, rows = self._observe(client)
            if self._baseline is None:
                if phase != "import" or rows:
                    raise ValueError(_ERROR)
                self._baseline = observed
            if observed != self._baseline:
                raise ValueError(_ERROR)
            expected = digest({"original": observed.current_digest, "artifact": self.parameters_digest,
                               "one_native_crl_verified": True})
            if phase == "import":
                if rows or self._created is not None or self._attempted[phase]:
                    raise ValueError(_ERROR)
                return observed.current_digest, expected
            if phase != "recover" or self._created is None or self._ack_digest is None or self._attempted[phase]:
                raise ValueError(_ERROR)
            self._verify_created(client, rows)
            self._zero_references(client)
            return expected, observed.current_digest

    def _verify_created(self, client: Any, rows: list[dict[str, Any]], *, first: bool = False) -> None:
        if len(rows) != 1 or self._baseline is None:
            raise ValueError(_ERROR)
        row = rows[0]
        if (type(row) is not dict or set(row) - _Q_FIELDS != set(_TYPES) | {"last-updated"}
                or type(row["name"]) is not str or _NAME.fullmatch(row["name"]) is None
                or type(row["last-updated"]) is not int or not 0 <= row["last-updated"] <= 4294967295
                or any(row[key] != self._baseline.defaults[key]
                    for key in _TYPES if key not in {"name", "crl"})):
            raise ValueError(_ERROR)
        if not first and row != self._created:
            raise ValueError(_ERROR)
        if first:
            self._created = row
        path = "/api/v2/monitor/system/certificate/download/" + quote(row["name"], safe="") + "?scope=vdom&type=crl"
        raw = self._request(client, "GET", path)
        try:
            downloaded = (x509.load_pem_x509_crl(bytes(raw)) if raw.startswith(b"-----BEGIN X509 CRL-----")
                          else x509.load_der_x509_crl(bytes(raw)))
            material = prepare_build29_crl_artifact(downloaded.public_bytes(Encoding.PEM), self._issuer,
                now=self._clock(), minimum_sequence=1)
            if material.sha256 != self._artifact.sha256:
                raise ValueError
        finally:
            raw[:] = bytes(len(raw))

    def _zero_references(self, client: Any) -> None:
        if self._created is None:
            raise ValueError
        raw = self._request(client, "GET", "/api/v2/monitor/web-ui/object-urls")
        try:
            frame = _frame(raw, self._serial, method="GET", path="web-ui", name="object-urls")
            types = frame["results"]["by_type"]
            matches = []
            for key, value in types.items():
                if value.get("path") == "vpn.certificate.crl":
                    if re.fullmatch(r"0|[1-9][0-9]{0,8}", key) is None:
                        raise ValueError
                    matches.append(int(key))
            if len(matches) != 1:
                raise ValueError
            if self._qtype is not None and self._qtype != matches[0]:
                raise ValueError
            self._qtype = matches[0]
        finally:
            raw[:] = bytes(len(raw))
        path = "/api/v2/monitor/system/object/usage?" + urlencode({"mkey": self._created["name"],
            "qtypes": json.dumps(matches, separators=(",", ":"))})
        raw = self._request(client, "GET", path)
        try:
            frame = _frame(raw, self._serial, method="GET", path="system", name="object")
            if (frame.get("mkey") != self._created["name"]
                    or frame["results"].get("currently_using") != []):
                raise ValueError
        finally:
            raw[:] = bytes(len(raw))

    def dispatch(self, phase: str, *, current_digest: str, plan: M4ExecutionPlan,
                 authorization: M4ExecutionAuthorization, store: PersistentM4ExecutionStateStore,
                 guard: Callable[[], None]) -> None:
        # The M4 adapter supplies guard and original verified-import ownership.
        if (phase not in self._attempted or self._attempted[phase]
                or plan.action_id != "crl-native-" + phase or plan.adapter_ref != CONTRACT
                or plan.parameters_digest != self.parameters_digest or plan.expected_current_digest != current_digest):
            raise ValueError(_ERROR)
        _require_m4_dispatch_ownership(plan, authorization, store)
        if self.inspect(phase)[0] != current_digest:
            raise ValueError(_ERROR)
        def final_guard() -> None:
            guard()
            _require_m4_dispatch_ownership(plan, authorization, store)
        with self._session() as client:
            observed, rows = self._observe(client)
            if observed != self._baseline:
                raise ValueError(_ERROR)
            if phase == "import":
                if rows:
                    raise ValueError(_ERROR)
                self._material()
                body = json.dumps({"scope": "vdom", "file_content": base64.b64encode(self._crl).decode("ascii")},
                    separators=(",", ":")).encode()
                path, method = IMPORT, "POST"
            else:
                self._verify_created(client, rows)
                self._zero_references(client)
                body = None
                path, method = COLLECTION + "/" + quote(self._created["name"], safe=""), "DELETE"  # type: ignore[index]
            final_guard()
            self._attempted[phase] = True
            raw = self._request(client, method, path, body=body, guard=final_guard)
            try:
                ack = _frame(raw, self._serial, method=method,
                    path="vpn-certificate" if phase == "import" else "vpn.certificate", name="crl")
                if (phase == "import" and ack.get("action") != "import"
                        or phase == "recover" and ack.get("mkey") != self._created["name"]):  # type: ignore[index]
                    raise ValueError
                if phase == "import":
                    self._ack_digest = hashlib.sha256(raw).hexdigest()
            finally:
                raw[:] = bytes(len(raw))

    def postcondition(self, phase: str) -> str:
        if not self._attempted[phase] or self._baseline is None:
            raise ValueError(_ERROR)
        with self._session() as client:
            observed, rows = self._observe(client)
            if observed != self._baseline:
                raise ValueError(_ERROR)
            if phase == "import":
                if self._ack_digest is None:
                    raise ValueError(_ERROR)
                self._verify_created(client, rows, first=True)
                self._zero_references(client)
                return digest({"original": observed.current_digest, "artifact": self.parameters_digest,
                               "one_native_crl_verified": True})
            if rows:
                raise ValueError(_ERROR)
            return observed.current_digest
