"""Bounded public remote leaf-certificate import and original-owned recovery."""
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
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from v4_planning import M4ExecutionAuthorization, M4ExecutionPlan
from v4_planning.execution_kernel import _require_m4_dispatch_ownership

from .crl_import_transport import _frame, _token, _fingerprint, digest
from .ldap_server_projection import _members
from .local_user_reset_fixture_preflight import _actor_context
from .owner_session_metadata import OwnerSessionMetadataTransport
from .m4_execution_store import PersistentM4ExecutionStateStore
from .target_api_dependency_reader import _private_http_logs
from .remote_certificate_identity import (RemoteCertificateIdentity,
    expected_remote_import_name, remote_certificate_identity_matches)

CONTRACT = "fortipam-700-build29-native-owned-remote-certificate-v2"
COLLECTION = "/api/v2/cmdb/vpn.certificate/remote"
IMPORT = "/api/v2/monitor/vpn-certificate/remote/import"
SELECTOR = "/api/v2/monitor/system/available-certificates?with_ca=1&with_crl=1&with_remote=1"
_ERROR = "The fixed remote certificate lifecycle is unavailable."
_LIMIT = 1048576
_TYPES = {"name": "string", "remote": "user", "range": "option", "source": "option"}
_Q_FIELDS = {"q_origin_key", "q_ref", "q_static", "q_global_entry", "q_mkey_type", "q_name",
    "q_no_edit", "q_no_rename", "q_path", "q_type"}
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,34}\Z")


def configured_row(row: dict[str, Any]) -> dict[str, Any]:
    if (type(row) is not dict or set(row) - _Q_FIELDS != set(_TYPES)
            or any(type(row[key]) is not str for key in _TYPES)
            or _NAME.fullmatch(row["name"]) is None
            or row.get("q_origin_key", row["name"]) != row["name"]
            or type(row.get("q_global_entry", False)) is not bool):
        raise ValueError(_ERROR)
    return {**{key: row[key] for key in _TYPES}, "global_entry": row.get("q_global_entry", False)}


def certificate_projection(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # UI edit hints are derived; identity, scope, trust and references stay bound.
    return sorted(({key: value for key, value in row.items() if key not in {"q_no_edit", "q_no_rename"}}
                   for row in entries), key=lambda row: row["name"])


@dataclass(frozen=True, slots=True, repr=False)
class RemoteCertificateBaseline:
    schema_digest: str
    defaults: dict[str, Any]
    rows: list[dict[str, Any]]
    certificates: list[dict[str, Any]]
    current_digest: str


class NativeRemoteCertificateTransport:
    """One self-signed disposable public leaf, preserving all original objects."""

    def __init__(self, *, owner_factory: Callable[[], OwnerSessionMetadataTransport],
                 owner_name: str, serial: str, certificate_pem: bytes,
                 nonce: str, clock: Callable[[], int] = lambda: int(time.time())) -> None:
        if (not callable(owner_factory) or not callable(clock) or type(owner_name) is not str
                or not owner_name or type(serial) is not str or not serial
                or type(nonce) is not str or re.fullmatch(r"[a-f0-9]{16}", nonce) is None
                or type(certificate_pem) is not bytes):
            raise ValueError(_ERROR)
        self._factory, self._owner, self._serial = owner_factory, owner_name, serial
        self._certificate, self._nonce, self._clock = certificate_pem, nonce, clock
        self._name = expected_remote_import_name(nonce)
        self._artifact = self._material()
        self.parameters_digest = digest({"contract": CONTRACT, "scope": "vdom", "nonce": nonce,
            "serial": serial, "owner_digest": hashlib.sha256(owner_name.encode()).hexdigest(),
            "certificate": self._artifact.sha256, "name": self._name})
        self._baseline: RemoteCertificateBaseline | None = None
        self._created: dict[str, Any] | None = None
        self._created_certificate: dict[str, Any] | None = None
        self._ack_digest: str | None = None
        self._qtype: int | None = None
        self._attempted = {"import": False, "recover": False}

    def _material(self) -> RemoteCertificateIdentity:
        artifact = RemoteCertificateIdentity.from_public_pem(self._name, self._certificate)
        cert = x509.load_pem_x509_certificate(self._certificate)
        public_key = cert.public_key()
        if (not artifact.valid_from <= self._clock() < artifact.valid_to - 300
                or artifact.valid_to - artifact.valid_from > 86400
                or cert.subject != cert.issuer
                or cert.subject != x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mcp-remote-" + self._nonce)])
                or not isinstance(public_key, ec.EllipticCurvePublicKey)
                or public_key.key_size < 256):
            raise ValueError(_ERROR)
        cert.verify_directly_issued_by(cert)
        if {type(ext.value) for ext in cert.extensions} != {x509.BasicConstraints, x509.KeyUsage}:
            raise ValueError(_ERROR)
        basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        if basic.ca or basic.path_length is not None or not usage.digital_signature or usage.key_cert_sign or usage.crl_sign:
            raise ValueError(_ERROR)
        if hasattr(self, "_artifact") and artifact != self._artifact:
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
        usage = "/api/v2/monitor/system/object/usage?" + urlencode({"mkey": str(owned),
            "qtypes": json.dumps([self._qtype], separators=(",", ":"))})
        if method == "GET":
            if path not in allowed_gets and not (owned and (self._qtype is not None and path == usage)):
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

    def _json(self, client: Any, path: str, *, monitor: bool = False) -> dict[str, Any]:
        raw = self._request(client, "GET", path)
        try:
            return _frame(raw, self._serial, method="GET",
                path="system" if monitor else "vpn.certificate",
                name="available-certificates" if monitor else "remote")
        finally:
            raw[:] = bytes(len(raw))

    def _observe(self, client: Any) -> tuple[RemoteCertificateBaseline, list[dict[str, Any]], list[dict[str, Any]]]:
        schema = self._json(client, COLLECTION + "?action=schema&with_meta=true")["results"]["children"]
        if ({key: value["type"] for key, value in schema.items()} != _TYPES
                or schema["name"].get("required") is not True or schema["name"].get("size") != 35):
            raise ValueError(_ERROR)
        defaults = self._json(client, COLLECTION + "?action=default&with_meta=true")["results"]
        if defaults != {"name": "", "remote": "", "range": "vdom", "source": "user"}:
            raise ValueError(_ERROR)
        frame = self._json(client, COLLECTION + "?with_meta=true")
        rows = frame["results"]
        if (type(rows) is not list or len(rows) > 33 or frame.get("limit_reached", False) is not False
                or frame.get("matched_count", len(rows)) != len(rows)):
            raise ValueError(_ERROR)
        rows = sorted((configured_row(row) for row in rows), key=lambda row: row["name"])
        if len({row["name"] for row in rows}) != len(rows):
            raise ValueError(_ERROR)
        entries = self._json(client, SELECTOR, monitor=True)["results"]
        if (type(entries) is not list or len(entries) > 200
                or len({row["name"] for row in entries}) != len(entries)):
            raise ValueError(_ERROR)
        entries = certificate_projection(entries)
        if sorted(row["name"] for row in entries if row["type"] == "remote-cer") != [row["name"] for row in rows]:
            raise ValueError(_ERROR)
        for row in entries:
            if row["name"] != self._name and row["type"] not in {"crl", "local-csr"}:
                if _fingerprint(row.get("fingerprint")) == self._artifact.sha256 or self._nonce in json.dumps(row):
                    raise ValueError(_ERROR)
        original_rows = [row for row in rows if row["name"] != self._name]
        original_certs = [row for row in entries if row["name"] != self._name]
        if len(original_rows) > 32 or len(original_certs) >= 200:
            raise ValueError(_ERROR)
        current = digest({"contract": CONTRACT, "serial": self._serial, "schema": digest(schema),
            "defaults": defaults, "rows": original_rows, "certificates": original_certs})
        baseline = RemoteCertificateBaseline(digest(schema), defaults, original_rows, original_certs, current)
        return baseline, [row for row in rows if row["name"] == self._name], [row for row in entries if row["name"] == self._name]

    def inspect(self, phase: str) -> tuple[str, str]:
        self._material()
        with self._session() as client:
            observed, rows, certs = self._observe(client)
            if self._baseline is None:
                if phase != "import" or rows or certs:
                    raise ValueError(_ERROR)
                self._baseline = observed
            if observed != self._baseline:
                raise ValueError(_ERROR)
            expected = digest({"original": observed.current_digest, "artifact": self.parameters_digest,
                               "one_native_remote_certificate_verified": True})
            if phase == "import":
                if rows or certs or self._created is not None or self._attempted[phase]:
                    raise ValueError(_ERROR)
                return observed.current_digest, expected
            if phase != "recover" or self._created is None or self._ack_digest is None or self._attempted[phase]:
                raise ValueError(_ERROR)
            self._verify_created(rows, certs)
            self._zero_references(client)
            return expected, observed.current_digest

    def _verify_created(self, rows: list[dict[str, Any]], certs: list[dict[str, Any]], *, first: bool = False) -> None:
        if len(rows) != 1 or len(certs) != 1 or self._baseline is None:
            raise ValueError(_ERROR)
        row, cert = rows[0], certs[0]
        # Build29 native scope=vdom import persists range=global, while the
        # CMDB row remains non-global-entry. Bind both observed fields exactly.
        if (row["name"] != self._name or row["global_entry"] is not False
                or row["range"] != "global" or row["source"] != "user"
                or not remote_certificate_identity_matches(cert, self._artifact)):
            raise ValueError(_ERROR)
        if not first and (row != self._created or cert != self._created_certificate):
            raise ValueError(_ERROR)
        if first:
            self._created, self._created_certificate = row, cert

    def _zero_references(self, client: Any) -> None:
        if self._created is None:
            raise ValueError
        raw = self._request(client, "GET", "/api/v2/monitor/web-ui/object-urls")
        try:
            frame = _frame(raw, self._serial, method="GET", path="web-ui", name="object-urls")
            types = frame["results"]["by_type"]
            matches = []
            for key, value in types.items():
                if value.get("path") == "vpn.certificate.remote":
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
                or plan.action_id != "remote-certificate-native-" + phase or plan.adapter_ref != CONTRACT
                or plan.parameters_digest != self.parameters_digest or plan.expected_current_digest != current_digest):
            raise ValueError(_ERROR)
        _require_m4_dispatch_ownership(plan, authorization, store)
        if self.inspect(phase)[0] != current_digest:
            raise ValueError(_ERROR)
        def final_guard() -> None:
            guard()
            _require_m4_dispatch_ownership(plan, authorization, store)
        with self._session() as client:
            observed, rows, certs = self._observe(client)
            if observed != self._baseline:
                raise ValueError(_ERROR)
            if phase == "import":
                if rows or certs:
                    raise ValueError(_ERROR)
                self._material()
                body = json.dumps({"scope": "vdom", "certname": self._nonce, "file_content": base64.b64encode(self._certificate).decode("ascii")},
                    separators=(",", ":")).encode()
                path, method = IMPORT, "POST"
            else:
                self._verify_created(rows, certs)
                self._zero_references(client)
                body = None
                path, method = COLLECTION + "/" + quote(self._created["name"], safe=""), "DELETE"  # type: ignore[index]
            final_guard()
            self._attempted[phase] = True
            raw = self._request(client, method, path, body=body, guard=final_guard)
            try:
                ack = _frame(raw, self._serial, method=method,
                    path="vpn-certificate" if phase == "import" else "vpn.certificate", name="remote")
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
            observed, rows, certs = self._observe(client)
            if observed != self._baseline:
                raise ValueError(_ERROR)
            if phase == "import":
                if self._ack_digest is None:
                    raise ValueError(_ERROR)
                self._verify_created(rows, certs, first=True)
                self._zero_references(client)
                return digest({"original": observed.current_digest, "artifact": self.parameters_digest,
                               "one_native_remote_certificate_verified": True})
            if rows or certs:
                raise ValueError(_ERROR)
            return observed.current_digest
