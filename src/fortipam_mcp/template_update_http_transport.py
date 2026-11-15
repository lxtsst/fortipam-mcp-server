"""Fixed build-29 native REST port update for one private disposable Template."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Protocol
from urllib.parse import quote

from .template_reconciliation_http_transport import (
    COLLECTION_PATH, MAX_RESPONSE_BYTES, TemplateReconciliationHttpTransportConfig,
    _ssl_context,
)
from .template_ssh_transport import (
    TemplateArchivePreflightReadback, TemplateUpdateBaselineReadback, TemplateUpdateReadback,
)


_UNAVAILABLE = "FortiPAM V4 Template update REST transport is unavailable."
_NAME = re.compile(r"mcp-v4-template-update-[A-Za-z0-9][A-Za-z0-9._-]{0,38}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class TemplateUpdateHttpTransportError(RuntimeError):
    """Non-disclosing failure; consumed transport claims must never be replayed."""


class TemplateUpdateInspectionTransport(Protocol):
    def update_baseline_readback(self, template_name: str) -> TemplateUpdateBaselineReadback: ...
    def updated_web_vnc_readback(self, template_name: str) -> TemplateUpdateReadback: ...
    def archive_preflight_readback(self, template_name: str) -> TemplateArchivePreflightReadback: ...


@dataclass(frozen=True, slots=True, repr=False)
class TemplateUpdateHttpBinding:
    """Owner-bound exact native API and full CLI baseline; no caller selector."""

    template_name: str
    api_configuration_digest: str
    cli_configuration_digest: str

    def __post_init__(self) -> None:
        if (not isinstance(self.template_name, str) or _NAME.fullmatch(self.template_name) is None
                or not all(isinstance(value, str) and _DIGEST.fullmatch(value) is not None
                           for value in (self.api_configuration_digest, self.cli_configuration_digest))):
            raise TemplateUpdateHttpTransportError(_UNAVAILABLE)


def load_template_update_http_binding(path: Path) -> TemplateUpdateHttpBinding:
    """Read one bounded owner-only binding without following a final symlink."""

    try:
        if not path.is_absolute():
            raise ValueError
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 4096):
                raise ValueError
            data = json.loads(stream.read(4097))
        if not isinstance(data, dict) or set(data) != {
            "contract", "template_name", "api_configuration_digest", "cli_configuration_digest",
        } or data["contract"] != "fortipam_v4_template_update_rest_binding_v1":
            raise ValueError
        return TemplateUpdateHttpBinding(
            data["template_name"], data["api_configuration_digest"], data["cli_configuration_digest"],
        )
    except Exception:
        raise TemplateUpdateHttpTransportError(_UNAVAILABLE) from None


class FortiPamTemplateUpdateHttpTransport:
    """Use native serialized metadata; change only Launcher 1's port once."""

    def __init__(
        self,
        config: TemplateReconciliationHttpTransportConfig,
        binding: TemplateUpdateHttpBinding,
        inspection: TemplateUpdateInspectionTransport,
        claim_path: Path,
        *,
        client_factory: Callable[..., Any] | None = None,
        restore_default_port: bool = False,
    ) -> None:
        if not isinstance(binding, TemplateUpdateHttpBinding) or type(restore_default_port) is not bool:
            raise TemplateUpdateHttpTransportError(_UNAVAILABLE)
        self._config = config
        self._binding = binding
        self._inspection = inspection
        self._claim_path = claim_path
        self._client_factory = client_factory
        self._restore_default_port = restore_default_port
        self._check_claim_parent()

    def update_baseline_readback(self, template_name: str) -> TemplateUpdateBaselineReadback | TemplateUpdateReadback:
        try:
            self._require_name(template_name)
            self._require_unconsumed()
            self._read_detail(port=5901 if self._restore_default_port else 5900)
            baseline = (self._inspection.updated_web_vnc_readback(template_name) if self._restore_default_port
                        else self._inspection.update_baseline_readback(template_name))
            expected_type = TemplateUpdateReadback if self._restore_default_port else TemplateUpdateBaselineReadback
            if (not isinstance(baseline, expected_type) or not baseline.verified
                    or not hmac.compare_digest(baseline.configuration_digest, self._binding.cli_configuration_digest)):
                raise ValueError
            self._require_references_absent(template_name)
            return baseline
        except Exception:
            raise TemplateUpdateHttpTransportError(_UNAVAILABLE) from None

    def update_web_vnc_port_and_readback(self, template_name: str) -> TemplateUpdateReadback | TemplateUpdateBaselineReadback:
        try:
            self.update_baseline_readback(template_name)
            self._reserve_claim()
            port = 5900 if self._restore_default_port else 5901
            status, payload = self._request("PUT", _native_body(template_name, port))
            _require_envelope(status, payload, "PUT")
            self._read_detail(port=port)
            result = (self._inspection.update_baseline_readback(template_name) if self._restore_default_port
                      else self._inspection.updated_web_vnc_readback(template_name))
            expected_type = TemplateUpdateBaselineReadback if self._restore_default_port else TemplateUpdateReadback
            if (not isinstance(result, expected_type) or not result.verified
                    or not hmac.compare_digest(result.configuration_digest, self._binding.cli_configuration_digest)):
                raise ValueError
            self._require_references_absent(template_name)
            return result
        except Exception:
            raise TemplateUpdateHttpTransportError(_UNAVAILABLE) from None

    def _require_name(self, name: str) -> None:
        if name != self._binding.template_name:
            raise TemplateUpdateHttpTransportError(_UNAVAILABLE)

    def _require_references_absent(self, name: str) -> None:
        references = self._inspection.archive_preflight_readback(name)
        if (not isinstance(references, TemplateArchivePreflightReadback)
                or references.secret_references_absent is not True
                or references.target_references_absent is not True):
            raise TemplateUpdateHttpTransportError(_UNAVAILABLE)

    def _read_detail(self, *, port: int) -> None:
        status, payload = self._request("GET", None)
        _require_envelope(status, payload, "GET")
        assert isinstance(payload, Mapping)
        row = payload.get("results")
        if isinstance(row, list) and len(row) == 1:
            row = row[0]
        if (not isinstance(row, Mapping)
                or json.dumps(row, sort_keys=True) != json.dumps(_native_baseline(self._binding.template_name, port), sort_keys=True)
                or not hmac.compare_digest(
                    template_update_api_configuration_digest(row), self._binding.api_configuration_digest,
                )):
            raise TemplateUpdateHttpTransportError(_UNAVAILABLE)

    def _request(self, method: str, body: Mapping[str, object] | None) -> tuple[int, object]:
        import httpx

        raw = bytearray()
        try:
            factory = self._client_factory or httpx.Client
            with factory(
                verify=_ssl_context(self._config), timeout=self._config.timeout_seconds,
                follow_redirects=False, trust_env=False,
            ) as client:
                with client.stream(
                    method, f"{self._config.base_url}{COLLECTION_PATH}/{quote(self._binding.template_name, safe='')}?vdom=root",
                    headers={"Accept": "application/json", "Authorization": f"Bearer {self._config.bearer_token}",
                             "Accept-Encoding": "identity", "Cache-Control": "no-cache, no-store"},
                    json=body,
                ) as response:
                    status = response.status_code
                    if "json" not in response.headers.get("content-type", "").lower():
                        raise ValueError
                    for chunk in response.iter_bytes():
                        if len(raw) + len(chunk) > MAX_RESPONSE_BYTES:
                            raise ValueError
                        raw.extend(chunk)
                return status, json.loads(raw)
        except Exception:
            raise TemplateUpdateHttpTransportError(_UNAVAILABLE) from None
        finally:
            for index in range(len(raw)):
                raw[index] = 0
            raw.clear()

    def _check_claim_parent(self) -> None:
        try:
            path = self._claim_path
            if not isinstance(path, Path) or not path.is_absolute():
                raise ValueError
            info = path.parent.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o700):
                raise ValueError
        except Exception:
            raise TemplateUpdateHttpTransportError(_UNAVAILABLE) from None

    def _require_unconsumed(self) -> None:
        self._check_claim_parent()
        if os.path.lexists(self._claim_path):
            raise TemplateUpdateHttpTransportError(_UNAVAILABLE)

    def _reserve_claim(self) -> None:
        self._require_unconsumed()
        parent = os.open(self._claim_path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(parent)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError
            descriptor = os.open(
                self._claim_path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600, dir_fd=parent,
            )
            with os.fdopen(descriptor, "w") as stream:
                json.dump({
                    "contract": "fortipam_v4_template_update_rest_claim_v1", "state": "execution_reserved",
                    "resource_binding_digest": hashlib.sha256(self._binding.template_name.encode()).hexdigest(),
                    "api_configuration_digest": self._binding.api_configuration_digest,
                    "cli_configuration_digest": self._binding.cli_configuration_digest,
                    "direction": "restore_default_port" if self._restore_default_port else "update_port",
                }, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(parent)
        finally:
            os.close(parent)


def template_update_api_configuration_digest(row: Mapping[str, Any]) -> str:
    """Seal every native API field except the sole expected port delta."""

    try:
        canonical = json.loads(json.dumps(row))
        launcher = canonical["launcher"]
        if (not isinstance(launcher, list) or len(launcher) != 1
                or launcher[0]["id"] != 1 or launcher[0]["launcher-name"] != "Web VNC"
                or type(launcher[0]["port"]) is not int or launcher[0]["port"] not in (5900, 5901)):
            raise ValueError
        launcher[0]["port"] = 5900
        return hashlib.sha256(json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    except Exception:
        raise TemplateUpdateHttpTransportError(_UNAVAILABLE) from None


def _require_envelope(status: int, payload: object, method: str) -> None:
    if (status != 200 or not isinstance(payload, Mapping)
            or payload.get("http_status") != 200 or payload.get("status") != "success"
            or payload.get("http_method") != method or payload.get("version") != "v7.0.0"
            or payload.get("build") != 29 or payload.get("path") != "secret" or payload.get("name") != "template"):
        raise TemplateUpdateHttpTransportError(_UNAVAILABLE)


def _native_body(name: str, port: int) -> dict[str, object]:
    return {
        "name": name, "$originalName": name, "access": "everyone", "user-permission": [], "group-permission": [],
        "field": [{"name": "Username", "type": "username", "mandatory": "enable"},
                  {"name": "Password", "type": "password", "mandatory": "enable"}],
        "launcher": [{"id": 1, "launcher-name": "Web VNC", "port": port}],
        "password-changer": {"password-changer-name": None, "port": 0, "password-policy": None,
                             "max-retry": 10, "max-history": 5, "verify-after-change": "enable", "type": ""},
        "totp-setting": {"totp-length": 6, "totp-duration": 30, "hash-type": "hmac-sha1"},
        "description": "", "server-info": "Unix-like", "web-filler": {"auth-path": "", "attribute": []},
        "enforce-sso-launch": "disable",
    }


def _native_baseline(name: str, port: int) -> dict[str, Any]:
    """The exact qualified native expansion of the fixed metadata-only body."""

    row: dict[str, Any] = _native_body(name, port)
    del row["$originalName"]
    row["q_origin_key"] = name
    row["ssh-term"] = "vanilla"
    for entry in row["field"]:
        entry["q_origin_key"] = entry["name"]
        entry["need-edit"] = "disable"
    row["launcher"][0]["q_origin_key"] = 1
    row["password-changer"]["password-changer-name"] = ""
    row["password-changer"]["password-policy"] = "default"
    row["password-changer"]["port"] = 22
    del row["password-changer"]["type"]
    return row
