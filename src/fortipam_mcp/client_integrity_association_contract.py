"""Non-dispatchable, single-field association for a privately owned SSH fixture.

The native build-29 form places this reference in the Windows OS-app row.
This module grants no ownership, reference eligibility, write or launch authority.
All names and complete configurations must remain inside the private adapter.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import hmac
import json
import re
from typing import Any

from .client_integrity_http_contract import _hash_name

CONTRACT = "fortipam_v4_client_integrity_putty_association_form_700_v1"
_NAME = re.compile(r"mcp-v4-putty-clone-[0-9]{8}-r[1-9][0-9]{0,3}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_UNAVAILABLE = "The fixed native Client Integrity association contract is unavailable."
_TOP = frozenset({"name", "type", "is-file-launcher", "elevation", "session-close-log",
                  "launch-timeout", "os_app"})
_APP_STRINGS = frozenset({"name", "os_type", "ua_pattern", "exe", "parameter", "client-software",
                          "multiprocess", "fullscreen-record", "proc-matcher-type",
                          "proc-matcher-pattern", "allow-global-match"})
_COMMANDS = frozenset({"init-commands", "clean-commands", "fct-script"})


class ClientIntegrityAssociationContractError(ValueError):
    """Stable error that never exposes a binding, configuration or parameter."""


@dataclass(frozen=True, slots=True, repr=False)
class ClientIntegrityAssociationReadback:
    configuration_digest: str


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _require_digest(actual: str, expected: str) -> None:
    if type(expected) is not str or _DIGEST.fullmatch(expected) is None or not hmac.compare_digest(actual, expected):
        raise ValueError


def _row(payload: object, *, launcher_name: str, software_name: str) -> dict[str, Any]:
    if type(launcher_name) is not str or _NAME.fullmatch(launcher_name) is None:
        raise ValueError
    if software_name:
        _hash_name(software_name)
    if not isinstance(payload, Mapping):
        raise ValueError
    fixed: dict[str, object] = {
        "version": "v7.0.0", "build": 29, "http_method": "GET", "http_status": 200,
        "path": "secret", "name": "launcher", "vdom": "root",
    }
    if (any(type(payload.get(k)) is not type(v) or payload[k] != v for k, v in fixed.items())
            or payload.get("status") not in {"success", "OK"}):
        raise ValueError
    row = payload.get("results")
    if type(row) is list and len(row) == 1:
        row = row[0]
    metadata: dict[str, object] = {
        "q_path": "secret", "q_name": "launcher", "q_global_entry": False,
        "q_mkey_type": "string", "q_no_edit": False, "q_no_rename": False,
        "q_origin_key": launcher_name, "q_static": False, "q_ref": 0,
    }
    if (not isinstance(row, Mapping) or set(row) != {*_TOP, *metadata, "q_type"}
            or row["name"] != launcher_name or row["type"] != "ssh"
            or any(type(row[k]) is not type(v) or row[k] != v for k, v in metadata.items())
            or type(row["q_type"]) is not int or not 0 <= row["q_type"] <= 999_999_999
            or type(row["launch-timeout"]) is not int or not 0 <= row["launch-timeout"] <= 3600
            or row["is-file-launcher"] != "false"):
        raise ValueError
    for key in ("is-file-launcher", "elevation", "session-close-log"):
        if type(row[key]) is not str or not 0 < len(row[key]) <= 64:
            raise ValueError
    apps = row["os_app"]
    if type(apps) is not list or len(apps) != 1 or not isinstance(apps[0], Mapping):
        raise ValueError
    app = apps[0]
    if (set(app) != {*_APP_STRINGS, *_COMMANDS, "id", "q_origin_key"}
            or type(app["id"]) is not int or not 1 <= app["id"] <= 999_999_999
            or type(app["q_origin_key"]) is not int or app["q_origin_key"] != app["id"]
            or app["os_type"] != "windows" or app["client-software"] != software_name):
        raise ValueError
    if any(type(app[key]) is not str or len(app[key]) > 4096 for key in _APP_STRINGS):
        raise ValueError
    # Only the qualified commandless built-in PuTTY shape is eligible.
    # It does not authorize a custom executable, command or Credential parameter.
    if (app["exe"] != "" or app["parameter"] != ""
            or any(type(app[key]) is not list or app[key] for key in _COMMANDS)):
        raise ValueError
    return deepcopy(dict(row))


def _body(row: dict[str, Any], software_name: str) -> dict[str, object]:
    app = row["os_app"][0]
    return {**{k: deepcopy(row[k]) for k in _TOP if k != "os_app"},
            "os_app": [{**{k: deepcopy(app[k]) for k in (*_APP_STRINGS, *_COMMANDS, "id")},
                        "client-software": software_name}], "$originalName": row["name"]}


def compile_native_putty_association_body(
    payload: object, *, launcher_name: str, software_name: str, expected_configuration_digest: str,
) -> dict[str, object]:
    """Change one reference in a sealed complete baseline; never authorize PUT.

    The eventual private transport must independently prove verified-owned clone
    eligibility, software presence/ownership, fresh references and device identity.
    The public built-in Launcher and old RDP clone namespace are refused.
    """
    try:
        _hash_name(software_name)
        row = _row(payload, launcher_name=launcher_name, software_name="")
        _require_digest(_digest(row), expected_configuration_digest)
        return _body(row, software_name)
    except Exception:
        raise ClientIntegrityAssociationContractError(_UNAVAILABLE) from None


def project_native_putty_association_detail(
    payload: object, *, launcher_name: str, software_name: str, baseline_configuration_digest: str,
) -> ClientIntegrityAssociationReadback:
    """Require complete baseline equality after reversing only the new reference."""
    try:
        _hash_name(software_name)
        row = _row(payload, launcher_name=launcher_name, software_name=software_name)
        digest = _digest(row)
        row["os_app"][0]["client-software"] = ""
        _require_digest(_digest(row), baseline_configuration_digest)
        return ClientIntegrityAssociationReadback(digest)
    except Exception:
        raise ClientIntegrityAssociationContractError(_UNAVAILABLE) from None


def compile_native_putty_association_restore_body(
    payload: object, *, launcher_name: str, software_name: str,
    baseline_configuration_digest: str, expected_associated_configuration_digest: str,
) -> dict[str, object]:
    """Prepare only the empty-reference baseline; no ownership or restore grant."""
    try:
        verified = project_native_putty_association_detail(
            payload, launcher_name=launcher_name, software_name=software_name,
            baseline_configuration_digest=baseline_configuration_digest,
        )
        _require_digest(verified.configuration_digest, expected_associated_configuration_digest)
        row = _row(payload, launcher_name=launcher_name, software_name=software_name)
        return _body(row, "")
    except Exception:
        raise ClientIntegrityAssociationContractError(_UNAVAILABLE) from None
