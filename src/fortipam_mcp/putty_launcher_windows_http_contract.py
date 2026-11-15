"""Private build-29 Windows PuTTY definition; no dispatch or launch authority.

The executable is an independently qualified, owned laboratory artifact. Its
path and hash never enter MCP inputs/results. The fixed variable-only argument
template is source-backed; this compiler never resolves credentials.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
import re
from typing import Any

from .client_integrity_association_contract import (
    ClientIntegrityAssociationReadback, _body, _digest, _require_digest, _row,
)
from .client_integrity_http_contract import _hash_name
from .putty_launcher_copy_http_contract import compile_native_putty_copy_body

CONTRACT = "fortipam_v4_putty_launcher_windows_form_700_v1"
ASSOCIATION_CONTRACT = "fortipam_v4_putty_launcher_windows_hash_association_form_700_v1"
PARAMETERS = "-l $USER -pw $PASSWORD $HOST"
_ARTIFACT = re.compile(r"C:\\Windows\\Temp\\fpam-bp009-putty-candidate-[0-9]{8}-r[1-9][0-9]{0,3}\.exe\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_UNAVAILABLE = "The fixed native Windows PuTTY Launcher contract is unavailable."


class WindowsPuttyLauncherContractError(ValueError):
    """Stable failure without paths, values or configuration."""


@dataclass(frozen=True, slots=True, repr=False)
class WindowsPuttyApplication:
    executable_path: str
    executable_sha256: str

    def __post_init__(self) -> None:
        if (type(self.executable_path) is not str or _ARTIFACT.fullmatch(self.executable_path) is None
                or type(self.executable_sha256) is not str or _HASH.fullmatch(self.executable_sha256) is None):
            raise WindowsPuttyLauncherContractError(_UNAVAILABLE)


def _application(value: object) -> WindowsPuttyApplication:
    if type(value) is not WindowsPuttyApplication:
        raise ValueError
    return value


def _native_form_fields(row: Mapping[str, Any]) -> None:
    app = row["os_app"][0]
    if (type(row["launch-timeout"]) is not int or not 15 <= row["launch-timeout"] <= 90
            or row["elevation"] != "none" or row["session-close-log"] not in {"single", "multiple"}
            or app["proc-matcher-type"] != "default" or app["proc-matcher-pattern"] != ""
            or any(app[key] != "disable" for key in ("multiprocess", "fullscreen-record", "allow-global-match"))):
        raise ValueError


def compile_native_windows_putty_body(
    payload: object, *, launcher_name: str, application: WindowsPuttyApplication,
    expected_source_configuration_digest: str,
) -> dict[str, object]:
    """Prepare one full custom definition from a sealed implicit built-in.

    Hash/signature/path qualification and destination absence are separate
    adapter prerequisites. Only the fixed executable/parameter delta is added;
    source fields, command arrays and software references remain protected.
    """
    try:
        app = _application(application)
        body = compile_native_putty_copy_body(payload, launcher_name=launcher_name,
            expected_source_configuration_digest=expected_source_configuration_digest)
        apps = body["os_app"]
        if type(apps) is not list or len(apps) != 1 or not isinstance(apps[0], dict) or apps[0]["id"] != 1:
            raise ValueError
        apps[0].update(exe=app.executable_path, parameter=PARAMETERS)
        _native_form_fields(body)
        return body
    except Exception:
        raise WindowsPuttyLauncherContractError(_UNAVAILABLE) from None


def project_native_windows_putty_row(
    payload: object, *, launcher_name: str, application: WindowsPuttyApplication,
    expected_configuration_digest: str,
) -> dict[str, Any]:
    """Require the complete fresh custom object, including exact private path."""
    try:
        app = _application(application)
        if not isinstance(payload, Mapping):
            raise ValueError
        row = payload.get("results")
        if type(row) is list and len(row) == 1:
            row = row[0]
        if not isinstance(row, Mapping):
            raise ValueError
        actual = deepcopy(dict(row))
        _native_form_fields(actual)
        apps = actual.get("os_app")
        if (type(apps) is not list or len(apps) != 1 or not isinstance(apps[0], dict)
                or apps[0].get("exe") != app.executable_path or apps[0].get("parameter") != PARAMETERS
                or type(apps[0].get("id")) is not int or apps[0]["id"] != 1):
            raise ValueError
        normalized = deepcopy(actual)
        normalized["os_app"][0].update(exe="", parameter="")
        _row({**payload, "results": normalized}, launcher_name=launcher_name, software_name="")
        _require_digest(_digest(actual), expected_configuration_digest)
        return actual
    except Exception:
        raise WindowsPuttyLauncherContractError(_UNAVAILABLE) from None


def compile_native_windows_putty_association_body(
    payload: object, *, launcher_name: str, software_name: str,
    application: WindowsPuttyApplication, baseline_configuration_digest: str,
) -> dict[str, object]:
    """Change only the software reference of the sealed fixed Windows profile.

    This pure compiler cannot prove either object's creation ownership, software
    hash equality, usage eligibility or dispatch authority. The eventual adapter
    must independently establish those prerequisites before a once-only PUT.
    """
    try:
        _hash_name(software_name)
        row = project_native_windows_putty_row(payload, launcher_name=launcher_name,
            application=application, expected_configuration_digest=baseline_configuration_digest)
        return _body(row, software_name)
    except Exception:
        raise WindowsPuttyLauncherContractError(_UNAVAILABLE) from None


def project_native_windows_putty_association_detail(
    payload: object, *, launcher_name: str, software_name: str,
    application: WindowsPuttyApplication, baseline_configuration_digest: str,
) -> ClientIntegrityAssociationReadback:
    """Verify complete equality after reversing only the fixed association."""
    try:
        _hash_name(software_name)
        if not isinstance(payload, Mapping):
            raise ValueError
        row = payload.get("results")
        if type(row) is list and len(row) == 1:
            row = row[0]
        if not isinstance(row, Mapping):
            raise ValueError
        normalized = deepcopy(dict(row))
        apps = normalized.get("os_app")
        if (type(apps) is not list or len(apps) != 1 or not isinstance(apps[0], dict)
                or apps[0].get("client-software") != software_name):
            raise ValueError
        apps[0]["client-software"] = ""
        project_native_windows_putty_row({**payload, "results": normalized},
            launcher_name=launcher_name, application=application,
            expected_configuration_digest=baseline_configuration_digest)
        return ClientIntegrityAssociationReadback(_digest(row))
    except Exception:
        raise WindowsPuttyLauncherContractError(_UNAVAILABLE) from None


def compile_native_windows_putty_association_restore_body(
    payload: object, *, launcher_name: str, software_name: str,
    application: WindowsPuttyApplication, baseline_configuration_digest: str,
    expected_associated_configuration_digest: str,
) -> dict[str, object]:
    """Prepare the original empty reference, refusing any associated-state drift."""
    try:
        evidence = project_native_windows_putty_association_detail(payload,
            launcher_name=launcher_name, software_name=software_name, application=application,
            baseline_configuration_digest=baseline_configuration_digest)
        _require_digest(evidence.configuration_digest, expected_associated_configuration_digest)
        # The projector has already validated the complete product/metadata shape.
        assert isinstance(payload, Mapping)
        row = payload["results"]
        if type(row) is list:
            row = row[0]
        return _body(deepcopy(dict(row)), "")
    except Exception:
        raise WindowsPuttyLauncherContractError(_UNAVAILABLE) from None
