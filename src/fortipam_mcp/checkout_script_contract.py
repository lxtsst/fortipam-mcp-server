"""Private build-29 fixed checkout/check-in and Windows probe Script contracts.

This compiler has no network or caller-defined script capability. Its private
body must remain inside a claimed transport. Creating an unattached Script
does not configure checkout or prove its execution or JIT effects.
"""

from collections.abc import Mapping
import re

_FIELDS = ("name", "type", "comments", "script", "expect-type", "expect-string", "log-trigger")
_UNAVAILABLE = "The fixed checkout Script contract is unavailable."


class CheckoutScriptContractError(ValueError):
    """Return no private source, selector, content or upstream error."""


def _envelope(payload: object, *, method: str, status: str) -> Mapping[str, object]:
    if not isinstance(payload, Mapping) or any(
        type(payload.get(key)) is not type(value) or payload.get(key) != value
        for key, value in {
            "version": "v7.0.0", "build": 29, "http_status": 200,
            "http_method": method, "status": status, "path": "secret", "name": "script",
        }.items()
    ):
        raise ValueError
    return payload


def _fixed_body(*, hook: str, target_name: str) -> dict[str, str]:
    if hook not in {"checkout", "checkin"} or type(target_name) is not str:
        raise ValueError
    label = "Checkout" if hook == "checkout" else "Checkin"
    if len(target_name) > 35 or re.fullmatch(r"MCPV4" + label + r"[0-9]{8}R[1-9][0-9]{0,2}", target_name) is None:
        raise ValueError
    marker = "BP008_CHECKOUT_OK" if hook == "checkout" else "BP008_CHECKIN_OK"
    return {
        "name": target_name, "type": "ssh-script",
        "comments": "BP008 fixed harmless checkout/check-in acceptance",
        "script": "echo " + marker, "expect-type": "success",
        "expect-string": marker, "log-trigger": "any",
    }


def compile_fixed_checkout_script_body(
    default: object, *, hook: str, target_name: str,
) -> dict[str, str]:
    """Require the observed blank PowerShell default; emit only seven fields."""
    try:
        _require_blank_default(default)
        return _fixed_body(hook=hook, target_name=target_name)
    except Exception:
        raise CheckoutScriptContractError(_UNAVAILABLE) from None


def fixed_checkout_script_readback(
    payload: object, *, hook: str, target_name: str, detail: bool = False,
) -> bool:
    """Verify exact protected Script content, without returning it or its name."""
    try:
        expected = _fixed_body(hook=hook, target_name=target_name)
        return _definition_matches(payload, expected, detail=detail)
    except Exception:
        return False


def _require_blank_default(default: object) -> None:
    row = _envelope(default, method="GET", status="success")["results"]
    if not isinstance(row, Mapping) or set(row) != set(_FIELDS) or any(
        type(row.get(key)) is not str or row.get(key) != value
        for key, value in {
            "name": "", "type": "powershell", "comments": "", "script": "",
            "expect-type": "success", "expect-string": "", "log-trigger": "failure",
        }.items()
    ):
        raise ValueError


def _windows_probe_body(target_name: str) -> dict[str, str]:
    if (type(target_name) is not str or len(target_name) > 35
            or re.fullmatch(r"MCPV4WinrmProbe[0-9]{8}R[1-9][0-9]{0,2}", target_name) is None):
        raise ValueError
    marker = "BP019_WINRM_PROBE_OK"
    return {"name": target_name, "type": "powershell",
        "comments": "BP019 fixed harmless Windows execution probe",
        "script": "Write-Output '" + marker + "'", "expect-type": "success",
        "expect-string": marker, "log-trigger": "any"}


def compile_fixed_windows_probe_script_body(default: object, *, target_name: str) -> dict[str, str]:
    """Compile only one constant marker; no target, credential or privilege action.

    The private producer still needs original M4/ACK custody, exact absence,
    readback and recovery. This compiler neither creates nor executes a Script.
    """
    try:
        _require_blank_default(default)
        return _windows_probe_body(target_name)
    except Exception:
        raise CheckoutScriptContractError(_UNAVAILABLE) from None


def fixed_windows_probe_script_readback(payload: object, *, target_name: str, detail: bool = False) -> bool:
    """Check all seven fields; this does not establish ownership or execution."""
    try:
        return _definition_matches(payload, _windows_probe_body(target_name), detail=detail)
    except Exception:
        return False


def _definition_matches(payload: object, expected: Mapping[str, str], *, detail: bool) -> bool:
    try:
        result = _envelope(payload, method="GET" if detail else "POST",
                           status="success")["results"]
        rows: object
        if detail:
            rows = result if isinstance(result, list) else [result]
        else:
            rows = result
        if not isinstance(rows, list) or not all(isinstance(row, Mapping) for row in rows):
            return False
        if detail and len(rows) != 1:
            return False
        matches = [row for row in rows if row.get("name") == expected["name"]]
        return len(matches) == 1 and "comment" not in matches[0] and all(
            type(matches[0].get(key)) is str and matches[0].get(key) == expected[key]
            for key in _FIELDS
        )
    except Exception:
        return False
