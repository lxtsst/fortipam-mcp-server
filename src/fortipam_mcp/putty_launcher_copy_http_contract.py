"""Non-dispatchable complete-form copy of one fixed native PuTTY profile.

The native bodyless clone does not preserve this source's OS-app subtable.
This compiler models the native append serializer, not rename or association.
Ownership, destination absence, device identity and execution require a separate
private adapter. Bodies and complete configurations must remain private.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from .client_integrity_association_contract import _body, _digest, _require_digest, _row

CONTRACT = "fortipam_v4_putty_launcher_copy_form_700_v1"
_UNAVAILABLE = "The fixed native PuTTY Launcher copy contract is unavailable."


class PuttyLauncherCopyContractError(ValueError):
    """Stable error without names, configuration or protected values."""


def compile_native_putty_copy_body(
    payload: object, *, launcher_name: str, expected_source_configuration_digest: str,
) -> dict[str, object]:
    """Compile all native fields from the unchanged, privately sealed source."""
    try:
        if not isinstance(payload, Mapping):
            raise ValueError
        source = payload.get("results")
        if type(source) is list and len(source) == 1:
            source = source[0]
        if (not isinstance(source, Mapping) or source.get("name") != "PuTTY"
                or source.get("q_origin_key") != "PuTTY"
                or type(source.get("q_ref")) is not int or source["q_ref"] < 0):
            raise ValueError
        _require_digest(_digest(dict(source)), expected_source_configuration_digest)
        proposed: dict[str, Any] = deepcopy(dict(source))
        proposed.update(name=launcher_name, q_origin_key=launcher_name, q_ref=0)
        row = _row({**payload, "results": proposed}, launcher_name=launcher_name, software_name="")
        body = _body(row, "")
        # A fresh append has no original-key override; never rename the source.
        del body["$originalName"]
        return body
    except Exception:
        raise PuttyLauncherCopyContractError(_UNAVAILABLE) from None


def validate_native_putty_copy_detail(
    payload: object, *, launcher_name: str, expected_configuration_digest: str,
) -> None:
    """Require the complete copied configuration, including the Windows child."""
    try:
        row = _row(payload, launcher_name=launcher_name, software_name="")
        _require_digest(_digest(row), expected_configuration_digest)
    except Exception:
        raise PuttyLauncherCopyContractError(_UNAVAILABLE) from None
