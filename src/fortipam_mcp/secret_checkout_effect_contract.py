"""Private build-29 script-free checkout/check-in prerequisite contract.

This module cannot authenticate, dispatch, load material, or register a Tool.
Private identifiers remain inside a fixed transport binding.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

from .secret_metadata_http_transport import _record

Operation = Literal["checkout", "checkin"]
CHECKOUT_PATH = "/api/v2/internal/secret-checkout"
CHECKIN_PATH = "/api/v2/internal/secret-checkin"
_UNAVAILABLE = "The fixed Secret checkout effect is unavailable."


class SecretCheckoutEffectContractError(ValueError):
    """Return no identifiers, material, or upstream response text."""


@dataclass(frozen=True, slots=True, repr=False)
class SecretCheckoutEffectBinding:
    secret_id: int
    folder_id: int
    secret_name: str
    target_name: str
    execution_secret_id: int
    owner_name: str


def compile_fixed_checkout_effect(
    payload: object, binding: SecretCheckoutEffectBinding, *, operation: Operation,
) -> tuple[str, dict[str, int]]:
    """Compile one native request only from the fixed eligible current state."""
    try:
        if not isinstance(binding, SecretCheckoutEffectBinding) or operation not in {"checkout", "checkin"}:
            raise ValueError
        for value in (binding.secret_id, binding.folder_id, binding.execution_secret_id):
            if type(value) is not int or not 0 < value <= 2_147_483_647:
                raise ValueError
        if (binding.secret_id == binding.execution_secret_id
                or type(binding.secret_name) is not str or not binding.secret_name
                or type(binding.target_name) is not str or not binding.target_name
                or type(binding.owner_name) is not str or not binding.owner_name
                or len(binding.owner_name.encode()) > 255
                or any(ord(c) < 32 or ord(c) == 127 for c in binding.owner_name)):
            raise ValueError
        if not isinstance(payload, Mapping) or any(
            type(payload.get(key)) is not type(value) or payload.get(key) != value
            for key, value in {"version": "v7.0.0", "build": 29, "http_status": 200,
                               "http_method": "GET", "status": "OK",
                               "path": "secret", "name": "database"}.items()
        ):
            raise ValueError
        row = _record(payload)
        if not isinstance(row, Mapping) or any(
            type(row.get(key)) is not type(value) or row.get(key) != value
            for key, value in {"id": binding.secret_id, "folder": binding.folder_id,
                               "name": binding.secret_name, "target": binding.target_name,
                               "template": "Unix Account (SSH Password)",
                               "associated-secret": binding.execution_secret_id,
                               "target-privilege-account": "disable",
                               "checkout": "enable", "checkout-duration": 5,
                               "checkout-script": "", "checkin-script": "",
                               "checkout-duration-renew": "disable",
                               "checkin-pwd-change": "disable",
                               "proxy": "enable", "recording": "enable"}.items()
        ):
            raise ValueError
        target_info = row.get("target-info")
        if (not isinstance(target_info, Mapping) or type(target_info.get("priv_acct")) is not int
                or target_info["priv_acct"] != 0):
            raise ValueError
        permissions = row.get("permissions")
        if not isinstance(permissions, Mapping):
            raise ValueError
        status, password_change = permissions.get("checkout_status"), permissions.get("passwd_change")
        if operation == "checkout":
            if status != "required" or password_change != "forbidden":
                raise ValueError
        elif status not in {"checked", "not-renewable"} or password_change != "allowed":
            raise ValueError
        if not fixed_checkout_lease_state(row, binding, held=operation == "checkin"):
            raise ValueError
        return (CHECKOUT_PATH if operation == "checkout" else CHECKIN_PATH,
                {"secret-id": binding.secret_id})
    except Exception:
        raise SecretCheckoutEffectContractError(_UNAVAILABLE) from None


def fixed_checkout_effect_state(payload: object, binding: SecretCheckoutEffectBinding, *,
                                checked_out: bool) -> bool:
    """Qualify only same-owner metadata state, not exclusivity or session effects."""
    if type(checked_out) is not bool:
        return False
    try:
        compile_fixed_checkout_effect(payload, binding,
                                     operation="checkin" if checked_out else "checkout")
        return True
    except SecretCheckoutEffectContractError:
        return False


def fixed_checkout_lease_state(row: object, binding: SecretCheckoutEffectBinding, *, held: bool) -> bool:
    """Qualify the observed build-29 same-Owner lease tuple, never expiry."""
    if (not isinstance(row, Mapping) or not isinstance(binding, SecretCheckoutEffectBinding)
            or type(held) is not bool or type(binding.owner_name) is not str or not binding.owner_name):
        return False
    expected = binding.owner_name if held else ""
    if (type(expected) is not str or held and not expected
            or any(type(row.get(key)) is not str or row.get(key) != expected
                   for key in ("checkout-user", "checkout-admin"))):
        return False
    value = row.get("checkout-time")
    return type(value) is int and (0 < value <= 2_147_483_647 if held else value == 0)
