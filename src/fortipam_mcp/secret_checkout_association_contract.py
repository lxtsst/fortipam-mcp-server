"""Private build-29 fixed harmless Script association and inverse compiler.

No network or authorization occurs here. Credential fields are never accepted
by this projection or emitted by this compiler; the trusted final dispatch
must retain them separately using the established Unix-field provider.
"""

from collections.abc import Mapping
import re

from .checkout_script_contract import fixed_checkout_script_readback

CONTROLS = frozenset({"checkout", "checkout-script", "checkin-script", "checkout-duration",
                      "checkout-duration-renew", "checkout-renew-times", "checkin-pwd-change"})
_IDENTITY = frozenset({"id", "name", "folder", "template"})
IDLE_FIELD = "force-checkout-idle-time"
PREREQUISITES = frozenset({"proxy", "recording"})
EXECUTION_ACCOUNT_FIELDS = frozenset({"target-privilege-account", "associated-secret", "target-info"})
_UNAVAILABLE = "The fixed Secret checkout association is unavailable."


class SecretCheckoutAssociationContractError(ValueError):
    """Never expose private selectors, contents or upstream errors."""


def project_secret_checkout_metadata(payload: object) -> dict[str, object]:
    try:
        if not isinstance(payload, Mapping):
            raise ValueError
        row = payload.get("results")
        if isinstance(row, list) and len(row) == 1:
            row = row[0]
        if not isinstance(row, Mapping):
            raise ValueError
        projected = {key: row[key] for key in _IDENTITY | CONTROLS | PREREQUISITES
                     | {IDLE_FIELD} | EXECUTION_ACCOUNT_FIELDS if key in row}
        target_info = projected.get("target-info")
        if isinstance(target_info, Mapping):
            projected["target-info"] = {"priv_acct": target_info.get("priv_acct")}
        return {**{key: payload.get(key) for key in (
            "version", "build", "status", "http_method", "http_status", "path", "name",
        )}, "results": projected}
    except Exception:
        raise SecretCheckoutAssociationContractError(_UNAVAILABLE) from None


def compile_fixed_secret_checkout_body(
    before: object, scripts: object, *, identity: Mapping[str, object],
    checkout_script: str, checkin_script: str, baseline_controls: Mapping[str, object],
    force_idle_time: int,
    execution_secret_id: int,
    restore: bool = False,
) -> dict[str, object]:
    """Attach only the fixed pair for five minutes, or restore its exact baseline."""
    try:
        if (type(restore) is not bool or type(force_idle_time) is not int or not 0 <= force_idle_time <= 30
                or type(execution_secret_id) is not int or not 0 < execution_secret_id <= 2_147_483_647
                or set(identity) != _IDENTITY
                or type(identity["id"]) is not int or not 0 < identity["id"] <= 2_147_483_647
                or type(identity["folder"]) is not int or not 0 < identity["folder"] <= 2_147_483_647
                or identity["template"] != "Unix Account (SSH Password)"
                or type(identity["name"]) is not str
                or re.fullmatch(r"mcp-v4-bp008-(?:denial|checkout)-[0-9]{8}-r[1-9][0-9]*", identity["name"]) is None):
            raise ValueError
        if type(checkout_script) is not str or type(checkin_script) is not str:
            raise ValueError
        script_free = checkout_script == checkin_script == ""
        if script_free:
            # Native basic checkout is independent of optional hook execution.
            if scripts is not None:
                raise ValueError
        else:
            matched = re.fullmatch(r"MCPV4Checkout([0-9]{8}R[1-9][0-9]{0,2})", checkout_script)
            if (matched is None or checkin_script != "MCPV4Checkin" + matched.group(1)
                    or not fixed_checkout_script_readback(scripts, hook="checkout", target_name=checkout_script)
                    or not fixed_checkout_script_readback(scripts, hook="checkin", target_name=checkin_script)):
                raise ValueError
        if (set(baseline_controls) != CONTROLS or any(
            type(baseline_controls.get(key)) is not str or baseline_controls[key] != value
            for key, value in {"checkout": "disable", "checkout-script": "", "checkin-script": "",
                               "checkout-duration-renew": "disable", "checkin-pwd-change": "disable"}.items()
        ) or type(baseline_controls["checkout-duration"]) is not int
                or not 3 <= baseline_controls["checkout-duration"] <= 1440
                or type(baseline_controls["checkout-renew-times"]) is not int
                or not 1 <= baseline_controls["checkout-renew-times"] <= 5):
            raise ValueError
        if not isinstance(before, Mapping) or any(
            type(before.get(key)) is not type(value) or before.get(key) != value
            for key, value in {"version": "v7.0.0", "build": 29, "http_status": 200,
                               "http_method": "GET", "status": "OK", "path": "secret", "name": "database"}.items()
        ):
            raise ValueError
        row = before.get("results")
        if (not isinstance(row, Mapping) or set(row) != _IDENTITY | CONTROLS | PREREQUISITES
                | {IDLE_FIELD} | EXECUTION_ACCOUNT_FIELDS
                or any(type(row.get(key)) is not str or row[key] != "enable" for key in PREREQUISITES)
                or type(row.get(IDLE_FIELD)) is not int or row[IDLE_FIELD] != force_idle_time
                or any(type(row.get(key)) is not type(value) or row[key] != value for key, value in identity.items())):
            raise ValueError
        # This profile uses one pre-existing associated SSH execution Secret only.
        # It cannot assign a target-wide privilege role or change that association.
        info = row["target-info"]
        if (row["target-privilege-account"] != "disable"
                or type(row["associated-secret"]) is not int
                or row["associated-secret"] != execution_secret_id
                or execution_secret_id == identity["id"]
                or not isinstance(info, Mapping) or set(info) != {"priv_acct"}
                or type(info["priv_acct"]) is not int or info["priv_acct"] != 0):
            raise ValueError
        associated = {**baseline_controls, "checkout": "enable", "checkout-duration": 5,
                      "checkout-script": checkout_script, "checkin-script": checkin_script}
        current, proposed = (associated, baseline_controls) if restore else (baseline_controls, associated)
        if any(type(row.get(key)) is not type(value) or row[key] != value for key, value in current.items()):
            raise ValueError
        # Preserve explicit renewal/password-change controls; never include fields or target here.
        return {**identity, "proxy": "enable", "recording": "enable",
                "associated-secret": execution_secret_id, "target-privilege-account": "disable",
                **proposed, IDLE_FIELD: force_idle_time}
    except Exception:
        raise SecretCheckoutAssociationContractError(_UNAVAILABLE) from None
