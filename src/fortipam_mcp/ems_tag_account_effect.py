"""Complete original Account delta under the fixed native local-user profile."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

from v4_planning.material_provider import _OpaqueC3Object

from .ems_tag_admin_contract import ProspectiveEmsTagManagerAccount
from .ems_tag_identity_contract import EmsTagIdentityScope, _admin_id

_ERROR = "The private original EMS account effect is unavailable."


@dataclass(frozen=True, slots=True, repr=False)
class EmsAccountCreatedDetail(_OpaqueC3Object):
    _raw: bytes

    @property
    def numeric_id(self) -> int:
        return _admin_id(json.loads(self._raw)["id"])

    @property
    def digest(self) -> str:
        return hashlib.sha256(self._raw).hexdigest()


def verify_account_created(before: EmsTagIdentityScope, after: EmsTagIdentityScope,
                           draft: ProspectiveEmsTagManagerAccount) -> EmsAccountCreatedDetail:
    """A complete delta is necessary; original active-M4 ACK/custody is separate."""
    try:
        if (type(before) is not EmsTagIdentityScope or type(after) is not EmsTagIdentityScope
                or type(draft) is not ProspectiveEmsTagManagerAccount):raise ValueError
        before.__post_init__();after.__post_init__();draft.__post_init__()
        if (before.schema.digest != after.schema.digest or before._role_rows != after._role_rows
                or tuple(d.digest for d in before._role_details) != tuple(d.digest for d in after._role_details)):
            raise ValueError
        def identity(raw: bytes) -> tuple[int, str | None]:
            value = json.loads(raw)
            return _admin_id(value["id"]), value["vdom"]
        prior = {identity(raw): (raw, detail) for raw, detail in zip(before._admin_rows, before._admin_details)}
        current = {identity(raw): (raw, detail) for raw, detail in zip(after._admin_rows, after._admin_details)}
        added = set(current) - set(prior)
        expected = draft._metadata_body
        if (len(added) != 1 or len(current) != len(prior) + 1
                or any(current.get(key) != value for key, value in prior.items())
                or any(json.loads(raw)["name"].casefold() == expected["name"].casefold() for raw in before._admin_rows)
                or before.role_is_referenced(draft.role_uid)):
            raise ValueError
        key = next(iter(added));row, raw = current[key];value = json.loads(raw)
        if (key[1] is not None or key[0] in {k[0] for k in prior}
                or not any(detail._uid == draft.role_uid and not json.loads(detail._raw)["is_super"]
                           and not json.loads(detail._raw)["is_built_in"] for detail in before._role_details)):
            raise ValueError
        fixed = dict(name=expected["name"], role_uid=draft.role_uid, user_type="EMS", vdom=None,
            comments=expected["comments"], trusted_hosts_enabled=True, trusted_hosts=draft.trusted_host,
            allow_all_domains=False, is_global=False, default_site_role_uid=None, inactive=False)
        if any(key not in value or type(value[key]) is not type(item) or value[key] != item for key, item in fixed.items()):
            raise ValueError
        # Native parsing treats absent sites/google-domain arrays as empty.
        if any(key in value and (type(value[key]) is not list or value[key]) for key in ("idps", "sites", "google_domains")):
            raise ValueError
        result = EmsAccountCreatedDetail(raw)
        if result.numeric_id != json.loads(row)["id"]:raise ValueError
        return result
    except (ValueError, TypeError, KeyError, StopIteration):raise ValueError(_ERROR) from None
