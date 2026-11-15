"""Fixed initial Account metadata/material relation; no execution authority."""
from __future__ import annotations

import secrets

from v4_planning import canonical_digest
from v4_planning.models import require_digest, require_ref

from .ems_tag_admin_contract import ProspectiveEmsTagManagerAccount
from .ems_tag_contract import _canonical
from .secret_metadata_http_transport import _zeroize_mutable

CONTRACT = "ems-7.4.8.2245-original-local-tag-account-v1"
ACTION_ID = "ems-tag-account-create"
ACTION_VERSION = "1.0.0"
ADAPTER_REF = CONTRACT + "-m4"
TARGET_REF = "bound-new-local-ems-tag-account"
_ERROR = "The private initial EMS account material is unavailable."
_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def variables(draft: ProspectiveEmsTagManagerAccount) -> tuple[str, str]:
    draft.__post_init__()
    prefix = "EMS_HOME_LAB_TAG_ACCOUNT_" + draft.nonce[:24].upper() + "_"
    return prefix + "USERNAME", prefix + "PASSWORD"


def parameters_digest(draft: ProspectiveEmsTagManagerAccount, reference: str, parent_digest: str) -> str:
    draft.__post_init__();require_ref(reference, "ems_account_material");require_digest(parent_digest, "ems_account_parent")
    return canonical_digest(dict(contract=CONTRACT, metadata=draft.parameters_digest, material_reference=reference, parent=parent_digest))


def current_digest(draft: ProspectiveEmsTagManagerAccount, reference: str, parent_digest: str,
                   scope_digest: str, source_digest: str) -> str:
    for value in (scope_digest, source_digest):require_digest(value, "ems_account_source")
    return canonical_digest(dict(contract=CONTRACT, parameters=parameters_digest(draft, reference, parent_digest),
        scope=scope_digest, source=source_digest))


def expected_digest(draft: ProspectiveEmsTagManagerAccount, reference: str, parent_digest: str,
                    scope_digest: str, source_digest: str) -> str:
    return canonical_digest(dict(contract=CONTRACT, relation="one-exact-original-account-with-complete-preservation",
        current=current_digest(draft, reference, parent_digest, scope_digest, source_digest)))


def _password_valid(raw: memoryview) -> bool:
    """Approved generated ASCII subset of native 8..70 / three-of-four rules."""
    if not 8 <= len(raw) <= 70 or any(byte not in _ALPHABET for byte in raw):return False
    groups = (any(65 <= byte <= 90 for byte in raw), any(97 <= byte <= 122 for byte in raw),
              any(48 <= byte <= 57 for byte in raw), any(byte in (45, 95) for byte in raw))
    return sum(groups) >= 3


def _generate_password() -> bytearray:
    raw = bytearray(b"Aa0_")
    try:
        raw.extend(_ALPHABET[secrets.randbelow(len(_ALPHABET))] for _ in range(40))
        for index in range(len(raw) - 1, 0, -1):
            other = secrets.randbelow(index + 1);raw[index], raw[other] = raw[other], raw[index]
        return raw
    except BaseException:_zeroize_mutable(raw);raise


def _encode_create(draft: ProspectiveEmsTagManagerAccount, username: memoryview, password: memoryview) -> bytearray:
    """Private lease consumer only; never decode material to an immutable str."""
    raw = bytearray()
    try:
        draft.__post_init__()
        if username != draft._metadata_body["name"].encode("ascii") or not _password_valid(password):raise ValueError
        raw.extend(_canonical(draft._metadata_body)[:-1]);raw.extend(b',"password":"')
        raw.extend(password);raw.extend(b'"}')
        return raw
    except Exception:_zeroize_mutable(raw);raise ValueError(_ERROR) from None
