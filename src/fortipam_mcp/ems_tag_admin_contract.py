"""Prospective EMS local test-account metadata; no material or write authority.

The fixed profile is 7.4.8.2245, sites disabled, global/site views enabled and
Chrome disabled. A protected writer must separately bind material, current
state, original role ownership and dispatch authority before adding a password.
"""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
from typing import Any

from v4_planning.material_provider import _OpaqueC3Object

from fortipam_mcp.ems_tag_role_contract import _digest

CONTRACT = "ems-7.4.8.2245-prospective-local-tag-account-v1"
ACCOUNT_CREATE_PATH = "/api/v1/admins/create"
ACCOUNT_TABLE_PATH = "/api/v1/admins/refresh"
_ERROR = "The prospective EMS tag-manager account is unavailable."


@dataclass(frozen=True, slots=True, repr=False)
class ProspectiveEmsTagManagerAccount(_OpaqueC3Object):
    role_uid: str
    nonce: str
    trusted_host: str

    def __post_init__(self) -> None:
        try:
            if (type(self.role_uid) is not str or re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", self.role_uid) is None
                    or type(self.nonce) is not str or re.fullmatch(r"[a-f0-9]{32}", self.nonce) is None
                    or type(self.trusted_host) is not str):
                raise ValueError
            host = ipaddress.IPv4Network(self.trusted_host, strict=True)
            if (host.prefixlen != 32 or str(host) != self.trusted_host
                    or host.network_address.is_unspecified or host.network_address.is_multicast
                    or host.network_address.is_loopback or host.network_address.is_link_local):
                raise ValueError
        except (ValueError, TypeError):
            raise ValueError(_ERROR) from None

    @property
    def _metadata_body(self) -> dict[str, Any]:
        self.__post_init__()
        return {"role_uid": self.role_uid, "vdom": None,
                "comments": "Disposable tag-manager lab account; fixed host and no domains.",
                "trusted_hosts_enabled": True, "trusted_hosts": [self.trusted_host],
                "name": "mcpv4u_" + self.nonce[:24], "allow_all_domains": False,
                "idp_guids": [], "is_global": False}

    @property
    def parameters_digest(self) -> str:
        self.__post_init__()
        return _digest({"contract": CONTRACT, "method": "POST", "path": ACCOUNT_CREATE_PATH,
                        "profile": {"sites_enabled": False, "show_global": True,
                                    "show_vdom": True, "chrome_enabled": False, "user_type": "EMS"},
                        "metadata_body": self._metadata_body})
