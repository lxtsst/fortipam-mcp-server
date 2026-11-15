"""Private fixed build-29 LDAPS create intent; no update or public selector API."""
from __future__ import annotations

from enum import StrEnum
import hashlib
import json
import re

from v4_planning.material_provider import C3MaterialBinding

ACTION_ID = "ldap-server-create"
ACTION_VERSION = "1.0.0"
CONTRACT = "fortipam-700-build29-ldap-create-private-v1"
_UNAVAILABLE = "The private LDAP server candidate is unavailable."
_NAME = re.compile(r"mcp-v4-ldap-[a-z0-9][a-z0-9-]{0,22}\Z")
_FQDN = re.compile(r"(?=.{1,63}\Z)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\Z")
_DN = re.compile(r"(?:OU=[A-Za-z0-9 _-]{1,64},)+(?:DC=[A-Za-z0-9-]{1,63},)*DC=[A-Za-z0-9-]{1,63}\Z", re.I)


class LdapServerCandidateError(RuntimeError):
    """Value-free refusal shared by the private action components."""


class LdapServerCreateOutcome(StrEnum):
    VERIFIED_CREATED = "verified_created"
    RECONCILIATION_REQUIRED = "reconciliation_required"


class LdapServerCreateBinding(C3MaterialBinding):
    """Trusted owner-side selectors; none may enter planning or MCP values."""

    name: str
    server: str
    dn: str
    ca_name: str
    username: str
    private_nonce: str
    ca_certificate_sha256: str

    def __init__(self, name: str, server: str, dn: str, ca_name: str, username: str,
                 private_nonce: str, ca_certificate_sha256: str) -> None:
        for key, value in (("name", name), ("server", server), ("dn", dn), ("ca_name", ca_name),
                           ("username", username), ("private_nonce", private_nonce),
                           ("ca_certificate_sha256", ca_certificate_sha256)):
            object.__setattr__(self, key, value)
        self.__post_init__()

    def __setattr__(self, name: str, value: object) -> None:
        raise LdapServerCandidateError(_UNAVAILABLE)

    def __delattr__(self, name: str) -> None:
        raise LdapServerCandidateError(_UNAVAILABLE)

    def __post_init__(self) -> None:
        try:
            if (any(type(value) is not str for value in (
                    self.name, self.server, self.dn, self.ca_name, self.username, self.private_nonce,
                    self.ca_certificate_sha256))
                or _NAME.fullmatch(self.name) is None or _FQDN.fullmatch(self.server) is None
                or len(self.dn) > 511 or _DN.fullmatch(self.dn) is None
                or not 1 <= len(self.ca_name) <= 79
                or re.search(r"[\x00-\x1f\x7f]", self.ca_name)
                or any(re.fullmatch(r"[0-9a-f]{64}", item) is None
                       for item in (self.private_nonce, self.ca_certificate_sha256))):
                raise ValueError
            domain = ".".join(re.findall(r"(?:^|,)DC=([^,]+)", self.dn, re.I))
            if (not self.server.casefold().endswith("." + domain.casefold())
                or not 1 <= len(self.username) <= 511
                or re.fullmatch(r"[A-Za-z0-9_.-]+@" + re.escape(domain), self.username, re.I) is None):
                raise ValueError
        except Exception:
            raise LdapServerCandidateError(_UNAVAILABLE) from None

    def desired_nonmaterial(self) -> dict[str, str | int]:
        self.__post_init__()
        return {"name": self.name, "server": self.server, "port": 636,
                "cnid": "sAMAccountName", "dn": self.dn, "type": "regular",
                "username": self.username, "ca-cert": self.ca_name, "secure": "ldaps",
                "server-identity-check": "enable", "group-member-check": "user-attr",
                "group-filter": "", "group-search-base": self.dn, "group-object-filter": "",
                "password-renewal": "disable", "member-attr": "memberOf", "gateway": ""}

    @property
    def parameters_digest(self) -> str:
        encoded = json.dumps({"contract": CONTRACT, "intent": self.desired_nonmaterial(),
            "private_nonce": self.private_nonce, "ca_certificate_sha256": self.ca_certificate_sha256},
            sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()

    def __repr__(self) -> str:
        return "<LdapServerCreateBinding protected>"

    __str__ = __repr__
    __slots__ = ("name", "server", "dn", "ca_name", "username", "private_nonce", "ca_certificate_sha256")
