"""Shared bounded contract types for FortiPAM Target API actions."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
from urllib.parse import urlsplit


DEFAULT_TEMPLATE = "Unix Account (SSH Password)"
TARGET_CLASS = "Other"
WEB_PROXY_STATUS = "disable"
DOMAIN_TEMPLATE = "Windows Domain Account"
DOMAIN_TEMPLATE_FIELD_TYPES = (
    ("Domain-Controller", "target-address"),
    ("Domain", "domain"),
    ("Username", "username"),
    ("Password", "password"),
)

WEB_TEMPLATE = "Web Account"
WEB_TEMPLATE_FIELD_TYPES = (("URL", "url"), ("Username", "username"), ("Password", "password"))


def validate_domain_target_classification_tag(value: str) -> None:
    """Validate the private build-29 class reference, not a Target type enum."""
    if (not isinstance(value, str)
            or re.fullmatch(r"[^\x00-\x1f\x7f]{1,79}", value) is None):
        raise ValueError("The private domain Target classification binding is unavailable.")


def validate_domain_target_reference(target_name: str, address: str, domain: str) -> None:
    """Validate private Domain selectors; existence and Owner need live readback."""
    try:
        if (not isinstance(target_name, str)
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", target_name) is None
                or not isinstance(address, str)
                or str(ipaddress.IPv4Address(address)) != address
                or not isinstance(domain, str)
                or len(domain) > 253
                or domain != domain.lower()
                or len(domain.split(".")) < 2
                or any(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) is None
                       for label in domain.split("."))):
            raise ValueError
    except (ValueError, TypeError):
        raise ValueError("The private domain Target binding is unavailable.") from None


@dataclass(frozen=True, slots=True, repr=False)
class WebTargetCreateInput:
    """Protected build-29 Web Target selectors; proxy enablement is separate."""

    target_name: str
    web_url: str

    def __post_init__(self) -> None:
        try:
            if (not isinstance(self.target_name, str)
                    or re.fullmatch(r"mcp-v4-target-web-[0-9]{8}-r[0-9]+", self.target_name) is None
                    or len(self.target_name) > 64
                    or not isinstance(self.web_url, str)
                    or not 1 <= len(self.web_url.encode("utf-8")) <= 255
                    or any(character.isspace() or ord(character) < 32 or ord(character) == 127
                           for character in self.web_url)):
                raise ValueError
            parsed = urlsplit(self.web_url)
            if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                    or parsed.username is not None or parsed.password is not None
                    or parsed.fragment or "#" in self.web_url or "\\" in self.web_url
                    or parsed.port == 0):
                raise ValueError
        except (ValueError, TypeError, UnicodeError):
            raise ValueError("The private Web Target binding is unavailable.") from None

    def __repr__(self) -> str:
        return "<WebTargetCreateInput protected>"


@dataclass(frozen=True, slots=True)
class WebTargetReadback:
    """Metadata-only evidence for the fixed proxy-disabled Web Target."""

    target_verified: bool
    url_matches: bool
    settings_match: bool
    permissions_match: bool

    @property
    def verified(self) -> bool:
        return all((self.target_verified, self.url_matches, self.settings_match, self.permissions_match))


@dataclass(frozen=True, slots=True, repr=False)
class DomainTargetCreateInput:
    """Private build-29 domain-controller binding; never an MCP selector."""

    target_name: str
    dc_ipv4_address: str
    domain_dns_root: str

    def __post_init__(self) -> None:
        try:
            if (not isinstance(self.target_name, str)
                    or re.fullmatch(r"mcp-v4-target-domain-[0-9]{8}-r[0-9]+", self.target_name) is None
                    or len(self.target_name) > 64):
                raise ValueError
            validate_domain_target_reference(self.target_name, self.dc_ipv4_address, self.domain_dns_root)
        except (ValueError, TypeError):
            raise ValueError("The private domain Target binding is unavailable.") from None

    def __repr__(self) -> str:
        return "<DomainTargetCreateInput protected>"


@dataclass(frozen=True, slots=True)
class DomainTargetReadback:
    """Categorical native domain Target identity and permission evidence."""

    target_verified: bool
    domain_matches: bool
    ldaps_configuration_matches: bool
    owner_relation_matches: bool
    create_secret_group_relation_matches: bool

    @property
    def verified(self) -> bool:
        return all((self.target_verified, self.domain_matches,
                    self.ldaps_configuration_matches, self.owner_relation_matches,
                    self.create_secret_group_relation_matches))


@dataclass(frozen=True, slots=True)
class TargetInspection:
    """Value-minimized Target preflight evidence."""

    exists: bool
    product_version: str | None = None
    product_build: int | None = None


@dataclass(frozen=True, slots=True)
class TargetReadback:
    """Value-minimized Target create/readback evidence."""

    target_exists: bool
    class_matches: bool
    template_matches: bool
    address_matches: bool
    web_proxy_disabled: bool
    owner_relation_matches: bool
    create_secret_group_relation_matches: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.target_exists,
                self.class_matches,
                self.template_matches,
                self.address_matches,
                self.web_proxy_disabled,
                self.owner_relation_matches,
                self.create_secret_group_relation_matches,
            )
        )


@dataclass(frozen=True, slots=True)
class TargetUpdateInspection:
    """Value-minimized Target description-update preflight evidence."""

    exists: bool
    description_matches: bool
    state_digest: str


@dataclass(frozen=True, slots=True)
class TargetUpdateReadback:
    """Value-minimized Target description-update readback evidence."""

    target_exists: bool
    description_matches: bool

    @property
    def verified(self) -> bool:
        return self.target_exists and self.description_matches


@dataclass(frozen=True, slots=True)
class TargetWebProxyEnableInspection:
    """Value-minimized Target Web Proxy enable preflight evidence."""

    exists: bool
    web_proxy_disabled: bool
    state_digest: str


@dataclass(frozen=True, slots=True)
class TargetWebProxyEnableReadback:
    """Categorical Target Web Proxy enable API readback evidence."""

    target_exists: bool
    web_proxy_enabled: bool

    @property
    def verified(self) -> bool:
        return self.target_exists and self.web_proxy_enabled


__all__ = [
    "DEFAULT_TEMPLATE",
    "TARGET_CLASS",
    "WEB_PROXY_STATUS",
    "TargetInspection",
    "TargetReadback",
    "TargetUpdateInspection",
    "TargetUpdateReadback",
    "TargetWebProxyEnableInspection",
    "TargetWebProxyEnableReadback",
]
