"""Private public-certificate identity checks for build29 monitor readback.

The CMDB ``remote`` slot can be empty despite a configured certificate. Identity
comes from the version-pinned monitor selector, not that slot. These functions
grant neither import/deletion authority nor creation ownership.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import hmac
import re

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,34}\Z")
_TOKEN = re.compile(r"[a-f0-9]{16}\Z")
_FINGERPRINT = re.compile(r"(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{2}(?::[a-fA-F0-9]{2}){31})\Z")
_UNAVAILABLE = "The remote certificate identity is unavailable."


def expected_remote_import_name(token: str) -> str:
    """Match the native caller's one-certificate naming expectation.

    This is a source-derived expectation; it does not prove backend import or
    supply ownership of a preexisting matching name.
    """
    if type(token) is not str or _TOKEN.fullmatch(token) is None:
        raise ValueError(_UNAVAILABLE)
    return "REMOTE_Cert_" + token + "_1"


@dataclass(frozen=True, slots=True, repr=False)
class RemoteCertificateIdentity:
    """Non-exporting expected identity from one public PEM certificate."""

    name: str
    sha256: str
    valid_from: int
    valid_to: int

    def __post_init__(self) -> None:
        if (type(self.name) is not str or _NAME.fullmatch(self.name) is None
                or type(self.sha256) is not str
                or re.fullmatch(r"[a-f0-9]{64}", self.sha256) is None
                or type(self.valid_from) is not int or type(self.valid_to) is not int
                or not 0 < self.valid_from < self.valid_to):
            raise ValueError(_UNAVAILABLE)

    @classmethod
    def from_public_pem(cls, name: str, data: bytes | bytearray) -> RemoteCertificateIdentity:
        try:
            if (type(data) not in {bytes, bytearray} or not 0 < len(data) <= 16384
                    or data.count(b"-----BEGIN CERTIFICATE-----") != 1
                    or data.count(b"-----END CERTIFICATE-----") != 1
                    or b"PRIVATE KEY" in data):
                raise ValueError
            certificate = x509.load_pem_x509_certificate(bytes(data))
            if certificate.public_bytes(Encoding.PEM).strip() != data.strip():
                raise ValueError
            return cls(name, hashlib.sha256(certificate.public_bytes(Encoding.DER)).hexdigest(),
                       int(certificate.not_valid_before_utc.timestamp()),
                       int(certificate.not_valid_after_utc.timestamp()))
        except Exception:
            raise ValueError(_UNAVAILABLE) from None


def remote_certificate_identity_matches(
    record: object, expected: RemoteCertificateIdentity,
) -> bool:
    """Check the monitor's exact name/type/SHA256/validity without material output.

    Complete collection, device/actor, references and other-field preservation
    remain the transport's responsibility. Extra monitor metadata is not ignored
    by a transport merely because this identity predicate succeeds.
    """
    try:
        if (type(expected) is not RemoteCertificateIdentity or not isinstance(record, Mapping)
                or record.get("name") != expected.name or record.get("type") != "remote-cer"
                or type(record.get("valid_from")) is not int
                or type(record.get("valid_to")) is not int
                or record["valid_from"] != expected.valid_from
                or record["valid_to"] != expected.valid_to):
            return False
        fingerprint = record.get("fingerprint")
        return (type(fingerprint) is str and _FINGERPRINT.fullmatch(fingerprint) is not None
                and hmac.compare_digest(fingerprint.replace(":", "").lower(), expected.sha256))
    except Exception:
        return False
