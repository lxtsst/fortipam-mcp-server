"""Private CRL validation and the source-pinned build29 user-field format.

This is not a transport, issuer-trust decision, replacement authorization, or
anti-replay store. Public issuer and CRL bytes stay inside the private adapter;
no registered MCP surface accepts or returns either artifact.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

_UNAVAILABLE = "The CRL import artifact is unavailable."
_MAX_BYTES = 262144


@dataclass(frozen=True, slots=True, repr=False)
class CrlImportArtifact:
    """Validated identity and private wire value, without dispatch authority."""

    sha256: str
    issuer_sha256: str
    this_update: int
    next_update: int
    sequence: int
    revoked_count: int
    _user_field: str


def _single_pem(data: bytes | bytearray, label: bytes, limit: int) -> bytes:
    if type(data) not in {bytes, bytearray} or not 0 < len(data) <= limit:
        raise ValueError
    raw = bytes(data)
    begin, end = b"-----BEGIN " + label + b"-----", b"-----END " + label + b"-----"
    if (raw.count(begin) != 1 or raw.count(end) != 1 or b"PRIVATE KEY" in raw
            or not raw.startswith(begin + b"\n") or not raw.endswith(end + b"\n")):
        raise ValueError
    return raw


def prepare_build29_crl_artifact(
    crl_pem: bytes | bytearray,
    issuer_pem: bytes | bytearray,
    *,
    now: int,
    minimum_sequence: int,
) -> CrlImportArtifact:
    """Validate one complete signed CRL and quote its canonical public PEM.

    The caller must obtain the sequence floor from its original bound baseline.
    A successful check does not prove that this issuer is trusted by a device or
    authorize import, deletion, replacement, retrieval, or automatic refresh.
    """
    try:
        if (type(now) is not int or now <= 0 or type(minimum_sequence) is not int
                or minimum_sequence < 0):
            raise ValueError
        raw = _single_pem(crl_pem, b"X509 CRL", _MAX_BYTES)
        issuer_raw = _single_pem(issuer_pem, b"CERTIFICATE", 16384)
        crl = x509.load_pem_x509_crl(raw)
        issuer = x509.load_pem_x509_certificate(issuer_raw)
        if (crl.public_bytes(serialization.Encoding.PEM) != raw
                or issuer.public_bytes(serialization.Encoding.PEM) != issuer_raw
                or crl.issuer != issuer.subject or crl.next_update_utc is None
                or len(crl) > 1024):
            raise ValueError
        constraints = issuer.extensions.get_extension_for_class(x509.BasicConstraints).value
        usage = issuer.extensions.get_extension_for_class(x509.KeyUsage).value
        key = issuer.public_key()
        if (not constraints.ca or not usage.crl_sign
                or not isinstance(key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey))
                or isinstance(key, rsa.RSAPublicKey) and key.key_size < 2048
                or isinstance(key, ec.EllipticCurvePublicKey) and key.key_size < 256
                or not isinstance(crl.signature_hash_algorithm, (hashes.SHA256, hashes.SHA384, hashes.SHA512))
                or not crl.is_signature_valid(key)):
            raise ValueError
        this_update = int(crl.last_update_utc.timestamp())
        next_update = int(crl.next_update_utc.timestamp())
        if not (int(issuer.not_valid_before_utc.timestamp()) <= this_update <= now
                < next_update <= int(issuer.not_valid_after_utc.timestamp())):
            raise ValueError
        number = crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
        if number < minimum_sequence:
            raise ValueError
        for extension in crl.extensions:
            if isinstance(extension.value, x509.DeltaCRLIndicator):
                raise ValueError
            if isinstance(extension.value, x509.IssuingDistributionPoint):
                raise ValueError
            if extension.critical and not isinstance(extension.value, (
                x509.CRLNumber, x509.AuthorityKeyIdentifier,
            )):
                raise ValueError
        serials: set[int] = set()
        for revoked in crl:
            if (revoked.serial_number in serials or revoked.serial_number <= 0
                    or int(revoked.revocation_date_utc.timestamp()) > this_update):
                raise ValueError
            for extension in revoked.extensions:
                if isinstance(extension.value, x509.CertificateIssuer):
                    raise ValueError
                if (isinstance(extension.value, x509.CRLReason)
                        and extension.value.reason is x509.ReasonFlags.remove_from_crl):
                    raise ValueError
                if extension.critical and not isinstance(extension.value, (x509.CRLReason, x509.InvalidityDate)):
                    raise ValueError
            serials.add(revoked.serial_number)
        # Official provider toCertFormat for versions before7.4.4: remove only
        # trailing LF, then wrap with literal quotes; JSON escaping is separate.
        user_field = '"' + raw.decode("ascii").rstrip("\n") + '"'
        return CrlImportArtifact(
            hashlib.sha256(crl.public_bytes(serialization.Encoding.DER)).hexdigest(),
            hashlib.sha256(issuer.public_bytes(serialization.Encoding.DER)).hexdigest(),
            this_update, next_update, number, len(serials), user_field,
        )
    except Exception:
        raise ValueError(_UNAVAILABLE) from None
