"""One combined public-CRL signature, lifetime, sequence and wire regression."""
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import pytest

from fortipam_mcp.crl_import_artifact import prepare_build29_crl_artifact


def test_crl_artifact_requires_signed_fresh_complete_material_and_exact_user_format() -> None:
    now = datetime(2026, 10, 13, tzinfo=timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic-crl.invalid")])
    usage = x509.KeyUsage(False, False, False, False, False, True, True, None, None)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .add_extension(usage, True).sign(key, hashes.SHA256()))
    issuer = cert.public_bytes(serialization.Encoding.PEM)
    revoked = (x509.RevokedCertificateBuilder().serial_number(7)
               .revocation_date(now - timedelta(hours=1)).build())
    builder = (x509.CertificateRevocationListBuilder().issuer_name(subject)
               .last_update(now).next_update(now + timedelta(hours=1))
               .add_extension(x509.CRLNumber(3), False).add_revoked_certificate(revoked))
    raw = builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)
    timestamp = int(now.timestamp())
    prepared = prepare_build29_crl_artifact(raw, issuer, now=timestamp, minimum_sequence=3)
    assert prepared.sequence == 3 and prepared.revoked_count == 1
    assert prepared.this_update == timestamp and prepared.next_update == timestamp + 3600
    assert prepared._user_field == '"' + raw.decode().rstrip("\n") + '"'
    assert len(prepared.sha256) == len(prepared.issuer_sha256) == 64
    assert "BEGIN" not in repr(prepared)
    foreign = builder.sign(ec.generate_private_key(ec.SECP256R1()), hashes.SHA256())
    delta = builder.add_extension(x509.DeltaCRLIndicator(2), True).sign(key, hashes.SHA256())
    indirect = builder.add_extension(x509.IssuingDistributionPoint(
        None, None, False, False, None, True, False), True).sign(key, hashes.SHA256())
    removed = (x509.RevokedCertificateBuilder().serial_number(8).revocation_date(now)
               .add_extension(x509.CRLReason(x509.ReasonFlags.remove_from_crl), False).build())
    removal = builder.add_revoked_certificate(removed).sign(key, hashes.SHA256())
    for candidate, selected_now, floor in (
        (raw, timestamp - 1, 3), (raw, timestamp + 3600, 3), (raw, timestamp, 4),
        (raw + raw, timestamp, 3), (raw[:-1], timestamp, 3), (b"not a CRL", timestamp, 3),
        (foreign.public_bytes(serialization.Encoding.PEM), timestamp, 3),
        (delta.public_bytes(serialization.Encoding.PEM), timestamp, 3),
        (indirect.public_bytes(serialization.Encoding.PEM), timestamp, 3),
        (removal.public_bytes(serialization.Encoding.PEM), timestamp, 3),
    ):
        with pytest.raises(ValueError, match="artifact is unavailable"):
            prepare_build29_crl_artifact(candidate, issuer, now=selected_now, minimum_sequence=floor)
    for selected_now, floor in ((True, 3), (timestamp, True), (timestamp, -1)):
        with pytest.raises(ValueError):
            prepare_build29_crl_artifact(raw, issuer, now=selected_now, minimum_sequence=floor)
