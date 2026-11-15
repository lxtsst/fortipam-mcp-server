"""Remote identity regression independent of an empty CMDB certificate slot."""
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import pytest

from fortipam_mcp.remote_certificate_identity import (
    RemoteCertificateIdentity, expected_remote_import_name,
    remote_certificate_identity_matches,
)


def test_monitor_identity_binds_public_certificate_and_rejects_wrong_or_private_inputs() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic.invalid")])
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(1).not_valid_before(start)
            .not_valid_after(start + timedelta(hours=1)).sign(key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM)
    name = expected_remote_import_name("0123456789abcdef")
    expected = RemoteCertificateIdentity.from_public_pem(name, pem)
    fingerprint = ":".join(expected.sha256[i:i + 2] for i in range(0, 64, 2)).upper()
    record = {"name": name, "type": "remote-cer", "fingerprint": fingerprint,
              "valid_from": expected.valid_from, "valid_to": expected.valid_to}
    assert name == "REMOTE_Cert_0123456789abcdef_1" and len(name) <= 35
    assert remote_certificate_identity_matches(record, expected)
    assert remote_certificate_identity_matches({**record, "fingerprint": expected.sha256}, expected)
    for field, value in (("name", "other"), ("type", "local-ca"),
                         ("fingerprint", "0" * 64), ("fingerprint", "00:" * 32),
                         ("valid_from", True), ("valid_to", expected.valid_to + 1)):
        assert not remote_certificate_identity_matches({**record, field: value}, expected)
    private_marker = b"-----BEGIN " + b"PRIVATE KEY-----"
    for value in (pem + pem, pem + private_marker, b"not a certificate"):
        with pytest.raises(ValueError, match="identity is unavailable"):
            RemoteCertificateIdentity.from_public_pem(name, value)
    for token in ("0123456789abcde", "0123456789abcdef/", "A" * 16):
        with pytest.raises(ValueError):
            expected_remote_import_name(token)
