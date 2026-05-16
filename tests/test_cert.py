"""Tests for certificate parsing helpers."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from analyzer.cert import describe_cert, load_pem, verify_chain


@pytest.fixture
def ecdsa_certs(tmp_path: Path):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "TestCA")]
    )
    now = datetime.now(timezone.utc)
    ca = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf.example")])
        )
        .issuer_name(issuer)
        .public_key(leaf_key.public_key())
        .serial_number(2)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=90))
        .sign(key, hashes.SHA256())
    )
    ca_path = tmp_path / "ca.pem"
    leaf_path = tmp_path / "leaf.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    leaf_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    return ca_path, leaf_path


def test_describe_ecdsa_p256(ecdsa_certs):
    _, leaf_path = ecdsa_certs
    info = describe_cert(load_pem(leaf_path))
    assert info.curve in ("secp256r1", "SECP256R1")
    assert info.key_bits == 256
    assert "leaf.example" in info.subject


def test_verify_chain(ecdsa_certs):
    ca_path, leaf_path = ecdsa_certs
    assert verify_chain(leaf_path, ca_path) is True
