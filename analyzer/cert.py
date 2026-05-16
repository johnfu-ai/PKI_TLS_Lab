"""X.509 certificate parsing helpers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import ExtensionOID


@dataclass
class CertInfo:
    subject: str
    issuer: str
    not_before: str
    not_after: str
    curve: str
    key_bits: int
    sans: list[str]
    serial: str


def load_pem(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def describe_cert(cert: x509.Certificate) -> CertInfo:
    pub = cert.public_key()
    curve = "unknown"
    bits = 0
    if isinstance(pub, ec.EllipticCurvePublicKey):
        curve = pub.curve.name
        bits = pub.curve.key_size

    sans: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = [str(n.value) for n in san_ext.value]
    except x509.ExtensionNotFound:
        pass

    return CertInfo(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        not_before=cert.not_valid_before_utc.isoformat(),
        not_after=cert.not_valid_after_utc.isoformat(),
        curve=curve,
        key_bits=bits,
        sans=sans,
        serial=format(cert.serial_number, "x"),
    )


def cert_table_row(info: CertInfo) -> dict[str, str]:
    return {
        "subject": info.subject,
        "issuer": info.issuer,
        "curve": info.curve,
        "key_bits": str(info.key_bits),
        "sans": ", ".join(info.sans) or "(none)",
        "valid_from": info.not_before,
        "valid_to": info.not_after,
        "serial": info.serial,
    }


def verify_chain(leaf_path: Path, ca_path: Path) -> bool:
    """Best-effort chain verification (single-tier CA)."""
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        leaf = load_pem(leaf_path)
        ca = load_pem(ca_path)
        if leaf.issuer != ca.subject:
            return False
        ca_key = ca.public_key()
        if isinstance(ca_key, ec.EllipticCurvePublicKey):
            ca_key.verify(
                leaf.signature,
                leaf.tbs_certificate_bytes,
                ec.ECDSA(hashes.SHA256()),
            )
            return True
        return False
    except Exception:
        return False
