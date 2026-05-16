"""Sanity checks on captures and PKI material."""

from __future__ import annotations

from pathlib import Path

from analyzer.cert import load_pem, verify_chain
from analyzer.cmp import CmpAnalysis
from analyzer.tls import TlsAnalysis


class CheckError(Exception):
    pass


def run_all(
    cmp_result: CmpAnalysis,
    tls12: TlsAnalysis,
    tls13: TlsAnalysis,
    pki_dir: Path,
    *,
    server_dns: str = "tls-server.lab.local",
    tls12_cipher: str = "ECDHE-ECDSA-AES256-GCM-SHA384",
    tls13_cipher: str = "TLS_AES_256_GCM_SHA384",
) -> list[str]:
    """Run checks; return list of warning/info messages. Raises CheckError on hard failure."""
    messages: list[str] = []

    ca = pki_dir / "ca-chain.pem"
    server_cert = pki_dir / "server.cert.pem"
    client_cert = pki_dir / "client.cert.pem"

    if not ca.exists():
        raise CheckError(f"Missing CA chain: {ca}")
    if server_cert.exists() and not verify_chain(server_cert, ca):
        raise CheckError("Server cert does not chain to ca-chain.pem")
    if client_cert.exists() and not verify_chain(client_cert, ca):
        raise CheckError("Client cert does not chain to ca-chain.pem")
    messages.append("Certificate chain validation: PASS")

    if server_cert.exists():
        leaf = load_pem(server_cert)
        sans = []
        try:
            from cryptography.x509.oid import ExtensionOID

            san = leaf.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            sans = [str(x.value) for x in san.value]
        except Exception:
            pass
        cn_ok = server_dns in leaf.subject.rfc4514_string() or server_dns in str(sans)
        if not cn_ok:
            messages.append(
                f"WARN: server cert may not match hostname {server_dns}"
            )
        else:
            messages.append(f"Server SAN/CN matches {server_dns}: PASS")

    if cmp_result.packet_count == 0:
        messages.append("WARN: cmp.pcap empty or missing CMP decode")
    elif cmp_result.messages:
        messages.append(f"CMP messages decoded: {len(cmp_result.messages)}")

    cipher_aliases = {
        "ECDHE-ECDSA-AES256-GCM-SHA384": ["0xc02c", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"],
        "TLS_AES_256_GCM_SHA384": ["0x1302", "TLS_AES_256_GCM_SHA384"],
    }
    for label, tls, expected_cipher in (
        ("TLS 1.2", tls12, tls12_cipher),
        ("TLS 1.3", tls13, tls13_cipher),
    ):
        if tls.packet_count == 0:
            messages.append(f"WARN: {label} pcap has no TLS packets")
            continue
        accepted = [expected_cipher] + cipher_aliases.get(expected_cipher, [])
        ok = any(a.lower() in (tls.negotiated_cipher or "").lower() for a in accepted)
        if tls.negotiated_cipher and not ok:
            raise CheckError(
                f"{label}: cipher mismatch expected {expected_cipher}, got {tls.negotiated_cipher}"
            )
        messages.append(
            f"{label} handshake packets: {tls.packet_count}, cipher: {tls.negotiated_cipher or '(unknown)'}"
        )

    return messages
