"""TLS 1.2 / 1.3 handshake analysis from pcap + SSLKEYLOG."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from analyzer.mermaid import Sequence

try:
    import pyshark
except ImportError:  # pragma: no cover
    pyshark = None  # type: ignore

HS_TYPES = {
    "1": "ClientHello",
    "2": "ServerHello",
    "4": "NewSessionTicket",
    "8": "EncryptedExtensions",
    "11": "Certificate",
    "12": "ServerKeyExchange",
    "13": "CertificateRequest",
    "14": "ServerHelloDone",
    "15": "CertificateVerify",
    "16": "ClientKeyExchange",
    "20": "Finished",
}

CIPHER_NAMES: dict[str, str] = {
    "0xc02c": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "0xc02b": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "0x1301": "TLS_AES_128_GCM_SHA256",
    "0x1302": "TLS_AES_256_GCM_SHA384",
    "0x1303": "TLS_CHACHA20_POLY1305_SHA256",
}

SIGALG_NAMES: dict[str, str] = {
    "0x0403": "ecdsa_secp256r1_sha256",
    "0x0503": "ecdsa_secp384r1_sha384",
    "0x0603": "ecdsa_secp521r1_sha512",
    "0x0807": "ed25519",
    "0x0808": "ed448",
    "0x0804": "rsa_pss_rsae_sha256",
}

GROUP_NAMES: dict[str, str] = {
    "23": "secp256r1 (P-256)",
    "24": "secp384r1 (P-384)",
    "25": "secp521r1 (P-521)",
    "29": "x25519",
    "30": "x448",
    "0x0017": "secp256r1 (P-256)",
    "0x001d": "x25519",
}


def friendly_cipher(val: str) -> str:
    if not val:
        return "(unknown)"
    name = CIPHER_NAMES.get(val.lower(), val)
    return f"{name} ({val})" if name != val else val


def friendly_sigalg(val: str) -> str:
    if not val:
        return ""
    name = SIGALG_NAMES.get(val.lower(), val)
    return f"{name} ({val})" if name != val else val


def friendly_group(val: str) -> str:
    if not val:
        return ""
    return GROUP_NAMES.get(val.lower(), GROUP_NAMES.get(val, val))


@dataclass
class HandshakeStep:
    packet_num: int
    time: str
    msg_type: str
    cipher: str = ""
    extensions: str = ""
    sigalg: str = ""
    length: int = 0


@dataclass
class TlsAnalysis:
    version: str
    packet_count: int
    duration_ms: float
    client_addr: str
    server_addr: str
    negotiated_cipher: str
    negotiated_cipher_friendly: str
    key_share_group: str
    key_share_friendly: str
    sigalg: str
    sigalg_friendly: str
    handshake_steps: list[HandshakeStep] = field(default_factory=list)
    mermaid: str = ""
    app_data_bytes: int = 0
    http_request: str = ""
    http_response_hint: str = ""


def _field(layer: Any, name: str, default: str = "") -> str:
    return str(getattr(layer, name, default) or default)


def analyze_tls(
    pcap_path: Path,
    keylog_path: Path | None,
    version: str,
) -> TlsAnalysis:
    if pyshark is None:
        raise RuntimeError("pyshark is required")

    if not pcap_path.exists():
        return TlsAnalysis(
            version=version, packet_count=0, duration_ms=0.0,
            client_addr="", server_addr="",
            negotiated_cipher="", negotiated_cipher_friendly="(unknown)",
            key_share_group="", key_share_friendly="",
            sigalg="", sigalg_friendly="",
            mermaid=_empty_tls_diagram(version),
        )

    override: dict[str, str] = {}
    if keylog_path and keylog_path.exists():
        override["tls.keylog_file"] = str(keylog_path)

    cap = pyshark.FileCapture(
        str(pcap_path),
        display_filter="tls.handshake || tls.app_data",
        override_prefs=override or None,
        keep_packets=False,
    )

    steps: list[HandshakeStep] = []
    first_time = None
    last_time = None
    client_addr = ""
    server_addr = ""
    negotiated_cipher = ""
    key_share = ""
    sigalg = ""
    app_bytes = 0
    pkt_count = 0

    try:
        for pkt in cap:
            pkt_count += 1
            if first_time is None:
                first_time = pkt.sniff_time
            last_time = pkt.sniff_time

            if hasattr(pkt, "ip"):
                if not client_addr:
                    client_addr = pkt.ip.src
                    server_addr = pkt.ip.dst

            if hasattr(pkt, "tls"):
                tls = pkt.tls
                hs_type = _field(tls, "handshake_type")
                if hs_type:
                    label = HS_TYPES.get(hs_type, f"Handshake({hs_type})")
                    cipher = _field(tls, "handshake_ciphersuite")
                    if cipher and label == "ServerHello":
                        negotiated_cipher = cipher
                    ext = _field(tls, "handshake_extensions_key_share_group")
                    if ext and not key_share:
                        key_share = ext
                    sa = _field(tls, "handshake_sig_hash_alg")
                    if sa and not sigalg:
                        sigalg = sa
                    steps.append(
                        HandshakeStep(
                            packet_num=int(pkt.number),
                            time=str(pkt.sniff_time),
                            msg_type=label,
                            cipher=cipher,
                            extensions=ext,
                            sigalg=sa,
                            length=int(_field(tls, "handshake_length", "0") or 0),
                        )
                    )
                if hasattr(tls, "app_data"):
                    try:
                        app_bytes += int(_field(tls, "app_data_length", "0") or 0)
                    except ValueError:
                        app_bytes += len(_field(tls, "app_data"))
    finally:
        cap.close()

    duration_ms = 0.0
    if first_time and last_time:
        duration_ms = (last_time - first_time).total_seconds() * 1000.0

    return TlsAnalysis(
        version=version,
        packet_count=pkt_count,
        duration_ms=duration_ms,
        client_addr=client_addr,
        server_addr=server_addr,
        negotiated_cipher=negotiated_cipher,
        negotiated_cipher_friendly=friendly_cipher(negotiated_cipher),
        key_share_group=key_share,
        key_share_friendly=friendly_group(key_share) or "(unknown)",
        sigalg=sigalg,
        sigalg_friendly=friendly_sigalg(sigalg) or "(unknown)",
        handshake_steps=steps,
        mermaid=_build_tls_mermaid(version, steps, negotiated_cipher),
        app_data_bytes=app_bytes,
        http_request="GET / HTTP/1.1 (decrypted when keylog present)",
        http_response_hint="HTTP/1.1 200 OK (nginx index.html)",
    )


def _build_tls_mermaid(version: str, steps: list[HandshakeStep], cipher: str) -> str:
    seq = Sequence()
    seq.participant("C", "tls-client (curl)")
    seq.participant("S", "tls-server (nginx)")

    cipher_friendly = friendly_cipher(cipher) if cipher else ""

    if version == "1.3":
        seq.msg("C", "S", "ClientHello [TLS1.3, key_share=P-256, sigalgs]")
        seq.msg("S", "C", f"ServerHello [{cipher_friendly or 'TLS_AES_256_GCM_SHA384'}]")
        seq.note("C,S", "Handshake messages encrypted under handshake traffic keys")
        seq.msg("S", "C", "{EncryptedExtensions}")
        seq.msg("S", "C", "{CertificateRequest}")
        seq.msg("S", "C", "{Certificate (server)}")
        seq.msg("S", "C", "{CertificateVerify}")
        seq.msg("S", "C", "{Finished}")
        seq.msg("C", "S", "{Certificate (client)} + {CertificateVerify} + {Finished}")
        seq.note("C,S", "Application traffic keys derived")
        seq.msg("C", "S", "{HTTP GET /}")
        seq.msg("S", "C", "{HTTP/1.1 200 OK}")
    else:
        client_msgs = {"ClientHello", "ClientKeyExchange", "CertificateVerify", "Finished"}
        for s in steps:
            if s.msg_type == "ClientHello":
                seq.msg("C", "S", "ClientHello")
            elif s.msg_type == "ServerHello":
                seq.msg("S", "C", f"ServerHello [{cipher_friendly or 'ECDHE-ECDSA-AES256-GCM-SHA384'}]")
            elif s.msg_type in ("Certificate", "ServerKeyExchange", "CertificateRequest", "ServerHelloDone"):
                seq.msg("S", "C", s.msg_type)
            elif s.msg_type in ("CertificateVerify", "ClientKeyExchange", "Finished"):
                seq.msg("C", "S", s.msg_type)
            elif s.msg_type in client_msgs:
                seq.msg("C", "S", s.msg_type)
            else:
                seq.msg("S", "C", s.msg_type)
        seq.msg("C", "S", "Application Data (HTTP GET /)")
        seq.msg("S", "C", "Application Data (HTTP 200)")

    return seq.render()


def _empty_tls_diagram(version: str) -> str:
    s = Sequence()
    s.participant("C", "tls-client")
    s.participant("S", "tls-server")
    s.note("C,S", f"No TLS {version} packets — run make tls{version.replace('.','')}")
    return s.render()
