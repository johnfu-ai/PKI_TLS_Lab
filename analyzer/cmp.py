"""CMP protocol analysis from pcap captures."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from analyzer.mermaid import Sequence

try:
    import pyshark
except ImportError:  # pragma: no cover
    pyshark = None  # type: ignore


PKIBODY_NAMES: dict[str, str] = {
    "0": "ir",
    "1": "ip",
    "2": "cr",
    "3": "cp",
    "4": "p10cr",
    "5": "popdecc",
    "6": "popdecr",
    "7": "kur",
    "8": "kup",
    "9": "krr",
    "10": "krp",
    "11": "rr",
    "12": "rp",
    "13": "ccr",
    "14": "ccp",
    "15": "ckuann",
    "16": "cann",
    "17": "rann",
    "18": "crlann",
    "19": "pkiconf",
    "20": "nested",
    "21": "genm",
    "22": "genp",
    "23": "error",
    "24": "certConf",
    "25": "pollReq",
    "26": "pollRep",
}

# Server-originated message types (CA -> client)
RESPONSE_BODIES = {"ip", "cp", "kup", "krp", "rp", "pkiconf", "genp", "error", "ccp", "pollRep"}


@dataclass
class CmpMessage:
    time: str
    src: str
    dst: str
    pki_body: str
    pki_body_name: str
    transaction_id: str
    sender: str
    recipient: str
    protection_alg: str
    cert_status: str = ""
    is_response: bool = False


@dataclass
class CmpAnalysis:
    packet_count: int
    messages: list[CmpMessage] = field(default_factory=list)
    transactions: dict[str, list[CmpMessage]] = field(default_factory=dict)
    mermaid: str = ""
    summary_rows: list[dict[str, str]] = field(default_factory=list)


def _get(layer: Any, *names: str, default: str = "") -> str:
    for name in names:
        if hasattr(layer, name):
            val = getattr(layer, name)
            if val is not None:
                s = str(val).strip()
                if s:
                    return s
    return default


def _pki_body_name(tag: str) -> str:
    tag = (tag or "").strip()
    return PKIBODY_NAMES.get(tag, f"body({tag or '?'})")


def analyze_cmp(pcap_path: Path) -> CmpAnalysis:
    if pyshark is None:
        raise RuntimeError("pyshark is required")
    if not pcap_path.exists():
        return CmpAnalysis(packet_count=0, mermaid=_empty_cmp_diagram())

    messages: list[CmpMessage] = []
    cap = pyshark.FileCapture(
        str(pcap_path),
        display_filter="cmp",
        keep_packets=False,
    )
    pkt_count = 0
    try:
        for pkt in cap:
            pkt_count += 1
            cmp = getattr(pkt, "cmp", None)
            if cmp is None:
                continue
            src = pkt.ip.src if hasattr(pkt, "ip") else ""
            dst = pkt.ip.dst if hasattr(pkt, "ip") else ""

            body = _get(cmp, "body", "pki_body")
            body_name = _pki_body_name(body)
            tx = _get(cmp, "header_transactionid", "transaction_id", default="")
            if tx:
                # Truncate hex transaction IDs to last 8 hex chars for compactness
                tx = tx.replace(":", "").replace(" ", "")
                if len(tx) > 16:
                    tx = "..." + tx[-12:]

            msg = CmpMessage(
                time=str(pkt.sniff_time),
                src=src,
                dst=dst,
                pki_body=body,
                pki_body_name=body_name,
                transaction_id=tx or "?",
                sender=_get(cmp, "header_sender", "sender"),
                recipient=_get(cmp, "header_recipient", "recipient"),
                protection_alg=_get(cmp, "header_protectionalg", "protection_alg"),
                cert_status=_get(cmp, "body_status", "status"),
                is_response=body_name in RESPONSE_BODIES,
            )
            messages.append(msg)
    finally:
        cap.close()

    # Group by direction-pair to infer transactions when transactionID is missing
    by_tx: dict[str, list[CmpMessage]] = defaultdict(list)
    fallback_tx = "tx-1"
    fallback_idx = 1
    last_was_response = True
    for m in messages:
        tx_key = m.transaction_id
        if tx_key == "?" or not tx_key:
            # New "transaction" starts whenever we see a request after a response
            if not m.is_response and last_was_response:
                fallback_tx = f"tx-{fallback_idx}"
                fallback_idx += 1
            tx_key = fallback_tx
        by_tx[tx_key].append(m)
        last_was_response = m.is_response

    seq = Sequence()
    seq.participant("C", "CMP client (openssl)")
    seq.participant("CA", "CMP responder (openssl mock)")
    for tx_id, msgs in by_tx.items():
        seq.note("C,CA", f"Transaction {tx_id}")
        for m in msgs:
            if m.is_response:
                seq.msg("CA", "C", f"{m.pki_body_name}")
            else:
                seq.msg("C", "CA", f"{m.pki_body_name}")

    summary_rows = [
        {
            "time": m.time,
            "direction": f"{m.src} -> {m.dst}",
            "pki_body": m.pki_body_name,
            "transaction_id": m.transaction_id,
            "protection": m.protection_alg or "(see ASN.1)",
        }
        for m in messages
    ]

    return CmpAnalysis(
        packet_count=pkt_count,
        messages=messages,
        transactions=dict(by_tx),
        mermaid=seq.render() if messages else _empty_cmp_diagram(),
        summary_rows=summary_rows,
    )


def _empty_cmp_diagram() -> str:
    s = Sequence()
    s.participant("C", "CMP client")
    s.participant("CA", "CMP responder")
    s.note("C,CA", "No CMP packets decoded — run make enroll with capture active")
    return s.render()
