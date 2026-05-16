"""CLI entry point for PKI_TLS_Lab analyzer."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from analyzer.cmp import analyze_cmp
from analyzer.checks import CheckError, run_all
from analyzer.cert import cert_table_row, describe_cert, load_pem
from analyzer.lib import template_env, write_report
from analyzer.tls import analyze_tls, friendly_cipher


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PKI_TLS_Lab protocol analyzer")
    parser.add_argument("--pcap-dir", type=Path, required=True)
    parser.add_argument("--keylog-dir", type=Path, required=True)
    parser.add_argument("--pki-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args(argv)

    pcap_dir = args.pcap_dir
    pki_dir = args.pki_dir
    out_dir = args.out_dir
    env = template_env()

    cmp_pcap = pcap_dir / "cmp.pcap"
    tls12_pcap = pcap_dir / "tls12.pcap"
    tls13_pcap = pcap_dir / "tls13.pcap"
    key12 = args.keylog_dir / "sslkeys-tls12.log"
    key13 = args.keylog_dir / "sslkeys-tls13.log"

    cmp_result = analyze_cmp(cmp_pcap)
    tls12 = analyze_tls(tls12_pcap, key12 if key12.exists() else None, "1.2")
    tls13 = analyze_tls(tls13_pcap, key13 if key13.exists() else None, "1.3")

    cert_infos = {}
    for role in ("client", "server"):
        cp = pki_dir / f"{role}.cert.pem"
        if cp.exists():
            cert_infos[role] = cert_table_row(describe_cert(load_pem(cp)))

    try:
        check_msgs = run_all(cmp_result, tls12, tls13, pki_dir)
    except CheckError as e:
        print(f"CHECK FAILED: {e}", file=sys.stderr)
        return 1

    for msg in check_msgs:
        print(msg)

    # Render reports
    tpl_cmp = env.get_template("01-cmp.md.j2")
    write_report(
        out_dir,
        "01-cmp-enrollment.md",
        tpl_cmp.render(cmp=cmp_result),
    )

    tpl12 = env.get_template("02-tls12.md.j2")
    write_report(
        out_dir,
        "02-tls12-handshake.md",
        tpl12.render(tls=tls12, certs=cert_infos),
    )

    tpl13 = env.get_template("03-tls13.md.j2")
    write_report(
        out_dir,
        "03-tls13-handshake.md",
        tpl13.render(tls=tls13, certs=cert_infos),
    )

    tpl_ov = env.get_template("00-overview.md.j2")
    write_report(
        out_dir,
        "00-overview.md",
        tpl_ov.render(
            cmp=cmp_result,
            tls12=tls12,
            tls13=tls13,
            checks=check_msgs,
            cert_infos=cert_infos,
        ),
    )

    print(f"Wrote reports to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
