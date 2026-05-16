# PKI_TLS_Lab — Design Specification

**Date:** 2026-05-16  
**Status:** Approved for implementation

## Purpose

Demonstrate CMP enrollment with ECDSA P-256 certificates against EJBCA, then mutual TLS 1.2 and TLS 1.3 between nginx and curl, with per-phase Wireshark captures and auto-generated Markdown + Mermaid protocol analysis.

## Locked decisions

- **CMP server:** EJBCA Community Edition (`keyfactor/ejbca-ce`)
- **TLS server:** nginx 1.27 (two ports: 4443 TLS 1.2, 4444 TLS 1.3)
- **TLS client:** curl 8.x with `SSLKEYLOGFILE`
- **Capture:** per-scenario containers via `network_mode: container:<target>`
- **Crypto:** ECDSA P-256; pinned ciphers per TLS version
- **Orchestration:** hybrid (`docker-compose` + `run-lab.sh` + `scripts/`)
- **Analysis:** pyshark + Jinja2 → four Markdown reports

## Container roster

| Container | Role |
|-----------|------|
| `pki-ca` | EJBCA + CMP HTTP endpoint |
| `tls-server` | nginx mTLS |
| `cmp-enroll-*` | openssl cmp (ephemeral) |
| `tls-client` | curl (ephemeral) |
| `capture-cmp` / `capture-tls12` / `capture-tls13` | tcpdump (ephemeral) |
| `analyzer` | offline report generator |

## Lifecycle

`make all` → clean → up (EJBCA bootstrap) → enroll (CMP + cmp.pcap) → tls12 → tls13 → analyze → reports in `output/analysis/`.

## Out of scope

CRL/OCSP, HSM, EST/ACME, TLS 1.0/1.1, load testing, web UI for captures.

See [README.md](../../README.md) and [architecture.md](../architecture.md) for operational detail.
