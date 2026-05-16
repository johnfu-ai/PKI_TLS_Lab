# PKI_TLS_Lab

Docker-based lab demonstrating **CMP certificate enrollment** (EJBCA, ECDSA P-256) and **mutual TLS** (nginx + curl) over **TLS 1.2** and **TLS 1.3**, with **Wireshark-ready pcaps** and auto-generated **Markdown + Mermaid** protocol analysis reports.

## Prerequisites

- **Docker Desktop** with **WSL 2 integration** enabled (Settings → Resources → WSL Integration)
- ~4 GB RAM free while EJBCA starts (~60 s first boot)
- ~3 GB disk

## Quickstart

```bash
cp .env.example .env
chmod +x run-lab.sh scripts/*.sh
make all
```

Outputs:

| Path | Contents |
|------|----------|
| `output/pcap/cmp.pcap` | CMP enrollment (HTTP + CMP) |
| `output/pcap/tls12.pcap` | TLS 1.2 mTLS handshake + HTTP |
| `output/pcap/tls13.pcap` | TLS 1.3 mTLS handshake + HTTP |
| `output/pki/sslkeys-tls*.log` | SSLKEYLOG for decryption |
| `output/analysis/*.md` | Protocol analysis reports |

## Phases

| Command | Description |
|---------|-------------|
| `make up` | Start EJBCA, bootstrap CA/profiles/CMP alias |
| `make enroll` | CMP enroll client + server certs (captures `cmp.pcap`) |
| `make tls12` | TLS 1.2 mTLS to nginx :4443 |
| `make tls13` | TLS 1.3 mTLS to nginx :4444 |
| `make analyze` | Generate reports from pcaps |
| `make all` | Full pipeline (clean → up → enroll → tls12 → tls13 → analyze) |
| `make test` | Run unit tests (no lab required) |
| `make clean` | Remove containers and `output/` |

## Inspect captures in Wireshark

1. Open `output/pcap/tls12.pcap` or `tls13.pcap`
2. **Edit → Preferences → Protocols → TLS** → **(Pre)-Master-Secret log filename** → `output/pki/sslkeys-tls12.log` (or `tls13`)
3. Filter `tls.handshake` or `http`

For CMP: open `output/pcap/cmp.pcap`, filter `cmp`.

## Architecture

See [docs/architecture.md](docs/architecture.md).

## Troubleshooting

- **Docker not found in WSL**: Enable Docker Desktop WSL integration and restart the distro.
- **EJBCA slow / unhealthy**: Wait up to 5 minutes on first run; check `docker logs pki-ca`.
- **Empty pcap**: Ensure capture containers started before the action phase; re-run `make enroll` or `make tls12`.
- **CMP enrollment fails**: Verify `output/pki/ca-chain.pem` exists after `make up`; check shared secret in `.env` matches EJBCA CMP alias.

## Glossary

See [docs/glossary.md](docs/glossary.md).
