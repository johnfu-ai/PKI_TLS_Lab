# Glossary

## CMP (RFC 4210)

| Term | Meaning |
|------|---------|
| **CMP** | Certificate Management Protocol — PKIX protocol for enrollment and lifecycle |
| **IR / IP** | Initialization Request / Response — first enrollment message pair |
| **CR / CP** | Certificate Request / Response — renewal/re-enrollment style exchange |
| **certConf** | Client confirms it accepted the issued certificate |
| **pkiConf** | CA confirms the transaction is complete |
| **PBM** | Password-Based MAC — CMP protection using a shared secret |
| **RA mode** | Registration Authority mode — CA trusts pre-registered end entities |
| **PoP** | Proof-of-Possession — proves the requester holds the private key |

## TLS

| Term | Meaning |
|------|---------|
| **mTLS** | Mutual TLS — both client and server present X.509 certificates |
| **ClientHello** | First handshake message; lists ciphers, extensions, key shares |
| **key_share** | TLS 1.3 extension carrying ECDHE public key (e.g. P-256) |
| **CertificateVerify** | Signature over the handshake transcript |
| **SSLKEYLOG** | NSS key log format; enables Wireshark decryption of TLS records |

## ECDSA

| Term | Meaning |
|------|---------|
| **P-256** | NIST curve `prime256v1` / `secp256r1` — 256-bit ECDSA keys |
| **ecdsa-with-SHA256** | Signature algorithm pairing ECDSA with SHA-256 |

## References

- [RFC 4210](https://www.rfc-editor.org/rfc/rfc4210) — CMP
- [RFC 5246](https://www.rfc-editor.org/rfc/rfc5246) — TLS 1.2
- [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) — TLS 1.3
