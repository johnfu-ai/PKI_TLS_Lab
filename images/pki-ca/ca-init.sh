#!/usr/bin/env bash
# Initialize the Lab Root CA and pre-issue end-entity certs (the mock CMP
# server returns these via -rsp_cert). Idempotent.
set -euo pipefail

PKI_DIR=/pki
mkdir -p "$PKI_DIR"
cd "$PKI_DIR"

if [[ -f ca-chain.pem ]] && [[ -f client.cert.pem ]] && [[ -f server.cert.pem ]]; then
  echo "[ca-init] PKI already initialized, skipping"
  exit 0
fi

echo "[ca-init] Generating Lab Root CA (ECDSA P-256)"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca.key.pem

cat >ca.cnf <<'EOF'
[req]
prompt = no
distinguished_name = dn
x509_extensions = v3_ca

[dn]
C  = US
O  = PKI_TLS_Lab
CN = LabRootCA

[v3_ca]
basicConstraints       = critical, CA:TRUE
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash
EOF

openssl req -new -x509 -sha256 -days 3650 -key ca.key.pem -config ca.cnf \
  -out ca-chain.pem

echo "[ca-init] CA fingerprint: $(openssl x509 -in ca-chain.pem -noout -fingerprint -sha256)"

# CMP responder identity (used by openssl cmp -port to sign responses)
echo "[ca-init] Generating CMP responder cert"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out cmp-srv.key.pem
openssl req -new -key cmp-srv.key.pem -subj "/C=US/O=PKI_TLS_Lab/CN=cmp-responder" -out cmp-srv.csr
openssl x509 -req -in cmp-srv.csr -CA ca-chain.pem -CAkey ca.key.pem -CAcreateserial \
  -days 365 -sha256 -out cmp-srv.cert.pem
rm -f cmp-srv.csr

issue_leaf() {
  local role="$1"
  local cn="$2"
  local eku="$3"
  echo "[ca-init] Issuing $role cert (CN=$cn, EKU=$eku)"

  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${role}.key.pem"

  cat >"${role}.cnf" <<EOF
[req]
prompt = no
distinguished_name = dn
req_extensions = v3_req
[dn]
C  = US
O  = PKI_TLS_Lab
CN = ${cn}
[v3_req]
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = ${eku}
subjectAltName = DNS:${cn}
EOF

  openssl req -new -key "${role}.key.pem" -config "${role}.cnf" -out "${role}.csr"
  openssl x509 -req -in "${role}.csr" -CA ca-chain.pem -CAkey ca.key.pem -CAcreateserial \
    -days 365 -sha256 -extfile "${role}.cnf" -extensions v3_req \
    -out "${role}.cert.pem"
  rm -f "${role}.csr"
}

issue_leaf client tls-client.lab.local clientAuth
issue_leaf server tls-server.lab.local serverAuth

# Mark sentinel
touch "$PKI_DIR/.ca-bootstrap.done"
echo "[ca-init] PKI initialized"
ls -la "$PKI_DIR" | head -25
