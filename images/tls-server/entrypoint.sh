#!/bin/sh
set -e

echo "Waiting for server certificate at /pki/server.cert.pem ..."
for i in $(seq 1 120); do
  if [ -f /pki/server.cert.pem ] && [ -f /pki/server.key.pem ] && [ -f /pki/ca-chain.pem ]; then
    break
  fi
  sleep 1
done

if [ ! -f /pki/server.cert.pem ]; then
  echo "ERROR: /pki/server.cert.pem not found after wait" >&2
  exit 1
fi

nginx -t
exec nginx -g 'daemon off;'
