#!/usr/bin/env bash
# Generate Linkerd's mTLS trust anchor + identity issuer (ECDSA P-256) for a
# LOCAL cluster. Keys are written to $1 (default var/linkerd), which is
# git-ignored; production should use cert-manager or an external CA instead.
# Idempotent: existing certs are kept so re-running up-local doesn't rotate them.
set -euo pipefail
out="${1:-var/linkerd}"
mkdir -p "$out"
cd "$out"
[[ -f issuer.crt && -f ca.crt ]] && { echo "linkerd certs exist in $out"; exit 0; }

printf '%s\n' "basicConstraints=critical,CA:TRUE,pathlen:0" "keyUsage=critical,keyCertSign,cRLSign" > issuer.ext

# trust anchor (root), 1 year
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -key ca.key -sha256 -days 365 -subj "/CN=root.linkerd.cluster.local" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca.crt

# identity issuer (intermediate), signed by the anchor, 1 year
openssl ecparam -name prime256v1 -genkey -noout -out issuer.key
openssl req -new -key issuer.key -subj "/CN=identity.linkerd.cluster.local" -out issuer.csr
openssl x509 -req -in issuer.csr -CA ca.crt -CAkey ca.key -CAcreateserial -sha256 -days 365 \
  -extfile issuer.ext -out issuer.crt
rm -f issuer.csr issuer.ext ca.srl
echo "linkerd certs written to $out"
