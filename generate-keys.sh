#!/bin/bash
set -euo pipefail

# Usage: ./generate-keys.sh [KEYS_DIR] [--force]
# Generates a 2048-bit RSA keypair (private.pem + public.pem) for JWT signing.
# Defaults to the main resources dir; pass a dir to target test resources.

KEYS_DIR="src/main/resources/keys"
FORCE=false

for arg in "$@"; do
  case "$arg" in
    --force) FORCE=true ;;
    *) KEYS_DIR="$arg" ;;
  esac
done

mkdir -p "$KEYS_DIR"

if [[ -f "$KEYS_DIR/private.pem" && "$FORCE" != true ]]; then
  echo "Keys already exist in $KEYS_DIR (use --force to regenerate)"
  exit 0
fi

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$KEYS_DIR/private.pem"
openssl pkey -in "$KEYS_DIR/private.pem" -pubout -out "$KEYS_DIR/public.pem"

echo "Keys generated in $KEYS_DIR"
