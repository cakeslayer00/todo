#!/bin/sh
# Runs inside the connect-init sidecar (not on the host).
# Waits for the outbox table to exist, then upserts the Debezium connector.
# Idempotent: PUT /connectors/<name>/config creates or updates.
set -eu

apk add --no-cache curl jq gettext >/dev/null

CONNECT_URL="http://connect:8083"
JSON="/debezium/outbox-connector.json"

echo "waiting for public.outbox to exist..."
until psql "postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}" \
        -tAc "select to_regclass('public.outbox')" 2>/dev/null | grep -q outbox; do
  sleep 2
done
echo "outbox table is ready."

NAME=$(jq -r '.name' "$JSON")
echo "registering connector '${NAME}'..."
jq '.config' "$JSON" \
  | envsubst '${POSTGRES_USER} ${POSTGRES_PASSWORD} ${POSTGRES_DB}' \
  | curl -fsS -X PUT "${CONNECT_URL}/connectors/${NAME}/config" \
      -H "Content-Type: application/json" -d @- >/dev/null

echo "connector '${NAME}' registered. Events flow to topic auth.email_verification."
