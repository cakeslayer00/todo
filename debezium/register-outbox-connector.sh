#!/usr/bin/env bash
# Registers the Debezium outbox connector with the local Kafka Connect.
# Reads DB credentials from .env and substitutes them into the connector JSON.
# The Debezium placeholder ${routedByValue} is left untouched on purpose.
set -euo pipefail

cd "$(dirname "$0")/.."
set -a; source .env; set +a

envsubst '${POSTGRES_USER} ${POSTGRES_PASSWORD} ${POSTGRES_DB}' \
  < debezium/outbox-connector.json \
  | curl -fsS -X POST http://localhost:8083/connectors \
      -H "Content-Type: application/json" \
      -d @- \
  | jq .
