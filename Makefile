.PHONY: help infra run down logs status clean

help:           ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "} {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

infra:          ## Start infra (Postgres, Kafka, Connect) + auto-register the connector
	docker compose up -d

run:            ## Run the auth service on the host (applies migrations on boot)
	./gradlew bootRun

down:           ## Stop infra (keeps volumes)
	docker compose down

clean:          ## Stop infra and delete volumes (full reset)
	docker compose down -v

logs:           ## Tail Connect + connector-init logs
	docker compose logs -f connect connect-init

status:         ## Show the Debezium connector status
	@curl -fsS localhost:8083/connectors/auth-outbox-connector/status | jq
