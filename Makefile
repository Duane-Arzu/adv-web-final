include .envrc

.PHONY: run/api
run/api:
	@echo  'Running application…'
	@go run ./cmd/api -port=4000 -env=development -limiter-burst=5 -limiter-rps=2 -limiter-enabled=true -db-dsn=${COMMENTS_DB_DSN}

.PHONY: db/psql
db/psql:
	psql ${COMMENTS_DB_DSN}

.PHONY: db/migrations/new
db/migrations/new:
	@echo 'Creating migration files for ${name}...'
	migrate create -seq -ext=.sql -dir=./migrations ${name}

.PHONY: db/migrations/up
db/migrations/up:
	@echo 'Running up migrations...'
	migrate -path ./migrations -database ${COMMENTS_DB_DSN} up