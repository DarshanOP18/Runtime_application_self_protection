.PHONY: dev prod test build stop clean logs shell \
        migrate health ps help

dev:
	@echo "Starting development server with hot-reload..."
	docker compose -f docker-compose.dev.yml up --build

prod:
	@echo "Starting production server..."
	docker compose up -d --build
	@echo "Backend running at http://127.0.0.1:8001"

test:
	@echo "Running test suite..."
	docker compose -f docker-compose.test.yml \
	  run --rm rasp-ai-test

build:
	@echo "Building production image..."
	docker compose build --no-cache

stop:
	@echo "Stopping all containers..."
	-docker compose down
	-docker compose -f docker-compose.dev.yml down

clean:
	@echo "WARNING: This deletes ALL data volumes!"
	@read -rp "Type YES to confirm: " C && [ "$$C" = "YES" ]
	docker compose down -v
	-docker compose -f docker-compose.dev.yml down -v
	@echo "Cleanup complete."

logs:
	docker compose logs -f rasp-ai-backend

shell:
	docker compose exec rasp-ai-backend /bin/bash

migrate:
	docker compose exec rasp-ai-backend \
	  python -m app.database.migrate

health:
	@curl -sf \
	  http://127.0.0.1:8001/api/v1/security/health \
	  | python3 -m json.tool \
	  || echo "Backend not reachable"

ps:
	docker compose ps

help:
	@echo ""
	@echo "RASP AI Backend — Available Commands"
	@echo "────────────────────────────────────"
	@echo "  make dev      Start dev server (hot-reload)"
	@echo "  make prod     Start production server"
	@echo "  make test     Run test suite in container"
	@echo "  make build    Rebuild production image"
	@echo "  make stop     Stop all containers"
	@echo "  make clean    Remove containers + volumes"
	@echo "  make logs     Follow container logs"
	@echo "  make shell    Open bash in container"
	@echo "  make migrate  Run DB migrations manually"
	@echo "  make health   Check backend health"
	@echo "  make ps       Show container status"
	@echo ""
