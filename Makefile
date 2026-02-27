COMPOSE := docker compose -f docker/docker-compose.yml
GRADLEW := ./gradlew

.PHONY: help up down rebuild logs test build run clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# --- Docker ---

up: ## Start verifier container (build if needed)
	$(COMPOSE) up -d --build

down: ## Stop and remove containers
	$(COMPOSE) down

rebuild: ## Force rebuild and restart
	$(COMPOSE) up -d --build --force-recreate

logs: ## Tail container logs
	$(COMPOSE) logs -f verifier

# --- Gradle ---

test: ## Run tests
	$(GRADLEW) test

build: ## Build JAR (with tests)
	$(GRADLEW) build

run: ## Run app locally (no Docker)
	$(GRADLEW) bootRun

clean: ## Clean build artifacts
	$(GRADLEW) clean
