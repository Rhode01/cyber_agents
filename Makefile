# Cybersecurity Agents Platform - root Makefile.
#
# Layout follows the luso8 convention: one directory per deployable service,
# named cyber.<service>, each with its OWN virtualenv and lockfile. Virtualenvs
# are never shared between services.
#
#   cyber.contracts    shared Finding / scan schemas (path dependency, no venv)
#   cyber.backend      :8000  FastAPI, owns all persistence and migrations
#   cyber.ai.engine    :8003  LangGraph agents, holds no database
#   cyber.frontend     :3000  Next.js
#   cyber.mcp.server   :8004  MCP server
#
# Target naming is <module>-<action>; the bare targets fan out to every module.

BACKEND    := cyber.backend
AI_ENGINE  := cyber.ai.engine
FRONTEND   := cyber.frontend
MCP_SERVER := cyber.mcp.server
CONTRACTS  := cyber.contracts

ifeq ($(OS),Windows_NT)
PS         := powershell -NoProfile -ExecutionPolicy Bypass
CLEAN      := $(PS) -File scripts/clean.ps1
VERIFY     := $(PS) -File scripts/verify.ps1
ENSURE_ENV := $(PS) -File scripts/ensure-env.ps1
else
CLEAN      := bash scripts/clean.sh
VERIFY     := bash scripts/verify.sh
ENSURE_ENV := bash scripts/ensure-env.sh
endif

.DEFAULT_GOAL := help

.PHONY: help env install lock dev up down down-v build logs ps \
        contracts-check \
        backend-install backend-dev backend-worker backend-lint backend-typecheck backend-test \
        ai-engine-install ai-engine-dev ai-engine-lint ai-engine-typecheck ai-engine-test \
        mcp-server-install mcp-server-dev mcp-server-lint mcp-server-typecheck mcp-server-test \
        frontend-install frontend-dev frontend-build frontend-lint frontend-typecheck \
        migrate migrate-sql migrate-create migrate-down migrate-history \
        lint format typecheck test check verify clean

# ---------------------------------------------------------------- help / env --

help:
	@echo Cybersecurity Agents Platform
	@echo.
	@echo   env                  Create .env from .env.example if missing
	@echo   install              Install every module into its own venv
	@echo   lock                 Refresh every lockfile
	@echo.
	@echo   up / down / down-v   Docker Compose lifecycle
	@echo   build / logs / ps    Docker Compose build, tail logs, list services
	@echo   dev                  Run all five processes locally in parallel
	@echo.
	@echo   backend-dev          uvicorn backend on port 8000
	@echo   backend-worker       arq worker against Redis
	@echo   ai-engine-dev        uvicorn ai.engine on port 8003
	@echo   frontend-dev         next dev on port 3000
	@echo   mcp-server-dev       uvicorn mcp.server on port 8004
	@echo.
	@echo   migrate              alembic upgrade head [backend only]
	@echo   migrate-sql          Render migrations as SQL without a database
	@echo   migrate-create       alembic revision --autogenerate m=your-message
	@echo   migrate-down         alembic downgrade -1
	@echo   migrate-history      alembic history --verbose
	@echo.
	@echo   lint / format / typecheck / test    Fan out to every module
	@echo   check                lint typecheck test
	@echo   verify               Probe every health endpoint [needs the stack up]
	@echo   clean                Remove venvs, caches, node_modules, .next

env:
	@$(ENSURE_ENV)

# ------------------------------------------------------------------ install --

install: contracts-check backend-install ai-engine-install mcp-server-install frontend-install
	@echo All modules installed into their own virtualenvs.

# contracts has no venv of its own: it is installed into backend and ai.engine
# as a path dependency, so this only validates the manifest.
contracts-check:
	cd $(CONTRACTS) && poetry check

backend-install:
	cd $(BACKEND) && poetry install --with dev

ai-engine-install:
	cd $(AI_ENGINE) && poetry install --with dev

mcp-server-install:
	cd $(MCP_SERVER) && poetry install --with dev

frontend-install:
	cd $(FRONTEND) && pnpm install

lock:
	cd $(CONTRACTS) && poetry lock
	cd $(BACKEND) && poetry lock
	cd $(AI_ENGINE) && poetry lock
	cd $(MCP_SERVER) && poetry lock
	cd $(FRONTEND) && pnpm install --lockfile-only

# ---------------------------------------------------------------------- dev --

dev:
	$(MAKE) -j5 backend-dev ai-engine-dev backend-worker frontend-dev mcp-server-dev

backend-dev:
	cd $(BACKEND) && poetry run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

backend-worker:
	cd $(BACKEND) && poetry run arq app.tasks.worker.WorkerSettings --watch app

ai-engine-dev:
	cd $(AI_ENGINE) && poetry run uvicorn app.main:app --reload --host 0.0.0.0 --port 8003

frontend-dev:
	cd $(FRONTEND) && pnpm dev

mcp-server-dev:
	cd $(MCP_SERVER) && poetry run uvicorn app.server:app --reload --host 0.0.0.0 --port 8004

# ------------------------------------------------------------------ compose --

up: env
	docker compose up -d --build

down:
	docker compose down

down-v:
	docker compose down -v

build:
	docker compose build

logs:
	docker compose logs -f

ps:
	docker compose ps

# --------------------------------------------------------------- migrations --
# Alembic lives in the backend only. The backend owns all database logic.

migrate:
	cd $(BACKEND) && poetry run alembic upgrade head

migrate-sql:
	cd $(BACKEND) && poetry run alembic upgrade head --sql

migrate-create:
ifndef m
	$(error Provide a message: make migrate-create m="add findings index")
endif
	cd $(BACKEND) && poetry run alembic revision --autogenerate -m "$(m)"

migrate-down:
	cd $(BACKEND) && poetry run alembic downgrade -1

migrate-history:
	cd $(BACKEND) && poetry run alembic history --verbose

# ------------------------------------------------------------------ quality --

lint: backend-lint ai-engine-lint mcp-server-lint frontend-lint

# contracts borrows the backend's ruff binary: it has no venv of its own, and its
# types are checked transitively by both consumers through py.typed.
backend-lint:
	cd $(BACKEND) && poetry run ruff check ../$(CONTRACTS)
	cd $(BACKEND) && poetry run ruff check .

ai-engine-lint:
	cd $(AI_ENGINE) && poetry run ruff check .

mcp-server-lint:
	cd $(MCP_SERVER) && poetry run ruff check .

frontend-lint:
	cd $(FRONTEND) && pnpm lint

format:
	cd $(BACKEND) && poetry run ruff format ../$(CONTRACTS) && poetry run ruff check --fix ../$(CONTRACTS)
	cd $(BACKEND) && poetry run ruff format . && poetry run ruff check --fix .
	cd $(AI_ENGINE) && poetry run ruff format . && poetry run ruff check --fix .
	cd $(MCP_SERVER) && poetry run ruff format . && poetry run ruff check --fix .
	cd $(FRONTEND) && pnpm format

typecheck: backend-typecheck ai-engine-typecheck mcp-server-typecheck frontend-typecheck

backend-typecheck:
	cd $(BACKEND) && poetry run mypy

ai-engine-typecheck:
	cd $(AI_ENGINE) && poetry run mypy

mcp-server-typecheck:
	cd $(MCP_SERVER) && poetry run mypy

frontend-typecheck:
	cd $(FRONTEND) && pnpm typecheck

test: backend-test ai-engine-test mcp-server-test frontend-build

backend-test:
	cd $(BACKEND) && poetry run pytest -q

ai-engine-test:
	cd $(AI_ENGINE) && poetry run pytest -q

mcp-server-test:
	cd $(MCP_SERVER) && poetry run pytest -q

frontend-build:
	cd $(FRONTEND) && pnpm build

check: lint typecheck test

verify:
	@$(VERIFY)

clean:
	@$(CLEAN)
