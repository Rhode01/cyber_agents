# Cybersecurity Agents Platform - root Makefile.
#
# Every target delegates into a module and uses that module's OWN virtualenv.
# Virtualenvs are never shared: backend/.venv, ai.engine/.venv, mcpserver/.venv,
# and frontend/node_modules are all independent.

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

.PHONY: help env install install-contracts install-backend install-ai-engine \
        install-mcpserver install-frontend lock \
        dev dev-backend dev-ai-engine dev-worker dev-frontend dev-mcpserver \
        up down down-v build logs ps \
        migrate migrate-sql revision downgrade \
        lint lint-contracts lint-backend lint-ai-engine lint-mcpserver lint-frontend \
        format typecheck typecheck-backend typecheck-ai-engine typecheck-mcpserver typecheck-frontend \
        test test-backend test-ai-engine test-mcpserver test-frontend \
        check verify clean

# ---------------------------------------------------------------- help / env --

help:
	@echo Cybersecurity Agents Platform - available targets
	@echo.
	@echo   env                Create .env from .env.example if missing
	@echo   install            Install every module into its own venv
	@echo   lock               Refresh every lockfile
	@echo.
	@echo   dev                Run all five processes locally in parallel
	@echo   dev-backend        uvicorn backend on port 8000
	@echo   dev-ai-engine      uvicorn ai.engine on port 8003
	@echo   dev-worker         arq worker against Redis
	@echo   dev-frontend       next dev on port 3000
	@echo   dev-mcpserver      uvicorn mcpserver on port 8004
	@echo.
	@echo   up                 docker compose up -d --build
	@echo   down               docker compose down
	@echo   down-v             docker compose down -v [drops the database volume]
	@echo   build              docker compose build
	@echo   logs               docker compose logs -f
	@echo   ps                 docker compose ps
	@echo.
	@echo   migrate            alembic upgrade head [backend only]
	@echo   migrate-sql        Render migrations as SQL without a database
	@echo   revision           alembic revision --autogenerate m=your-message
	@echo   downgrade          alembic downgrade -1
	@echo.
	@echo   lint               ruff check + next lint, every module
	@echo   format             ruff format + ruff check --fix, every module
	@echo   typecheck          mypy + tsc --noEmit, every module
	@echo   test               pytest + next build, every module
	@echo   check              lint typecheck test
	@echo   verify             Probe every health endpoint [needs the stack up]
	@echo   clean              Remove venvs, caches, node_modules, .next

env:
	@$(ENSURE_ENV)

# ------------------------------------------------------------------ install --

install: install-contracts install-backend install-ai-engine install-mcpserver install-frontend
	@echo All modules installed into their own virtualenvs.

# The contracts package is consumed as a path dependency by backend and
# ai.engine, so it has no venv of its own - this target only sanity-checks it.
install-contracts:
	cd contracts && poetry check

install-backend:
	cd backend && poetry install --with dev

install-ai-engine:
	cd ai.engine && poetry install --with dev

install-mcpserver:
	cd mcpserver && poetry install --with dev

install-frontend:
	cd frontend && pnpm install

lock:
	cd contracts && poetry lock
	cd backend && poetry lock
	cd ai.engine && poetry lock
	cd mcpserver && poetry lock
	cd frontend && pnpm install --lockfile-only

# ---------------------------------------------------------------------- dev --

dev:
	$(MAKE) -j5 dev-backend dev-ai-engine dev-worker dev-frontend dev-mcpserver

dev-backend:
	cd backend && poetry run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

dev-ai-engine:
	cd ai.engine && poetry run uvicorn ai_engine.main:app --reload --host 0.0.0.0 --port 8003

dev-worker:
	cd backend && poetry run arq app.worker.settings.WorkerSettings --watch app

dev-frontend:
	cd frontend && pnpm dev

dev-mcpserver:
	cd mcpserver && poetry run uvicorn mcpserver.server:app --reload --host 0.0.0.0 --port 8004

# ------------------------------------------------------------------- compose --

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

# ------------------------------------------------------------------ migrations --
# Alembic lives in the backend only. The backend owns all database logic.

migrate:
	cd backend && poetry run alembic upgrade head

migrate-sql:
	cd backend && poetry run alembic upgrade head --sql

revision:
ifndef m
	$(error Provide a message: make revision m="add findings index")
endif
	cd backend && poetry run alembic revision --autogenerate -m "$(m)"

downgrade:
	cd backend && poetry run alembic downgrade -1

# ------------------------------------------------------------------ quality --

lint: lint-contracts lint-backend lint-ai-engine lint-mcpserver lint-frontend

# contracts has no venv of its own, so it borrows the backend's ruff binary.
# Its types are checked transitively: both consumers mypy it through py.typed.
lint-contracts:
	cd backend && poetry run ruff check ../contracts

lint-backend:
	cd backend && poetry run ruff check .

lint-ai-engine:
	cd ai.engine && poetry run ruff check .

lint-mcpserver:
	cd mcpserver && poetry run ruff check .

lint-frontend:
	cd frontend && pnpm lint

format:
	cd backend && poetry run ruff format ../contracts && poetry run ruff check --fix ../contracts
	cd backend && poetry run ruff format . && poetry run ruff check --fix .
	cd ai.engine && poetry run ruff format . && poetry run ruff check --fix .
	cd mcpserver && poetry run ruff format . && poetry run ruff check --fix .
	cd frontend && pnpm format

typecheck: typecheck-backend typecheck-ai-engine typecheck-mcpserver typecheck-frontend

typecheck-backend:
	cd backend && poetry run mypy

typecheck-ai-engine:
	cd ai.engine && poetry run mypy

typecheck-mcpserver:
	cd mcpserver && poetry run mypy

typecheck-frontend:
	cd frontend && pnpm typecheck

test: test-backend test-ai-engine test-mcpserver test-frontend

test-backend:
	cd backend && poetry run pytest -q

test-ai-engine:
	cd ai.engine && poetry run pytest -q

test-mcpserver:
	cd mcpserver && poetry run pytest -q

test-frontend:
	cd frontend && pnpm build

check: lint typecheck test

verify:
	@$(VERIFY)

clean:
	@$(CLEAN)
