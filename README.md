# Cybersecurity Agents Platform

A modular defensive security platform. It ingests output from security tools you
already run, interprets it with rules plus LLM reasoning, correlates findings
into incidents, and surfaces them to an analyst.

Four detection agents share one pipeline:

| Agent | Ingests | Produces |
| --- | --- | --- |
| Vulnerability assessment | Nmap, OpenVAS, Trivy | CVE correlation, remediation priority |
| Phishing detection | Emails, URLs, domains | SPF/DKIM/DMARC alignment, reputation, verdict |
| Network traffic analysis | NetFlow, Zeek, Suricata | Anomalies, DDoS and DNS floods, beaconing |
| Web application | ZAP, Nuclei | OWASP Top 10 findings |

**Everything an agent ingests is untrusted data, never instructions.** Email
bodies, HTTP responses, and log fields are attacker-controllable. The boundary is
enforced in one place: `ai.engine/ai_engine/agents/common/untrusted.py`. Nothing
reaches a prompt without passing through it.

> **This repository is at Phase 1: scaffolding.** Every module boots, every
> health endpoint answers, every agent graph compiles - and no detection logic,
> no live LLM call, and no MCP tool exists yet. See
> [Deferred](#deferred-past-phase-1).

---

## Architecture

One project folder, four independent modules. Each module manages **its own
dependencies in its own virtualenv**. Nothing is shared through a venv - the
modules are tied together only by the root `Makefile` and `docker-compose.yml`.

```
                                 ┌──────────────┐
   security tools ──────────────► │   backend    │ :8000
   (nmap, zap, zeek, mail)        │              │
                                  │  owns ALL    │◄──── frontend :3000
                                  │  persistence │
                                  └──┬────────┬──┘
                                     │        │
                       PostgreSQL ◄──┘        └──► ai.engine :8003
                       Redis (arq)                 LangGraph agents
                                                   no database at all
                                  mcpserver :8004  (stub)
```

| Module | Port | Stack | Package manager |
| --- | --- | --- | --- |
| `backend/` | **8000** | FastAPI, SQLAlchemy 2.0 async, asyncpg, Alembic, arq | Poetry (`backend/.venv`) |
| `ai.engine/` | **8003** | FastAPI, LangChain, LangGraph, `langchain-openai` | Poetry (`ai.engine/.venv`) |
| `frontend/` | **3000** | Next.js App Router, React, TypeScript | pnpm (`frontend/node_modules`) |
| `mcpserver/` | **8004** | MCP Python SDK over Streamable HTTP | Poetry (`mcpserver/.venv`) |
| `contracts/` | – | The shared `Finding` schema, pydantic only | consumed as a path dependency |

Shared infrastructure runs as containers: PostgreSQL and Redis. Background and
scheduled jobs run through **arq** inside the backend.

### Data flow

1. A security tool's output arrives at the **backend** (`:8000`), which
   normalises and stores it.
2. The backend calls an **ai.engine** agent endpoint (`:8003`) - inline, or via
   an arq job when the run is long.
3. The ai.engine runs that agent's LangGraph graph and returns `Finding` objects.
4. The backend persists them, correlates them (later phase), and serves the
   **frontend** (`:3000`).

**The ai.engine never touches the database.** When it needs platform state it
calls the backend over HTTP. This is enforced by a test, not by convention:
`ai.engine/tests/test_no_database_imports.py` parses every module under
`ai_engine/` and fails on any database import, and checks the declared
dependencies too.

### The `Finding` contract

Both services exchange one shape, defined once in `contracts/` and installed
into each module's **own** virtualenv as a Poetry path dependency
(`develop = true`). One definition, two virtualenvs, no drift. The backend's
`tests/test_finding_contract.py` is the guard that the database table keeps up
with it.

Because of the path dependency, the backend and ai.engine Docker builds use the
**repository root** as their build context (`dockerfile: backend/Dockerfile`).

---

## Prerequisites

| Tool | Min Version | Required for |
| --- | --- | --- |
| Python | **3.12+** | backend, ai.engine, mcpserver, contracts |
| Poetry | **2.x** | all Python modules (dependency management) |
| Node.js | **≥ 20.9** | frontend |
| pnpm | **11.x** | frontend |
| Docker + Compose v2 | any recent | `make up` (PostgreSQL, Redis, all services) |
| GNU make | **4.x** | all `make *` targets |

### Install on Debian / Kali / Ubuntu Linux

**Python 3.12+**
```bash
sudo apt-get install -y python3 python3-pip python3-venv
python3 --version   # must be ≥ 3.12
```

**Poetry 2.x** (official installer — do NOT use `apt`, it ships an old version)
```bash
curl -sSL https://install.python-poetry.org | python3 -
# Add Poetry to PATH (add this line to ~/.bashrc or ~/.zshrc too)
export PATH="$HOME/.local/bin:$PATH"
poetry --version   # should print Poetry (version 2.x.x)
```

**Node.js ≥ 20.9** (via NodeSource)
```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs
node --version   # must be ≥ 20.9
```

**pnpm 11.x**
```bash
corepack enable pnpm
pnpm --version
# Or if corepack is unavailable:
npm install -g pnpm@11
```

**Docker + Compose v2**
```bash
sudo apt-get update
sudo apt-get install -y docker.io docker-compose-v2
sudo systemctl enable --now docker
# Allow running docker without sudo (requires logout/login to take effect):
sudo usermod -aG docker $USER
newgrp docker   # activate the group in the current session without logout
docker --version
docker compose version
```

**GNU make**
```bash
sudo apt-get install -y make
make --version   # must be ≥ 4.x
```

### Install on Windows

Open PowerShell as Administrator:

```powershell
# Python
winget install Python.Python.3.12

# Poetry
(Invoke-WebRequest -Uri https://install.python-poetry.org -UseBasicParsing).Content | python -

# Node.js
winget install OpenJS.NodeJS.LTS

# pnpm
corepack enable pnpm

# Docker Desktop (includes Compose v2)
winget install Docker.DockerDesktop

# GNU make
winget install ezwinports.make
```

> **Important:** Open a **new** shell after installing — the installers extend
> `PATH` and an already-open session will not see `poetry`, `pnpm`, or `make`.

---

## One-command setup

```bash
make env        # create .env from .env.example
make install    # install every module into its OWN venv
make up         # db, redis, backend, ai-engine, worker, frontend, mcpserver
make migrate    # apply the baseline migration
make verify     # probe every health endpoint
```

Then:

- <http://localhost:3000> – landing page, reads the backend's `/health`
- <http://localhost:8000/docs> – backend OpenAPI
- <http://localhost:8003/docs> – ai.engine OpenAPI, one route per agent
- <http://localhost:8004/health> – mcpserver liveness (its MCP endpoint is `/mcp`)

Running without Docker? `make install`, point `DATABASE_URL` and `REDIS_URL` at
your own PostgreSQL and Redis, then `make dev` (or the individual `make dev-*`
targets, one per terminal).

---

## Make targets

| Target | Does |
| --- | --- |
| `env` | Create `.env` from `.env.example` if missing |
| `install` | Install all five modules, each into its own venv |
| `lock` | Refresh every lockfile |
| `dev` | Run all five processes in parallel |
| `dev-backend` / `dev-ai-engine` / `dev-worker` / `dev-frontend` / `dev-mcpserver` | One process each |
| `up` / `down` / `down-v` / `build` / `logs` / `ps` | Docker Compose |
| `migrate` | `alembic upgrade head` (backend) |
| `migrate-sql` | Render migrations as SQL with no database |
| `revision m="..."` | `alembic revision --autogenerate` |
| `downgrade` | Roll back one revision |
| `lint` / `format` / `typecheck` / `test` | Fan out to every module |
| `check` | `lint typecheck test` |
| `verify` | Probe every health endpoint (stack must be up) |
| `clean` | Remove venvs, caches, `node_modules`, `.next` |

Every target changes into the module directory and uses **that module's** venv.

---

## Configuration

All configuration is environment variables; nothing is committed. See
[`.env.example`](.env.example) for the annotated list.

The LLM is fully reconfigurable without code changes. `langchain-openai`'s
`ChatOpenAI` is the single interface and OpenAI's hosted API is the default
provider:

```bash
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4.1-mini
OPENAI_BASE_URL=            # empty = OpenAI; set for any OpenAI-compatible endpoint
```

The model is constructed lazily and cached. Phase 1 builds it and never calls it,
so the stack boots fine with no API key at all - `GET :8003/health` reports the
resolved configuration (never the key).

One other setting is easy to trip over: the MCP SDK rejects unexpected `Host` and
`Origin` headers as DNS-rebinding protection and answers `421 Misdirected
Request`. `MCP_ALLOWED_HOSTS` and `MCP_ALLOWED_ORIGINS` default to
localhost / 127.0.0.1 / the `mcpserver` service name on `MCP_PORT`; set them
explicitly for any real deployment hostname.

---

## Database

The backend owns **all** persistence and **all** migrations. No other module
contains a database library.

- Async throughout: SQLAlchemy 2.0 + asyncpg, engine created lazily so imports
  never open a socket.
- Alembic is async (`alembic/env.py`) and takes its URL from
  `app.core.config`, so the database location is defined in exactly one place.
- One baseline migration, `0001_baseline-findings`, creates the `findings` table.

`agent` and `severity` are `VARCHAR` with `CHECK` constraints rather than native
PostgreSQL enums: the Python `StrEnum` in `contracts/` stays the single
validator, and adding a severity level later is a constraint swap instead of an
`ALTER TYPE`.

---

## Adding an agent

Each agent is a self-contained LangGraph package under
`ai.engine/ai_engine/agents/`, always the same five modules:

```
state.py    the graph's state schema
prompts.py  prompt text, isolated from graph wiring
tools.py    tools the agent may call
nodes.py    node functions
graph.py    the StateGraph, its edges, and the compiled graph
```

`agents/vulnerability/` is the reference implementation - its graph is wired
explicitly so the pattern is readable in one file. The other three build the same
shape through `agents/common/graph.py`. Each agent sits behind its own router in
`ai_engine/routers/`, mounted at `POST /agents/<name>/analyze`.

---

## What the Phase 1 checks actually prove

`make lint`, `make typecheck`, and `make test` are clean across every module
(ruff, mypy `strict`, 50 tests, plus `tsc --noEmit` and `next build`). Beyond the
obvious, a few tests exist specifically to stop the architecture eroding:

| Test | Guards |
| --- | --- |
| `ai.engine/tests/test_no_database_imports.py` | ai.engine stays free of database code, in source *and* in declared dependencies |
| `ai.engine/tests/test_agent_routers.py` | Every agent response validates against the shared `FindingBatch` with `extra="forbid"` |
| `ai.engine/tests/test_graphs.py` | All four graphs compile and run; untrusted input reaches the prompt only fenced |
| `backend/tests/test_finding_contract.py` | The `findings` columns still match the shared contract exactly |
| `backend/tests/test_migrations.py` | The baseline migration's DDL matches the ORM model, rendered offline with no database |
| `mcpserver/tests/test_server.py` | A real MCP `initialize` handshake succeeds over Streamable HTTP |

Two things cannot be checked without infrastructure: `GET /health/db` and the
findings routes need PostgreSQL, and the arq worker needs Redis. `make up`
provides both.

## Deferred past Phase 1

Marked `TODO(phase-2)` in the code:

- Real parsers for Nmap, OpenVAS, Trivy, ZAP, Nuclei, Zeek, Suricata, and MIME
- Live LLM reasoning and tool binding (the graphs assemble prompts and stop)
- Actual MCP tools (`mcpserver` registers one descriptive tool and nothing else)
- The correlation engine that groups findings into incidents
- Authentication, RBAC, and audit beyond the placeholder in `core/security.py`
- Threat-intel integrations, ML models, network baselining
- Any dashboard beyond the health-check page
