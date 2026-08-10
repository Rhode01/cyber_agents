# Cybersecurity Agents Platform

A modular defensive security platform. It discovers what is reachable, runs
four LLM-driven detection agents over it, correlates the results into
findings, and surfaces them to an analyst through a live dashboard.

Four detection agents share one pipeline:

| Agent | Ingests | Produces |
| --- | --- | --- |
| Vulnerability assessment | Nmap, OpenVAS, Trivy | CVE correlation, remediation priority |
| Phishing detection | Emails, URLs, domains | SPF/DKIM/DMARC alignment, reputation, verdict |
| Network traffic analysis | NetFlow, Zeek, Suricata | Anomalies, DDoS and DNS floods, beaconing |
| Web application | ZAP, Nuclei | OWASP Top 10 findings |

**Everything an agent ingests is untrusted data, never instructions.** Email
bodies, HTTP responses, and log fields are attacker-controllable. The boundary is
enforced in one place: `cyber.ai.engine/app/agents/common/untrusted.py`. Nothing
reaches a prompt without passing through it.

The MVP pipeline is live end to end: the frontend launches a run, the backend
persists it, ai.engine discovers the device's own interfaces and probes them,
the four agent graphs reason over the results (live LLM with a graceful
no-key fallback), and findings land back on the dashboard.

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
                                                  + nmap, nuclei on the host
                                  mcpserver :8004  (stub)
```

| Module | Port | Stack | Package manager |
| --- | --- | --- | --- |
| `cyber.backend/` | **8000** | FastAPI, SQLAlchemy 2.0 async, asyncpg, Alembic, arq | Poetry (`cyber.backend/.venv`) |
| `cyber.ai.engine/` | **8003** | FastAPI, LangChain, LangGraph, `langchain-openai` / `langchain-anthropic` | Poetry (`cyber.ai.engine/.venv`) |
| `cyber.frontend/` | **3000** | Next.js App Router, React, TypeScript, Tailwind | pnpm (`cyber.frontend/node_modules`) |
| `cyber.mcp.server/` | **8004** | MCP Python SDK over Streamable HTTP | Poetry (`cyber.mcp.server/.venv`) |
| `cyber.contracts/` | – | Shared `Finding` and `DiscoveryReport` schemas, pydantic only | consumed as a path dependency |

### Layout

One directory per deployable service, named `cyber.<service>`. Every Python
service uses `app` as its package name and the same internal shape, so moving
between them costs nothing:

```
cyber.<service>/
├── pyproject.toml  poetry.toml  poetry.lock  Dockerfile
└── app/
    ├── main.py                 FastAPI app factory      (server.py in mcp.server)
    ├── api/
    │   ├── deps.py             shared route dependencies
    │   └── v1/
    │       ├── api.py          the aggregate router
    │       └── endpoints/      one module per resource
    ├── core/                   config, logging, security
    ├── schemas/                pydantic DTOs
    ├── services/               outbound clients and domain logic
    └── tasks/                  background work (arq)
```

The backend adds `crud/` (one `crud_<model>.py` per model over a shared
`CRUDBase`), `db/`, `models/` and `alembic/`. The ai.engine adds `agents/<name>/`
(`graph`, `nodes`, `state`, `prompt`, `tools`), `parsers/`, `discovery/` and
`llm/`. The frontend follows the same idea under `src/`: `app/`, `components/`,
`lib/`, `types/`. Tests live in `tests/unit/` with shared fixtures in
`tests/conftest.py`.

Deployment config lives in `infrastructure/`, away from application code.

Shared infrastructure runs as containers: PostgreSQL and Redis. Background and
scheduled jobs run through **arq** inside the backend. The ai.engine image ships
`nmap` and `nuclei` so the agents can launch their own scans.

### Data flow

1. The frontend creates a **run** (a scan target + mode) on the backend
   (`:8000`), which persists it.
2. **Discovery** runs on the ai.engine host (`POST /discovery/run`): it
   enumerates the device's own network interfaces and probes their addresses -
   it never sweeps the subnet. A light `nmap -Pn -sV` pass reports
   services, products, and versions for the Services Active page.
3. The backend calls an **ai.engine** agent endpoint (`:8003`) - inline, or via
   an arq job when the run is long.
4. The ai.engine runs that agent's LangGraph graph and returns `Finding` objects.
5. The backend persists them, associates them with the run, and serves the
   **frontend** (`:3000`).

**The ai.engine never touches the database.** When it needs platform state it
calls the backend over HTTP. This is enforced by a test, not by convention:
`cyber.ai.engine/tests/unit/test_no_database_imports.py` parses every module under
`app/` and fails on any database import, and checks the declared
dependencies too.

### The shared contracts

Both services exchange shapes defined once in `cyber.contracts/` and installed into
each module's **own** virtualenv as a Poetry path dependency
(`develop = true`). One definition, two virtualenvs, no drift. The backend's
`tests/unit/test_finding_contract.py` is the guard that the database table keeps up
with `Finding`; `cyber.ai.engine/tests/unit/test_discovery.py` guards `DiscoveryReport` and
its `ServicePort` rows.

Because of the path dependency, the backend and ai.engine Docker builds use the
**repository root** as their build context (`dockerfile: cyber.backend/Dockerfile`).

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

`nmap` (and optionally `nuclei`) must be on the ai.engine host or baked into its
image - the Docker image installs them automatically. When `nmap` is missing,
discovery degrades to TCP probing and reports the services it could reach.

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

- <http://localhost:3000> – Detection Overview: quick auto-scan, severity and
  agent coverage, latest detections, recent scans, live module map
- <http://localhost:3000/run> – Run Agent: configure and launch the pipeline
- <http://localhost:3000/services> – Services Active: hosts, ports, services,
  versions, and per-service findings from discovery
- <http://localhost:3000/scans> – scan history
- <http://localhost:3000/settings/email-connect> – Gmail / Microsoft 365 /
  IMAP email integration for the phishing agent
- <http://localhost:8000/docs> – backend OpenAPI
- <http://localhost:8003/docs> – ai.engine OpenAPI, one route per agent
- <http://localhost:8004/health> – mcpserver liveness (its MCP endpoint is `/mcp`)

Running without Docker? `make install`, point `DATABASE_URL` and `REDIS_URL` at
your own PostgreSQL and Redis, then `make dev` (or the individual `make *-dev`
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

The LLM is fully reconfigurable without code changes. `ChatOpenAI` (OpenAI) and
`ChatAnthropic` are the supported backends, constructed lazily and cached:

```bash
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4.1-mini
OPENAI_BASE_URL=            # empty = OpenAI; set for any OpenAI-compatible endpoint

ANTHROPIC_API_KEY=          # optional second provider
ANTHROPIC_MODEL=
```

Each agent reasons over its inputs and produces findings; if no API key is
present the graph degrades gracefully and emits findings from its deterministic
rules alone. `GET :8003/health` reports the resolved configuration (never the
key).

The MCP SDK rejects unexpected `Host` and `Origin` headers as DNS-rebinding
protection and answers `421 Misdirected Request`. `MCP_ALLOWED_HOSTS` and
`MCP_ALLOWED_ORIGINS` default to localhost / 127.0.0.1 / the `mcpserver` service
name on `MCP_PORT`; set them explicitly for any real deployment hostname.

Email integration is configured from the UI (Settings → Email Integration) and
stored encrypted in the `settings` table; no credentials are committed.

---

## Database

The backend owns **all** persistence and **all** migrations. No other module
contains a database library.

- Async throughout: SQLAlchemy 2.0 + asyncpg, engine created lazily so imports
  never open a socket.
- Alembic is async (`alembic/env.py`) and takes its URL from
  `app.core.config`, so the database location is defined in exactly one place.
- Migrations (`cyber.backend/alembic/versions/`): `0001` baseline findings, `0002`
  scan intake + finding detail (evidence, asset, agent trace), `0003` finding
  indexes, `0004` settings table, `0005` CVE IDs as a text array, `0006` runs
  table, `0007` findings → run association.

`agent` and `severity` are `VARCHAR` with `CHECK` constraints rather than native
PostgreSQL enums: the Python `StrEnum` in `cyber.contracts/` stays the single
validator, and adding a severity level later is a constraint swap instead of an
`ALTER TYPE`.

---

## Discovery and the Services Active page

Discovery is deliberately scoped: it scans **only the addresses of the device
it runs on** (each interface's own IP plus `127.0.0.1`), never the surrounding
subnet. `cyber.ai.engine/app/discovery/tools.py`:

1. `list_interfaces()` – parses `ip -o -4 addr show`, discards loopback ranges,
   host-routed /32s, and oversized subnets.
2. TCP-probes the common web ports on those addresses.
3. Runs `nmap -Pn -sV -p <ports> --open` and parses the XML into
   `ServicePort` rows (service, product, version).

The report is exposed at `POST /discovery/run` and rendered on the Services
Active page (`/services`) with per-service findings, risk, and remediation
matched by host and port.

---

## Adding an agent

Each agent is a self-contained LangGraph package under
`cyber.ai.engine/app/agents/`, always the same five modules:

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
`ai_engine/routers/`, mounted at `POST /agents/<name>/analyze`. Discovery is not
an agent - it feeds the pipeline a target list - so it lives on its own router.

---

## What the checks actually prove

`make lint`, `make typecheck`, and `make test` are clean across every module
(ruff, mypy `strict`, plus `tsc --noEmit` and `next build`). Beyond the obvious,
a few tests exist specifically to stop the architecture eroding:

| Test | Guards |
| --- | --- |
| `cyber.ai.engine/tests/unit/test_no_database_imports.py` | ai.engine stays free of database code, in source *and* in declared dependencies |
| `cyber.ai.engine/tests/unit/test_agent_routers.py` | Every agent response validates against the shared `FindingBatch` with `extra="forbid"` |
| `cyber.ai.engine/tests/unit/test_graphs.py` | All four graphs compile and run; untrusted input reaches the prompt only fenced |
| `cyber.ai.engine/tests/unit/test_discovery.py` | Interface filtering, service parsing, and graceful degradation when `nmap` is missing |
| `cyber.ai.engine/tests/unit/test_llm_factory.py` | Provider selection, lazy construction, and the no-key fallback |
| `cyber.backend/tests/unit/test_finding_contract.py` | The `findings` columns still match the shared contract exactly |
| `cyber.backend/tests/unit/test_migrations.py` | The migrations' DDL matches the ORM models, rendered offline with no database |
| `cyber.backend/tests/unit/test_runs.py` / `test_discovery.py` | Run lifecycle and discovery proxy endpoints |
| `cyber.mcp.server/tests/unit/test_server.py` | A real MCP `initialize` handshake succeeds over Streamable HTTP |

Two things cannot be checked without infrastructure: `GET /health/db` and the
findings routes need PostgreSQL, and the arq worker needs Redis. `make up`
provides both.

## Deferred

Marked `TODO(phase-2)` in the code:

- Real MCP tools (`mcpserver` registers one descriptive tool and nothing else)
- The correlation engine that groups findings into incidents
- Authentication, RBAC, and audit beyond the placeholder in `core/security.py`
- Threat-intel integrations, ML models, network baselining
- Scheduled (non-interactive) runs and email auto-polling
