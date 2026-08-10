# Build context is the REPOSITORY ROOT, not backend/, so that the
# contracts/ path dependency resolves. See docker-compose.yml.
#
#   docker build -f backend/Dockerfile .

FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    POETRY_VERSION=2.4.1 \
    POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=1

RUN pip install "poetry==${POETRY_VERSION}"

WORKDIR /src/backend

# The path dependency is declared as ../contracts, so mirror the repo layout.
COPY contracts /src/contracts
COPY backend/pyproject.toml backend/poetry.lock backend/poetry.toml /src/backend/

RUN poetry install --only main --no-root

FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/src/backend/.venv/bin:${PATH}"

RUN groupadd --system app && useradd --system --gid app --home-dir /src app

WORKDIR /src/backend

COPY contracts /src/contracts
COPY backend /src/backend
COPY --from=builder /src/backend/.venv /src/backend/.venv

RUN chown -R app:app /src
USER app

EXPOSE 8000

# The worker service overrides this with: arq app.worker.settings.WorkerSettings
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
