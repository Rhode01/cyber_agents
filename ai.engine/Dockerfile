# Build context is the REPOSITORY ROOT, not ai.engine/, so that the
# contracts/ path dependency resolves. See docker-compose.yml.
#
#   docker build -f ai.engine/Dockerfile .

FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    POETRY_VERSION=2.4.1 \
    POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=1

RUN pip install "poetry==${POETRY_VERSION}"

WORKDIR /src/ai.engine

COPY contracts /src/contracts
COPY ai.engine/pyproject.toml ai.engine/poetry.lock ai.engine/poetry.toml /src/ai.engine/

RUN poetry install --only main --no-root

FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/src/ai.engine/.venv/bin:${PATH}"

RUN groupadd --system app && useradd --system --gid app --home-dir /src app

WORKDIR /src/ai.engine

COPY contracts /src/contracts
COPY ai.engine /src/ai.engine
COPY --from=builder /src/ai.engine/.venv /src/ai.engine/.venv

RUN chown -R app:app /src
USER app

EXPOSE 8003

CMD ["uvicorn", "ai_engine.main:app", "--host", "0.0.0.0", "--port", "8003"]
