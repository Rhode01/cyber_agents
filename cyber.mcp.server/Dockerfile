# Build context is mcpserver/ - this module has no path dependencies.

FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    POETRY_VERSION=2.4.1 \
    POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=1

RUN pip install "poetry==${POETRY_VERSION}"

WORKDIR /src

COPY pyproject.toml poetry.lock poetry.toml /src/

RUN poetry install --only main --no-root

FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/src/.venv/bin:${PATH}"

RUN groupadd --system app && useradd --system --gid app --home-dir /src app

WORKDIR /src

COPY . /src
COPY --from=builder /src/.venv /src/.venv

RUN chown -R app:app /src
USER app

EXPOSE 8004

CMD ["uvicorn", "mcpserver.server:app", "--host", "0.0.0.0", "--port", "8004"]
