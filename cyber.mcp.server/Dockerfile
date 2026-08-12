# Build context is app/ - this module has no path dependencies.

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

# nmap is the scanner behind the nmap_service_scan tool. Tool execution lives in
# this service, so the binary lives in this image. The ai.engine image also
# carries nmap, deliberately: it needs one for self-discovery of its own
# interfaces, which is not an agent tool and does not come through MCP.
RUN apt-get update \
 && apt-get install --no-install-recommends -y \
      nmap \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN groupadd --system app && useradd --system --gid app --home-dir /src app

WORKDIR /src

COPY . /src
COPY --from=builder /src/.venv /src/.venv

RUN chown -R app:app /src
USER app

EXPOSE 8004

CMD ["uvicorn", "app.server:app", "--host", "0.0.0.0", "--port", "8004"]
