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

# Scanners the agents launch themselves (MVP): nmap for hosts, nuclei for web
# apps, dig/curl for phishing URL checks. The test hosts used by the agents are
# safe, but the platform is a scanning tool by design.
RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 \
        nmap \
        dnsutils \
        curl \
        unzip \
        ca-certificates \
    && NUCLEI_VER="3.3.10" \
    && curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_amd64.zip" -o /tmp/nuclei.zip \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin \
    && rm -f /tmp/nuclei.zip \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN groupadd --system app && useradd --system --gid app --home-dir /src app

WORKDIR /src/ai.engine

COPY contracts /src/contracts
COPY ai.engine /src/ai.engine
COPY --from=builder /src/ai.engine/.venv /src/ai.engine/.venv

RUN chown -R app:app /src
USER app

# Nuclei ships without templates; fetch the official set so the webapp agent's
# self-launched scans can actually detect anything. Nuclei resolves its template
# store to $HOME/nuclei-templates (HOME=/src for the app user), so install there
# rather than in the config dir.
RUN mkdir -p /src/nuclei-templates \
    && nuclei -update-templates -silent \
    && test -n "$(ls -A /src/nuclei-templates)"

EXPOSE 8003

CMD ["uvicorn", "ai_engine.main:app", "--host", "0.0.0.0", "--port", "8003"]
